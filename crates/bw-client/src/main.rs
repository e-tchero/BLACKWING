//! BLACKWING client — native viewer shell with a video rendering loop.
//!
//! Opens a window via `winit`, renders decoded video frames into a `pixels`
//! pixel buffer, and presents it on every redraw. The video source is a
//! background Tokio task that generates dummy RGB frames, standing in for the
//! QUIC network receiver until the client is fully wired (TASK-104/105).

#![allow(clippy::unwrap_used, clippy::expect_used)]
// ^ Justification: this is a binary crate; fatal errors during window / pixel
//   buffer setup and rendering are reported by panicking with a message, which
//   is the standard convention for native application entry points. This
//   override is scoped to the binary target only.

use std::sync::Arc;
use std::sync::mpsc;

use bw_decoder::DecodedImage;
use bw_protocol::message::ProtocolMessage;
use pixels::{Pixels, PixelsBuilder, SurfaceTexture};
use winit::application::ApplicationHandler;
use winit::dpi::PhysicalSize;
use winit::event::{DeviceEvent, DeviceId, ElementState, MouseButton, WindowEvent};
use winit::event_loop::{ActiveEventLoop, EventLoop};
use winit::keyboard::PhysicalKey;
use winit::window::{Window, WindowAttributes, WindowId};

/// Initial window width in physical pixels.
const WINDOW_WIDTH: u32 = 1280;
/// Initial window height in physical pixels.
const WINDOW_HEIGHT: u32 = 720;
/// The virtual viewport width that decoder frames are produced at.
const VIEW_WIDTH: u32 = 320;
/// The virtual viewport height that decoder frames are produced at.
const VIEW_HEIGHT: u32 = 180;

/// Application state for the winit event loop.
struct App {
    /// The main window, leaked to `'static` so the pixel buffer can borrow it.
    window: Option<&'static Arc<Window>>,
    /// The pixel buffer and GPU surface, sized to the window.
    pixels: Option<Pixels<'static>>,
    /// Channel carrying decoded frames from the (simulated) network receiver.
    frame_rx: mpsc::Receiver<DecodedImage>,
    /// The most recent decoded frame, ready to be blitted.
    last_image: Option<DecodedImage>,
    /// Channel carrying captured input messages to the (simulated) QUIC sender.
    input_tx: tokio::sync::mpsc::Sender<ProtocolMessage>,
    /// Held receiver keeps the input channel alive until the network sender
    /// is wired up.
    _input_rx: tokio::sync::mpsc::Receiver<ProtocolMessage>,
    /// Current mouse button state: bit 0 = left, bit 1 = right, bit 2 = middle.
    buttons_mask: u8,
}

impl App {
    /// Creates the application state with a frame receiver.
    fn new(frame_rx: mpsc::Receiver<DecodedImage>) -> Self {
        let (input_tx, _input_rx) = tokio::sync::mpsc::channel::<ProtocolMessage>(256);
        Self {
            window: None,
            pixels: None,
            frame_rx,
            last_image: None,
            input_tx,
            _input_rx,
            buttons_mask: 0,
        }
    }

    /// Sends a captured input message to the (simulated) network sender,
    /// dropping it if the channel is full (backpressure).
    fn send_input(&self, message: ProtocolMessage) {
        let _ = self.input_tx.try_send(message);
    }

    /// Blits the latest decoded frame into the pixel buffer and presents it.
    fn render(&mut self) {
        // Drain the simulated network receiver, keeping only the newest frame.
        while let Ok(image) = self.frame_rx.try_recv() {
            self.last_image = Some(image);
        }

        let Some(pixels) = self.pixels.as_mut() else {
            return;
        };
        let Some(image) = self.last_image.as_ref() else {
            return;
        };

        blit_rgb_to_frame(pixels.frame_mut(), image);
        pixels.render().expect("failed to render pixel buffer");
    }
}

impl ApplicationHandler for App {
    fn resumed(&mut self, event_loop: &ActiveEventLoop) {
        // Guard against redundant `Resumed` events on some platforms.
        if self.pixels.is_some() {
            return;
        }

        let attrs = WindowAttributes::default()
            .with_title("BLACKWING Client")
            .with_inner_size(PhysicalSize::new(WINDOW_WIDTH, WINDOW_HEIGHT));
        let window = Arc::new(
            event_loop
                .create_window(attrs)
                .expect("failed to create window"),
        );

        // Leak the window handle so the pixel buffer can borrow it for the
        // lifetime of the process (a native app window lives until exit).
        let window: &'static Arc<Window> = Box::leak(Box::new(window));

        let surface = SurfaceTexture::new(WINDOW_WIDTH, WINDOW_HEIGHT, window);
        let pixels = PixelsBuilder::new(WINDOW_WIDTH, WINDOW_HEIGHT, surface)
            .build()
            .expect("failed to build pixel buffer");

        self.window = Some(window);
        self.pixels = Some(pixels);
        window.request_redraw();
    }

    fn window_event(
        &mut self,
        event_loop: &ActiveEventLoop,
        _window_id: WindowId,
        event: WindowEvent,
    ) {
        match event {
            WindowEvent::CloseRequested => event_loop.exit(),
            WindowEvent::Resized(size) => {
                if let Some(pixels) = self.pixels.as_mut() {
                    let _ = pixels.resize_surface(size.width, size.height);
                }
            }
            WindowEvent::RedrawRequested => {
                self.render();
                if let Some(window) = self.window {
                    window.request_redraw();
                }
            }
            WindowEvent::MouseInput { state, button, .. } => {
                // Update the button-state mask and report it to the server.
                if let Some(bit) = button_bit(button) {
                    if state == ElementState::Pressed {
                        self.buttons_mask |= bit;
                    } else {
                        self.buttons_mask &= !bit;
                    }
                }
                let message =
                    ProtocolMessage::mouse_event(0, 0, self.buttons_mask).expect("mouse event");
                self.send_input(message);
            }
            WindowEvent::KeyboardInput { event, .. } => {
                // Key repeats are redundant for a remote-control stream.
                if event.repeat {
                    return;
                }
                if let PhysicalKey::Code(code) = event.physical_key {
                    // winit 0.30 `KeyCode` is a fieldless enum; its discriminant is a stable
                    // per-key identifier (HID usage order). A full HID -> VK translation table
                    // is future work for the real input path.
                    let keycode = code as u32 as u16;
                    let is_down = event.state == ElementState::Pressed;
                    let message =
                        ProtocolMessage::keyboard_event(keycode, is_down).expect("keyboard event");
                    self.send_input(message);
                }
            }
            _ => {}
        }
    }

    fn device_event(
        &mut self,
        _event_loop: &ActiveEventLoop,
        _device_id: DeviceId,
        event: DeviceEvent,
    ) {
        if let DeviceEvent::MouseMotion { delta } = event {
            let message =
                ProtocolMessage::mouse_event(delta.0 as i32, delta.1 as i32, self.buttons_mask)
                    .expect("mouse event");
            self.send_input(message);
        }
    }
}

/// Copies an RGB8 image (3 bytes/pixel) into an RGBA8 pixel-buffer frame
/// (4 bytes/pixel), setting alpha to 255. Oversized sources are clipped.
fn blit_rgb_to_frame(frame: &mut [u8], image: &DecodedImage) {
    for (dst, src_px) in frame.chunks_exact_mut(4).zip(image.rgb.chunks_exact(3)) {
        dst[..3].copy_from_slice(src_px);
        dst[3] = 0xFF;
    }
}

/// Maps a winit mouse button to its bit in the protocol button-state mask.
///
/// Matches the TASK-103 bit convention: bit 0 = left, bit 1 = right,
/// bit 2 = middle.
fn button_bit(button: MouseButton) -> Option<u8> {
    match button {
        MouseButton::Left => Some(0b001),
        MouseButton::Right => Some(0b010),
        MouseButton::Middle => Some(0b100),
        // winit's MouseButton is #[non_exhaustive] (Back/Forward/Other exist).
        _ => None,
    }
}

/// Spawns a background Tokio task that emulates the QUIC network receiver,
/// producing dummy decoded frames at ~20 fps.
fn spawn_video_source() -> mpsc::Receiver<DecodedImage> {
    let (tx, rx) = mpsc::channel::<DecodedImage>();
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("failed to build tokio runtime");
        runtime.block_on(async move {
            let mut sequence: u32 = 0;
            loop {
                tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

                // Solid-color gradient frame so movement is visible.
                let mut rgb = vec![0u8; (VIEW_WIDTH * VIEW_HEIGHT * 3) as usize];
                for (i, px) in rgb.chunks_exact_mut(3).enumerate() {
                    let t = sequence.wrapping_add(i as u32);
                    px[0] = (t & 0xFF) as u8;
                    px[1] = ((t >> 3) & 0xFF) as u8;
                    px[2] = ((t >> 6) & 0xFF) as u8;
                }
                sequence = sequence.wrapping_add(1);

                let image = DecodedImage {
                    width: VIEW_WIDTH,
                    height: VIEW_HEIGHT,
                    rgb,
                };
                if tx.send(image).is_err() {
                    break; // Window closed; stop producing frames.
                }
            }
        });
    });
    rx
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let frame_rx = spawn_video_source();
    let event_loop = EventLoop::new()?;
    let mut app = App::new(frame_rx);
    event_loop.run_app(&mut app)?;
    Ok(())
}
