//! BLACKWING client — native viewer that connects to a running server.
//!
//! Wire flow:
//!
//! ```text
//! QUIC connect ── open bidi stream ── OPAQUE login (bw-session::wire)
//!   └── MessageSession ── split ── sender: queue captured input
//!                              └── receiver: decode video → winit window
//! ```
//!
//! Usage:
//!
//! ```text
//! bw-client --server 127.0.0.1:9000 --id <device-id> --password <password>
//! ```

#![allow(clippy::unwrap_used, clippy::expect_used)]
// ^ Justification: this is a binary crate; fatal errors during window / pixel
//   buffer setup and rendering are reported by panicking with a message, which
//   is the standard convention for native application entry points. This
//   override is scoped to the binary target only.

use std::sync::mpsc;
use std::sync::{Arc, Mutex};

use bw_audio::{AudioCodecConfig, AudioPlayback};
use bw_clipboard::{ClipboardImage, ClipboardManager};
use bw_decoder::DecodedImage;
use bw_decoder::DecoderPipeline;
use bw_protocol::dispatcher::{DispatchError, MessageDispatcher};
use bw_protocol::message::{ClipboardEvent, ClipboardFormat, MessageType, ProtocolMessage};
use bw_protocol::routing::{MessageEnvelope, NodeId, Route, SessionId};
use bw_protocol::session::SessionManager;
use bw_session::wire;
use bw_transport::QuicClient;
use bw_transport::adapter::QuicProtocolAdapter;
use pixels::{Pixels, PixelsBuilder, SurfaceTexture};
use winit::application::ApplicationHandler;
use winit::dpi::PhysicalSize;
use winit::event::{
    DeviceEvent, DeviceId as WinitDeviceId, ElementState, MouseButton, WindowEvent,
};
use winit::event_loop::{ActiveEventLoop, EventLoop};
use winit::keyboard::PhysicalKey;
use winit::window::{Window, WindowAttributes, WindowId};

/// Initial window width in physical pixels.
const WINDOW_WIDTH: u32 = 1280;
/// Initial window height in physical pixels.
const WINDOW_HEIGHT: u32 = 720;

/// Simple positional/flag argument parser.
struct Args {
    server: String,
    id: String,
    password: String,
    relay: Option<String>,
}

fn parse_args() -> Args {
    let mut server: Option<String> = None;
    let mut id: Option<String> = None;
    let mut password: Option<String> = None;
    let mut relay: Option<String> = None;

    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--server" => server = Some(it.next().expect("--server requires an address")),
            "--id" => id = Some(it.next().expect("--id requires a device id")),
            "--password" => {
                password = Some(it.next().expect("--password requires a value"));
            }
            "--relay" => relay = Some(it.next().expect("--relay requires a relay address")),
            "--help" | "-h" => {
                eprintln!("usage: bw-client --server ADDR --id ID --password PASS [--relay ADDR]");
                std::process::exit(0);
            }
            other => {
                eprintln!("unknown argument: {other}");
                std::process::exit(2);
            }
        }
    }
    Args {
        server: server.expect("--server is required"),
        id: id.expect("--id is required"),
        password: password.expect("--password is required"),
        relay,
    }
}

/// Application state for the winit event loop.
struct App {
    /// The main window, leaked to `'static` so the pixel buffer can borrow it.
    window: Option<&'static Arc<Window>>,
    /// The pixel buffer and GPU surface, sized to the window.
    pixels: Option<Pixels<'static>>,
    /// Channel carrying decoded frames from the network receiver.
    frame_rx: mpsc::Receiver<DecodedImage>,
    /// The most recent decoded frame, ready to be blitted.
    last_image: Option<DecodedImage>,
    /// Channel carrying captured input messages to the session sender task.
    input_tx: tokio::sync::mpsc::Sender<ProtocolMessage>,
    /// Current mouse button state: bit 0 = left, bit 1 = right, bit 2 = middle.
    buttons_mask: u8,
    /// Dispatcher that routes inbound messages (clipboard, audio) to handlers.
    _dispatcher: Arc<MessageDispatcher>,
}

impl App {
    /// Creates the application state with a frame receiver and input sender.
    fn new(
        frame_rx: mpsc::Receiver<DecodedImage>,
        input_tx: tokio::sync::mpsc::Sender<ProtocolMessage>,
        dispatcher: Arc<MessageDispatcher>,
    ) -> Self {
        Self {
            window: None,
            pixels: None,
            frame_rx,
            last_image: None,
            input_tx,
            buttons_mask: 0,
            _dispatcher: dispatcher,
        }
    }

    /// Sends a captured input message to the session sender, dropping it if the
    /// channel is full (backpressure).
    fn send_input(&self, message: ProtocolMessage) {
        let _ = self.input_tx.try_send(message);
    }

    /// Blits the latest decoded frame into the pixel buffer and presents it.
    fn render(&mut self) {
        // Drain the network receiver, keeping only the newest frame.
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
                    // winit 0.30 `KeyCode` is a fieldless enum; its discriminant
                    // is a stable per-key identifier (HID usage order). A full
                    // HID -> VK translation table is future work.
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
        _device_id: WinitDeviceId,
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

/// Applies a decoded [`ClipboardEvent`] to the local OS clipboard.
fn apply_clipboard_event(
    manager: &mut ClipboardManager,
    event: &ClipboardEvent,
) -> Result<(), DispatchError> {
    match &event.format {
        ClipboardFormat::Text => {
            let text = std::str::from_utf8(&event.data)
                .map_err(|e| DispatchError::Handler(format!("invalid clipboard UTF-8: {e}")))?;
            manager
                .set_text(text)
                .map_err(|e| DispatchError::Handler(format!("clipboard write failed: {e}")))?;
        }
        ClipboardFormat::ImageRgba8 { width, height } => {
            let image = ClipboardImage::new(*width, *height, event.data.clone())
                .map_err(|e| DispatchError::Handler(format!("invalid clipboard image: {e}")))?;
            manager
                .set_image(&image)
                .map_err(|e| DispatchError::Handler(format!("clipboard write failed: {e}")))?;
        }
    }
    Ok(())
}

/// Registers the clipboard handler on the client's dispatcher.
fn register_clipboard_handler(
    dispatcher: &MessageDispatcher,
    clipboard: Arc<Mutex<ClipboardManager>>,
) {
    dispatcher.register_handler(
        MessageType::ClipboardData,
        Arc::new(move |envelope: MessageEnvelope| {
            let event = envelope.message.as_clipboard_event().ok_or_else(|| {
                DispatchError::Handler("undecodable clipboard event payload".into())
            })?;
            let mut manager = clipboard
                .lock()
                .map_err(|e| DispatchError::Handler(format!("clipboard lock poisoned: {e}")))?;
            apply_clipboard_event(&mut manager, &event)
        }),
    );
}

/// Registers the audio handler on the client's dispatcher.
fn register_audio_handler(dispatcher: &MessageDispatcher, playback: Arc<Mutex<AudioPlayback>>) {
    dispatcher.register_handler(
        MessageType::AudioData,
        Arc::new(move |envelope: MessageEnvelope| {
            let payload = envelope
                .message
                .as_audio_data()
                .ok_or_else(|| DispatchError::Handler("undecodable audio payload".into()))?;
            let playback = playback
                .lock()
                .map_err(|e| DispatchError::Handler(format!("audio lock poisoned: {e}")))?;
            playback
                .feed(payload.channels, payload.sample_rate, &payload.opus_data)
                .map_err(|e| DispatchError::Handler(format!("audio decode failed: {e}")))
        }),
    );
}

/// Builds the client's inbound dispatcher (clipboard + audio handlers).
fn build_dispatcher() -> Arc<MessageDispatcher> {
    let dispatcher = Arc::new(MessageDispatcher::new());
    match ClipboardManager::new() {
        Ok(manager) => {
            register_clipboard_handler(&dispatcher, Arc::new(Mutex::new(manager)));
        }
        Err(e) => {
            eprintln!("warning: clipboard unavailable — remote clipboard sync disabled: {e}");
        }
    }
    let audio_config = AudioCodecConfig::new(48_000, 2).expect("48 kHz stereo is a valid config");
    match AudioPlayback::new(audio_config) {
        Ok(playback) => register_audio_handler(&dispatcher, Arc::new(Mutex::new(playback))),
        Err(e) => {
            eprintln!("warning: audio playback unavailable — remote audio disabled: {e}");
        }
    }
    dispatcher
}

/// Routes an inbound protocol message through the client's dispatcher.
fn handle_incoming_message(
    dispatcher: &MessageDispatcher,
    message: ProtocolMessage,
) -> Result<(), DispatchError> {
    let envelope = MessageEnvelope {
        source: NodeId(bw_crypto::DeviceId::from_digest([0x02; 32])),
        destination: NodeId(bw_crypto::DeviceId::from_digest([0x01; 32])),
        session_id: SessionId([0u8; 16]),
        route: Route::Direct,
        message,
        routing_flags: 0,
    };
    dispatcher.dispatch(envelope)
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
fn button_bit(button: MouseButton) -> Option<u8> {
    match button {
        MouseButton::Left => Some(0b001),
        MouseButton::Right => Some(0b010),
        MouseButton::Middle => Some(0b100),
        _ => None,
    }
}

/// Spawns the network session on a background Tokio runtime thread.
///
/// The session connects, authenticates with the server via OPAQUE, then runs
/// until the connection drops — after which it retries every 2 seconds. Decoded
/// video frames are pushed to `frame_tx` for the winit window; captured input
/// messages are drained from `input_rx` and sent to the server.
fn spawn_session(
    args: Args,
    frame_tx: mpsc::Sender<DecodedImage>,
    mut input_rx: tokio::sync::mpsc::Receiver<ProtocolMessage>,
    dispatcher: Arc<MessageDispatcher>,
) {
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("failed to build tokio runtime");
        runtime.block_on(async move {
            loop {
                match run_session(&args, &mut input_rx, &frame_tx, &dispatcher).await {
                    Ok(()) => break,
                    Err(e) => {
                        eprintln!("session error: {e} — retrying in 2s");
                        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                    }
                }
            }
        });
    });
}

/// Runs one authenticated session: OPAQUE login, then forward input and decode
/// video until the connection drops.
async fn run_session(
    args: &Args,
    input_rx: &mut tokio::sync::mpsc::Receiver<ProtocolMessage>,
    frame_tx: &mpsc::Sender<DecodedImage>,
    dispatcher: &Arc<MessageDispatcher>,
) -> Result<(), Box<dyn std::error::Error>> {
    let server_addr: std::net::SocketAddr = args.server.parse()?;

    let quic_client = if let Some(relay_addr) = &args.relay {
        let relay_sock: std::net::SocketAddr = relay_addr.parse()?;
        let token = [0xABu8; 32];
        QuicClient::bind(Some((relay_sock, token)))?
    } else {
        QuicClient::bind(None)?
    };

    eprintln!("connecting to {}", args.server);
    let conn = quic_client.connect(server_addr).await?;
    eprintln!("connected; authenticating...");

    let (send, recv) = conn.open_bi().await?;
    let adapter = QuicProtocolAdapter::new(send, recv);
    let session_manager = Arc::new(SessionManager::new());
    let session = wire::client_establish(
        adapter,
        session_manager,
        args.id.as_bytes(),
        args.password.as_bytes(),
    )
    .await?;
    eprintln!("authenticated with server");

    let (mut sender, mut receiver) = session.into_split();

    // Receiver task: decode video frames into the display channel and route
    // control messages (clipboard/audio) to the dispatcher.
    let frame_tx = frame_tx.clone();
    let dispatcher = Arc::clone(dispatcher);
    let recv_task = tokio::spawn(async move {
        let mut decoder = match DecoderPipeline::new() {
            Ok(d) => d,
            Err(e) => {
                eprintln!("failed to initialize decoder: {e}");
                return;
            }
        };
        let mut frames_rendered: u64 = 0;
        let mut video_received: u64 = 0;
        loop {
            let message = match receiver.recv_message().await {
                Ok(m) => m,
                Err(e) => {
                    eprintln!("recv: session ended ({e})");
                    break;
                }
            };
            if let Some(payload) = message.as_video_data() {
                if video_received == 0 {
                    eprintln!(
                        "video: received first frame ({} bytes)",
                        payload.encoded_frame.len()
                    );
                }
                video_received += 1;
                if let Ok(frame) = bw_encoder::EncodedFrame::from_bytes(&payload.encoded_frame) {
                    match decoder.decode(&frame) {
                        Ok(Some(image)) => {
                            if frame_tx.send(image).is_err() {
                                break; // window closed
                            }
                            frames_rendered += 1;
                            if frames_rendered == 1 || frames_rendered.is_multiple_of(600) {
                                eprintln!("video: {frames_rendered} frames rendered");
                            }
                        }
                        Ok(None) => {} // decoder needs more data
                        Err(e) => eprintln!("video decode failed: {e}"),
                    }
                }
            } else if let Err(e) = handle_incoming_message(&dispatcher, message) {
                eprintln!("dispatch error: {e}");
            }
        }
    });

    // Forward captured input to the server until the connection drops.
    while let Some(message) = input_rx.recv().await {
        if sender.send_message(&message).await.is_err() {
            break;
        }
    }

    recv_task.abort();
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = parse_args();

    let (frame_tx, frame_rx) = mpsc::channel::<DecodedImage>();
    let (input_tx, input_rx) = tokio::sync::mpsc::channel::<ProtocolMessage>(256);
    let dispatcher = build_dispatcher();

    spawn_session(args, frame_tx, input_rx, Arc::clone(&dispatcher));

    let event_loop = EventLoop::new()?;
    let mut app = App::new(frame_rx, input_tx, dispatcher);
    event_loop.run_app(&mut app)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bw_audio::AudioEncoder;
    use bw_protocol::message::AudioPayload;
    use std::sync::OnceLock;

    /// Serializes access to the global OS clipboard across tests in this
    /// process (parallel clipboard operations can fail or clobber each other).
    fn clipboard_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    /// Opens a clipboard manager, or skips when no clipboard is available
    /// (e.g. a headless CI session).
    fn open_clipboard() -> Option<ClipboardManager> {
        match ClipboardManager::new() {
            Ok(manager) => Some(manager),
            Err(e) => {
                eprintln!("skipping clipboard test: clipboard unavailable ({e})");
                None
            }
        }
    }

    #[test]
    fn test_clipboard_handler_applies_remote_text_event() {
        let _guard = clipboard_lock().lock().unwrap_or_else(|e| e.into_inner());
        let Some(clipboard) = open_clipboard() else {
            return;
        };
        let clipboard = Arc::new(Mutex::new(clipboard));
        let dispatcher = MessageDispatcher::new();
        register_clipboard_handler(&dispatcher, clipboard.clone());

        let message = ProtocolMessage::clipboard_event(ClipboardEvent {
            format: ClipboardFormat::Text,
            data: b"remote clipboard from server".to_vec(),
        })
        .unwrap();
        handle_incoming_message(&dispatcher, message).unwrap();

        let mut manager = clipboard.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(manager.get_text().unwrap(), "remote clipboard from server");
    }

    #[test]
    fn test_clipboard_handler_rejects_undecodable_payload() {
        let _guard = clipboard_lock().lock().unwrap_or_else(|e| e.into_inner());
        let Some(clipboard) = open_clipboard() else {
            return;
        };
        let clipboard = Arc::new(Mutex::new(clipboard));
        let dispatcher = MessageDispatcher::new();
        register_clipboard_handler(&dispatcher, clipboard.clone());

        let message = ProtocolMessage {
            message_type: MessageType::ClipboardData,
            message_id: 0,
            flags: 0,
            payload: vec![0xde, 0xad, 0xbe, 0xef],
        };
        let err = handle_incoming_message(&dispatcher, message).unwrap_err();
        assert!(matches!(err, DispatchError::Handler(_)));
    }

    #[test]
    fn test_audio_handler_feeds_playback() {
        let config = AudioCodecConfig::new(48_000, 2).expect("48 kHz stereo is a valid config");
        let Ok(playback) = AudioPlayback::new(config.clone()) else {
            eprintln!("skipping audio test: no output device");
            return;
        };
        let playback = Arc::new(Mutex::new(playback));
        let dispatcher = MessageDispatcher::new();
        register_audio_handler(&dispatcher, playback);

        // Encode a short 48k stereo sine wave and feed it through the handler.
        let mut encoder = AudioEncoder::new(config).expect("encoder init");
        let samples: Vec<f32> = (0..(960 * 2))
            .map(|i| (i as f32 * 0.05).sin() * 0.25)
            .collect();
        let opus_data = encoder.encode_frame(&samples).expect("encode");
        let message = ProtocolMessage::audio_data(AudioPayload {
            channels: 2,
            sample_rate: 48_000,
            opus_data,
        })
        .expect("audio message");
        assert!(handle_incoming_message(&dispatcher, message).is_ok());
    }
}
