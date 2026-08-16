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

use std::sync::mpsc;
use std::sync::{Arc, Mutex};

use bw_audio::{AudioCodecConfig, AudioPlayback};
use bw_clipboard::{ClipboardImage, ClipboardManager};
use bw_crypto::DeviceId;
use bw_decoder::DecodedImage;
use bw_ice::IcePeer;
use bw_protocol::dispatcher::{DispatchError, MessageDispatcher};
use bw_protocol::message::{ClipboardEvent, ClipboardFormat, MessageType, ProtocolMessage};
use bw_protocol::routing::{MessageEnvelope, NodeId, Route, SessionId};
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
    /// Dispatcher that routes inbound messages (e.g. remote clipboard
    /// changes) to their registered handlers.
    ///
    /// Kept alive for the upcoming QUIC receiver path; the inbound routing
    /// entry point (`handle_incoming_message`) is wired and unit-tested.
    _dispatcher: MessageDispatcher,
    /// The client-side ICE signaling peer (controlling agent).
    ///
    /// Held so its background candidate-gathering worker stays alive; the
    /// QUIC receiver will pump `IceCandidate` messages into it and, once a
    /// direct path is negotiated, migrate the QUIC connection onto it
    /// (TASK-118/119).
    _ice_peer: Arc<IcePeer>,
}

impl App {
    /// Creates the application state with a frame receiver.
    fn new(frame_rx: mpsc::Receiver<DecodedImage>) -> Self {
        let (input_tx, _input_rx) = tokio::sync::mpsc::channel::<ProtocolMessage>(256);
        let dispatcher = MessageDispatcher::new();
        match ClipboardManager::new() {
            Ok(manager) => register_clipboard_handler(&dispatcher, Arc::new(Mutex::new(manager))),
            Err(e) => {
                eprintln!("warning: clipboard unavailable — remote clipboard sync disabled: {e}");
            }
        }
        let audio_config =
            AudioCodecConfig::new(48_000, 2).expect("48 kHz stereo is a valid config");
        match AudioPlayback::new(audio_config) {
            Ok(playback) => register_audio_handler(&dispatcher, Arc::new(Mutex::new(playback))),
            Err(e) => {
                eprintln!("warning: audio playback unavailable — remote audio disabled: {e}");
            }
        }

        // Start the client-side ICE signaling peer (controlling agent) on a
        // background runtime. The relay token is a placeholder until the
        // QUIC/relay handshake is wired; both sides derive identical ICE
        // credentials from it (TASK-119).
        let ice_peer = start_ice_peer();
        register_ice_handler(&dispatcher, Arc::clone(&ice_peer));

        Self {
            window: None,
            pixels: None,
            frame_rx,
            last_image: None,
            input_tx,
            _input_rx,
            buttons_mask: 0,
            _dispatcher: dispatcher,
            _ice_peer: ice_peer,
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
///
/// Mirrors `bw-server`'s `apply_clipboard_event`: text events are written via
/// [`ClipboardManager::set_text`], image events via
/// [`ClipboardManager::set_image`]. Failures are reported as
/// [`DispatchError::Handler`] so they propagate without panicking.
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
///
/// Inbound [`MessageType::ClipboardData`] messages are decoded into a
/// [`ClipboardEvent`] and applied to the shared [`ClipboardManager`] (the
/// server's clipboard content, injected into the local OS clipboard).
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
///
/// Inbound [`MessageType::AudioData`] messages are decoded into an
/// [`AudioPayload`] and fed to the shared [`AudioPlayback`] (the server's
/// captured host audio, played on the client's output device).
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

/// Registers the ICE signaling handler on the client's dispatcher.
///
/// Inbound [`MessageType::IceCandidate`] messages (received from the server
/// over the relay / signaling channel) are forwarded into the client's
/// [`IcePeer`], which feeds them into its ICE agent for connectivity checks.
fn register_ice_handler(dispatcher: &MessageDispatcher, peer: Arc<IcePeer>) {
    dispatcher.register_handler(
        MessageType::IceCandidate,
        Arc::new(move |envelope: MessageEnvelope| {
            peer.push_candidate(&envelope.message)
                .map_err(|e| DispatchError::Handler(e.to_string()))
        }),
    );
}

/// Starts the client-side [`IcePeer`] (controlling agent) on a background
/// Tokio runtime.
///
/// The relay token is a placeholder until the QUIC/relay handshake is wired;
/// both sides derive identical ICE credentials from it. Returns the peer,
/// whose background candidate-gathering worker is driven by the runtime
/// thread (kept alive for the process lifetime).
fn start_ice_peer() -> Arc<IcePeer> {
    let runtime = tokio::runtime::Runtime::new().expect("failed to start ICE runtime");
    let relay_token = [0u8; 32];
    let peer = runtime
        .block_on(IcePeer::new(
            &relay_token,
            true,
            bw_ice::IceConfig::default().urls,
        ))
        .expect("failed to start ICE peer");
    std::thread::spawn(move || {
        // Keep the runtime (and the peer's worker task) alive for the
        // process lifetime.
        runtime.block_on(std::future::pending::<()>());
    });
    Arc::new(peer)
}

/// Routes an inbound protocol message through the client's dispatcher.
///
/// This is the entry point the QUIC network receiver will call when a server
/// message arrives (currently only clipboard changes are wired). Placeholder
/// routing coordinates are used until the session layer supplies real node
/// identities.
#[allow(dead_code)] // The QUIC receiver is not yet wired; exercised by the unit test.
fn handle_incoming_message(
    dispatcher: &MessageDispatcher,
    message: ProtocolMessage,
) -> Result<(), DispatchError> {
    let envelope = MessageEnvelope {
        source: NodeId(DeviceId::from_digest([0x01; 32])),
        destination: NodeId(DeviceId::from_digest([0x02; 32])),
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

#[cfg(test)]
mod tests {
    use super::*;
    use bw_audio::AudioEncoder;
    use bw_protocol::message::AudioPayload;
    use std::sync::{Mutex, OnceLock};

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

        // Encode a silent stereo frame and route it through the dispatcher.
        let mut encoder = AudioEncoder::new(config.clone()).expect("encoder builds");
        let frame = vec![0.0f32; config.frame_size * 2];
        let packet = encoder.encode_frame(&frame).expect("frame encodes");
        let message = ProtocolMessage::audio_data(AudioPayload {
            channels: config.channels,
            sample_rate: config.sample_rate,
            opus_data: packet,
        })
        .expect("audio message builds");
        handle_incoming_message(&dispatcher, message).expect("audio message handled");

        // A second packet with a different format exercises decoder recreation.
        let config_mono = AudioCodecConfig::new(16_000, 1).expect("16 kHz mono is a valid config");
        let mut encoder_mono = AudioEncoder::new(config_mono.clone()).expect("encoder builds");
        let frame_mono = vec![0.0f32; config_mono.frame_size];
        let packet_mono = encoder_mono
            .encode_frame(&frame_mono)
            .expect("frame encodes");
        let message_mono = ProtocolMessage::audio_data(AudioPayload {
            channels: config_mono.channels,
            sample_rate: config_mono.sample_rate,
            opus_data: packet_mono,
        })
        .expect("audio message builds");
        handle_incoming_message(&dispatcher, message_mono).expect("format-switch handled");
    }

    #[test]
    fn test_audio_handler_rejects_undecodable_payload() {
        let config = AudioCodecConfig::new(48_000, 2).expect("48 kHz stereo is a valid config");
        let Ok(playback) = AudioPlayback::new(config.clone()) else {
            eprintln!("skipping audio test: no output device");
            return;
        };
        let playback = Arc::new(Mutex::new(playback));
        let dispatcher = MessageDispatcher::new();
        register_audio_handler(&dispatcher, playback);

        let message = ProtocolMessage {
            message_type: MessageType::AudioData,
            message_id: 0,
            flags: 0,
            payload: vec![0xde, 0xad, 0xbe, 0xef],
        };
        let err = handle_incoming_message(&dispatcher, message).unwrap_err();
        assert!(matches!(err, DispatchError::Handler(_)));
    }

    #[tokio::test]
    async fn test_ice_peer_produces_candidate_messages() {
        // Host-only gathering (no STUN urls) so the test is deterministic
        // and network-independent.
        let peer = IcePeer::new(&[0x42; 32], true, Vec::new())
            .await
            .expect("peer starts");

        let mut seen = 0;
        while let Some(message) = peer.next_outbound().await {
            assert_eq!(message.message_type, MessageType::IceCandidate);
            let payload = message.as_ice_candidate().expect("candidate payload");
            assert!(!payload.candidate_str.is_empty());
            seen += 1;
        }
        assert!(seen >= 1, "expected at least one gathered candidate");
    }

    #[tokio::test]
    async fn test_ice_handler_routes_candidate_to_peer() {
        let peer = Arc::new(
            IcePeer::new(&[0x42; 32], false, Vec::new())
                .await
                .expect("peer starts"),
        );
        let dispatcher = MessageDispatcher::new();
        register_ice_handler(&dispatcher, Arc::clone(&peer));

        // A well-formed loopback host candidate routes through the dispatcher
        // into the peer without error.
        let message = ProtocolMessage::ice_candidate(bw_protocol::message::IceCandidatePayload {
            candidate_str: "candidate:1 1 UDP 2130706431 127.0.0.1 50000 typ host".to_string(),
            sdp_mid: None,
            sdp_mline_index: None,
        })
        .expect("candidate message builds");
        handle_incoming_message(&dispatcher, message).expect("candidate handled");
    }

    #[tokio::test]
    async fn test_push_candidate_rejects_non_ice_message() {
        let peer = Arc::new(
            IcePeer::new(&[0x42; 32], false, Vec::new())
                .await
                .expect("peer starts"),
        );
        let data_message = ProtocolMessage {
            message_type: MessageType::Data,
            message_id: 0,
            flags: 0,
            payload: b"not an ice candidate".to_vec(),
        };
        let err = peer.push_candidate(&data_message).expect_err("rejected");
        assert!(matches!(err, bw_ice::IceError::InvalidCandidate(_, _)));
    }
}
