//! BLACKWING server — receives remote input messages and injects them into the
//! operating system.
//!
//! Registers the protocol [`MessageDispatcher`] handlers from the `bw_server`
//! library and idles. The QUIC listener (via `bw-session`) is future work; the
//! full client-to-OS injection flow is proven end-to-end by the integration
//! test (TASK-107).

#![allow(clippy::unwrap_used, clippy::expect_used)]
// ^ Justification: binary crate entry points report fatal startup errors by
//   panicking with a message, per native-application convention.

use std::sync::mpsc;
use std::sync::{Arc, Mutex};

use bw_audio::AudioCapture;
use bw_clipboard::ClipboardManager;
use bw_ice::IcePeer;
use bw_input::InputInjector;
use bw_protocol::dispatcher::MessageDispatcher;
use bw_protocol::message::ProtocolMessage;
use bw_server::{
    audio_packet_message, register_clipboard_handler, register_ice_handler, register_input_handlers,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let dispatcher = MessageDispatcher::new();
    register_input_handlers(&dispatcher, InputInjector::new());
    let clipboard = Arc::new(Mutex::new(ClipboardManager::new()?));
    register_clipboard_handler(&dispatcher, clipboard);

    // Start the server-side ICE signaling peer (controlled role). The relay
    // token is a placeholder until the QUIC/relay handshake is wired; both
    // sides derive identical ICE credentials from it. Candidates exchanged
    // over the relay negotiate a direct P2P path (TASK-119).
    let relay_token = [0u8; 32];
    let ice_peer = start_ice_peer(&relay_token, false);
    register_ice_handler(&dispatcher, ice_peer);

    // Start host audio capture and queue the encoded frames as outbound
    // AudioData messages. Held so the outbound queue (and the capture thread)
    // lives for the process; the QUIC transport drains it once wired.
    let _outbound_audio = start_audio_capture();

    eprintln!("BLACKWING server ready — input, clipboard, audio and ICE signaling registered");
    eprintln!("QUIC listener (bw-session) not yet wired; process idles until then.");

    // Keep the process alive; the dispatcher path is exercised by the E2E test.
    std::thread::park();
    Ok(())
}

/// Starts the server-side [`IcePeer`] on a background Tokio runtime.
///
/// Returns the peer, whose background candidate-gathering worker is driven by
/// the runtime thread (kept alive for the process lifetime).
fn start_ice_peer(token: &[u8; 32], is_controlling: bool) -> Arc<IcePeer> {
    let runtime = tokio::runtime::Runtime::new().expect("failed to start ICE runtime");
    let peer = runtime
        .block_on(IcePeer::new(
            token,
            is_controlling,
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

/// Starts host audio capture and forwards each Opus frame as an outbound
/// [`MessageType::AudioData`] protocol message.
///
/// Returns the receiving end of the outbound message queue (or `None` when no
/// capture could be opened — e.g. no audio device or no loopback support). The
/// QUIC transport will drain this queue and send the messages to the client;
/// the returned receiver is held in `main` to keep the queue alive.
fn start_audio_capture() -> Option<mpsc::Receiver<ProtocolMessage>> {
    let (capture, packets) = match AudioCapture::new() {
        Ok(captured) => captured,
        Err(e) => {
            eprintln!("warning: audio capture unavailable — host audio disabled: {e}");
            return None;
        }
    };
    let channels = capture.config().channels;
    let sample_rate = capture.config().sample_rate;

    let (out_tx, out_rx) = mpsc::channel::<ProtocolMessage>();
    std::thread::spawn(move || {
        // Own the capture so its stream (and thus the audio device) stays
        // alive for the lifetime of this thread.
        let _capture = capture;
        for packet in packets {
            match audio_packet_message(channels, sample_rate, packet) {
                Ok(message) => {
                    if out_tx.send(message).is_err() {
                        break; // Transport dropped; stop capturing.
                    }
                }
                Err(e) => eprintln!("audio message serialization failed: {e}"),
            }
        }
    });
    Some(out_rx)
}
