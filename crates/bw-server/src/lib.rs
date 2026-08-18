//! BLACKWING server — library portion.
//!
//! Provides the remote-input handler wiring ([`register_input_handlers`]) that
//! the `bw-server` binary uses at startup and that the E2E integration test
//! (TASK-107) exercises against a recording injection backend.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use bw_clipboard::{ClipboardImage, ClipboardManager};
use bw_ice::IcePeer;
use bw_input::{InputInjector, MouseButton};
use bw_protocol::dispatcher::{DispatchError, MessageDispatcher};
use bw_protocol::message::{
    AudioPayload, ClipboardEvent, ClipboardFormat, KeyboardEvent, MessageType, MouseEvent,
};
use bw_protocol::routing::{MessageEnvelope, SessionId};

/// Button-mask bits for the three standard mouse buttons.
///
/// Matches the TASK-103 bit convention: bit 0 = left, bit 1 = right,
/// bit 2 = middle.
pub const BUTTON_BITS: [(u8, MouseButton); 3] = [
    (0b001, MouseButton::Left),
    (0b010, MouseButton::Right),
    (0b100, MouseButton::Middle),
];

/// Registers the remote-input handlers on the dispatcher.
///
/// The keyboard handler injects key press/release events via
/// [`InputInjector::inject_keyboard`]. The mouse handler injects relative
/// movement via [`InputInjector::inject_mouse_move`] and translates button
/// mask transitions into presses and releases via
/// [`InputInjector::inject_mouse_click`]: a bit that appears in the mask is
/// pressed, and a bit that disappears is released. Per-session state tracks
/// the previous mask so releases are not lost.
pub fn register_input_handlers(dispatcher: &MessageDispatcher, injector: InputInjector) {
    let keyboard_injector = injector.clone();
    dispatcher.register_handler(
        MessageType::InputKeyboard,
        Arc::new(move |envelope: MessageEnvelope| {
            let event = parse_keyboard(&envelope)?;
            keyboard_injector
                .inject_keyboard(event.keycode, event.is_down)
                .map_err(|e| DispatchError::Handler(e.to_string()))
        }),
    );

    let mouse_injector = injector.clone();
    // Per-session button state so release transitions can be detected. The
    // client reports the *current* mask on every event; pressing vs. releasing
    // is a transition from bit-set to bit-clear, which requires remembering
    // the previous mask for each session.
    let button_states: Arc<Mutex<HashMap<SessionId, u8>>> = Arc::new(Mutex::new(HashMap::new()));
    dispatcher.register_handler(
        MessageType::InputMouse,
        Arc::new(move |envelope: MessageEnvelope| {
            let event = parse_mouse(&envelope)?;
            if event.dx != 0 || event.dy != 0 {
                mouse_injector
                    .inject_mouse_move(event.dx, event.dy)
                    .map_err(|e| DispatchError::Handler(e.to_string()))?;
            }
            let mut states = button_states.lock().unwrap_or_else(|e| e.into_inner());
            // Bound the map: a server keeps a small number of live sessions.
            if states.len() >= 64 && !states.contains_key(&envelope.session_id) {
                states.clear();
            }
            let prev_mask = *states.get(&envelope.session_id).unwrap_or(&0);
            for (bit, button) in BUTTON_BITS {
                let was_down = prev_mask & bit != 0;
                let is_down = event.buttons_mask & bit != 0;
                if is_down && !was_down {
                    mouse_injector
                        .inject_mouse_click(button, true)
                        .map_err(|e| DispatchError::Handler(e.to_string()))?;
                } else if !is_down && was_down {
                    mouse_injector
                        .inject_mouse_click(button, false)
                        .map_err(|e| DispatchError::Handler(e.to_string()))?;
                }
            }
            states.insert(envelope.session_id, event.buttons_mask);
            Ok(())
        }),
    );
}

/// Extracts the [`KeyboardEvent`] carried by an input-keyboard envelope.
fn parse_keyboard(envelope: &MessageEnvelope) -> Result<KeyboardEvent, DispatchError> {
    envelope
        .message
        .as_keyboard_event()
        .ok_or_else(|| DispatchError::Handler("undecodable keyboard event payload".into()))
}

/// Extracts the [`MouseEvent`] carried by an input-mouse envelope.
fn parse_mouse(envelope: &MessageEnvelope) -> Result<MouseEvent, DispatchError> {
    envelope
        .message
        .as_mouse_event()
        .ok_or_else(|| DispatchError::Handler("undecodable mouse event payload".into()))
}

/// Applies a decoded [`ClipboardEvent`] to the local OS clipboard.
///
/// Text events are written via [`ClipboardManager::set_text`]; image events
/// are validated and written via [`ClipboardManager::set_image`]. Failures are
/// reported as [`DispatchError::Handler`] so they propagate out of the
/// dispatcher without panicking.
pub fn apply_clipboard_event(
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

/// Registers the clipboard handler on the dispatcher.
///
/// The handler decodes the `ClipboardData` payload into a [`ClipboardEvent`]
/// and applies it to the shared [`ClipboardManager`]. The manager is shared
/// behind a mutex because `arboard` requires `&mut` for every operation and
/// the clipboard may only be opened by one thread at a time.
pub fn register_clipboard_handler(
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

/// Builds an outbound [`MessageType::AudioData`] message from an encoded
/// Opus frame.
///
/// Used by the server's audio-forwarding thread (TASK-114) to wrap each
/// captured frame with its format metadata before it is queued for the QUIC
/// transport.
pub fn audio_packet_message(
    channels: u16,
    sample_rate: u32,
    opus_data: Vec<u8>,
) -> Result<bw_protocol::message::ProtocolMessage, bw_protocol::error::ProtocolError> {
    bw_protocol::message::ProtocolMessage::audio_data(AudioPayload {
        channels,
        sample_rate,
        opus_data,
    })
}

/// Registers the ICE signaling handler on the dispatcher.
///
/// Inbound [`MessageType::IceCandidate`] messages (received from the remote
/// peer over the relay / signaling channel) are forwarded into the
/// [`IcePeer`], which feeds them into its ICE agent for connectivity checks.
pub fn register_ice_handler(dispatcher: &MessageDispatcher, peer: Arc<IcePeer>) {
    dispatcher.register_handler(
        MessageType::IceCandidate,
        Arc::new(move |envelope: MessageEnvelope| {
            peer.push_candidate(&envelope.message)
                .map_err(|e| DispatchError::Handler(e.to_string()))
        }),
    );
}
