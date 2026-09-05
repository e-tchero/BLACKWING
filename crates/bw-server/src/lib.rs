//! BLACKWING server — library portion.
//!
//! Provides the remote-input handler wiring ([`register_input_handlers`]) that
//! the `bw-server` binary uses at startup and that the E2E integration test
//! (TASK-107) exercises against a recording injection backend.

pub mod rendezvous;

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
                if event.is_absolute {
                    mouse_injector
                        .inject_mouse_move_absolute(event.dx, event.dy)
                        .map_err(|e| DispatchError::Handler(e.to_string()))?;
                } else {
                    mouse_injector
                        .inject_mouse_move(event.dx, event.dy)
                        .map_err(|e| DispatchError::Handler(e.to_string()))?;
                }
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

/// Spawns a clipboard polling thread that detects local clipboard changes
/// and sends them as [`ClipboardData`] messages to the client.
///
/// Uses [`bw_clipboard::ClipboardPoller`] to detect text/image changes on a
/// background thread, then bridges into the async [`tokio::sync::mpsc`]
/// channel via a [`std::sync::mpsc`] relay.
pub fn spawn_clipboard_poller(
    out_tx: tokio::sync::mpsc::Sender<bw_protocol::message::ProtocolMessage>,
) {
    let poller = bw_clipboard::ClipboardPoller::default_intervals();
    let _handle = poller.spawn(move |change| {
        let event = bw_protocol::message::ClipboardEvent {
            format: if change.is_text {
                bw_protocol::message::ClipboardFormat::Text
            } else {
                bw_protocol::message::ClipboardFormat::ImageRgba8 {
                    width: change.image_width.unwrap_or(0),
                    height: change.image_height.unwrap_or(0),
                }
            },
            data: if change.is_text {
                change.text.unwrap_or_default().into_bytes()
            } else {
                change.image_data.unwrap_or_default()
            },
        };
        match bw_protocol::message::ProtocolMessage::clipboard_event(event) {
            Ok(message) => {
                // out_tx is a tokio channel — use blocking_send from the sync thread.
                if out_tx.blocking_send(message).is_err() {
                    // Session closed — poller will stop when the handle is dropped.
                }
            }
            Err(e) => eprintln!("clipboard poller: serialization failed: {e}"),
        }
    });
    if let Err(e) = _handle {
        eprintln!("warning: failed to start clipboard poller: {e}");
    }
}

/// Composites a cursor overlay onto a BGRA frame buffer.
///
/// Draws an inverted crosshair at the cursor position so the remote user
/// can see where the server's cursor is. The crosshair uses XOR blending
/// (inverted colors) so it's visible on any background.
///
/// # Arguments
///
/// * `buffer` — mutable BGRA pixel buffer (4 bytes per pixel, row-major)
/// * `stride` — bytes per row (may include padding beyond `width * 4`)
/// * `width` — frame width in pixels
/// * `height` — frame height in pixels
/// * `cursor_x` — cursor X position in display coordinates
/// * `cursor_y` — cursor Y position in display coordinates
/// * `cursor_visible` — whether the cursor should be drawn
pub fn composite_cursor(
    buffer: &mut [u8],
    stride: u32,
    width: u32,
    height: u32,
    cursor_x: i32,
    cursor_y: i32,
    cursor_visible: bool,
) {
    if !cursor_visible || buffer.is_empty() {
        return;
    }

    // Clamp cursor to frame bounds.
    let cx = cursor_x.clamp(0, width as i32 - 1) as u32;
    let cy = cursor_y.clamp(0, height as i32 - 1) as u32;

    // Draw a small crosshair (6px arms) with inverted colors.
    // This technique is used by screen capture tools — XOR-ing the pixel
    // values makes the crosshair visible on both light and dark backgrounds.
    let arm = 6u32;

    // Horizontal line (left and right of cursor)
    for i in 1..=arm {
        if cx >= i {
            xor_bgra_pixel(buffer, stride, width, height, cx - i, cy);
        }
        if cx + i < width {
            xor_bgra_pixel(buffer, stride, width, height, cx + i, cy);
        }
    }

    // Vertical line (above and below cursor)
    for i in 1..=arm {
        if cy >= i {
            xor_bgra_pixel(buffer, stride, width, height, cx, cy - i);
        }
        if cy + i < height {
            xor_bgra_pixel(buffer, stride, width, height, cx, cy + i);
        }
    }

    // Center pixel
    xor_bgra_pixel(buffer, stride, width, height, cx, cy);
}

/// XOR-blends a single BGRA pixel, inverting its color.
fn xor_bgra_pixel(buffer: &mut [u8], stride: u32, width: u32, height: u32, x: u32, y: u32) {
    if x >= width || y >= height {
        return;
    }
    let offset = (y * stride + x * 4) as usize;
    if offset + 3 < buffer.len() {
        buffer[offset] ^= 0xFF; // B
        buffer[offset + 1] ^= 0xFF; // G
        buffer[offset + 2] ^= 0xFF; // R
        // Alpha channel stays the same
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn composite_cursor_invisible_does_nothing() {
        let mut buffer = vec![0xAA; 400]; // 10x10 BGRA
        let original = buffer.clone();
        composite_cursor(&mut buffer, 40, 10, 10, 5, 5, false);
        assert_eq!(
            buffer, original,
            "invisible cursor should not modify buffer"
        );
    }

    #[test]
    fn composite_cursor_out_of_bounds_does_nothing() {
        let mut buffer = vec![0xAA; 400];
        let original = buffer.clone();
        // Cursor outside frame bounds — should be clamped and not panic.
        composite_cursor(&mut buffer, 40, 10, 10, 100, 100, true);
        // Center pixel should be XOR'd (clamped to 9,9).
        assert_ne!(buffer, original, "cursor should modify at least one pixel");
    }

    #[test]
    fn composite_cursor_xor_blends_center_pixel() {
        let mut buffer = vec![0x00; 400]; // 10x10, all black
        composite_cursor(&mut buffer, 40, 10, 10, 5, 5, true);
        // Center pixel (5,5) should be XOR'd: 0x00 ^ 0xFF = 0xFF for BGR.
        let offset = (5 * 40 + 5 * 4) as usize;
        assert_eq!(buffer[offset], 0xFF, "blue channel should be XOR'd");
        assert_eq!(buffer[offset + 1], 0xFF, "green channel should be XOR'd");
        assert_eq!(buffer[offset + 2], 0xFF, "red channel should be XOR'd");
        assert_eq!(buffer[offset + 3], 0x00, "alpha should not change");
    }

    #[test]
    fn composite_cursor_does_not_panic_on_empty_buffer() {
        let mut buffer: Vec<u8> = vec![];
        composite_cursor(&mut buffer, 0, 0, 0, 0, 0, true);
    }
}
