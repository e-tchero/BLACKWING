//! BLACKWING server — library portion.
//!
//! Provides the remote-input handler wiring ([`register_input_handlers`]) that
//! the `bw-server` binary uses at startup and that the E2E integration test
//! (TASK-107) exercises against a recording injection backend.

use std::sync::{Arc, Mutex};

use bw_clipboard::{ClipboardImage, ClipboardManager};
use bw_input::{InputInjector, MouseButton};
use bw_protocol::dispatcher::{DispatchError, MessageDispatcher};
use bw_protocol::message::{
    ClipboardEvent, ClipboardFormat, KeyboardEvent, MessageType, MouseEvent,
};
use bw_protocol::routing::MessageEnvelope;

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
/// movement via [`InputInjector::inject_mouse_move`] and presses any buttons
/// set in the event's [`MouseEvent::buttons_mask`] mask (releases arrive as
/// subsequent events with the corresponding bit cleared).
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
    dispatcher.register_handler(
        MessageType::InputMouse,
        Arc::new(move |envelope: MessageEnvelope| {
            let event = parse_mouse(&envelope)?;
            if event.dx != 0 || event.dy != 0 {
                mouse_injector
                    .inject_mouse_move(event.dx, event.dy)
                    .map_err(|e| DispatchError::Handler(e.to_string()))?;
            }
            for (bit, button) in BUTTON_BITS {
                if event.buttons_mask & bit != 0 {
                    mouse_injector
                        .inject_mouse_click(button, true)
                        .map_err(|e| DispatchError::Handler(e.to_string()))?;
                }
            }
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
