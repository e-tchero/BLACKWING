//! BLACKWING server — receives remote input messages and injects them into the
//! operating system.
//!
//! Wires the protocol [`MessageDispatcher`] to the `bw-input` OS-injection API:
//! `InputKeyboard` messages are translated into [`InputInjector::inject_keyboard`]
//! calls, and `InputMouse` messages into [`InputInjector::inject_mouse_move`] /
//! [`InputInjector::inject_mouse_click`] calls.
//!
//! The QUIC listener (via `bw-session`) is future work; for now the binary
//! registers the handlers and idles, and the same registration function is
//! exercised end-to-end by the integration test (TASK-107).

#![allow(clippy::unwrap_used, clippy::expect_used)]
// ^ Justification: binary crate entry points report fatal startup errors by
//   panicking with a message, per native-application convention. The handler
//   registration logic itself is covered by the E2E test.

use std::sync::Arc;

use bw_input::{InputInjector, MouseButton};
use bw_protocol::dispatcher::{DispatchError, MessageDispatcher};
use bw_protocol::message::{KeyboardEvent, MessageType, MouseEvent};
use bw_protocol::routing::MessageEnvelope;

/// Button-mask bits for the three standard mouse buttons.
///
/// Matches the TASK-103 bit convention: bit 0 = left, bit 1 = right,
/// bit 2 = middle.
const BUTTON_BITS: [(u8, MouseButton); 3] = [
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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let dispatcher = MessageDispatcher::new();
    register_input_handlers(&dispatcher, InputInjector::new());

    eprintln!("BLACKWING server ready — input handlers registered");
    eprintln!("QUIC listener (bw-session) not yet wired; process idles until then.");

    // Keep the process alive; the dispatcher path is exercised by the E2E test.
    std::thread::park();
    Ok(())
}
