#![allow(missing_docs)] // Integration-test crate (repo convention)
#![allow(clippy::unwrap_used, clippy::expect_used)] // Test code may panic on failure (repo convention)

use bw_crypto::DeviceId;
use bw_input::InputInjector;
use bw_input::inject::RecordingBackend;
use bw_input::input::{InjectedInput, MouseButton};
use bw_protocol::dispatcher::{DispatchError, MessageDispatcher};
use bw_protocol::message::{MessageType, ProtocolMessage};
use bw_protocol::routing::{MessageEnvelope, NodeId, Route, SessionId};
use bw_server::register_input_handlers;
use std::sync::Arc;

fn make_node_id(val: u8) -> NodeId {
    NodeId(DeviceId::from_digest([val; 32]))
}

/// Wraps a protocol message in a directly-routed envelope, matching what the
/// client (TASK-105) would produce.
fn wrap(message: ProtocolMessage) -> MessageEnvelope {
    MessageEnvelope {
        source: make_node_id(1),
        destination: make_node_id(2),
        session_id: SessionId([0u8; 16]),
        route: Route::Direct,
        message,
        routing_flags: 0,
    }
}

/// Builds a dispatcher with the TASK-106 handlers backed by a recording
/// backend, so no real OS injection happens.
fn test_setup() -> (MessageDispatcher, Arc<RecordingBackend>) {
    let dispatcher = MessageDispatcher::new();
    let backend = Arc::new(RecordingBackend::default());
    let injector = InputInjector::with_backend(backend.clone());
    register_input_handlers(&dispatcher, injector);
    (dispatcher, backend)
}

#[test]
fn test_client_keyboard_input_to_injection() {
    let (dispatcher, backend) = test_setup();

    // Simulate TASK-105 client output: key press then release.
    dispatcher
        .dispatch(wrap(ProtocolMessage::keyboard_event(0x41, true).unwrap()))
        .unwrap();
    dispatcher
        .dispatch(wrap(ProtocolMessage::keyboard_event(0x41, false).unwrap()))
        .unwrap();

    assert_eq!(
        backend.events(),
        vec![
            InjectedInput::Keyboard {
                keycode: 0x41,
                down: true
            },
            InjectedInput::Keyboard {
                keycode: 0x41,
                down: false
            },
        ]
    );
}

#[test]
fn test_client_mouse_input_to_injection() {
    let (dispatcher, backend) = test_setup();

    // Movement + left button held (mask bit 0).
    dispatcher
        .dispatch(wrap(ProtocolMessage::mouse_event(100, -50, 0b001).unwrap()))
        .unwrap();

    assert_eq!(
        backend.events(),
        vec![
            InjectedInput::MouseMove { dx: 100, dy: -50 },
            InjectedInput::MouseClick {
                button: MouseButton::Left,
                down: true
            },
        ]
    );
}

#[test]
fn test_mouse_multi_button_mask_injects_all_pressed() {
    let (dispatcher, backend) = test_setup();

    // All three buttons held, no movement.
    dispatcher
        .dispatch(wrap(ProtocolMessage::mouse_event(0, 0, 0b111).unwrap()))
        .unwrap();

    assert_eq!(
        backend.events(),
        vec![
            InjectedInput::MouseClick {
                button: MouseButton::Left,
                down: true
            },
            InjectedInput::MouseClick {
                button: MouseButton::Right,
                down: true
            },
            InjectedInput::MouseClick {
                button: MouseButton::Middle,
                down: true
            },
        ]
    );
}

#[test]
fn test_undecodable_input_payload_reports_handler_error() {
    let (dispatcher, backend) = test_setup();

    // An InputKeyboard message whose payload is not valid CBOR for a
    // KeyboardEvent must surface as a handler error, not a panic.
    let envelope = wrap(ProtocolMessage {
        message_type: MessageType::InputKeyboard,
        message_id: 0,
        flags: 0,
        payload: vec![0xde, 0xad, 0xbe, 0xef],
    });

    let err = dispatcher.dispatch(envelope).unwrap_err();
    assert!(matches!(err, DispatchError::Handler(_)));
    assert!(backend.events().is_empty());
}
