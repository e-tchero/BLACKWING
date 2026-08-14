#![allow(missing_docs)] // Integration-test crate (repo convention)
#![allow(clippy::unwrap_used, clippy::expect_used)] // Test code may panic on failure (repo convention)

use bw_crypto::DeviceId;
use bw_protocol::dispatcher::{DispatchError, MessageDispatcher};
use bw_protocol::message::{MessageType, ProtocolMessage};
use bw_protocol::routing::{MessageEnvelope, NodeId, Route, SessionId};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

fn make_node_id(val: u8) -> NodeId {
    NodeId(DeviceId::from_digest([val; 32]))
}

fn make_envelope(message_type: MessageType) -> MessageEnvelope {
    let msg = ProtocolMessage {
        message_type,
        message_id: 1,
        flags: 0,
        payload: vec![],
    };
    MessageEnvelope {
        source: make_node_id(1),
        destination: make_node_id(2),
        session_id: SessionId([0u8; 16]),
        route: Route::Direct,
        message: msg,
        routing_flags: 0,
    }
}

#[test]
fn test_dispatch_routes_to_registered_handler() {
    let dispatcher = MessageDispatcher::new();
    let calls = Arc::new(AtomicUsize::new(0));
    let calls_clone = Arc::clone(&calls);

    dispatcher.register_handler(
        MessageType::Ping,
        Arc::new(move |envelope| {
            assert_eq!(envelope.message.message_type, MessageType::Ping);
            calls_clone.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }),
    );

    dispatcher
        .dispatch(make_envelope(MessageType::Ping))
        .unwrap();

    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn test_dispatch_returns_no_handler_error() {
    let dispatcher = MessageDispatcher::new();

    let err = dispatcher
        .dispatch(make_envelope(MessageType::Data))
        .unwrap_err();

    assert_eq!(err, DispatchError::NoHandler(MessageType::Data));
}

#[test]
fn test_dispatch_validates_before_routing() {
    let dispatcher = MessageDispatcher::new();
    let calls = Arc::new(AtomicUsize::new(0));
    let calls_clone = Arc::clone(&calls);

    dispatcher.register_handler(
        MessageType::Ping,
        Arc::new(move |_| {
            calls_clone.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }),
    );

    // A Data message with an empty payload and non-zero flags is invalid and
    // must be rejected before the handler registry is consulted.
    let invalid = MessageEnvelope {
        message: ProtocolMessage {
            message_type: MessageType::Data,
            message_id: 1,
            flags: 0x0001,
            payload: vec![],
        },
        source: make_node_id(1),
        destination: make_node_id(2),
        session_id: SessionId([0u8; 16]),
        route: Route::Direct,
        routing_flags: 0,
    };

    let err = dispatcher.dispatch(invalid).unwrap_err();
    assert!(matches!(
        err,
        DispatchError::Validation(bw_protocol::error::ProtocolError::InvalidPayloadLength)
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn test_dispatch_replaces_handler_for_type() {
    let dispatcher = MessageDispatcher::new();
    let first_calls = Arc::new(AtomicUsize::new(0));
    let second_calls = Arc::new(AtomicUsize::new(0));
    let first = Arc::clone(&first_calls);
    let second = Arc::clone(&second_calls);

    dispatcher.register_handler(
        MessageType::Ping,
        Arc::new(move |_| {
            first.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }),
    );
    dispatcher.register_handler(
        MessageType::Ping,
        Arc::new(move |_| {
            second.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }),
    );

    dispatcher
        .dispatch(make_envelope(MessageType::Ping))
        .unwrap();

    assert_eq!(first_calls.load(Ordering::SeqCst), 0);
    assert_eq!(second_calls.load(Ordering::SeqCst), 1);
}

#[test]
fn test_handler_error_propagates() {
    let dispatcher = MessageDispatcher::new();

    dispatcher.register_handler(
        MessageType::Ping,
        Arc::new(|_| Err(DispatchError::NoHandler(MessageType::Ping))),
    );

    let err = dispatcher
        .dispatch(make_envelope(MessageType::Ping))
        .unwrap_err();

    assert_eq!(err, DispatchError::NoHandler(MessageType::Ping));
}

#[test]
fn test_dispatch_routes_input_keyboard_to_handler() {
    let dispatcher = MessageDispatcher::new();
    let received = Arc::new(Mutex::new(None));
    let received_clone = Arc::clone(&received);

    dispatcher.register_handler(
        MessageType::InputKeyboard,
        Arc::new(move |envelope| {
            assert_eq!(envelope.message.message_type, MessageType::InputKeyboard);
            let event = envelope
                .message
                .as_keyboard_event()
                .expect("keyboard event must decode");
            *received_clone.lock().unwrap() = Some((event.keycode, event.is_down));
            Ok(())
        }),
    );

    // VK_A down.
    let msg = ProtocolMessage::keyboard_event(0x41, true).unwrap();
    let envelope = MessageEnvelope {
        source: make_node_id(1),
        destination: make_node_id(2),
        session_id: SessionId([0u8; 16]),
        route: Route::Direct,
        message: msg,
        routing_flags: 0,
    };

    dispatcher.dispatch(envelope).unwrap();

    let got = received
        .lock()
        .unwrap()
        .take()
        .expect("handler must have been called");
    assert_eq!(got, (0x41, true));
}

#[test]
fn test_dispatch_routes_input_mouse_to_handler() {
    let dispatcher = MessageDispatcher::new();
    let received = Arc::new(Mutex::new(None));
    let received_clone = Arc::clone(&received);

    dispatcher.register_handler(
        MessageType::InputMouse,
        Arc::new(move |envelope| {
            assert_eq!(envelope.message.message_type, MessageType::InputMouse);
            let event = envelope
                .message
                .as_mouse_event()
                .expect("mouse event must decode");
            *received_clone.lock().unwrap() = Some((event.dx, event.dy, event.buttons_mask));
            Ok(())
        }),
    );

    // Move right/down 100/-50 with left + middle buttons held.
    let msg = ProtocolMessage::mouse_event(100, -50, 0b101).unwrap();
    let envelope = MessageEnvelope {
        source: make_node_id(1),
        destination: make_node_id(2),
        session_id: SessionId([0u8; 16]),
        route: Route::Direct,
        message: msg,
        routing_flags: 0,
    };

    dispatcher.dispatch(envelope).unwrap();

    let got = received
        .lock()
        .unwrap()
        .take()
        .expect("handler must have been called");
    assert_eq!(got, (100, -50, 0b101));
}

#[test]
fn test_input_message_with_empty_payload_is_rejected_before_routing() {
    let dispatcher = MessageDispatcher::new();
    let calls = Arc::new(AtomicUsize::new(0));
    let calls_clone = Arc::clone(&calls);

    dispatcher.register_handler(
        MessageType::InputKeyboard,
        Arc::new(move |_| {
            calls_clone.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }),
    );

    // An InputKeyboard message must carry a serialized event payload; an empty
    // one fails validation before the handler registry is consulted.
    let invalid = MessageEnvelope {
        message: ProtocolMessage {
            message_type: MessageType::InputKeyboard,
            message_id: 1,
            flags: 0,
            payload: vec![],
        },
        source: make_node_id(1),
        destination: make_node_id(2),
        session_id: SessionId([0u8; 16]),
        route: Route::Direct,
        routing_flags: 0,
    };

    let err = dispatcher.dispatch(invalid).unwrap_err();
    assert!(matches!(
        err,
        DispatchError::Validation(bw_protocol::error::ProtocolError::InvalidPayloadLength)
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}
