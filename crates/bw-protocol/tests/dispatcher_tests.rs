//! Integration tests for the MessageDispatcher route handler registry.
//!
//! Tests cover:
//! - Handler receives the correct message type
//! - Multiple handlers for the same message type (fan-out)
//! - Unregistered message types are silently ignored (no error)
//! - Handler errors propagate and stop subsequent handlers
//! - Envelope validation occurs before handlers are invoked
//! - Handler registration and unregistration

use bw_crypto::DeviceId;
use bw_protocol::dispatcher::{MessageDispatcher, MessageHandler};
use bw_protocol::error::ProtocolError;
use bw_protocol::message::{MessageType, ProtocolMessage};
use bw_protocol::routing::{MessageEnvelope, NodeId, Route, SessionId};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

// ── Helpers ──────────────────────────────────────────────────────────────────

fn make_node_id(val: u8) -> NodeId {
    NodeId(DeviceId::from_digest([val; 32]))
}

fn make_envelope(msg_type: MessageType) -> MessageEnvelope {
    let msg = ProtocolMessage {
        message_type: msg_type,
        message_id: 1,
        flags: 0,
        payload: vec![],
    };
    MessageEnvelope {
        source: make_node_id(1),
        destination: make_node_id(2),
        session_id: SessionId([0xAB; 16]),
        route: Route::Direct,
        message: msg,
        routing_flags: 0,
    }
}

/// A handler that records the message types it receives.
struct RecorderHandler {
    recorded: Arc<std::sync::Mutex<Vec<MessageType>>>,
}

impl MessageHandler for RecorderHandler {
    fn handle(&self, envelope: &MessageEnvelope) -> Result<(), ProtocolError> {
        self.recorded
            .lock()
            .unwrap()
            .push(envelope.message.message_type);
        Ok(())
    }
}

/// A handler that always returns an error.
struct ErrorHandler {
    error: ProtocolError,
}

impl MessageHandler for ErrorHandler {
    fn handle(&self, _envelope: &MessageEnvelope) -> Result<(), ProtocolError> {
        Err(self.error.clone())
    }
}

/// A counter handler that increments a counter and optionally errors after N calls.
struct CounterHandler {
    count: Arc<AtomicUsize>,
}

impl MessageHandler for CounterHandler {
    fn handle(&self, _envelope: &MessageEnvelope) -> Result<(), ProtocolError> {
        self.count.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[test]
fn test_handler_receives_correct_message_type() {
    let dispatcher = MessageDispatcher::new();
    let recorded = Arc::new(std::sync::Mutex::new(Vec::new()));

    dispatcher
        .register_handler(
            MessageType::Ping,
            RecorderHandler {
                recorded: Arc::clone(&recorded),
            },
        )
        .unwrap();

    let envelope = make_envelope(MessageType::Ping);
    dispatcher.dispatch(envelope).unwrap();

    let log = recorded.lock().unwrap();
    assert_eq!(log.len(), 1, "Handler should have been called once");
    assert_eq!(log[0], MessageType::Ping, "Handler should receive Ping");
}

#[test]
fn test_multiple_handlers_for_same_type() {
    let dispatcher = MessageDispatcher::new();
    let recorded1 = Arc::new(std::sync::Mutex::new(Vec::new()));
    let recorded2 = Arc::new(std::sync::Mutex::new(Vec::new()));

    dispatcher
        .register_handler(
            MessageType::Data,
            RecorderHandler {
                recorded: Arc::clone(&recorded1),
            },
        )
        .unwrap();
    dispatcher
        .register_handler(
            MessageType::Data,
            RecorderHandler {
                recorded: Arc::clone(&recorded2),
            },
        )
        .unwrap();

    let envelope = make_envelope(MessageType::Data);
    dispatcher.dispatch(envelope).unwrap();

    assert_eq!(
        recorded1.lock().unwrap().len(),
        1,
        "First handler should be called"
    );
    assert_eq!(
        recorded2.lock().unwrap().len(),
        1,
        "Second handler should be called"
    );
}

#[test]
fn test_unregistered_type_is_silently_dropped() {
    let dispatcher = MessageDispatcher::new();
    let count = Arc::new(AtomicUsize::new(0));

    // Register handler only for Ping, not for Heartbeat
    dispatcher
        .register_handler(
            MessageType::Ping,
            CounterHandler {
                count: Arc::clone(&count),
            },
        )
        .unwrap();

    // Dispatch Heartbeat — no handler registered, should be silently dropped
    let envelope = make_envelope(MessageType::Heartbeat);
    let result = dispatcher.dispatch(envelope);

    assert!(
        result.is_ok(),
        "Unregistered type should not produce an error"
    );
    assert_eq!(
        count.load(Ordering::SeqCst),
        0,
        "Handler should not be called"
    );
}

#[test]
fn test_handler_error_propagates_and_stops_subsequent_handlers() {
    let dispatcher = MessageDispatcher::new();
    let count = Arc::new(AtomicUsize::new(0));

    // ErrorHandler registered first
    dispatcher
        .register_handler(
            MessageType::Control,
            ErrorHandler {
                error: ProtocolError::InvalidHandshake,
            },
        )
        .unwrap();
    // CounterHandler registered second — should never be reached
    dispatcher
        .register_handler(
            MessageType::Control,
            CounterHandler {
                count: Arc::clone(&count),
            },
        )
        .unwrap();

    let envelope = make_envelope(MessageType::Control);
    let result = dispatcher.dispatch(envelope);

    assert!(
        result.is_err(),
        "Handler error should propagate from dispatch"
    );
    assert_eq!(
        result.err().unwrap(),
        ProtocolError::InvalidHandshake,
        "Should propagate the exact error"
    );
    assert_eq!(
        count.load(Ordering::SeqCst),
        0,
        "Second handler should NOT be called after error"
    );
}

#[test]
fn test_validation_occurs_before_handlers() {
    let dispatcher = MessageDispatcher::new();
    let count = Arc::new(AtomicUsize::new(0));

    dispatcher
        .register_handler(
            MessageType::Ping,
            CounterHandler {
                count: Arc::clone(&count),
            },
        )
        .unwrap();

    // Create an invalid envelope: self-addressed with Route::Direct (forbidden)
    let invalid_msg = ProtocolMessage {
        message_type: MessageType::Ping,
        message_id: 1,
        flags: 0,
        payload: vec![],
    };
    let invalid_envelope = MessageEnvelope {
        source: make_node_id(1),
        destination: make_node_id(1), // same as source — fails Route::Direct validation
        session_id: SessionId([0xAB; 16]),
        route: Route::Direct,
        message: invalid_msg,
        routing_flags: 0,
    };

    let result = dispatcher.dispatch(invalid_envelope);

    assert!(result.is_err(), "Invalid envelope should fail validation");
    assert_eq!(
        result.err().unwrap(),
        ProtocolError::InvalidDestination,
        "Should fail with routing validation error"
    );
    assert_eq!(
        count.load(Ordering::SeqCst),
        0,
        "Handler should NOT be called when validation fails"
    );
}

#[test]
fn test_multiple_message_types_independent_routing() {
    let dispatcher = MessageDispatcher::new();
    let recorded = Arc::new(std::sync::Mutex::new(Vec::new()));

    dispatcher
        .register_handler(
            MessageType::Ping,
            RecorderHandler {
                recorded: Arc::clone(&recorded),
            },
        )
        .unwrap();
    dispatcher
        .register_handler(
            MessageType::Pong,
            RecorderHandler {
                recorded: Arc::clone(&recorded),
            },
        )
        .unwrap();

    // Dispatch Ping, then Pong, then Ping
    dispatcher
        .dispatch(make_envelope(MessageType::Ping))
        .unwrap();
    dispatcher
        .dispatch(make_envelope(MessageType::Pong))
        .unwrap();
    dispatcher
        .dispatch(make_envelope(MessageType::Ping))
        .unwrap();

    let log = recorded.lock().unwrap();
    assert_eq!(log.len(), 3, "Should have dispatched 3 messages total");
    assert_eq!(log[0], MessageType::Ping);
    assert_eq!(log[1], MessageType::Pong);
    assert_eq!(log[2], MessageType::Ping);
}

#[test]
fn test_unregister_handlers() {
    let dispatcher = MessageDispatcher::new();
    let count = Arc::new(AtomicUsize::new(0));

    dispatcher
        .register_handler(
            MessageType::Ping,
            CounterHandler {
                count: Arc::clone(&count),
            },
        )
        .unwrap();

    // Handler should fire
    dispatcher
        .dispatch(make_envelope(MessageType::Ping))
        .unwrap();
    assert_eq!(count.load(Ordering::SeqCst), 1, "Handler should fire once");

    // Unregister and dispatch again
    dispatcher.unregister_handlers(&MessageType::Ping).unwrap();
    dispatcher
        .dispatch(make_envelope(MessageType::Ping))
        .unwrap();
    assert_eq!(
        count.load(Ordering::SeqCst),
        1,
        "Handler should NOT fire after unregister"
    );
}

#[test]
fn test_dispatch_does_not_deadlock_on_concurrent_access() {
    let dispatcher = Arc::new(MessageDispatcher::new());
    let count = Arc::new(AtomicUsize::new(0));

    dispatcher
        .register_handler(
            MessageType::Heartbeat,
            CounterHandler {
                count: Arc::clone(&count),
            },
        )
        .unwrap();

    let mut handles = Vec::new();
    for _ in 0..10 {
        let d = Arc::clone(&dispatcher);
        let handle = std::thread::spawn(move || {
            for _ in 0..100 {
                let envelope = make_envelope(MessageType::Heartbeat);
                let _ = d.dispatch(envelope);
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().expect("Thread panicked");
    }

    assert_eq!(
        count.load(Ordering::SeqCst),
        1000,
        "All 1000 dispatches should have reached the handler"
    );
}
