//! Full-stack integration test: SessionPipeline → MessageDispatcher.
//!
//! Proves the complete message flow from serialization through the
//! reliability+encryption composition pipeline and into the route handler
//! registry — without any networking or mocking of protocol internals.
//!
//! ```text
//! ProtocolMessage
//!   → serialize → SessionPipeline::send  (reliable-wrap + encrypt)
//!   → EncryptedFrame
//!   → SessionPipeline::receive (decrypt + reliable-receive)
//!   → payload bytes
//!   → ProtocolMessage::deserialize
//!   → MessageEnvelope::wrap
//!   → MessageDispatcher::dispatch
//!   → registered handler asserts correct message
//! ```

use bw_crypto::hkdf_derive;
use bw_protocol::dispatcher::{MessageDispatcher, MessageHandler};
use bw_protocol::encryption::{EncryptionContext, KeyRotationPolicy, SessionKeys};
use bw_protocol::error::ProtocolError;
use bw_protocol::message::{MessageType, ProtocolMessage};
use bw_protocol::pipeline::SessionPipeline;
use bw_protocol::reliability::TimeoutPolicy;
use bw_protocol::routing::{MessageEnvelope, NodeId, Route, SessionId};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Build test session keys from a label.
fn make_session_keys(label: &[u8]) -> SessionKeys {
    let k = hkdf_derive(None, label, None).unwrap();
    SessionKeys {
        send_key: k.clone(),
        recv_key: k,
        epoch: 0,
    }
}

/// A handler that records call count and verifies message content.
struct AssertHandler {
    call_count: Arc<AtomicUsize>,
    expected_type: MessageType,
    expected_payload: Vec<u8>,
}

impl MessageHandler for AssertHandler {
    fn handle(&self, envelope: &MessageEnvelope) -> Result<(), ProtocolError> {
        self.call_count.fetch_add(1, Ordering::SeqCst);

        // Verify message type
        assert_eq!(
            envelope.message.message_type, self.expected_type,
            "Handler should receive the correct message type"
        );

        // Verify payload integrity
        assert_eq!(
            envelope.message.payload, self.expected_payload,
            "Handler should receive the correct payload bytes"
        );

        Ok(())
    }
}

// ── Test: Full pipeline → dispatcher round-trip with real data ──────────────

#[test]
fn test_full_pipeline_to_dispatcher_roundtrip() {
    // ── 1. Setup: pipeline + dispatcher + handler ─────────────────────────
    let mut pipeline = SessionPipeline::new(
        32,
        TimeoutPolicy {
            rto: Duration::from_millis(200),
            max_retransmissions: 5,
        },
    );

    let dispatcher = MessageDispatcher::new();
    let call_count = Arc::new(AtomicUsize::new(0));

    let expected_payload = b"Hello from the pipeline!".to_vec();
    dispatcher
        .register_handler(
            MessageType::Data,
            AssertHandler {
                call_count: Arc::clone(&call_count),
                expected_type: MessageType::Data,
                expected_payload: expected_payload.clone(),
            },
        )
        .expect("handler registration");

    // ── 2. Create encryption context (simulates a session) ────────────────
    let keys = make_session_keys(b"integration-test");
    let mut enc_ctx = EncryptionContext::new(keys, KeyRotationPolicy::Manual);

    // ── 3. Create the original message ────────────────────────────────────
    let original_msg = ProtocolMessage {
        message_type: MessageType::Data,
        message_id: 42,
        flags: 0,
        payload: expected_payload,
    };

    let message_bytes = original_msg.serialize().expect("serialize message");

    // ── 4. Outbound: push through pipeline (reliable → encrypt) ──────────
    let encrypted = pipeline
        .send(&mut enc_ctx, &message_bytes)
        .expect("pipeline send");

    // Verify the encryptor counter advanced
    assert_eq!(
        encrypted.nonce.counter(),
        0,
        "First frame should use nonce counter 0"
    );

    // ── 5. Inbound: pull through pipeline (decrypt → reliable receive) ───
    let received_payloads = pipeline
        .receive(&mut enc_ctx, &encrypted)
        .expect("pipeline receive");

    assert_eq!(
        received_payloads.len(),
        1,
        "Pipeline should yield exactly one payload"
    );

    // ── 6. Deserialize the ProtocolMessage ────────────────────────────────
    let received_msg =
        ProtocolMessage::deserialize(&received_payloads[0]).expect("deserialize message");

    assert_eq!(
        received_msg.message_type,
        MessageType::Data,
        "Message type should survive the round-trip"
    );
    assert_eq!(
        received_msg.message_id, 42,
        "Message ID should survive the round-trip"
    );
    assert_eq!(
        received_msg.payload, original_msg.payload,
        "Payload should survive the round-trip"
    );

    // ── 7. Wrap in envelope and dispatch ──────────────────────────────────
    let envelope = MessageEnvelope {
        source: NodeId(bw_crypto::DeviceId::from_digest([0x01; 32])),
        destination: NodeId(bw_crypto::DeviceId::from_digest([0x02; 32])),
        session_id: SessionId([0xAB; 16]),
        route: Route::Direct,
        message: received_msg,
        routing_flags: 0,
    };

    dispatcher
        .dispatch(envelope)
        .expect("dispatch must succeed");

    // ── 8. Verify the handler was called exactly once with correct data ───
    assert_eq!(
        call_count.load(Ordering::SeqCst),
        1,
        "Handler should have been called exactly once"
    );
}

// ── Test: Multiple messages preserve ordering ────────────────────────────────

/// A handler that only counts calls, without checking payload content.
struct CountHandler {
    count: Arc<AtomicUsize>,
}

impl MessageHandler for CountHandler {
    fn handle(&self, _envelope: &MessageEnvelope) -> Result<(), ProtocolError> {
        self.count.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

#[test]
fn test_pipeline_to_dispatcher_multiple_messages() {
    let mut pipeline = SessionPipeline::new(
        32,
        TimeoutPolicy {
            rto: Duration::from_millis(200),
            max_retransmissions: 5,
        },
    );

    let dispatcher = MessageDispatcher::new();
    let call_count = Arc::new(AtomicUsize::new(0));

    dispatcher
        .register_handler(
            MessageType::Data,
            CountHandler {
                count: Arc::clone(&call_count),
            },
        )
        .expect("handler registration");

    let keys = make_session_keys(b"ordering");
    let mut enc_ctx = EncryptionContext::new(keys, KeyRotationPolicy::Manual);

    // Send three messages with distinct payloads
    let messages = vec!["msg-A", "msg-B", "msg-C"];
    let mut encrypted_frames = Vec::new();

    for content in &messages {
        let msg = ProtocolMessage {
            message_type: MessageType::Data,
            message_id: 1,
            flags: 0,
            payload: content.as_bytes().to_vec(),
        };
        let bytes = msg.serialize().unwrap();
        let encrypted = pipeline.send(&mut enc_ctx, &bytes).unwrap();
        encrypted_frames.push((encrypted, msg));
    }

    // Receive all three — they should come out in order
    for (i, (encrypted, original_msg)) in encrypted_frames.iter().enumerate() {
        let payloads = pipeline.receive(&mut enc_ctx, encrypted).unwrap();
        assert_eq!(
            payloads.len(),
            1,
            "Message {} should yield exactly one payload",
            i
        );

        let received = ProtocolMessage::deserialize(&payloads[0]).unwrap();
        assert_eq!(
            received.payload, original_msg.payload,
            "Payload for message {} should survive the round-trip",
            i
        );

        let envelope = MessageEnvelope {
            source: NodeId(bw_crypto::DeviceId::from_digest([0x01; 32])),
            destination: NodeId(bw_crypto::DeviceId::from_digest([0x02; 32])),
            session_id: SessionId([0xAB; 16]),
            route: Route::Direct,
            message: received,
            routing_flags: 0,
        };
        dispatcher.dispatch(envelope).unwrap();
    }

    assert_eq!(
        call_count.load(Ordering::SeqCst),
        3,
        "Handler should have been called 3 times"
    );
}

// ── Test: Tampered ciphertext is rejected before reaching the dispatcher ─────

#[test]
fn test_tampered_ciphertext_rejected_by_pipeline() {
    let mut pipeline = SessionPipeline::new(
        32,
        TimeoutPolicy {
            rto: Duration::from_millis(200),
            max_retransmissions: 5,
        },
    );

    let dispatcher = MessageDispatcher::new();
    let call_count = Arc::new(AtomicUsize::new(0));

    dispatcher
        .register_handler(
            MessageType::Data,
            AssertHandler {
                call_count: Arc::clone(&call_count),
                expected_type: MessageType::Data,
                expected_payload: vec![],
            },
        )
        .expect("handler registration");

    let keys = make_session_keys(b"tamper");
    let mut enc_ctx = EncryptionContext::new(keys, KeyRotationPolicy::Manual);

    // Create and send a valid message
    let msg = ProtocolMessage {
        message_type: MessageType::Data,
        message_id: 1,
        flags: 0,
        payload: b"secret data".to_vec(),
    };
    let bytes = msg.serialize().unwrap();
    let mut encrypted = pipeline.send(&mut enc_ctx, &bytes).unwrap();

    // Tamper with the ciphertext
    if !encrypted.ciphertext.is_empty() {
        encrypted.ciphertext[0] ^= 0xFF;
    }

    // Receiving the tampered frame should fail
    let result = pipeline.receive(&mut enc_ctx, &encrypted);
    assert!(result.is_err(), "Tampered ciphertext should be rejected");

    // Handler should NOT have been called
    assert_eq!(
        call_count.load(Ordering::SeqCst),
        0,
        "Handler should not be called for tampered data"
    );
}

// ── Test: Unregistered message types are silently dropped ────────────────────

#[test]
fn test_unregistered_message_type_silently_dropped() {
    let mut pipeline = SessionPipeline::new(
        32,
        TimeoutPolicy {
            rto: Duration::from_millis(200),
            max_retransmissions: 5,
        },
    );

    // Only register for Data, not for Ping
    let dispatcher = MessageDispatcher::new();
    let call_count = Arc::new(AtomicUsize::new(0));

    dispatcher
        .register_handler(
            MessageType::Data,
            AssertHandler {
                call_count: Arc::clone(&call_count),
                expected_type: MessageType::Data,
                expected_payload: vec![],
            },
        )
        .expect("handler registration");

    let keys = make_session_keys(b"unregistered");
    let mut enc_ctx = EncryptionContext::new(keys, KeyRotationPolicy::Manual);

    // Send a Ping message — no handler registered
    let msg = ProtocolMessage {
        message_type: MessageType::Ping,
        message_id: 1,
        flags: 0,
        payload: vec![],
    };
    let bytes = msg.serialize().unwrap();
    let encrypted = pipeline.send(&mut enc_ctx, &bytes).unwrap();
    let payloads = pipeline.receive(&mut enc_ctx, &encrypted).unwrap();

    let received = ProtocolMessage::deserialize(&payloads[0]).unwrap();
    let envelope = MessageEnvelope {
        source: NodeId(bw_crypto::DeviceId::from_digest([0x01; 32])),
        destination: NodeId(bw_crypto::DeviceId::from_digest([0x02; 32])),
        session_id: SessionId([0xAB; 16]),
        route: Route::Direct,
        message: received,
        routing_flags: 0,
    };

    // Dispatch should succeed but handler should NOT be called
    let result = dispatcher.dispatch(envelope);
    assert!(result.is_ok(), "Unregistered type should not error");
    assert_eq!(
        call_count.load(Ordering::SeqCst),
        0,
        "Handler should not be called for unregistered type"
    );
}
