//! Reliability ↔ Encryption composition pipeline.
//!
//! Bridges the [`reliability`] and [`encryption`] subsystems so that
//! outbound messages are first wrapped in a [`ReliableFrame`] (with
//! sequence number and retransmission tracking) and then encrypted via
//! [`EncryptionContext`].  The inbound path reverses the process: decrypt,
//! deserialise the [`ReliableFrame`], feed it to the [`ReliableReceiver`]
//! for duplicate filtering and ordered assembly, and yield the original
//! payload bytes.
//!
//! # Ownership
//!
//! [`SessionPipeline`] owns the per-session [`ReliableSender`] and
//! [`ReliableReceiver`].  The [`EncryptionContext`] is borrowed from the
//! [`SessionManager`](crate::session::SessionManager) via
//! [`with_session_context`](crate::session::SessionManager::with_session_context)
//! — the pipeline does **not** own cryptographic state.

use crate::encryption::{EncryptedFrame, EncryptionContext};
use crate::error::ProtocolError;
use crate::frame::OwnedProtocolFrame;
use crate::header::{PacketHeader, PROTOCOL_MAGIC};
use crate::reliability::{
    AckFrame, ReliableFrame, ReliableReceiver, ReliableSender, SequenceNumber, TimeoutPolicy,
};
use crate::version::CURRENT_VERSION;

/// Per-session pipeline state combining reliable delivery and encryption.
///
/// Create one instance per active session.
///
/// # Example
///
/// ```ignore
/// let mut pipeline = SessionPipeline::new(32, TimeoutPolicy {
///     rto: Duration::from_millis(200),
///     max_retransmissions: 5,
/// });
///
/// // Outbound
/// let encrypted = session.with_session_context(&session_id, |ctx| {
///     pipeline.send(ctx, &message_bytes)
/// })?;
///
/// // Inbound
/// let payloads = session.with_session_context(&session_id, |ctx| {
///     pipeline.receive(ctx, &encrypted)
/// })?;
/// ```
#[derive(Debug)]
pub struct SessionPipeline {
    /// Reliable delivery sender for outbound frames.
    pub sender: ReliableSender,
    /// Reliable delivery receiver for inbound frames.
    pub receiver: ReliableReceiver,
}

impl SessionPipeline {
    /// Creates a new `SessionPipeline` with the given window size and timeout policy.
    pub fn new(window_size: u32, policy: TimeoutPolicy) -> Self {
        Self {
            sender: ReliableSender::new(window_size, policy),
            receiver: ReliableReceiver::new(),
        }
    }

    /// Composes the outbound path: reliable-wrap → frame → encrypt.
    ///
    /// 1. Wraps `message_bytes` in a [`ReliableFrame`] with the next
    ///    sequence number.
    /// 2. Serialises the [`ReliableFrame`] to CBOR.
    /// 3. Wraps the CBOR in a [`PacketHeader`] to form an
    ///    [`OwnedProtocolFrame`].
    /// 4. Encrypts the frame via `enc_ctx` and returns the
    ///    [`EncryptedFrame`].
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::WindowFull`] if the sender's window is
    /// exhausted.  Returns [`ProtocolError::EncryptionError`] if AEAD
    /// encryption fails.
    pub fn send(
        &mut self,
        enc_ctx: &mut EncryptionContext,
        message_bytes: &[u8],
    ) -> Result<EncryptedFrame, ProtocolError> {
        // 1. Reliable wrapping
        let reliable = self.sender.send(message_bytes.to_vec())?;

        // 2. Serialise ReliableFrame to CBOR
        let mut payload = Vec::new();
        ciborium::into_writer(&reliable, &mut payload)
            .map_err(|_| ProtocolError::SerializationError)?;

        // 3. Wrap in protocol frame
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_micros() as u64)
            .unwrap_or(0);

        let header = PacketHeader {
            magic: PROTOCOL_MAGIC,
            schema_version: u16::from(CURRENT_VERSION),
            flags: 0,
            packet_type: 5, // MessageType::Data as u16
            payload_length: payload.len() as u16,
            sequence_number: reliable.seq.0 as u32,
            session_epoch: enc_ctx.current_key_epoch() as u64,
            monotonic_timestamp: timestamp,
        };
        let frame = OwnedProtocolFrame { header, payload };

        // 4. Encrypt
        enc_ctx.encrypt_frame(&frame)
    }

    /// Composes the inbound path: decrypt → deserialise reliable → ordered delivery.
    ///
    /// 1. Decrypts `encrypted` via `enc_ctx` to obtain an
    ///    [`OwnedProtocolFrame`].
    /// 2. Deserialises the frame's payload as a [`ReliableFrame`].
    /// 3. Feeds the [`ReliableFrame`] to the [`ReliableReceiver`] for
    ///    duplicate filtering and ordered assembly.
    ///
    /// # Returns
    ///
    /// A vector of payload byte-vectors that are ready for application
    /// processing.  The vector may be empty if the frame was a duplicate
    /// or if the assembled sequence has gaps.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::EncryptionError`] if AEAD decryption or
    /// replay verification fails.  Returns [`ProtocolError::DeserializationError`]
    /// if the decrypted payload is not a valid CBOR-encoded
    /// [`ReliableFrame`].
    pub fn receive(
        &mut self,
        enc_ctx: &mut EncryptionContext,
        encrypted: &EncryptedFrame,
    ) -> Result<Vec<Vec<u8>>, ProtocolError> {
        // 1. Decrypt
        let owned = enc_ctx.decrypt_frame(encrypted)?;

        // 2. Deserialise ReliableFrame from the decrypted payload
        let reliable: ReliableFrame = ciborium::de::from_reader(&owned.payload[..])
            .map_err(|_| ProtocolError::DeserializationError)?;

        // 3. Process through reliable receiver (duplicate filter + ordered assembly)
        self.receiver.receive(reliable)
    }

    /// Processes an incoming acknowledgment frame.
    ///
    /// Delegates to [`ReliableSender::ack`] to mark frames as delivered
    /// and slide the send window.
    pub fn process_ack(&mut self, ack: &AckFrame) -> Result<(), ProtocolError> {
        self.sender.ack(ack)
    }

    /// Returns the sequence number that the receiver expects next.
    ///
    /// This value should be included in outgoing ACK frames so the remote
    /// sender knows which frames have been received.
    pub fn next_expected_seq(&self) -> SequenceNumber {
        self.receiver.next_expected()
    }

    /// Returns the number of available slots in the sender's window.
    pub fn window_available(&self) -> u32 {
        self.sender.window_available()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encryption::{KeyRotationPolicy, SessionKeys};
    use bw_crypto::hkdf_derive;

    /// Helper: build test session keys where both directions use the same key.
    ///
    /// This matches what a real peer would have after a handshake: the
    /// sender's encrypt key equals the receiver's decrypt key (and vice
    /// versa).  For round-trip tests within a single pipeline we use
    /// identical keys.
    fn make_test_keys(label: &[u8]) -> SessionKeys {
        let k = hkdf_derive(None, label, None).unwrap();
        SessionKeys {
            send_key: k.clone(),
            recv_key: k,
            epoch: 0,
        }
    }

    #[test]
    fn test_pipeline_send_receive_roundtrip() {
        let mut pipeline = SessionPipeline::new(
            32,
            TimeoutPolicy {
                rto: std::time::Duration::from_millis(200),
                max_retransmissions: 5,
            },
        );

        let keys = make_test_keys(b"roundtrip");
        let mut enc_ctx = EncryptionContext::new(keys, KeyRotationPolicy::Manual);

        let original = b"Hello, Blackwing!";
        let encrypted = pipeline
            .send(&mut enc_ctx, original)
            .expect("send must succeed");

        let payloads = pipeline
            .receive(&mut enc_ctx, &encrypted)
            .expect("receive must succeed");

        assert_eq!(payloads.len(), 1, "Should yield exactly one payload");
        assert_eq!(payloads[0], original, "Payload must match original");
    }

    #[test]
    fn test_pipeline_sequence_numbers_increment() {
        let mut pipeline = SessionPipeline::new(
            32,
            TimeoutPolicy {
                rto: std::time::Duration::from_millis(200),
                max_retransmissions: 5,
            },
        );

        let keys = make_test_keys(b"seq-incr");
        let mut enc_ctx = EncryptionContext::new(keys, KeyRotationPolicy::Manual);

        let e1 = pipeline.send(&mut enc_ctx, b"msg-1").unwrap();
        let e2 = pipeline.send(&mut enc_ctx, b"msg-2").unwrap();
        let e3 = pipeline.send(&mut enc_ctx, b"msg-3").unwrap();

        // Sequence numbers should be 0, 1, 2
        let r1 = pipeline.receive(&mut enc_ctx, &e1).unwrap();
        let r2 = pipeline.receive(&mut enc_ctx, &e2).unwrap();
        let r3 = pipeline.receive(&mut enc_ctx, &e3).unwrap();

        assert_eq!(r1[0], b"msg-1");
        assert_eq!(r2[0], b"msg-2");
        assert_eq!(r3[0], b"msg-3");
    }

    #[test]
    fn test_pipeline_encryption_counters_advance() {
        let mut pipeline = SessionPipeline::new(
            32,
            TimeoutPolicy {
                rto: std::time::Duration::from_millis(200),
                max_retransmissions: 5,
            },
        );

        let keys = make_test_keys(b"counter");
        let mut enc_ctx = EncryptionContext::new(keys, KeyRotationPolicy::Manual);

        // Each send produces an EncryptedFrame with a unique nonce counter
        let e1 = pipeline.send(&mut enc_ctx, b"frame-1").unwrap();
        assert_eq!(
            e1.nonce.counter(),
            0,
            "First frame should use nonce counter 0"
        );

        let e2 = pipeline.send(&mut enc_ctx, b"frame-2").unwrap();
        assert_eq!(
            e2.nonce.counter(),
            1,
            "Second frame should use nonce counter 1"
        );

        let e3 = pipeline.send(&mut enc_ctx, b"frame-3").unwrap();
        assert_eq!(
            e3.nonce.counter(),
            2,
            "Third frame should use nonce counter 2"
        );
    }

    #[test]
    fn test_pipeline_duplicate_rejection() {
        let mut pipeline = SessionPipeline::new(
            32,
            TimeoutPolicy {
                rto: std::time::Duration::from_millis(200),
                max_retransmissions: 5,
            },
        );

        let keys = make_test_keys(b"dup");
        let mut enc_ctx = EncryptionContext::new(keys, KeyRotationPolicy::Manual);

        let encrypted = pipeline.send(&mut enc_ctx, b"unique").unwrap();

        // First receive — should yield the payload
        let first = pipeline.receive(&mut enc_ctx, &encrypted).unwrap();
        assert_eq!(first.len(), 1);

        // Second receive of the *same* encrypted frame — should be rejected by
        // replay protection (same nonce counter used twice)
        let second = pipeline.receive(&mut enc_ctx, &encrypted);
        assert!(
            second.is_err(),
            "Replaying the same encrypted frame should be rejected"
        );
    }

    #[test]
    fn test_pipeline_window_full_error() {
        // Use window size 2, then send 3 messages
        let mut pipeline = SessionPipeline::new(
            2,
            TimeoutPolicy {
                rto: std::time::Duration::from_millis(200),
                max_retransmissions: 5,
            },
        );

        let keys = make_test_keys(b"window");
        let mut enc_ctx = EncryptionContext::new(keys, KeyRotationPolicy::Manual);

        // First two should succeed
        pipeline.send(&mut enc_ctx, b"a").unwrap();
        pipeline.send(&mut enc_ctx, b"b").unwrap();

        // Third should fail — window full
        let result = pipeline.send(&mut enc_ctx, b"c");
        assert!(
            matches!(result, Err(ProtocolError::WindowFull)),
            "Expected WindowFull, got {:?}",
            result
        );
    }

    #[test]
    fn test_pipeline_ack_slides_window() {
        let mut pipeline = SessionPipeline::new(
            3,
            TimeoutPolicy {
                rto: std::time::Duration::from_millis(200),
                max_retransmissions: 5,
            },
        );

        let keys = make_test_keys(b"ack");
        let mut enc_ctx = EncryptionContext::new(keys, KeyRotationPolicy::Manual);

        pipeline.send(&mut enc_ctx, b"msg-1").unwrap();
        pipeline.send(&mut enc_ctx, b"msg-2").unwrap();

        // Window should have 1 slot available (3 - 2 unacked)
        assert_eq!(pipeline.window_available(), 1);

        // ACK seq 0 — slides window past frame 0
        let ack = AckFrame {
            acked_seq: SequenceNumber(0),
            ack_bits: 0,
        };
        pipeline.process_ack(&ack).unwrap();

        // After acking seq 0: base slides to 1, next_seq=2, so 1 pending out of 3
        assert_eq!(
            pipeline.window_available(),
            2,
            "After acking seq 0: 1 pending, 2 available"
        );

        // Send another (seq 2) — should succeed
        pipeline.send(&mut enc_ctx, b"msg-3").unwrap();

        // ACK seq 1 — slides window past frame 1
        let ack = AckFrame {
            acked_seq: SequenceNumber(1),
            ack_bits: 0,
        };
        pipeline.process_ack(&ack).unwrap();

        // After acking seq 1: base slides to 2, next_seq=3, so 1 pending out of 3
        assert_eq!(
            pipeline.window_available(),
            2,
            "After acking seq 1: 1 pending, 2 available"
        );

        // Send one more (seq 3)
        pipeline.send(&mut enc_ctx, b"msg-4").unwrap();
    }
}
