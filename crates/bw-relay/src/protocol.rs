use crate::candidate::Candidate;
use bw_crypto::DeviceId;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

/// All control messages exchanged between endpoints and the relay server.
///
/// The relay operates purely on the control plane. It never handles
/// `bw-session` encryption keys or `bw-encoder` media payloads.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RelayMessage {
    // ─── Phase 1: Registration & Discovery ───────────────────────────────────
    /// Register this endpoint with the relay.
    ///
    /// The `signature_bytes` field MUST be an Ed25519 signature over:
    /// `SHA-256(device_id || verify_key_bytes || timestamp.to_be_bytes())`
    ///
    /// This expanded signed payload (Phase 2 upgrade from Phase 1) binds the
    /// claimed identity, the public key, and the freshness nonce into a single
    /// attested statement, preventing partial-substitution attacks.
    RegisterRequest {
        /// The device's self-declared identity (must equal SHA-256 of verify_key).
        device_id: DeviceId,
        /// The device's Ed25519 public verification key (32 bytes).
        verify_key_bytes: [u8; 32],
        /// Current timestamp in milliseconds (UNIX epoch) for replay prevention.
        timestamp: u64,
        /// Ed25519 signature over SHA-256(device_id || verify_key_bytes || timestamp).
        signature_bytes: Vec<u8>,
    },
    /// Relay acknowledgement of successful registration.
    RegisterAck {
        /// Monotonically-increasing session identifier assigned by the relay.
        relay_session_id: u64,
        /// The server-reflexive address observed by the relay for this endpoint.
        /// Endpoints should include this in their candidate set for ConnectIntent.
        server_reflexive_addr: Option<SocketAddr>,
    },
    /// Query whether a target device is currently registered.
    DiscoverRequest {
        /// The device ID to look up.
        target: DeviceId,
    },
    /// Response to a discovery request.
    DiscoverResponse {
        /// The queried device ID.
        target: DeviceId,
        /// Whether the target is currently registered and considered online.
        is_online: bool,
    },
    /// Relay rejection of a prior request.
    ErrorResponse {
        /// Human-readable rejection reason. Never contains secrets.
        reason: String,
    },

    // ─── Phase 2: Rendezvous & Connect-Intent ────────────────────────────────
    /// Declare intent to connect to a target device.
    ///
    /// The `signature_bytes` field MUST be an Ed25519 signature over:
    /// `SHA-256(intent_id || initiator_device_id || target || timestamp.to_be_bytes())`
    ///
    /// The relay validates that `initiator_device_id` is registered and that the
    /// signature matches their registered public key before forwarding the invite.
    ConnectIntent {
        /// The device ID of the initiator (must be registered).
        initiator_device_id: DeviceId,
        /// Target device to connect to.
        target: DeviceId,
        /// A 16-byte random nonce uniquely identifying this connect attempt.
        intent_id: Vec<u8>,
        /// Initiator's candidates, shared with the target after acceptance.
        candidates: Vec<Candidate>,
        /// Timestamp for replay prevention (same ±5-minute window as registration).
        timestamp: u64,
        /// Ed25519 signature over SHA-256(intent_id || initiator_device_id || target || timestamp).
        signature_bytes: Vec<u8>,
    },
    /// Forwarded by the relay to the target when an initiator declares intent.
    ///
    /// In the current in-process model, this is returned to the caller (initiator),
    /// who delivers it to the target. In a full network implementation, the relay
    /// pushes this directly to the target's established connection.
    ConnectInvite {
        /// The device ID of the initiator.
        from: DeviceId,
        /// The intent identifier the target must use in `AcceptConnect`.
        intent_id: Vec<u8>,
    },
    /// Accept a connect invitation from an initiator.
    ///
    /// The `signature_bytes` field MUST be an Ed25519 signature over:
    /// `SHA-256(intent_id || acceptor_device_id || initiator_device_id || timestamp.to_be_bytes())`
    ///
    /// On success, the relay returns `CandidateExchange` containing the initiator's
    /// candidates so the acceptor can attempt direct connectivity checks.
    AcceptConnect {
        /// The device ID of the accepting party (must match the intent's target).
        acceptor_device_id: DeviceId,
        /// The intent identifier, matching the prior `ConnectInvite`.
        intent_id: Vec<u8>,
        /// The acceptor's candidates for direct connectivity.
        candidates: Vec<Candidate>,
        /// Timestamp for replay prevention.
        timestamp: u64,
        /// Ed25519 signature over SHA-256(intent_id || acceptor_device_id || initiator_device_id || timestamp).
        signature_bytes: Vec<u8>,
    },
    /// Sent by the relay to deliver the remote party's candidates.
    ///
    /// - Returned to the **acceptor** in response to `AcceptConnect`
    ///   (contains the initiator's candidates).
    /// - Returned to the **initiator** in response to `GetCandidates`
    ///   (contains the target's candidates, available only after acceptance).
    CandidateExchange {
        /// The intent this exchange belongs to.
        intent_id: Vec<u8>,
        /// The remote party's candidates.
        candidates: Vec<Candidate>,
    },
    /// Request the target's candidates after acceptance (used by the initiator).
    GetCandidates {
        /// The initiator's device ID.
        requester_device_id: DeviceId,
        /// The intent identifier.
        intent_id: Vec<u8>,
    },
    /// Sent to the initiator when the target did not accept within the timeout.
    ConnectTimeout {
        /// The target device that did not respond.
        target: DeviceId,
    },
    /// Sent to the initiator when the target was offline or the intent was rejected.
    ConnectRejected {
        /// The target device.
        target: DeviceId,
        /// Reason for rejection.
        reason: String,
    },
}
