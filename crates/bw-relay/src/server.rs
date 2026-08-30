use crate::clock::{Clock, SystemClock};
use crate::forwarding::{ForwardingTable, RATE_LIMIT_BYTES_PER_SEC, SESSION_EXPIRY_MS};
use crate::protocol::RelayMessage;
use crate::rendezvous::RendezvousRegistry;
use bw_crypto::{DeviceId, Signature, VerifyKey};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use thiserror::Error;

/// Maximum acceptable clock skew for signed messages (5 minutes in milliseconds).
const TIMESTAMP_WINDOW_MS: u64 = 300_000;

/// Error type for relay server operations.
#[derive(Error, Debug)]
pub enum RelayError {
    /// A message failed cryptographic authentication.
    #[error("Authentication failed: {0}")]
    AuthFailed(&'static str),
    /// A referenced device was not found in the registry.
    #[error("Device not found")]
    NotFound,
    /// An unexpected internal relay error occurred.
    #[error("Internal error: {0}")]
    Internal(String),
}

/// The relay-side context stored for each registered endpoint.
#[derive(Debug, Clone)]
pub struct ClientContext {
    /// The relay-assigned session identifier.
    pub session_id: u64,
    /// Timestamp (ms) of the most recent activity from this client.
    pub last_seen: u64,
    /// Stored public key bytes for verifying future signed messages from this device.
    pub verify_key_bytes: [u8; 32],
    /// The server-reflexive address observed when this device registered.
    /// This is the device's external NAT-mapped address as seen by the relay.
    pub server_reflexive_addr: Option<SocketAddr>,
}

/// The relay server: maintains endpoint registrations and mediates rendezvous.
///
/// Security model:
/// - The relay never holds `bw-session` encryption keys.
/// - All message authentication uses the endpoint's long-term Ed25519 identity key.
/// - Candidate data is never released until both endpoints have signed their intent.
/// - Private addressing metadata (candidates) is not logged.
pub struct RelayServer {
    registry: RwLock<HashMap<DeviceId, ClientContext>>,
    rendezvous: Arc<RendezvousRegistry>,
    /// The forwarding table routing data-plane packets based on authenticated relay tokens.
    pub forwarding: Arc<ForwardingTable>,
    next_session_id: std::sync::atomic::AtomicU64,
    clock: Arc<dyn Clock>,
}

impl RelayServer {
    /// Creates a new, empty relay server wrapped in an `Arc` using the system clock.
    pub fn new() -> Arc<Self> {
        Self::with_clock(Arc::new(SystemClock))
    }

    /// Creates a new relay server with a specific clock for testing.
    pub fn with_clock(clock: Arc<dyn Clock>) -> Arc<Self> {
        Self::with_clock_and_rate_limit(clock, RATE_LIMIT_BYTES_PER_SEC)
    }

    /// Creates a new relay server with a specific clock and per-session rate
    /// limit (bytes per second). Operators must size the rate limit above the
    /// peak stream bitrate — IDR keyframes burst well above the encoder's
    /// average target, and a limit equal to the average silently drops the
    /// keyframes the decoder needs to resync.
    pub fn with_clock_and_rate_limit(
        clock: Arc<dyn Clock>,
        rate_limit_bytes_per_sec: u64,
    ) -> Arc<Self> {
        Self::with_clock_and_limits(clock, rate_limit_bytes_per_sec, SESSION_EXPIRY_MS)
    }

    /// Creates a new relay server with a specific clock, per-session rate
    /// limit (bytes/sec), and absolute session lifetime (milliseconds).
    pub fn with_clock_and_limits(
        clock: Arc<dyn Clock>,
        rate_limit_bytes_per_sec: u64,
        session_expiry_ms: u64,
    ) -> Arc<Self> {
        Arc::new(Self {
            registry: RwLock::new(HashMap::new()),
            rendezvous: RendezvousRegistry::with_clock(clock.clone()),
            forwarding: Arc::new(ForwardingTable::with_limits(
                clock.clone(),
                rate_limit_bytes_per_sec,
                session_expiry_ms,
            )),
            next_session_id: std::sync::atomic::AtomicU64::new(1),
            clock,
        })
    }

    /// Handles an incoming control message.
    ///
    /// Equivalent to `handle_message_from(message, None)`.
    pub fn handle_message(&self, message: RelayMessage) -> Result<RelayMessage, RelayError> {
        self.handle_message_from(message, None)
    }

    /// Handles a message with an optional observed peer address.
    ///
    /// In a real network deployment, `peer_addr` is the socket address of the sender
    /// as observed by the relay's UDP/QUIC listener. This becomes the `ServerReflexive`
    /// candidate for that endpoint.
    pub fn handle_message_from(
        &self,
        message: RelayMessage,
        peer_addr: Option<SocketAddr>,
    ) -> Result<RelayMessage, RelayError> {
        match message {
            // ── Registration ─────────────────────────────────────────────────
            RelayMessage::RegisterRequest {
                device_id,
                verify_key_bytes,
                timestamp,
                signature_bytes,
            } => self.handle_register(
                device_id,
                verify_key_bytes,
                timestamp,
                signature_bytes,
                peer_addr,
            ),

            // ── Discovery ────────────────────────────────────────────────────
            RelayMessage::DiscoverRequest { target } => {
                let is_online = self.is_registered(&target);
                Ok(RelayMessage::DiscoverResponse { target, is_online })
            }

            // ── Rendezvous: Connect Intent ────────────────────────────────────
            RelayMessage::ConnectIntent {
                initiator_device_id,
                target,
                intent_id,
                candidates,
                timestamp,
                signature_bytes,
            } => self.handle_connect_intent(
                initiator_device_id,
                target,
                intent_id,
                candidates,
                timestamp,
                signature_bytes,
            ),

            // ── Rendezvous: Accept Connect ────────────────────────────────────
            RelayMessage::AcceptConnect {
                acceptor_device_id,
                intent_id,
                candidates,
                timestamp,
                signature_bytes,
            } => self.handle_accept_connect(
                acceptor_device_id,
                intent_id,
                candidates,
                timestamp,
                signature_bytes,
            ),

            // ── Rendezvous: Get Candidates ────────────────────────────────────
            RelayMessage::GetCandidates {
                requester_device_id,
                intent_id,
            } => self.handle_get_candidates(requester_device_id, intent_id),

            // ── Phase 3: Relay Establish ──────────────────────────────────────
            RelayMessage::RelayEstablishRequest {
                intent_id,
                device_id,
                timestamp,
                signature_bytes,
            } => self.handle_relay_establish(
                intent_id,
                device_id,
                timestamp,
                signature_bytes,
                peer_addr,
            ),

            // ── Phase 4: Server-Side Polling ──────────────────────────────
            RelayMessage::PollPendingIntents { device_id } => {
                self.handle_poll_pending_intents(device_id)
            }

            _ => Err(RelayError::Internal(
                "Message type not valid for server-side processing".into(),
            )),
        }
    }

    /// Returns `true` if the given device is currently registered.
    pub fn is_registered(&self, target: &DeviceId) -> bool {
        self.registry
            .read()
            .map(|r| r.contains_key(target))
            .unwrap_or(false)
    }

    // ── Private handlers ──────────────────────────────────────────────────────

    fn handle_register(
        &self,
        device_id: DeviceId,
        verify_key_bytes: [u8; 32],
        timestamp: u64,
        signature_bytes: Vec<u8>,
        peer_addr: Option<SocketAddr>,
    ) -> Result<RelayMessage, RelayError> {
        let now = self.clock.now_ms();

        // Replay prevention
        if now.abs_diff(timestamp) > TIMESTAMP_WINDOW_MS {
            return Err(RelayError::AuthFailed("Timestamp out of acceptable bounds"));
        }

        // Reconstruct and validate the public key
        let verify_key = VerifyKey::from_bytes(verify_key_bytes)
            .map_err(|_| RelayError::AuthFailed("Invalid Ed25519 public key"))?;

        // Identity binding: verify SHA-256(public_key) == device_id
        if verify_key.device_id() != device_id {
            return Err(RelayError::AuthFailed(
                "Device ID does not match the provided public key",
            ));
        }

        // Validate signature length
        if signature_bytes.len() != 64 {
            return Err(RelayError::AuthFailed("Signature must be exactly 64 bytes"));
        }

        // Verify expanded signed payload: SHA-256(device_id || verify_key_bytes || timestamp)
        // This binding (Phase 2 upgrade) prevents partial-substitution attacks.
        let mut hasher = Sha256::new();
        hasher.update(device_id.as_bytes());
        hasher.update(verify_key_bytes);
        hasher.update(timestamp.to_be_bytes());
        let payload: [u8; 32] = hasher.finalize().into();

        let sig_arr: [u8; 64] = signature_bytes
            .try_into()
            .map_err(|_| RelayError::AuthFailed("Signature conversion failed"))?;
        let signature = Signature::from_bytes(sig_arr);

        verify_key
            .verify(&payload, &signature)
            .map_err(|_| RelayError::AuthFailed("Signature verification failed"))?;

        // Register the endpoint
        let session_id = self
            .next_session_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        self.registry
            .write()
            .map_err(|_| RelayError::Internal("Registry write lock poisoned".into()))?
            .insert(
                device_id,
                ClientContext {
                    session_id,
                    last_seen: now,
                    verify_key_bytes,
                    server_reflexive_addr: peer_addr,
                },
            );

        Ok(RelayMessage::RegisterAck {
            relay_session_id: session_id,
            server_reflexive_addr: peer_addr,
        })
    }

    fn handle_connect_intent(
        &self,
        initiator_device_id: DeviceId,
        target: DeviceId,
        intent_id: Vec<u8>,
        candidates: Vec<crate::candidate::Candidate>,
        timestamp: u64,
        signature_bytes: Vec<u8>,
    ) -> Result<RelayMessage, RelayError> {
        let now = self.clock.now_ms();

        if now.abs_diff(timestamp) > TIMESTAMP_WINDOW_MS {
            return Err(RelayError::AuthFailed(
                "ConnectIntent timestamp out of bounds",
            ));
        }

        // Verify the initiator is registered and retrieve their key
        let verify_key = self.verify_key_for(&initiator_device_id)?;

        // Verify the target is registered
        if !self.is_registered(&target) {
            return Ok(RelayMessage::ConnectRejected {
                target,
                reason: "Target device is not registered".into(),
            });
        }

        // Parse and validate intent_id (must be 16 bytes)
        if intent_id.len() != 16 {
            return Err(RelayError::AuthFailed("intent_id must be exactly 16 bytes"));
        }
        let mut id_arr = [0u8; 16];
        id_arr.copy_from_slice(&intent_id);

        // Validate signature length
        if signature_bytes.len() != 64 {
            return Err(RelayError::AuthFailed("Signature must be exactly 64 bytes"));
        }

        // Verify: SHA-256(intent_id || initiator_device_id || target || timestamp)
        let mut hasher = Sha256::new();
        hasher.update(&intent_id);
        hasher.update(initiator_device_id.as_bytes());
        hasher.update(target.as_bytes());
        hasher.update(timestamp.to_be_bytes());
        let payload: [u8; 32] = hasher.finalize().into();

        let sig_arr: [u8; 64] = signature_bytes
            .try_into()
            .map_err(|_| RelayError::AuthFailed("Signature conversion failed"))?;
        verify_key
            .verify(&payload, &Signature::from_bytes(sig_arr))
            .map_err(|_| RelayError::AuthFailed("ConnectIntent signature verification failed"))?;

        // Register the intent in the rendezvous registry
        self.rendezvous
            .register_intent(id_arr, initiator_device_id, target, candidates)
            .map_err(|e| RelayError::Internal(e.into()))?;

        // Return ConnectInvite for delivery to the target
        Ok(RelayMessage::ConnectInvite {
            from: initiator_device_id,
            intent_id: intent_id.to_vec(),
        })
    }

    fn handle_accept_connect(
        &self,
        acceptor_device_id: DeviceId,
        intent_id: Vec<u8>,
        candidates: Vec<crate::candidate::Candidate>,
        timestamp: u64,
        signature_bytes: Vec<u8>,
    ) -> Result<RelayMessage, RelayError> {
        let now = self.clock.now_ms();

        if now.abs_diff(timestamp) > TIMESTAMP_WINDOW_MS {
            return Err(RelayError::AuthFailed(
                "AcceptConnect timestamp out of bounds",
            ));
        }

        // Verify the acceptor is registered and retrieve their key
        let verify_key = self.verify_key_for(&acceptor_device_id)?;

        if intent_id.len() != 16 {
            return Err(RelayError::AuthFailed("intent_id must be exactly 16 bytes"));
        }
        let mut id_arr = [0u8; 16];
        id_arr.copy_from_slice(&intent_id);

        // To verify the signature, we need to know the initiator's device_id.
        // Peek at the intent to get it (read-only, before the write in accept_intent).
        let initiator_device_id = self.peek_initiator(id_arr)?;

        if signature_bytes.len() != 64 {
            return Err(RelayError::AuthFailed("Signature must be exactly 64 bytes"));
        }

        // Verify: SHA-256(intent_id || acceptor_device_id || initiator_device_id || timestamp)
        let mut hasher = Sha256::new();
        hasher.update(&intent_id);
        hasher.update(acceptor_device_id.as_bytes());
        hasher.update(initiator_device_id.as_bytes());
        hasher.update(timestamp.to_be_bytes());
        let payload: [u8; 32] = hasher.finalize().into();

        let sig_arr: [u8; 64] = signature_bytes
            .try_into()
            .map_err(|_| RelayError::AuthFailed("Signature conversion failed"))?;
        verify_key
            .verify(&payload, &Signature::from_bytes(sig_arr))
            .map_err(|_| RelayError::AuthFailed("AcceptConnect signature verification failed"))?;

        // Accept the intent and retrieve the initiator's candidates and relay token
        let (initiator, initiator_candidates, relay_token) = self
            .rendezvous
            .accept_intent(id_arr, acceptor_device_id, candidates)
            .map_err(|e| RelayError::Internal(e.into()))?;

        // Authorize the forwarding pair in the ForwardingTable
        self.forwarding
            .authorize_pair(id_arr, relay_token, initiator, acceptor_device_id);

        // Return the initiator's candidates and relay token to the acceptor
        Ok(RelayMessage::CandidateExchange {
            intent_id,
            candidates: initiator_candidates,
            relay_token,
        })
    }

    fn handle_get_candidates(
        &self,
        requester_device_id: DeviceId,
        intent_id: Vec<u8>,
    ) -> Result<RelayMessage, RelayError> {
        if intent_id.len() != 16 {
            return Err(RelayError::AuthFailed("intent_id must be exactly 16 bytes"));
        }
        let mut id_arr = [0u8; 16];
        id_arr.copy_from_slice(&intent_id);

        // Requester must be registered
        if !self.is_registered(&requester_device_id) {
            return Err(RelayError::AuthFailed("Requester is not registered"));
        }

        let (candidates, relay_token) = self
            .rendezvous
            .get_target_candidates(id_arr, requester_device_id)
            .map_err(|e| RelayError::Internal(e.into()))?;

        Ok(RelayMessage::CandidateExchange {
            intent_id,
            candidates,
            relay_token,
        })
    }

    /// Retrieves and reconstructs the `VerifyKey` for a registered device.
    fn verify_key_for(&self, device_id: &DeviceId) -> Result<VerifyKey, RelayError> {
        let registry = self
            .registry
            .read()
            .map_err(|_| RelayError::Internal("Registry read lock poisoned".into()))?;

        let ctx = registry.get(device_id).ok_or(RelayError::NotFound)?;

        VerifyKey::from_bytes(ctx.verify_key_bytes)
            .map_err(|_| RelayError::Internal("Stored public key is invalid".into()))
    }

    /// Peeks at an intent's initiator without modifying state.
    fn peek_initiator(&self, intent_id: [u8; 16]) -> Result<DeviceId, RelayError> {
        // This accesses rendezvous internals via a read path; we expose a helper
        // by directly delegating to the rendezvous registry's internal read.
        // Since RendezvousRegistry is private, we use a dedicated accessor.
        self.rendezvous
            .peek_initiator(intent_id)
            .map_err(|e| RelayError::Internal(e.into()))
    }

    fn handle_poll_pending_intents(&self, device_id: DeviceId) -> Result<RelayMessage, RelayError> {
        // Verify the device is registered
        if !self.is_registered(&device_id) {
            return Err(RelayError::AuthFailed("Device not registered"));
        }

        let pending = self.rendezvous.pending_for(device_id);
        let intents: Vec<crate::protocol::PendingIntentInfo> = pending
            .into_iter()
            .map(
                |(intent_id, initiator)| crate::protocol::PendingIntentInfo {
                    from: initiator,
                    intent_id: intent_id.to_vec(),
                },
            )
            .collect();

        Ok(RelayMessage::PendingIntents { intents })
    }

    fn handle_relay_establish(
        &self,
        intent_id: Vec<u8>,
        device_id: DeviceId,
        timestamp: u64,
        signature_bytes: Vec<u8>,
        peer_addr: Option<SocketAddr>,
    ) -> Result<RelayMessage, RelayError> {
        let now = self.clock.now_ms();

        if now.abs_diff(timestamp) > TIMESTAMP_WINDOW_MS {
            return Err(RelayError::AuthFailed(
                "RelayEstablishRequest timestamp out of bounds",
            ));
        }

        if intent_id.len() != 16 {
            return Err(RelayError::AuthFailed("intent_id must be exactly 16 bytes"));
        }
        let mut id_arr = [0u8; 16];
        id_arr.copy_from_slice(&intent_id);

        if signature_bytes.len() != 64 {
            return Err(RelayError::AuthFailed("Signature must be exactly 64 bytes"));
        }

        // Device must be registered
        let verify_key = self.verify_key_for(&device_id)?;

        // Verify: SHA-256(intent_id || device_id || timestamp)
        let mut hasher = Sha256::new();
        hasher.update(&intent_id);
        hasher.update(device_id.as_bytes());
        hasher.update(timestamp.to_be_bytes());
        let payload: [u8; 32] = hasher.finalize().into();

        let sig_arr: [u8; 64] = signature_bytes
            .try_into()
            .map_err(|_| RelayError::AuthFailed("Signature conversion failed"))?;
        verify_key
            .verify(&payload, &Signature::from_bytes(sig_arr))
            .map_err(|_| {
                RelayError::AuthFailed("RelayEstablishRequest signature verification failed")
            })?;

        // Bind the authenticated network address
        let addr = peer_addr.ok_or(RelayError::AuthFailed(
            "RelayEstablishRequest requires a known peer address",
        ))?;

        self.forwarding
            .update_binding(id_arr, device_id, addr)
            .map_err(|e| RelayError::Internal(e.into()))?;

        Ok(RelayMessage::RelayEstablishAck { intent_id })
    }
}
