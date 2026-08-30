//! Relay control-plane client for BLACKWING.
//!
//! Provides the client-side half of the relay's CBOR-over-UDP signaling protocol.
//! Both `bw-client` and `bw-server` use this to register with the relay,
//! exchange candidates, and obtain the shared relay token through the
//! existing `CandidateExchange` flow.

use crate::candidate::Candidate;
use crate::protocol::RelayMessage;
use bw_crypto::{DeviceId, SigningKey};
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

/// Control-plane magic prefix (must match the relay binary).
const CONTROL_MAGIC: &[u8; 6] = b"BWCTL\x01";

/// Errors produced by the relay control-plane client.
#[derive(Debug, Error)]
pub enum RelayClientError {
    /// I/O error from the UDP socket.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// The relay rejected the request with a human-readable reason.
    #[error("Relay rejected request: {0}")]
    Rejected(String),
    /// CBOR serialization or deserialization failed.
    #[error("CBOR error: {0}")]
    Cbor(String),
    /// The relay response did not match the expected protocol message type.
    #[error("Protocol error: {0}")]
    Protocol(String),
}

/// An authenticated control-plane client for communicating with a BLACKWING relay.
pub struct RelayControlClient {
    sock: tokio::net::UdpSocket,
    relay_addr: SocketAddr,
    signing_key: SigningKey,
    device_id: DeviceId,
}

impl RelayControlClient {
    /// Creates a new control client bound to an ephemeral port.
    pub async fn connect(
        relay_addr: SocketAddr,
        signing_key: SigningKey,
    ) -> Result<Self, RelayClientError> {
        let sock = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
        let device_id = signing_key.verify_key().device_id();
        Ok(Self {
            sock,
            relay_addr,
            signing_key,
            device_id,
        })
    }

    /// Returns the device's identity.
    pub fn device_id(&self) -> DeviceId {
        self.device_id
    }

    /// Sends a control-plane message and waits for the response.
    async fn send_recv(&self, msg: &RelayMessage) -> Result<RelayMessage, RelayClientError> {
        let mut body = Vec::new();
        ciborium::ser::into_writer(msg, &mut body)
            .map_err(|e| RelayClientError::Cbor(e.to_string()))?;

        let mut packet = Vec::with_capacity(CONTROL_MAGIC.len() + body.len());
        packet.extend_from_slice(CONTROL_MAGIC);
        packet.extend_from_slice(&body);

        self.sock.send_to(&packet, self.relay_addr).await?;

        let mut buf = vec![0u8; 4096];
        let (n, _) = self.sock.recv_from(&mut buf).await?;
        let resp_bytes = &buf[..n];

        // Strip control magic prefix
        if resp_bytes.len() < CONTROL_MAGIC.len()
            || &resp_bytes[..CONTROL_MAGIC.len()] != CONTROL_MAGIC
        {
            return Err(RelayClientError::Protocol(
                "Response missing control magic".into(),
            ));
        }
        let body = &resp_bytes[CONTROL_MAGIC.len()..];
        ciborium::from_reader(body).map_err(|e| RelayClientError::Cbor(e.to_string()))
    }

    fn current_time_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }

    /// Registers this endpoint with the relay. Returns the relay session ID.
    pub async fn register(&self) -> Result<u64, RelayClientError> {
        let timestamp = Self::current_time_ms();
        let verify_key_bytes = *self.signing_key.verify_key().as_bytes();

        let mut hasher = Sha256::new();
        hasher.update(self.device_id.as_bytes());
        hasher.update(verify_key_bytes);
        hasher.update(timestamp.to_be_bytes());
        let payload: [u8; 32] = hasher.finalize().into();

        let signature = self.signing_key.sign(&payload);
        let signature_bytes = signature.as_bytes().to_vec();

        let req = RelayMessage::RegisterRequest {
            device_id: self.device_id,
            verify_key_bytes,
            timestamp,
            signature_bytes,
        };

        match self.send_recv(&req).await? {
            RelayMessage::RegisterAck {
                relay_session_id, ..
            } => Ok(relay_session_id),
            RelayMessage::ErrorResponse { reason } => Err(RelayClientError::Rejected(reason)),
            other => Err(RelayClientError::Protocol(format!(
                "Unexpected response: {other:?}"
            ))),
        }
    }

    /// Sends a ConnectIntent to the relay, targeting the given device.
    pub async fn connect_intent(
        &self,
        target: DeviceId,
        intent_id: [u8; 16],
        candidates: Vec<Candidate>,
    ) -> Result<(), RelayClientError> {
        let timestamp = Self::current_time_ms();

        let mut hasher = Sha256::new();
        hasher.update(intent_id);
        hasher.update(self.device_id.as_bytes());
        hasher.update(target.as_bytes());
        hasher.update(timestamp.to_be_bytes());
        let payload: [u8; 32] = hasher.finalize().into();

        let signature = self.signing_key.sign(&payload);
        let signature_bytes = signature.as_bytes().to_vec();

        let req = RelayMessage::ConnectIntent {
            initiator_device_id: self.device_id,
            target,
            intent_id: intent_id.to_vec(),
            candidates,
            timestamp,
            signature_bytes,
        };

        match self.send_recv(&req).await? {
            RelayMessage::ConnectInvite { .. } => Ok(()),
            RelayMessage::ConnectRejected { reason, .. } => Err(RelayClientError::Rejected(reason)),
            RelayMessage::ErrorResponse { reason } => Err(RelayClientError::Rejected(reason)),
            other => Err(RelayClientError::Protocol(format!(
                "Unexpected response: {other:?}"
            ))),
        }
    }

    /// Accepts a connect invitation. Returns the relay token and initiator's candidates.
    pub async fn accept_connect(
        &self,
        intent_id: [u8; 16],
        initiator: DeviceId,
        candidates: Vec<Candidate>,
    ) -> Result<([u8; 32], Vec<Candidate>), RelayClientError> {
        let timestamp = Self::current_time_ms();

        let mut hasher = Sha256::new();
        hasher.update(intent_id);
        hasher.update(self.device_id.as_bytes());
        hasher.update(initiator.as_bytes());
        hasher.update(timestamp.to_be_bytes());
        let payload: [u8; 32] = hasher.finalize().into();

        let signature = self.signing_key.sign(&payload);
        let signature_bytes = signature.as_bytes().to_vec();

        let req = RelayMessage::AcceptConnect {
            acceptor_device_id: self.device_id,
            intent_id: intent_id.to_vec(),
            candidates,
            timestamp,
            signature_bytes,
        };

        match self.send_recv(&req).await? {
            RelayMessage::CandidateExchange {
                relay_token,
                candidates,
                ..
            } => Ok((relay_token, candidates)),
            RelayMessage::ErrorResponse { reason } => Err(RelayClientError::Rejected(reason)),
            other => Err(RelayClientError::Protocol(format!(
                "Unexpected response: {other:?}"
            ))),
        }
    }

    /// Retrieves the target's candidates and relay token after acceptance.
    pub async fn get_candidates(
        &self,
        intent_id: [u8; 16],
    ) -> Result<([u8; 32], Vec<Candidate>), RelayClientError> {
        let req = RelayMessage::GetCandidates {
            requester_device_id: self.device_id,
            intent_id: intent_id.to_vec(),
        };

        match self.send_recv(&req).await? {
            RelayMessage::CandidateExchange {
                relay_token,
                candidates,
                ..
            } => Ok((relay_token, candidates)),
            RelayMessage::ErrorResponse { reason } => Err(RelayClientError::Rejected(reason)),
            other => Err(RelayClientError::Protocol(format!(
                "Unexpected response: {other:?}"
            ))),
        }
    }

    /// Polls the relay for pending ConnectIntents targeting this device.
    ///
    /// Returns a list of (intent_id, initiator_device_id) tuples for
    /// pending connection requests that have not yet been accepted.
    pub async fn poll_pending_intents(
        &self,
    ) -> Result<Vec<([u8; 16], DeviceId)>, RelayClientError> {
        let req = RelayMessage::PollPendingIntents {
            device_id: self.device_id,
        };

        match self.send_recv(&req).await? {
            RelayMessage::PendingIntents { intents } => {
                let mut result = Vec::new();
                for invite in intents {
                    let mut id_arr = [0u8; 16];
                    let len = invite.intent_id.len().min(16);
                    id_arr[..len].copy_from_slice(&invite.intent_id[..len]);
                    result.push((id_arr, invite.from));
                }
                Ok(result)
            }
            RelayMessage::ErrorResponse { reason } => Err(RelayClientError::Rejected(reason)),
            other => Err(RelayClientError::Protocol(format!(
                "Unexpected response: {other:?}"
            ))),
        }
    }

    /// Sends a RelayEstablishRequest to bind this endpoint's address to the token.
    pub async fn establish_relay(&self, intent_id: [u8; 16]) -> Result<(), RelayClientError> {
        let timestamp = Self::current_time_ms();

        let mut hasher = Sha256::new();
        hasher.update(intent_id);
        hasher.update(self.device_id.as_bytes());
        hasher.update(timestamp.to_be_bytes());
        let payload: [u8; 32] = hasher.finalize().into();

        let signature = self.signing_key.sign(&payload);
        let signature_bytes = signature.as_bytes().to_vec();

        let req = RelayMessage::RelayEstablishRequest {
            intent_id: intent_id.to_vec(),
            device_id: self.device_id,
            timestamp,
            signature_bytes,
        };

        match self.send_recv(&req).await? {
            RelayMessage::RelayEstablishAck { .. } => Ok(()),
            RelayMessage::ErrorResponse { reason } => Err(RelayClientError::Rejected(reason)),
            other => Err(RelayClientError::Protocol(format!(
                "Unexpected response: {other:?}"
            ))),
        }
    }
}

/// Generates a random 16-byte intent ID using OS entropy.
pub fn generate_intent_id() -> [u8; 16] {
    let mut id = [0u8; 16];
    // SAFETY: getrandom never fails on supported platforms (Windows, Linux, macOS).
    // On unsupported platforms it returns an error, which we handle gracefully.
    if getrandom::getrandom(&mut id).is_err() {
        // Fallback: use timestamp-based pseudo-random (dev only)
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        id.copy_from_slice(&ts.to_le_bytes()[..16]);
    }
    id
}

/// Loads or generates a signing key, persisting it to the given path.
///
/// If the file exists and contains 32 bytes, the key is loaded.
/// Otherwise a fresh key is generated and saved.
pub fn load_or_generate_key(path: &std::path::Path) -> Result<SigningKey, std::io::Error> {
    if path.exists() {
        let bytes = std::fs::read(path)?;
        if bytes.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            return bw_crypto::SigningKey::from_secret_bytes(arr)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()));
        }
    }
    let key = bw_crypto::SigningKey::generate_ed25519()
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    std::fs::write(path, key.to_bytes())?;
    Ok(key)
}
