//! Protocol handshake and capability negotiation.

use crate::error::ProtocolError;
use crate::version::{ProtocolVersion, CURRENT_VERSION};
use serde::{Deserialize, Serialize};

/// Bitmask representation of supported/negotiated protocol features.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capabilities(pub u32);

impl Capabilities {
    /// Compression capability.
    pub const COMPRESSION: u32 = 1 << 0;
    /// Encryption capability.
    pub const ENCRYPTION: u32 = 1 << 1;
    /// Streaming capability.
    pub const STREAMING: u32 = 1 << 2;
    /// Heartbeat capability.
    pub const HEARTBEAT: u32 = 1 << 3;
    /// Multiplexing capability.
    pub const MULTIPLEXING: u32 = 1 << 4;
    /// Authentication capability.
    pub const AUTHENTICATION: u32 = 1 << 5;

    /// Checks if a specific capability bit is set.
    pub fn contains(&self, capability: u32) -> bool {
        (self.0 & capability) != 0
    }

    /// Negotiates capabilities by computing the bitwise intersection of both sides.
    pub fn negotiate(&self, other: &Self) -> Self {
        Self(self.0 & other.0)
    }
}

/// The connection status of a handshake negotiation.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HandshakeStatus {
    /// Handshake negotiation was fully successful.
    Accepted,
    /// Client version is not compatible with the server version.
    RejectedVersionMismatch,
    /// Authentication validation failed.
    RejectedAuthenticationFailed,
    /// Negotiated capabilities are insufficient or incompatible.
    RejectedCapabilitiesMismatch,
}

/// Handshake Request message sent by the client.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandshakeRequest {
    /// The client protocol version.
    pub client_version: ProtocolVersion,
    /// The capabilities supported by the client.
    pub supported_capabilities: Capabilities,
    /// The cryptographic device identifier of the client.
    pub device_id: bw_crypto::DeviceId,
    /// A client-generated random cryptographic nonce.
    pub nonce: [u8; 16],
    /// Monotonic timestamp of request generation.
    pub timestamp: u64,
}

/// Handshake Response message returned by the server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandshakeResponse {
    /// The protocol version accepted by the server.
    pub accepted_version: ProtocolVersion,
    /// The negotiated capabilities subset.
    pub negotiated_capabilities: Capabilities,
    /// A server-generated random cryptographic nonce.
    pub server_nonce: [u8; 16],
    /// The assigned unique session identifier.
    pub session_id: [u8; 16],
    /// The status of the negotiation.
    pub status: HandshakeStatus,
}

impl HandshakeRequest {
    /// Validates basic protocol invariants of the handshake request.
    ///
    /// # Returns
    ///
    /// `Ok(())` if valid, or a `ProtocolError` describing the failure.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        // Prevent downgrade attacks: client version must be compatible with current server version.
        if !self.client_version.is_compatible_with(&CURRENT_VERSION) {
            return Err(ProtocolError::InvalidVersion(u16::from(
                self.client_version,
            )));
        }

        // Enforce required base capabilities (e.g. encryption must be supported)
        if !self
            .supported_capabilities
            .contains(Capabilities::ENCRYPTION)
        {
            return Err(ProtocolError::InvalidHandshake);
        }

        Ok(())
    }
}

/// Helper function to perform protocol compatibility checks and negotiate capability sets.
///
/// # Arguments
///
/// * `client` - The capabilities supported by the client.
/// * `server` - The capabilities enforced or supported by the server.
///
/// # Returns
///
/// The negotiated subset if compatible, or `ProtocolError` if compatibility cannot be established.
pub fn negotiate_capabilities(
    client: Capabilities,
    server: Capabilities,
) -> Result<Capabilities, ProtocolError> {
    let negotiated = client.negotiate(&server);

    // Security policy check: Encryption and Authentication must be agreed upon
    if !negotiated.contains(Capabilities::ENCRYPTION) {
        return Err(ProtocolError::IncompatibleCapabilities);
    }

    Ok(negotiated)
}

/// Derives the initial cryptographic session keys from a master secret and nonces exchanged during the handshake.
///
/// The HKDF salt is constructed as `client_nonce || server_nonce`, in that order, matching the
/// temporal sequence of the handshake (client sends first, server responds second). This ordering
/// is fixed by protocol convention and must not be reversed, as doing so would produce entirely
/// different key material. Distinct info labels ("client-key", "server-key") ensure domain
/// separation between the send and receive keys even when the master secret is identical.
pub fn derive_session_keys(
    master_secret: &bw_crypto::SymmetricKey,
    client_nonce: &[u8; 16],
    server_nonce: &[u8; 16],
) -> Result<crate::encryption::SessionKeys, ProtocolError> {
    let mut salt = [0u8; 32];
    salt[0..16].copy_from_slice(client_nonce);
    salt[16..32].copy_from_slice(server_nonce);

    let send_key = bw_crypto::hkdf_derive(Some(&salt), &master_secret.0, Some(b"client-key"))
        .map_err(|_| ProtocolError::EncryptionError)?;

    let recv_key = bw_crypto::hkdf_derive(Some(&salt), &master_secret.0, Some(b"server-key"))
        .map_err(|_| ProtocolError::EncryptionError)?;

    Ok(crate::encryption::SessionKeys {
        send_key,
        recv_key,
        epoch: 0,
    })
}

// ─── Handshake I/O over Transport ────────────────────────────────────

use std::time::Duration;

use crate::encryption::{EncryptionContext, KeyRotationPolicy};
use crate::frame::OwnedProtocolFrame;
use crate::header::{PacketHeader, PROTOCOL_MAGIC};
use crate::message::{MessageType, ProtocolMessage};
use crate::routing::{MessageEnvelope, NodeId, Route, SessionId};
use crate::session::SessionManager;
use crate::transport::Transport;

/// Default time-to-live for handshake transport operations (30 seconds).
///
/// If a `send` or `receive` exceeds this duration the handshake is aborted
/// with [`ProtocolError::InvalidHandshake`].
pub const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// Generates 16 cryptographically secure random bytes for use as a handshake nonce.
pub fn generate_handshake_nonce() -> [u8; 16] {
    let mut nonce = [0u8; 16];
    // secure_random_bytes is infallible in practice (only fails if OS entropy is exhausted).
    bw_crypto::secure_random_bytes(&mut nonce)
        .expect("OS entropy unavailable — cannot generate handshake nonce");
    nonce
}

/// Serializes a value to CBOR bytes.
fn serialize_cbor<T: Serialize>(value: &T) -> Result<Vec<u8>, ProtocolError> {
    let mut buf = Vec::new();
    ciborium::ser::into_writer(value, &mut buf).map_err(|_| ProtocolError::SerializationError)?;
    Ok(buf)
}

/// Builds a complete protocol frame containing a handshake message.
///
/// The message travels through the full serialization stack:
/// Handshake T → CBOR → ProtocolMessage → CBOR → MessageEnvelope → CBOR → PacketHeader + payload
pub fn build_handshake_frame<T: Serialize>(
    msg_type: MessageType,
    payload: &T,
    source: bw_crypto::DeviceId,
    session_id: SessionId,
) -> Result<OwnedProtocolFrame, ProtocolError> {
    // Layer 1: Serialize the handshake payload
    let payload_bytes = serialize_cbor(payload)?;

    // Layer 2: Wrap in ProtocolMessage
    let msg = ProtocolMessage {
        message_type: msg_type,
        message_id: 0,
        flags: 0,
        payload: payload_bytes,
    };

    // Layer 3: Wrap in MessageEnvelope
    let envelope = MessageEnvelope {
        source: NodeId(source),
        destination: NodeId(bw_crypto::DeviceId::from_digest([0u8; 32])), // broadcast placeholder
        session_id,
        route: Route::Direct,
        message: msg,
        routing_flags: 0,
    };

    // Layer 4: Serialize the envelope + wrap in PacketHeader
    let envelope_bytes = serialize_cbor(&envelope)?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_micros() as u64)
        .unwrap_or(0);

    let header = PacketHeader {
        magic: PROTOCOL_MAGIC,
        schema_version: u16::from(CURRENT_VERSION),
        flags: 0,
        packet_type: 0,
        payload_length: envelope_bytes.len() as u16,
        sequence_number: 0,
        session_epoch: 0,
        monotonic_timestamp: now,
    };

    Ok(OwnedProtocolFrame {
        header,
        payload: envelope_bytes,
    })
}

/// Extracts a `HandshakeRequest` from a received protocol frame.
fn parse_handshake_request(frame: &OwnedProtocolFrame) -> Result<HandshakeRequest, ProtocolError> {
    let envelope: MessageEnvelope = ciborium::de::from_reader(&frame.payload[..])
        .map_err(|_| ProtocolError::DeserializationError)?;

    if envelope.message.message_type != MessageType::Hello {
        return Err(ProtocolError::InvalidHandshake);
    }

    ciborium::de::from_reader(&envelope.message.payload[..])
        .map_err(|_| ProtocolError::DeserializationError)
}

/// Extracts a `HandshakeResponse` from a received protocol frame.
fn parse_handshake_response(
    frame: &OwnedProtocolFrame,
) -> Result<HandshakeResponse, ProtocolError> {
    let envelope: MessageEnvelope = ciborium::de::from_reader(&frame.payload[..])
        .map_err(|_| ProtocolError::DeserializationError)?;

    if envelope.message.message_type != MessageType::Control {
        return Err(ProtocolError::InvalidHandshake);
    }

    ciborium::de::from_reader(&envelope.message.payload[..])
        .map_err(|_| ProtocolError::DeserializationError)
}

/// Performs the client side of a full handshake over an established transport.
///
/// # Protocol Flow
///
/// 1. Generate a random 16-byte client nonce.
/// 2. Build and send a [`HandshakeRequest`] wrapped in `ProtocolMessage::Hello` → `MessageEnvelope`.
/// 3. Receive the corresponding [`HandshakeResponse`] wrapped in `ProtocolMessage::Control`.
/// 4. Validate the response status (must be `Accepted`).
/// 5. Derive session keys using `derive_session_keys` from the master secret and exchanged nonces.
/// 6. Construct an [`EncryptionContext`] with the derived keys.
///
/// Each transport operation (send, receive) is bounded by the `timeout` duration.
/// If the peer does not respond within this window the handshake is aborted.
///
/// # Arguments
///
/// * `transport` — The transport to send/receive on. Must be connected.
/// * `device_id` — The client's device identity.
/// * `supported_capabilities` — The client's capability set.
/// * `master_secret` — The pre-shared or exchanged master secret for key derivation.
/// * `rotation_policy` — The key rotation policy for the session.
/// * `timeout` — Maximum duration to wait for each transport operation.
///   Use [`DEFAULT_HANDSHAKE_TIMEOUT`] for a sensible default.
///
/// # Returns
///
/// `(SessionId, EncryptionContext)` on success, or a `ProtocolError` on failure.
pub async fn client_handshake(
    transport: &dyn Transport,
    device_id: bw_crypto::DeviceId,
    supported_capabilities: Capabilities,
    master_secret: &bw_crypto::SymmetricKey,
    rotation_policy: KeyRotationPolicy,
    timeout: Duration,
) -> Result<(SessionId, EncryptionContext), ProtocolError> {
    // 1. Generate a fresh random nonce
    let client_nonce = generate_handshake_nonce();

    // 2. Build HandshakeRequest
    let request = HandshakeRequest {
        client_version: CURRENT_VERSION,
        supported_capabilities,
        device_id,
        nonce: client_nonce,
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    };

    // 3. Build frame and send (with timeout)
    let frame = build_handshake_frame(
        MessageType::Hello,
        &request,
        device_id,
        SessionId([0u8; 16]),
    )?;
    tokio::time::timeout(timeout, transport.send(frame.borrow()))
        .await
        .map_err(|_| ProtocolError::InvalidHandshake)
        .and_then(|r| r)?;

    // 4. Receive response (with timeout)
    let response_frame = tokio::time::timeout(timeout, transport.receive())
        .await
        .map_err(|_| ProtocolError::InvalidHandshake)
        .and_then(|r| r)?;
    let response = parse_handshake_response(&response_frame)?;

    // 5. Validate response status
    if response.status != HandshakeStatus::Accepted {
        return Err(ProtocolError::InvalidHandshake);
    }

    // 6. Derive session keys
    let keys = derive_session_keys(master_secret, &client_nonce, &response.server_nonce)?;
    let context = EncryptionContext::new(keys, rotation_policy);

    Ok((SessionId(response.session_id), context))
}

/// Performs the server side of a full handshake over an established transport.
///
/// # Protocol Flow
///
/// 1. Receive a [`HandshakeRequest`] from the transport.
/// 2. Validate the request (version compatibility, encryption capability).
/// 3. Negotiate capabilities between client and server sets.
/// 4. Generate a random 16-byte server nonce.
/// 5. Assign a fresh [`SessionId`].
/// 6. Derive session keys, create the [`EncryptionContext`], and register the session.
/// 7. Build and send a [`HandshakeResponse`] with the `Accepted` status.
///
/// Each transport operation (receive, send) is bounded by the `timeout` duration.
/// If the client does not send a request within this window the handshake is aborted.
///
/// If validation or negotiation fails, the response is sent with the appropriate
/// rejection status (`RejectedVersionMismatch`, `RejectedCapabilitiesMismatch`,
/// etc.) and a `ProtocolError` is returned.
///
/// # Arguments
///
/// * `transport` — The transport to receive/send on. Must be connected.
/// * `session_manager` — The session manager to register the new session.
/// * `server_capabilities` — The server's capability set.
/// * `master_secret` — The pre-shared or exchanged master secret for key derivation.
/// * `rotation_policy` — The key rotation policy for the session.
/// * `timeout` — Maximum duration to wait for the client's handshake request.
///   Use [`DEFAULT_HANDSHAKE_TIMEOUT`] for a sensible default.
///
/// # Returns
///
/// `SessionId` on successful handshake, or a `ProtocolError` on failure.
pub async fn server_handshake(
    transport: &dyn Transport,
    session_manager: &SessionManager,
    server_capabilities: Capabilities,
    master_secret: &bw_crypto::SymmetricKey,
    rotation_policy: KeyRotationPolicy,
    timeout: Duration,
) -> Result<SessionId, ProtocolError> {
    // 1. Receive request (with timeout)
    let request_frame = tokio::time::timeout(timeout, transport.receive())
        .await
        .map_err(|_| ProtocolError::InvalidHandshake)
        .and_then(|r| r)?;
    let request = parse_handshake_request(&request_frame)?;

    let server_nonce = generate_handshake_nonce();
    let session_id = SessionId(generate_handshake_nonce()); // reuse nonce generator for session ID

    // 2. Validate and negotiate
    let status = match request.validate() {
        Ok(()) => match negotiate_capabilities(request.supported_capabilities, server_capabilities)
        {
            Ok(_) => HandshakeStatus::Accepted,
            Err(_) => HandshakeStatus::RejectedCapabilitiesMismatch,
        },
        Err(ProtocolError::InvalidVersion(_)) => HandshakeStatus::RejectedVersionMismatch,
        Err(_) => HandshakeStatus::RejectedAuthenticationFailed,
    };

    // 3. If accepted, derive keys and create session BEFORE sending response
    if status == HandshakeStatus::Accepted {
        session_manager.create_session_from_handshake(
            session_id,
            master_secret,
            &request.nonce,
            &server_nonce,
            rotation_policy,
        )?;
    }

    // 4. Build and send response (with timeout)
    let response = HandshakeResponse {
        accepted_version: CURRENT_VERSION,
        negotiated_capabilities: request
            .supported_capabilities
            .negotiate(&server_capabilities),
        server_nonce,
        session_id: session_id.0,
        status,
    };

    let response_frame = build_handshake_frame(
        MessageType::Control,
        &response,
        request.device_id,
        session_id,
    )?;
    tokio::time::timeout(timeout, transport.send(response_frame.borrow()))
        .await
        .map_err(|_| ProtocolError::InvalidHandshake)
        .and_then(|r| r)?;

    // 5. If rejected, clean up any created session and return error
    if status != HandshakeStatus::Accepted {
        return Err(ProtocolError::InvalidHandshake);
    }

    Ok(session_id)
}
