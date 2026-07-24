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
