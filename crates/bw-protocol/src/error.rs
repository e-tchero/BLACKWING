//! Protocol-specific error definitions.

use thiserror::Error;

/// Errors that can occur during packet serialization, deserialization, or framing validation.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum ProtocolError {
    /// The buffer provided was too small to read a valid header.
    #[error("Buffer is too small to contain the required struct header")]
    BufferTooSmall,

    /// The protocol magic identifier did not match the expected bytes.
    #[error("Invalid protocol magic")]
    InvalidMagic,

    /// The schema version is not supported by this version of the library.
    #[error("Invalid or unsupported schema version: {0}")]
    InvalidVersion(u16),

    /// The payload length specified exceeds the maximum limit or is malformed.
    #[error("Invalid payload length")]
    InvalidPayloadLength,

    /// Capabilities negotiation failed due to incompatible feature sets.
    #[error("Incompatible connection capabilities")]
    IncompatibleCapabilities,

    /// Handshake validation failed.
    #[error("Invalid protocol handshake")]
    InvalidHandshake,
}
