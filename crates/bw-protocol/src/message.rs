//! Protocol messages layer.

use crate::error::ProtocolError;
use serde::{Deserialize, Serialize};

/// The type classification of a protocol message.
#[derive(Serialize, Deserialize, Debug, Copy, Clone, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum MessageType {
    /// Keep-alive ping query.
    Ping = 0,
    /// Keep-alive pong response.
    Pong = 1,
    /// Init connection handshake start.
    Hello = 2,
    /// Disconnection termination signal.
    Goodbye = 3,
    /// Periodic health/liveness heartbeat.
    Heartbeat = 4,
    /// Raw application payload carrier.
    Data = 5,
    /// Handshake negotiation or runtime connection controls.
    Control = 6,
    /// Failure reports or protocol error notifications.
    Error = 7,
}

/// A structured protocol message with metadata and an owned payload.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ProtocolMessage {
    /// The classification type of the message.
    pub message_type: MessageType,
    /// Unique identifier for matching queries and responses.
    pub message_id: u32,
    /// Operation-specific flag bitmask.
    pub flags: u16,
    /// The owned inner message payload.
    pub payload: Vec<u8>,
}

impl ProtocolMessage {
    /// Serializes the protocol message into a compact binary representation (CBOR).
    ///
    /// # Returns
    ///
    /// The serialized byte vector, or `ProtocolError` on serialization failure.
    pub fn serialize(&self) -> Result<Vec<u8>, ProtocolError> {
        let mut buffer = Vec::new();
        ciborium::ser::into_writer(self, &mut buffer)
            .map_err(|_| ProtocolError::SerializationError)?;
        Ok(buffer)
    }

    /// Deserializes a byte slice into a structured `ProtocolMessage`.
    ///
    /// # Arguments
    ///
    /// * `bytes` - The raw byte slice to deserialize from.
    ///
    /// # Returns
    ///
    /// The deserialized `ProtocolMessage`, or `ProtocolError` on failure.
    pub fn deserialize(bytes: &[u8]) -> Result<Self, ProtocolError> {
        ciborium::de::from_reader(bytes).map_err(|_| ProtocolError::DeserializationError)
    }

    /// Validates protocol constraints on the message fields.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        // Enforce that type values are within the valid defined enum representation
        // (Rust's enum matching enforces this, but validation can check other rules)

        // Example: Data messages must not have empty payload if flags indicate data presence
        if self.message_type == MessageType::Data && self.payload.is_empty() && self.flags != 0 {
            return Err(ProtocolError::InvalidPayloadLength);
        }

        Ok(())
    }
}
