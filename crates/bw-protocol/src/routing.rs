//! Protocol routing layer and message envelope.

use crate::error::ProtocolError;
use crate::message::ProtocolMessage;
use serde::{Deserialize, Serialize};

/// Represents a unique cryptographic participant node identifier.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NodeId(pub bw_crypto::DeviceId);

impl NodeId {
    /// Returns the special broadcast NodeId containing all zeroes.
    pub fn broadcast() -> Self {
        Self(bw_crypto::DeviceId::from_digest([0u8; 32]))
    }

    /// Checks if this NodeId represents a broadcast destination.
    pub fn is_broadcast(&self) -> bool {
        self.0.as_bytes() == &[0u8; 32]
    }
}

/// Represents a unique connection session identifier.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionId(pub [u8; 16]);

/// Defines the routing path schema for a message envelope.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    /// Direct point-to-point routing.
    Direct,
    /// One-to-many broadcast routing.
    Broadcast,
    /// Local node self-addressing.
    Loopback,
    /// Routing forwarded through a relay node.
    Relay {
        /// The intermediate node that forwards the traffic.
        via: NodeId,
    },
}

/// An envelope wrapping a protocol message with session metadata and routing coordinates.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct MessageEnvelope {
    /// The source node ID originating the message.
    pub source: NodeId,
    /// The final destination node ID.
    pub destination: NodeId,
    /// The session context identifier.
    pub session_id: SessionId,
    /// The routing scheme applied to the envelope.
    pub route: Route,
    /// The inner protocol message payload.
    pub message: ProtocolMessage,
    /// Operational routing flag bitmask.
    pub routing_flags: u16,
}

impl MessageEnvelope {
    /// Validates the routing coordinates and envelope properties.
    ///
    /// # Returns
    ///
    /// `Ok(())` if the envelope is valid, or a `ProtocolError` explaining the failure.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        // Run inner protocol message validations
        self.message.validate()?;

        match self.route {
            Route::Loopback => {
                if self.source != self.destination {
                    return Err(ProtocolError::InvalidRoute);
                }
            }
            Route::Direct => {
                if self.source == self.destination {
                    return Err(ProtocolError::InvalidDestination);
                }
                if self.destination.is_broadcast() {
                    return Err(ProtocolError::InvalidDestination);
                }
            }
            Route::Broadcast => {
                if !self.destination.is_broadcast() {
                    return Err(ProtocolError::InvalidDestination);
                }
            }
            Route::Relay { via } => {
                if self.source == self.destination {
                    return Err(ProtocolError::InvalidDestination);
                }
                if via == self.source || via == self.destination {
                    return Err(ProtocolError::InvalidRoute);
                }
                if self.destination.is_broadcast() {
                    return Err(ProtocolError::InvalidDestination);
                }
            }
        }

        Ok(())
    }

    /// Serializes the envelope into a compact binary representation (CBOR).
    pub fn serialize(&self) -> Result<Vec<u8>, ProtocolError> {
        let mut buffer = Vec::new();
        ciborium::ser::into_writer(self, &mut buffer)
            .map_err(|_| ProtocolError::SerializationError)?;
        Ok(buffer)
    }

    /// Deserializes a byte slice into a structured `MessageEnvelope`.
    pub fn deserialize(bytes: &[u8]) -> Result<Self, ProtocolError> {
        ciborium::de::from_reader(bytes).map_err(|_| ProtocolError::DeserializationError)
    }
}
