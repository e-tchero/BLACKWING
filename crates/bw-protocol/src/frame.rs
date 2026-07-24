//! Protocol framing definitions.
//!
//! Defines the core frame structure used to bundle headers and payloads.

use crate::header::PacketHeader;

/// A structured protocol frame consisting of a header and a borrowed payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolFrame<'a> {
    /// The parsed packet header.
    pub header: PacketHeader,
    /// The borrowed payload slice.
    pub payload: &'a [u8],
}

/// An owned protocol frame containing an owned header and payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedProtocolFrame {
    /// The packet header.
    pub header: PacketHeader,
    /// The owned payload.
    pub payload: Vec<u8>,
}

impl OwnedProtocolFrame {
    /// Returns a borrowed view of this owned frame.
    pub fn borrow(&self) -> ProtocolFrame<'_> {
        ProtocolFrame {
            header: self.header,
            payload: &self.payload,
        }
    }
}
