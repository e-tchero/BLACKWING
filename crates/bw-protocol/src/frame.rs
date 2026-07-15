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
