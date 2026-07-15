//! Packet header mapping.

use crate::error::ProtocolError;
use crate::version::{ProtocolVersion, CURRENT_VERSION};

/// Protocol magic identifier constant ('BWPG' in ASCII).
pub const PROTOCOL_MAGIC: [u8; 4] = [0x42, 0x57, 0x50, 0x47];

/// Master Packet Header conforming exactly to Section 2.1 (32-Byte Layout).
///
/// Aligns to 8-byte boundaries to satisfy modern architecture requirements.
/// Implements `bytemuck::Pod` and `bytemuck::Zeroable` to safely permit
/// zero-copy casting from arbitrary byte slices.
#[repr(C, align(8))]
#[derive(Copy, Clone, Debug, Default, PartialEq, bytemuck::Pod, bytemuck::Zeroable)]
pub struct PacketHeader {
    /// Protocol magic identifier.
    pub magic: [u8; 4],
    /// Protocol schema version (packed major/minor).
    pub schema_version: u16,
    /// Protocol flags bitmask.
    pub flags: u16,
    /// Application-defined packet type identifier.
    pub packet_type: u16,
    /// Length of the payload following this header.
    pub payload_length: u16,
    /// Packet sequence number.
    pub sequence_number: u32,
    /// Cryptographically secure run epoch identifier.
    pub session_epoch: u64,
    /// Monotonic microsecond timestamp of packet generation.
    pub monotonic_timestamp: u64,
}

impl PacketHeader {
    /// Zero-copy cast a slice of bytes into a structured `PacketHeader` reference.
    ///
    /// # Arguments
    ///
    /// * `bytes` - The raw byte slice to cast from.
    ///
    /// # Returns
    ///
    /// Returns a shared reference to the structured `PacketHeader`, or a
    /// `ProtocolError` if the slice is invalid or fails validation rules.
    pub fn try_from_bytes(bytes: &[u8]) -> Result<&Self, ProtocolError> {
        if bytes.len() < std::mem::size_of::<PacketHeader>() {
            return Err(ProtocolError::BufferTooSmall);
        }
        let header_bytes = &bytes[..std::mem::size_of::<PacketHeader>()];
        let header: &Self = bytemuck::from_bytes(header_bytes);

        header.validate()?;
        Ok(header)
    }

    /// Zero-copy cast a structured `PacketHeader` reference into raw byte slice representation.
    ///
    /// # Returns
    ///
    /// Returns a shared reference to the raw underlying bytes.
    pub fn as_bytes(&self) -> &[u8] {
        bytemuck::bytes_of(self)
    }

    /// Validates the structural invariants of the packet header.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if validation succeeds, or a `ProtocolError` describing the failure.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.magic != PROTOCOL_MAGIC {
            return Err(ProtocolError::InvalidMagic);
        }

        let version = ProtocolVersion::from(self.schema_version);
        if !version.is_compatible_with(&CURRENT_VERSION) {
            return Err(ProtocolError::InvalidVersion(self.schema_version));
        }

        Ok(())
    }
}
