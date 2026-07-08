#![allow(dead_code)]
//! Zero-copy buffer casting primitives.
//!
//! Provides safely implemented zero-allocation casting of memory buffers
//! into structured types.

use thiserror::Error;

/// Errors that can occur during zero-copy buffer casting and protocol operations.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum BufferError {
    /// The provided byte slice was too small to contain the required struct.
    #[error("Buffer is too small to contain the required struct header")]
    BufferTooSmall,
    /// An invalid schema version was detected.
    #[error("Invalid schema version detected: {0}")]
    InvalidVersion(u16),
}

/// Master Packet Header conforming exactly to Section 2.1 (32-Byte Layout).
///
/// Aligns to 8-byte boundaries to satisfy modern architecture requirements.
/// Implements `bytemuck::Pod` and `bytemuck::Zeroable` to safely permit
/// zero-copy casting from arbitrary byte slices.
#[repr(C, align(8))]
#[derive(Copy, Clone, Debug, Default, PartialEq, bytemuck::Pod, bytemuck::Zeroable)]
pub(crate) struct PacketHeader {
    /// Protocol schema version.
    pub(crate) schema_version: u16,
    /// Protocol flags bitmask.
    pub(crate) flags: u16,
    /// Application-defined packet type identifier.
    pub(crate) packet_type: u16,
    /// Length of the payload following this header.
    pub(crate) payload_length: u16,
    /// Packet sequence number.
    pub(crate) sequence_number: u32,
    /// Padding for 8-byte structural alignment.
    pub(crate) padding: u32,
    /// Cryptographically secure run epoch identifier.
    pub(crate) session_epoch: u64,
    /// Monotonic microsecond timestamp of packet generation.
    pub(crate) monotonic_timestamp: u64,
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
    /// `BufferError` if the slice is too small to contain the struct.
    pub(crate) fn try_from_bytes(bytes: &[u8]) -> Result<&Self, BufferError> {
        if bytes.len() < std::mem::size_of::<PacketHeader>() {
            return Err(BufferError::BufferTooSmall);
        }
        // Take exact slice window matching Header bounds
        let header_bytes = &bytes[..std::mem::size_of::<PacketHeader>()];
        Ok(bytemuck::from_bytes(header_bytes))
    }

    /// Zero-copy cast a structured `PacketHeader` reference into raw byte slice representation.
    ///
    /// # Returns
    ///
    /// Returns a shared reference to the raw underlying bytes.
    pub(crate) fn as_bytes(&self) -> &[u8] {
        bytemuck::bytes_of(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_size_and_alignment() {
        assert_eq!(std::mem::size_of::<PacketHeader>(), 32);
        assert_eq!(std::mem::align_of::<PacketHeader>(), 8);
    }

    #[test]
    fn test_zero_copy_roundtrip() {
        let original_header = PacketHeader {
            schema_version: 1,
            flags: 0x0001,
            packet_type: 3,
            payload_length: 512,
            sequence_number: 1029,
            padding: 0,
            session_epoch: 1289381019842,
            monotonic_timestamp: 918239012,
        };

        // Casting struct reference to raw bytes representation
        let raw_bytes = original_header.as_bytes();
        assert_eq!(raw_bytes.len(), 32);

        // Verification of Little Endian byte offsets inside the mapped struct
        // schema_version at offset 0 (LE serialization check)
        assert_eq!(raw_bytes[0], 1);
        assert_eq!(raw_bytes[1], 0);

        // Casting raw bytes back to structured reference (zero-copy validation)
        let cast_header = PacketHeader::try_from_bytes(raw_bytes).unwrap();
        assert_eq!(cast_header.schema_version, original_header.schema_version);
        assert_eq!(cast_header.flags, original_header.flags);
        assert_eq!(cast_header.packet_type, original_header.packet_type);
        assert_eq!(cast_header.payload_length, original_header.payload_length);
        assert_eq!(cast_header.sequence_number, original_header.sequence_number);
        assert_eq!(cast_header.session_epoch, original_header.session_epoch);
        assert_eq!(
            cast_header.monotonic_timestamp,
            original_header.monotonic_timestamp
        );
    }

    #[test]
    fn test_header_casting_buffer_too_small() {
        let invalid_short_buffer = vec![0u8; 16];
        let result = PacketHeader::try_from_bytes(&invalid_short_buffer);
        assert_eq!(result.err(), Some(BufferError::BufferTooSmall));
    }
}
