#![deny(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

//! # bw-protocol
//! 
//! This crate implements the core binary serialization formats, zero-copy packet casting,
//! and capabilities negotiation schemas for PROJECT BLACKWING.

use bytemuck::{Pod, Zeroable};
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use thiserror::Error;
use zeroize::Zeroize;

/// Binary serialization error types.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum ProtocolError {
    #[error("Buffer is too small to contain the required struct header")]
    BufferTooSmall,
    #[error("Invalid schema version detected: {0}")]
    InvalidVersion(u16),
    #[error("Serialization failed on capabilities payload")]
    SerializationError,
    #[error("Deserialization failed on capabilities payload")]
    DeserializationError,
}

// =========================================================================
// 1. Packets & Zero-Copy Casting
// =========================================================================

/// Master Packet Header conforming exactly to Section 2.1 (32-Byte Layout).
/// Aligning to 8-byte boundaries to satisfy modern architecture requirements.
#[repr(C, align(8))]
#[derive(Copy, Clone, Debug, Default, PartialEq)]
pub struct PacketHeader {
    pub schema_version: u16,     // 2 bytes
    pub flags: u16,              // 2 bytes
    pub packet_type: u16,        // 2 bytes
    pub payload_length: u16,     // 2 bytes
    pub sequence_number: u32,    // 4 bytes
    pub padding: u32,            // 4 bytes (explicit structural alignment)
    pub session_epoch: u64,      // 8 bytes (cryptographically secure run epoch)
    pub monotonic_timestamp: u64,// 8 bytes (monotonic microsecond timestamp)
}

// Safety: Bytemuck validation guarantees that this raw memory block contains 
// no uninitialized padding bytes, permitting safe casting from arbitrary bytes.
unsafe impl Zeroable for PacketHeader {}
unsafe impl Pod for PacketHeader {}

impl PacketHeader {
    /// Zero-copy cast a slice of bytes into a structured `PacketHeader` reference.
    pub fn try_from_bytes(bytes: &[u8]) -> Result<&Self, ProtocolError> {
        if bytes.len() < std::mem::size_of::<PacketHeader>() {
            return Err(ProtocolError::BufferTooSmall);
        }
        // Take exact slice window matching Header bounds
        let header_bytes = &bytes[..std::mem::size_of::<PacketHeader>()];
        Ok(bytemuck::from_bytes(header_bytes))
    }

    /// Zero-copy cast a structured `PacketHeader` reference into raw byte slice representation.
    pub fn as_bytes(&self) -> &[u8] {
        bytemuck::bytes_of(self)
    }
}

// =========================================================================
// 2. Capabilities Negotiation Schema (CBOR / Serde Integration)
// =========================================================================

/// Structured capabilities exchange payload conforming to CBOR schema definitions.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Zeroize)]
#[zeroize(drop)]
pub struct FeatureManifest {
    pub codecs: u16,                  // Bitmask: Bit 0 = H264, Bit 1 = AV1, Bit 2 = HEVC
    pub audio_profiles: u8,           // Bitmask: Bit 0 = Opus 48k, Bit 1 = Opus 24k
    pub input_types: u8,              // Bitmask: Bit 0 = Abs Mouse, Bit 1 = Rel Mouse
    pub security_hardening: u16,      // Bitmask: Bit 0 = TPM Wrapped, Bit 1 = Locked RAM
    pub max_resolution_width: u16,
    pub max_resolution_height: u16,
    pub max_fps: u8,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Zeroize)]
#[zeroize(drop)]
pub struct DisplayProfile {
    pub monitors_detected: u8,
    pub hdr_present: bool,
    pub color_space: u8,              // Enum: 0 = sRGB, 1 = Rec709, 2 = Rec2020
}

/// Consolidated handshake message passed over control Stream 0.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Zeroize)]
#[zeroize(drop)]
pub struct CapabilityMessage {
    pub schema_version: u16,
    pub min_supported_version: u16,
    pub session_epoch: u64,
    pub features: FeatureManifest,
    pub display_profile: DisplayProfile,
}

impl CapabilityMessage {
    /// Serializes capability exchange message to compact binary format (CBOR).
    pub fn serialize_to_vec(&self) -> Result<Vec<u8>, ProtocolError> {
        let mut buffer = Vec::new();
        ciborium::ser::into_writer(self, &mut buffer)
            .map_err(|_| ProtocolError::SerializationError)?;
        Ok(buffer)
    }

    /// Deserializes compact binary format (CBOR) payload back into capability structure.
    pub fn deserialize_from_slice(slice: &[u8]) -> Result<Self, ProtocolError> {
        ciborium::de::from_reader(slice)
            .map_err(|_| ProtocolError::DeserializationError)
    }
}

// =========================================================================
// 3. Automated Protocol Unit Tests
// =========================================================================

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
        assert_eq!(cast_header.monotonic_timestamp, original_header.monotonic_timestamp);
    }

    #[test]
    fn test_header_casting_buffer_too_small() {
        let invalid_short_buffer = vec![0u8; 16];
        let result = PacketHeader::try_from_bytes(&invalid_short_buffer);
        assert_eq!(result.err(), Some(ProtocolError::BufferTooSmall));
    }

    #[test]
    fn test_cbor_capabilities_serialization_roundtrip() {
        let test_message = CapabilityMessage {
            schema_version: 1,
            min_supported_version: 1,
            session_epoch: 9812390123901,
            features: FeatureManifest {
                codecs: 0x0003, // AV1 and H264
                audio_profiles: 0x01, // Opus 48k
                input_types: 0x03, // Relative + Absolute
                security_hardening: 0x0003, // TPM + Locked RAM
                max_resolution_width: 1920,
                max_resolution_height: 1080,
                max_fps: 60,
            },
            display_profile: DisplayProfile {
                monitors_detected: 2,
                hdr_present: true,
                color_space: 2, // Rec2020
            },
        };

        let serialized_bytes = test_message.serialize_to_vec().unwrap();
        
        // Assert that CBOR serialization fits nicely within MTU limits
        assert!(serialized_bytes.len() < 1280);

        let deserialized_message = CapabilityMessage::deserialize_from_slice(&serialized_bytes).unwrap();
        assert_eq!(deserialized_message, test_message);
    }
}