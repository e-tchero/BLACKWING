#![allow(missing_docs)] // Integration-test crate (repo convention)
#![allow(clippy::unwrap_used, clippy::expect_used)] // Test code may panic on failure (repo convention)
use bw_protocol::error::ProtocolError;
use bw_protocol::header::{PacketHeader, PROTOCOL_MAGIC};
use bw_protocol::version::{ProtocolVersion, CURRENT_VERSION};

#[test]
fn test_valid_header_casting_and_roundtrip() {
    let original = PacketHeader {
        magic: PROTOCOL_MAGIC,
        schema_version: u16::from(CURRENT_VERSION),
        flags: 0x0001,
        packet_type: 5,
        payload_length: 128,
        sequence_number: 42,
        session_epoch: 99999,
        monotonic_timestamp: 123456,
    };

    let bytes = original.as_bytes();
    assert_eq!(bytes.len(), 32);

    let casted = PacketHeader::try_from_bytes(bytes).unwrap();
    assert_eq!(casted.magic, original.magic);
    assert_eq!(casted.schema_version, original.schema_version);
    assert_eq!(casted.flags, original.flags);
    assert_eq!(casted.packet_type, original.packet_type);
    assert_eq!(casted.payload_length, original.payload_length);
    assert_eq!(casted.sequence_number, original.sequence_number);
    assert_eq!(casted.session_epoch, original.session_epoch);
    assert_eq!(casted.monotonic_timestamp, original.monotonic_timestamp);
}

#[test]
fn test_invalid_magic() {
    let header = PacketHeader {
        magic: [0, 0, 0, 0],
        schema_version: u16::from(CURRENT_VERSION),
        flags: 0,
        packet_type: 0,
        payload_length: 0,
        sequence_number: 0,
        session_epoch: 0,
        monotonic_timestamp: 0,
    };

    let bytes = header.as_bytes();
    let result = PacketHeader::try_from_bytes(bytes);
    assert_eq!(result.err(), Some(ProtocolError::InvalidMagic));
}

#[test]
fn test_unsupported_version() {
    let incompatible_version = ProtocolVersion::new(CURRENT_VERSION.major + 1, 0);
    let header = PacketHeader {
        magic: PROTOCOL_MAGIC,
        schema_version: u16::from(incompatible_version),
        flags: 0,
        packet_type: 0,
        payload_length: 0,
        sequence_number: 0,
        session_epoch: 0,
        monotonic_timestamp: 0,
    };

    let bytes = header.as_bytes();
    let result = PacketHeader::try_from_bytes(bytes);
    assert_eq!(
        result.err(),
        Some(ProtocolError::InvalidVersion(u16::from(
            incompatible_version
        )))
    );
}

#[test]
fn test_buffer_too_small() {
    let short_buffer = [0u8; 15];
    let result = PacketHeader::try_from_bytes(&short_buffer);
    assert_eq!(result.err(), Some(ProtocolError::BufferTooSmall));
}

#[test]
fn test_header_alignment_and_size() {
    assert_eq!(std::mem::size_of::<PacketHeader>(), 32);
    assert_eq!(std::mem::align_of::<PacketHeader>(), 8);
}
