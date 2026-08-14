#![allow(missing_docs)] // Integration-test crate (repo convention)
#![allow(clippy::unwrap_used, clippy::expect_used)] // Test code may panic on failure (repo convention)
use bw_protocol::codec::{decode_frame, encode_frame};
use bw_protocol::error::ProtocolError;
use bw_protocol::frame::ProtocolFrame;
use bw_protocol::header::{PacketHeader, PROTOCOL_MAGIC};
use bw_protocol::version::CURRENT_VERSION;

fn make_valid_header(payload_len: u16) -> PacketHeader {
    PacketHeader {
        magic: PROTOCOL_MAGIC,
        schema_version: u16::from(CURRENT_VERSION),
        flags: 0,
        packet_type: 1,
        payload_length: payload_len,
        sequence_number: 100,
        session_epoch: 12345,
        monotonic_timestamp: 67890,
    }
}

#[test]
fn test_valid_frame_encode_and_decode() {
    let payload = b"Hello, BLACKWING protocol!";
    let header = make_valid_header(payload.len() as u16);
    let frame = ProtocolFrame {
        header,
        payload: payload.as_slice(),
    };

    let encoded = encode_frame(&frame);
    assert_eq!(encoded.len(), 32 + payload.len());

    let decoded = decode_frame(&encoded).unwrap();
    assert_eq!(decoded.header, header);
    assert_eq!(decoded.payload, payload);
}

#[test]
fn test_empty_payload() {
    let payload = b"";
    let header = make_valid_header(0);
    let frame = ProtocolFrame { header, payload };

    let encoded = encode_frame(&frame);
    assert_eq!(encoded.len(), 32);

    let decoded = decode_frame(&encoded).unwrap();
    assert_eq!(decoded.header, header);
    assert_eq!(decoded.payload, payload);
}

#[test]
fn test_maximum_supported_payload() {
    let payload = vec![0xAA; 65535];
    let header = make_valid_header(65535);
    let frame = ProtocolFrame {
        header,
        payload: &payload,
    };

    let encoded = encode_frame(&frame);
    assert_eq!(encoded.len(), 32 + 65535);

    let decoded = decode_frame(&encoded).unwrap();
    assert_eq!(decoded.header, header);
    assert_eq!(decoded.payload, &payload[..]);
}

#[test]
fn test_truncated_frame() {
    let payload = b"some payload data";
    let header = make_valid_header(payload.len() as u16);
    let frame = ProtocolFrame { header, payload };

    let encoded = encode_frame(&frame);
    // Truncate by 1 byte
    let truncated = &encoded[..encoded.len() - 1];
    let result = decode_frame(truncated);
    assert_eq!(result.err(), Some(ProtocolError::BufferTooSmall));
}

#[test]
fn test_payload_length_mismatch() {
    let payload = b"payload";
    let header = make_valid_header(100); // Specifies longer payload than actual data appended
    let frame = ProtocolFrame { header, payload };

    let encoded = encode_frame(&frame);
    let result = decode_frame(&encoded);
    assert_eq!(result.err(), Some(ProtocolError::BufferTooSmall));

    let header_short = make_valid_header(2); // Specifies shorter payload than actual data appended
    let frame_short = ProtocolFrame {
        header: header_short,
        payload,
    };
    let encoded_short = encode_frame(&frame_short);
    let result_short = decode_frame(&encoded_short);
    assert_eq!(
        result_short.err(),
        Some(ProtocolError::InvalidPayloadLength)
    );
}

#[test]
fn test_invalid_magic_frame() {
    let payload = b"data";
    let mut header = make_valid_header(payload.len() as u16);
    header.magic = [0, 0, 0, 0];
    let frame = ProtocolFrame { header, payload };

    let encoded = encode_frame(&frame);
    let result = decode_frame(&encoded);
    assert_eq!(result.err(), Some(ProtocolError::InvalidMagic));
}

#[test]
fn test_invalid_version_frame() {
    let payload = b"data";
    let mut header = make_valid_header(payload.len() as u16);
    header.schema_version = 0x9999;
    let frame = ProtocolFrame { header, payload };

    let encoded = encode_frame(&frame);
    let result = decode_frame(&encoded);
    assert_eq!(result.err(), Some(ProtocolError::InvalidVersion(0x9999)));
}
