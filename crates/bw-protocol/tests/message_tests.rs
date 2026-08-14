#![allow(missing_docs)] // Integration-test crate (repo convention)
#![allow(clippy::unwrap_used, clippy::expect_used)] // Test code may panic on failure (repo convention)
use bw_protocol::error::ProtocolError;
use bw_protocol::message::{MessageType, ProtocolMessage};

#[test]
fn test_message_types_serialization_roundtrip() {
    let types = [
        MessageType::Ping,
        MessageType::Pong,
        MessageType::Hello,
        MessageType::Goodbye,
        MessageType::Heartbeat,
        MessageType::Data,
        MessageType::Control,
        MessageType::Error,
    ];

    for &msg_type in &types {
        let msg = ProtocolMessage {
            message_type: msg_type,
            message_id: 1234,
            flags: 0x000F,
            payload: b"test payload data".to_vec(),
        };

        let encoded = msg.serialize().unwrap();
        let decoded = ProtocolMessage::deserialize(&encoded).unwrap();
        assert_eq!(decoded, msg);
    }
}

#[test]
fn test_validation_rules() {
    // Data message with empty payload but non-zero flags -> invalid
    let invalid_msg = ProtocolMessage {
        message_type: MessageType::Data,
        message_id: 1,
        flags: 0x0001,
        payload: vec![],
    };
    assert_eq!(
        invalid_msg.validate().err(),
        Some(ProtocolError::InvalidPayloadLength)
    );

    // Data message with empty payload and zero flags -> valid
    let valid_empty_data = ProtocolMessage {
        message_type: MessageType::Data,
        message_id: 2,
        flags: 0,
        payload: vec![],
    };
    assert!(valid_empty_data.validate().is_ok());
}

#[test]
fn test_duplicate_ids() {
    // Session level tracks duplicates, but structurally messages with identical IDs are independent
    let msg1 = ProtocolMessage {
        message_type: MessageType::Ping,
        message_id: 999,
        flags: 0,
        payload: vec![],
    };
    let msg2 = ProtocolMessage {
        message_type: MessageType::Pong,
        message_id: 999,
        flags: 0,
        payload: vec![],
    };

    assert_eq!(msg1.message_id, msg2.message_id);
    assert!(msg1.validate().is_ok());
    assert!(msg2.validate().is_ok());
}

#[test]
fn test_malformed_message_deserialization() {
    let bad_bytes = b"not a CBOR message payload";
    let result = ProtocolMessage::deserialize(bad_bytes);
    assert_eq!(result.err(), Some(ProtocolError::DeserializationError));
}

#[test]
fn test_unknown_message_type() {
    // We serialize a struct with an out-of-bounds MessageType integer manually via CBOR
    // to verify the deserializer fails gracefully.
    let serialized_invalid_type = vec![
        0xa4, // map(4)
        0x6c, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x5f, 0x74, 0x79, 0x70,
        0x65, // "message_type"
        0x18, 0x63, // 99 (invalid representation)
        0x6a, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x5f, 0x69, 0x64, // "message_id"
        0x19, 0x03, 0xe7, // 1000
        0x65, 0x66, 0x6c, 0x61, 0x67, 0x73, // "flags"
        0x00, // 0
        0x67, 0x70, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64, // "payload"
        0x40, // h'' (empty bytes)
    ];

    let result = ProtocolMessage::deserialize(&serialized_invalid_type);
    assert_eq!(result.err(), Some(ProtocolError::DeserializationError));
}
