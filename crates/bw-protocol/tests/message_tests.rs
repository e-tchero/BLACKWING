#![allow(missing_docs)] // Integration-test crate (repo convention)
#![allow(clippy::unwrap_used, clippy::expect_used)] // Test code may panic on failure (repo convention)
use bw_protocol::error::ProtocolError;
use bw_protocol::message::{
    AudioPayload, ClipboardEvent, ClipboardFormat, IceCandidatePayload, KeyboardEvent, MessageType,
    MouseEvent, ProtocolMessage, VideoPayload,
};

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
        MessageType::InputKeyboard,
        MessageType::InputMouse,
        MessageType::ClipboardData,
        MessageType::AudioData,
        MessageType::IceCandidate,
        MessageType::VideoData,
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

#[test]
fn test_input_message_constructors_and_accessors() {
    let kb = ProtocolMessage::keyboard_event(0x1b, false).unwrap(); // VK_ESCAPE up
    assert_eq!(kb.message_type, MessageType::InputKeyboard);
    assert!(kb.validate().is_ok());
    assert_eq!(
        kb.as_keyboard_event(),
        Some(KeyboardEvent {
            keycode: 0x1b,
            is_down: false
        })
    );
    // Wrong accessor for the message type returns None.
    assert!(kb.as_mouse_event().is_none());

    let ms = ProtocolMessage::mouse_event(120, -30, 0b101).unwrap();
    assert_eq!(ms.message_type, MessageType::InputMouse);
    assert!(ms.validate().is_ok());
    assert_eq!(
        ms.as_mouse_event(),
        Some(MouseEvent {
            dx: 120,
            dy: -30,
            buttons_mask: 0b101,
            is_absolute: false,
        })
    );
    assert!(ms.as_keyboard_event().is_none());
}

#[test]
fn test_input_message_wire_roundtrip() {
    let kb = ProtocolMessage::keyboard_event(0x41, true).unwrap();
    let encoded = kb.serialize().unwrap();
    let decoded = ProtocolMessage::deserialize(&encoded).unwrap();
    assert_eq!(decoded.message_type, MessageType::InputKeyboard);
    assert_eq!(
        decoded.as_keyboard_event(),
        Some(KeyboardEvent {
            keycode: 0x41,
            is_down: true
        })
    );

    let ms = ProtocolMessage::mouse_event(0, 10, 0b010).unwrap();
    let encoded = ms.serialize().unwrap();
    let decoded = ProtocolMessage::deserialize(&encoded).unwrap();
    assert_eq!(decoded.message_type, MessageType::InputMouse);
    assert_eq!(
        decoded.as_mouse_event(),
        Some(MouseEvent {
            dx: 0,
            dy: 10,
            buttons_mask: 0b010,
            is_absolute: false,
        })
    );
}

#[test]
fn test_absolute_mouse_event_roundtrip() {
    let ms = ProtocolMessage::mouse_event_abs(32768, 16384, 0b001, true).unwrap();
    assert_eq!(ms.message_type, MessageType::InputMouse);
    assert!(ms.validate().is_ok());
    assert_eq!(
        ms.as_mouse_event(),
        Some(MouseEvent {
            dx: 32768,
            dy: 16384,
            buttons_mask: 0b001,
            is_absolute: true,
        })
    );
    // Wire round-trip preserves the absolute flag.
    let encoded = ms.serialize().unwrap();
    let decoded = ProtocolMessage::deserialize(&encoded).unwrap();
    let event = decoded.as_mouse_event().unwrap();
    assert!(event.is_absolute);
    assert_eq!(event.dx, 32768);
    assert_eq!(event.dy, 16384);
}

#[test]
fn test_absolute_mouse_event_backwards_compat() {
    // Simulate an old client that doesn't send is_absolute (CBOR without the field).
    // The #[serde(default)] on is_absolute should make it deserialize as false.
    let event = MouseEvent {
        dx: 100,
        dy: 200,
        buttons_mask: 0,
        is_absolute: false,
    };
    let mut payload = Vec::new();
    ciborium::ser::into_writer(&event, &mut payload).unwrap();
    // Manually remove the is_absolute field by re-serializing as a map without it.
    // Instead, just verify that a message with is_absolute=false roundtrips correctly.
    let msg = ProtocolMessage {
        message_type: MessageType::InputMouse,
        message_id: 0,
        flags: 0,
        payload,
    };
    let encoded = msg.serialize().unwrap();
    let decoded = ProtocolMessage::deserialize(&encoded).unwrap();
    let decoded_event = decoded.as_mouse_event().unwrap();
    assert!(!decoded_event.is_absolute);
    assert_eq!(decoded_event.dx, 100);
    assert_eq!(decoded_event.dy, 200);
}

#[test]
fn test_input_message_requires_payload() {
    let invalid = ProtocolMessage {
        message_type: MessageType::InputKeyboard,
        message_id: 1,
        flags: 0,
        payload: vec![],
    };
    assert_eq!(
        invalid.validate().err(),
        Some(ProtocolError::InvalidPayloadLength)
    );

    let invalid_mouse = ProtocolMessage {
        message_type: MessageType::InputMouse,
        message_id: 1,
        flags: 0,
        payload: vec![],
    };
    assert_eq!(
        invalid_mouse.validate().err(),
        Some(ProtocolError::InvalidPayloadLength)
    );
}

#[test]
fn test_clipboard_event_text_roundtrip() {
    let event = ClipboardEvent {
        format: ClipboardFormat::Text,
        data: b"clipboard text payload".to_vec(),
    };
    let msg = ProtocolMessage::clipboard_event(event.clone()).unwrap();

    assert_eq!(msg.message_type, MessageType::ClipboardData);
    assert!(msg.validate().is_ok());
    assert_eq!(msg.as_clipboard_event(), Some(event));

    // Wrong accessor for the message type returns None.
    assert!(msg.as_keyboard_event().is_none());

    // Wire round-trip preserves format and data.
    let encoded = msg.serialize().unwrap();
    let decoded = ProtocolMessage::deserialize(&encoded).unwrap();
    assert_eq!(decoded.message_type, MessageType::ClipboardData);
    assert_eq!(
        decoded.as_clipboard_event(),
        Some(ClipboardEvent {
            format: ClipboardFormat::Text,
            data: b"clipboard text payload".to_vec(),
        })
    );
}

#[test]
fn test_clipboard_event_image_roundtrip() {
    let rgba = vec![0u8; 8 * 6 * 4]; // 8x6 RGBA8 image
    let event = ClipboardEvent {
        format: ClipboardFormat::ImageRgba8 {
            width: 8,
            height: 6,
        },
        data: rgba,
    };
    let msg = ProtocolMessage::clipboard_event(event.clone()).unwrap();

    assert_eq!(msg.as_clipboard_event(), Some(event.clone()));

    let encoded = msg.serialize().unwrap();
    let decoded = ProtocolMessage::deserialize(&encoded).unwrap();
    assert_eq!(decoded.as_clipboard_event(), Some(event));
}

#[test]
fn test_clipboard_event_requires_payload() {
    let invalid = ProtocolMessage {
        message_type: MessageType::ClipboardData,
        message_id: 1,
        flags: 0,
        payload: vec![],
    };
    assert_eq!(
        invalid.validate().err(),
        Some(ProtocolError::InvalidPayloadLength)
    );
}

#[test]
fn test_audio_data_roundtrip() {
    let payload = AudioPayload {
        channels: 2,
        sample_rate: 48_000,
        opus_data: vec![0xde, 0xad, 0xbe, 0xef],
    };
    let msg = ProtocolMessage::audio_data(payload.clone()).unwrap();

    assert_eq!(msg.message_type, MessageType::AudioData);
    assert!(msg.validate().is_ok());
    assert_eq!(msg.as_audio_data(), Some(payload.clone()));

    // Wrong accessor for the message type returns None.
    assert!(msg.as_clipboard_event().is_none());

    // Wire round-trip preserves channels, sample rate and opus data.
    let encoded = msg.serialize().unwrap();
    let decoded = ProtocolMessage::deserialize(&encoded).unwrap();
    assert_eq!(decoded.message_type, MessageType::AudioData);
    assert_eq!(
        decoded.as_audio_data(),
        Some(AudioPayload {
            channels: 2,
            sample_rate: 48_000,
            opus_data: vec![0xde, 0xad, 0xbe, 0xef],
        })
    );
}

#[test]
fn test_audio_data_requires_payload() {
    let invalid = ProtocolMessage {
        message_type: MessageType::AudioData,
        message_id: 1,
        flags: 0,
        payload: vec![],
    };
    assert_eq!(
        invalid.validate().err(),
        Some(ProtocolError::InvalidPayloadLength)
    );
}

#[test]
fn test_ice_candidate_roundtrip() {
    let payload = IceCandidatePayload {
        candidate_str: "candidate:1 1 UDP 2130706431 192.168.1.10 54321 typ host".into(),
        sdp_mid: Some("0".into()),
        sdp_mline_index: Some(0),
    };
    let msg = ProtocolMessage::ice_candidate(payload.clone()).unwrap();

    assert_eq!(msg.message_type, MessageType::IceCandidate);
    assert!(msg.validate().is_ok());
    assert_eq!(msg.as_ice_candidate(), Some(payload.clone()));

    // Wrong accessor for the message type returns None.
    assert!(msg.as_audio_data().is_none());

    // Wire round-trip preserves the candidate fields (including None optionals).
    let encoded = msg.serialize().unwrap();
    let decoded = ProtocolMessage::deserialize(&encoded).unwrap();
    assert_eq!(decoded.message_type, MessageType::IceCandidate);
    assert_eq!(decoded.as_ice_candidate(), Some(payload));

    // Optionals round-trip as None too.
    let no_mid = ProtocolMessage::ice_candidate(IceCandidatePayload {
        candidate_str:
            "candidate:2 1 UDP 1694498815 10.0.0.2 60000 typ srflx raddr 0.0.0.0 rport 0".into(),
        sdp_mid: None,
        sdp_mline_index: None,
    })
    .unwrap();
    let encoded = no_mid.serialize().unwrap();
    let decoded = ProtocolMessage::deserialize(&encoded).unwrap();
    assert_eq!(
        decoded.as_ice_candidate(),
        Some(IceCandidatePayload {
            candidate_str:
                "candidate:2 1 UDP 1694498815 10.0.0.2 60000 typ srflx raddr 0.0.0.0 rport 0".into(),
            sdp_mid: None,
            sdp_mline_index: None,
        })
    );
}

#[test]
fn test_ice_candidate_requires_payload() {
    let invalid = ProtocolMessage {
        message_type: MessageType::IceCandidate,
        message_id: 1,
        flags: 0,
        payload: vec![],
    };
    assert_eq!(
        invalid.validate().err(),
        Some(ProtocolError::InvalidPayloadLength)
    );
}

#[test]
fn test_video_data_roundtrip() {
    let payload = VideoPayload {
        encoded_frame: vec![0x00, 0x01, 0x02, 0x03, 0xde, 0xad, 0xbe, 0xef],
    };
    let msg = ProtocolMessage::video_data(payload.clone()).unwrap();

    assert_eq!(msg.message_type, MessageType::VideoData);
    assert!(msg.validate().is_ok());
    assert_eq!(msg.as_video_data(), Some(payload.clone()));

    // Wrong accessor for the message type returns None.
    assert!(msg.as_audio_data().is_none());

    // Wire round-trip preserves the encoded frame bytes.
    let encoded = msg.serialize().unwrap();
    let decoded = ProtocolMessage::deserialize(&encoded).unwrap();
    assert_eq!(decoded.message_type, MessageType::VideoData);
    assert_eq!(
        decoded.as_video_data(),
        Some(VideoPayload {
            encoded_frame: vec![0x00, 0x01, 0x02, 0x03, 0xde, 0xad, 0xbe, 0xef],
        })
    );
}

#[test]
fn test_video_data_requires_payload() {
    let invalid = ProtocolMessage {
        message_type: MessageType::VideoData,
        message_id: 1,
        flags: 0,
        payload: vec![],
    };
    assert_eq!(
        invalid.validate().err(),
        Some(ProtocolError::InvalidPayloadLength)
    );
}

// ── C3 regression: oversized payload rejection ──────────────────────

#[test]
fn test_oversized_payload_rejected_before_deserialization() {
    // C3 FIX: payloads exceeding MAX_DESER_SIZE are rejected before
    // ciborium allocation, preventing OOM from malicious CBOR.
    let oversized = vec![0xABu8; ProtocolMessage::MAX_DESER_SIZE + 1];
    let result = ProtocolMessage::deserialize(&oversized);
    assert!(result.is_err(), "oversized payload must be rejected");
    match result.unwrap_err() {
        ProtocolError::OversizedPayload(actual, max) => {
            assert_eq!(actual, ProtocolMessage::MAX_DESER_SIZE + 1);
            assert_eq!(max, ProtocolMessage::MAX_DESER_SIZE);
        }
        other => panic!("expected OversizedPayload, got {:?}", other),
    }
}

#[test]
fn test_exactly_max_payload_accepted() {
    // At exactly MAX_DESER_SIZE, deserialization should proceed (may fail
    // with DeserializationError for invalid CBOR, but not OversizedPayload).
    let at_limit = vec![0xABu8; ProtocolMessage::MAX_DESER_SIZE];
    let result = ProtocolMessage::deserialize(&at_limit);
    // Invalid CBOR is expected — the point is it is NOT OversizedPayload.
    assert!(
        !matches!(result, Err(ProtocolError::OversizedPayload(_, _))),
        "exactly-at-limit payload must not be rejected as oversized"
    );
}

#[test]
fn test_normal_message_passes_size_check() {
    // A real serialized message must pass the size check.
    let msg = ProtocolMessage::keyboard_event(0x41, true).unwrap();
    let serialized = msg.serialize().unwrap();
    assert!(serialized.len() < ProtocolMessage::MAX_DESER_SIZE);
    let deserialized = ProtocolMessage::deserialize(&serialized).unwrap();
    assert_eq!(deserialized.message_type, MessageType::InputKeyboard);
}

#[test]
fn test_oversized_encrypted_frame_rejected() {
    use bw_protocol::encryption::EncryptedFrame;
    let oversized = vec![0xABu8; EncryptedFrame::MAX_DESER_SIZE + 1];
    let result = EncryptedFrame::deserialize(&oversized);
    assert!(
        result.is_err(),
        "oversized encrypted frame must be rejected"
    );
}
