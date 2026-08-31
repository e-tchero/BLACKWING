#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Phase 3 Adversarial Validation — Protocol Fuzzing
//!
//! Actively attempts to break BLACKWING protocol deserialization,
//! fragment reassembly, and message handling.

use bw_protocol::message::MessageType;
use bw_protocol::message::{ClipboardEvent, ClipboardFormat, KeyboardEvent, ProtocolMessage};
use bw_protocol::routing::{MessageEnvelope, NodeId, Route, SessionId};

fn make_envelope(msg: ProtocolMessage) -> MessageEnvelope {
    MessageEnvelope {
        source: NodeId(bw_crypto::DeviceId::from_digest([1u8; 32])),
        destination: NodeId(bw_crypto::DeviceId::from_digest([2u8; 32])),
        session_id: SessionId([0u8; 16]),
        route: Route::Direct,
        message: msg,
        routing_flags: 0,
    }
}

// ═══════════════════════════════════════════════════
// ATTACK 1: CBOR DESERIALIZATION
// ═══════════════════════════════════════════════════

#[test]
fn attack_empty_cbor() {
    let result = ProtocolMessage::deserialize(&[]);
    assert!(result.is_err(), "Empty payload must be rejected");
}

#[test]
fn attack_single_byte() {
    let result = ProtocolMessage::deserialize(&[0xFF]);
    assert!(result.is_err(), "Single invalid byte must be rejected");
}

#[test]
fn attack_truncated_cbor() {
    let result = ProtocolMessage::deserialize(&[0x84]);
    assert!(result.is_err(), "Truncated CBOR must be rejected");
}

#[test]
fn attack_huge_array_declaration() {
    let data = vec![0x9D; 20];
    let result = ProtocolMessage::deserialize(&data);
    let _ = result; // No panic
}

#[test]
fn attack_nested_indefinite_strings() {
    let data = vec![0x7F, 0x7F, 0x7F, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF];
    let result = ProtocolMessage::deserialize(&data);
    let _ = result;
}

#[test]
fn attack_valid_message_near_limit() {
    let event = KeyboardEvent {
        keycode: 0x41,
        is_down: true,
    };
    let mut payload = Vec::new();
    ciborium::ser::into_writer(&event, &mut payload).unwrap();
    let msg = ProtocolMessage {
        message_type: bw_protocol::message::MessageType::InputKeyboard,
        message_id: 0,
        flags: 0,
        payload,
    };
    let serialized = msg.serialize().unwrap();
    let result = ProtocolMessage::deserialize(&serialized);
    assert!(result.is_ok(), "Valid message should deserialize");
}

#[test]
fn attack_oversized_message() {
    let huge = vec![0x84u8; 5 * 1024 * 1024]; // 5 MiB
    let result = ProtocolMessage::deserialize(&huge);
    assert!(result.is_err(), "Oversized payload must be rejected");
}

#[test]
fn attack_tampered_message_type() {
    let event = KeyboardEvent {
        keycode: 0x41,
        is_down: true,
    };
    let mut payload = Vec::new();
    ciborium::ser::into_writer(&event, &mut payload).unwrap();
    let msg = ProtocolMessage {
        message_type: bw_protocol::message::MessageType::InputKeyboard,
        message_id: 0,
        flags: 0,
        payload,
    };
    let mut serialized = msg.serialize().unwrap();
    serialized[0] = 0xFF; // Tamper message type
    let result = ProtocolMessage::deserialize(&serialized);
    let _ = result; // No panic
}

#[test]
fn attack_deeply_nested_cbor() {
    let mut data = Vec::new();
    for _ in 0..100 {
        data.push(0x81); // array of 1
    }
    data.push(0x00); // terminal value
    let result = ProtocolMessage::deserialize(&data);
    let _ = result;
}

#[test]
fn attack_huge_cbor_map() {
    let mut data = vec![0xB9, 0xFF, 0xFF]; // map(65535)
    for _ in 0..10 {
        data.push(0x00);
        data.push(0x00);
    }
    let result = ProtocolMessage::deserialize(&data);
    let _ = result;
}

// ═══════════════════════════════════════════════════
// ATTACK 2: CLIPBOARD EDGE CASES
// ═══════════════════════════════════════════════════

#[test]
fn attack_clipboard_max_text() {
    let event = ClipboardEvent {
        format: ClipboardFormat::Text,
        data: vec![0x42; 1024 * 1024],
    };
    let msg = ProtocolMessage::clipboard_event(event).unwrap();
    assert!(msg.as_clipboard_event().is_some());
}

#[test]
fn attack_clipboard_over_text() {
    let event = ClipboardEvent {
        format: ClipboardFormat::Text,
        data: vec![0x42; 1024 * 1024 + 1],
    };
    let msg = ProtocolMessage::clipboard_event(event).unwrap();
    assert!(msg.as_clipboard_event().is_none());
}

#[test]
fn attack_clipboard_zero_dim_with_data() {
    let event = ClipboardEvent {
        format: ClipboardFormat::ImageRgba8 {
            width: 0,
            height: 0,
        },
        data: vec![0x42; 100],
    };
    let msg = ProtocolMessage::clipboard_event(event).unwrap();
    assert!(msg.as_clipboard_event().is_none());
}

#[test]
fn attack_clipboard_dim_overflow() {
    let event = ClipboardEvent {
        format: ClipboardFormat::ImageRgba8 {
            width: usize::MAX,
            height: 2,
        },
        data: vec![0x42; 8],
    };
    let msg = ProtocolMessage::clipboard_event(event).unwrap();
    assert!(msg.as_clipboard_event().is_none());
}

#[test]
fn attack_clipboard_huge_dim() {
    let event = ClipboardEvent {
        format: ClipboardFormat::ImageRgba8 {
            width: 100_000,
            height: 100_000,
        },
        data: vec![],
    };
    let msg = ProtocolMessage::clipboard_event(event).unwrap();
    assert!(msg.as_clipboard_event().is_none());
}

// ═══════════════════════════════════════════════════
// ATTACK 3: INPUT EVENT EDGE CASES
// ═══════════════════════════════════════════════════

#[test]
fn attack_keyboard_max_keycode() {
    let msg = ProtocolMessage::keyboard_event(u16::MAX, true).unwrap();
    let decoded = msg.as_keyboard_event();
    assert!(decoded.is_some());
    assert_eq!(decoded.unwrap().keycode, u16::MAX);
}

#[test]
fn attack_mouse_max_coords() {
    let msg = ProtocolMessage::mouse_event(i32::MAX, i32::MAX, 0xFF).unwrap();
    let decoded = msg.as_mouse_event();
    assert!(decoded.is_some());
    let evt = decoded.unwrap();
    assert_eq!(evt.dx, i32::MAX);
    assert_eq!(evt.dy, i32::MAX);
    assert_eq!(evt.buttons_mask, 0xFF);
}

#[test]
fn attack_mouse_negative_coords() {
    let msg = ProtocolMessage::mouse_event(-1, -1, 0).unwrap();
    assert!(msg.as_mouse_event().is_some());
}

#[test]
fn attack_mouse_all_buttons() {
    let msg = ProtocolMessage::mouse_event(0, 0, 0xFF).unwrap();
    let decoded = msg.as_mouse_event();
    assert!(decoded.is_some());
    assert_eq!(decoded.unwrap().buttons_mask, 0xFF);
}

// ═══════════════════════════════════════════════════
// ATTACK 4: MESSAGE ENVELOPE
// ═══════════════════════════════════════════════════

#[test]
fn attack_envelope_zero_session() {
    let msg = ProtocolMessage::keyboard_event(0x41, true).unwrap();
    let envelope = MessageEnvelope {
        source: NodeId(bw_crypto::DeviceId::from_digest([1u8; 32])),
        destination: NodeId(bw_crypto::DeviceId::from_digest([2u8; 32])),
        session_id: SessionId([0u8; 16]),
        route: Route::Direct,
        message: msg,
        routing_flags: 0,
    };
    assert_eq!(envelope.session_id.0, [0u8; 16]);
}

#[test]
fn attack_envelope_max_session() {
    let msg = ProtocolMessage::keyboard_event(0x41, true).unwrap();
    let envelope = MessageEnvelope {
        source: NodeId(bw_crypto::DeviceId::from_digest([1u8; 32])),
        destination: NodeId(bw_crypto::DeviceId::from_digest([2u8; 32])),
        session_id: SessionId([0xFF; 16]),
        route: Route::Direct,
        message: msg,
        routing_flags: 0,
    };
    assert_eq!(envelope.session_id.0, [0xFF; 16]);
}

#[test]
fn attack_empty_input_payload() {
    let msg = ProtocolMessage {
        message_type: bw_protocol::message::MessageType::InputKeyboard,
        message_id: 0,
        flags: 0,
        payload: vec![],
    };
    assert!(msg.validate().is_err());
}

#[test]
fn attack_empty_clipboard_payload() {
    let msg = ProtocolMessage {
        message_type: bw_protocol::message::MessageType::ClipboardData,
        message_id: 0,
        flags: 0,
        payload: vec![],
    };
    assert!(msg.validate().is_err());
}

// ═══════════════════════════════════════════════════
// ATTACK 5: ROUNDTRIP INTEGRITY
// ═══════════════════════════════════════════════════

#[test]
fn attack_roundtrip_integrity() {
    let original = ProtocolMessage::keyboard_event(0x41, true).unwrap();
    let serialized = original.serialize().unwrap();
    let deserialized = ProtocolMessage::deserialize(&serialized).unwrap();
    assert_eq!(original.message_type, deserialized.message_type);
    assert_eq!(original.payload, deserialized.payload);
}

#[test]
fn attack_tampered_serialized() {
    let original = ProtocolMessage::keyboard_event(0x41, true).unwrap();
    let mut serialized = original.serialize().unwrap();
    if let Some(last) = serialized.last_mut() {
        *last ^= 0xFF;
    }
    let result = ProtocolMessage::deserialize(&serialized);
    if let Ok(deserialized) = result {
        assert_ne!(original.payload, deserialized.payload);
    }
}

// ═══════════════════════════════════════════════════
// ATTACK 6: CONSTANT BOUNDARY CHECKS
// ═══════════════════════════════════════════════════

#[test]
fn attack_clipboard_text_limit_boundary() {
    let event_at = ClipboardEvent {
        format: ClipboardFormat::Text,
        data: vec![0x42; ProtocolMessage::MAX_CLIPBOARD_TEXT_LEN],
    };
    let msg = ProtocolMessage::clipboard_event(event_at).unwrap();
    assert!(msg.as_clipboard_event().is_some());

    let event_over = ClipboardEvent {
        format: ClipboardFormat::Text,
        data: vec![0x42; ProtocolMessage::MAX_CLIPBOARD_TEXT_LEN + 1],
    };
    let msg = ProtocolMessage::clipboard_event(event_over).unwrap();
    assert!(msg.as_clipboard_event().is_none());
}

#[test]
fn attack_clipboard_image_dim_boundary() {
    let dim = ProtocolMessage::MAX_CLIPBOARD_IMAGE_DIM;

    let event_at = ClipboardEvent {
        format: ClipboardFormat::ImageRgba8 {
            width: dim,
            height: 1,
        },
        data: vec![0u8; dim * 4],
    };
    let msg = ProtocolMessage::clipboard_event(event_at).unwrap();
    assert!(msg.as_clipboard_event().is_some());

    let event_over = ClipboardEvent {
        format: ClipboardFormat::ImageRgba8 {
            width: dim + 1,
            height: 1,
        },
        data: vec![0u8; (dim + 1) * 4],
    };
    let msg = ProtocolMessage::clipboard_event(event_over).unwrap();
    assert!(msg.as_clipboard_event().is_none());
}
