#![allow(clippy::unwrap_used, clippy::expect_used)]
//! M1 Regression Tests — Clipboard Payload Size Limits
//!
//! Tests that oversized clipboard payloads are rejected at the protocol layer.

use bw_protocol::message::{ClipboardEvent, ClipboardFormat, ProtocolMessage};

#[test]
fn test_m1_normal_text_accepted() {
    let event = ClipboardEvent {
        format: ClipboardFormat::Text,
        data: b"Hello, world!".to_vec(),
    };
    let msg = ProtocolMessage::clipboard_event(event).unwrap();
    let decoded = msg.as_clipboard_event();
    assert!(
        decoded.is_some(),
        "Normal text clipboard event should be accepted"
    );
    assert_eq!(decoded.unwrap().data, b"Hello, world!");
}

#[test]
fn test_m1_oversized_text_rejected() {
    let event = ClipboardEvent {
        format: ClipboardFormat::Text,
        data: vec![0x42; 2 * 1024 * 1024], // 2 MiB — exceeds 1 MiB limit
    };
    let msg = ProtocolMessage::clipboard_event(event).unwrap();
    let decoded = msg.as_clipboard_event();
    assert!(decoded.is_none(), "Oversized text should be rejected");
}

#[test]
fn test_m1_normal_image_accepted() {
    let width = 1920;
    let height = 1080;
    let data = vec![0u8; width * height * 4];
    let event = ClipboardEvent {
        format: ClipboardFormat::ImageRgba8 { width, height },
        data,
    };
    let msg = ProtocolMessage::clipboard_event(event).unwrap();
    let decoded = msg.as_clipboard_event();
    assert!(
        decoded.is_some(),
        "Normal image clipboard event should be accepted"
    );
    let evt = decoded.unwrap();
    assert_eq!(evt.data.len(), 1920 * 1080 * 4);
}

#[test]
fn test_m1_oversized_image_dimension_rejected() {
    let event = ClipboardEvent {
        format: ClipboardFormat::ImageRgba8 {
            width: 100_000,
            height: 100_000,
        },
        data: vec![0u8; 100], // Dimension doesn't match, but dimension check fires first
    };
    let msg = ProtocolMessage::clipboard_event(event).unwrap();
    let decoded = msg.as_clipboard_event();
    assert!(
        decoded.is_none(),
        "Oversized image dimensions should be rejected"
    );
}

#[test]
fn test_m1_image_dimension_mismatch_rejected() {
    let event = ClipboardEvent {
        format: ClipboardFormat::ImageRgba8 {
            width: 100,
            height: 100,
        },
        data: vec![0u8; 50], // Should be 100*100*4 = 40000 bytes
    };
    let msg = ProtocolMessage::clipboard_event(event).unwrap();
    let decoded = msg.as_clipboard_event();
    assert!(
        decoded.is_none(),
        "Image with mismatched data length should be rejected"
    );
}

#[test]
fn test_m1_max_dimension_accepted() {
    let dim = ProtocolMessage::MAX_CLIPBOARD_IMAGE_DIM;
    // Small pixel count but at the dimension limit.
    let event = ClipboardEvent {
        format: ClipboardFormat::ImageRgba8 {
            width: dim,
            height: 1,
        },
        data: vec![0u8; dim * 4],
    };
    let msg = ProtocolMessage::clipboard_event(event).unwrap();
    let decoded = msg.as_clipboard_event();
    assert!(
        decoded.is_some(),
        "Image at max dimension should be accepted"
    );
}

#[test]
fn test_m1_zero_dimension_accepted() {
    let event = ClipboardEvent {
        format: ClipboardFormat::ImageRgba8 {
            width: 0,
            height: 0,
        },
        data: vec![],
    };
    let msg = ProtocolMessage::clipboard_event(event).unwrap();
    let decoded = msg.as_clipboard_event();
    assert!(
        decoded.is_some(),
        "Zero-dimension image should be accepted (empty data)"
    );
}

#[test]
fn test_m1_empty_text_accepted() {
    let event = ClipboardEvent {
        format: ClipboardFormat::Text,
        data: vec![],
    };
    let msg = ProtocolMessage::clipboard_event(event).unwrap();
    let decoded = msg.as_clipboard_event();
    assert!(decoded.is_some(), "Empty text should be accepted");
}
