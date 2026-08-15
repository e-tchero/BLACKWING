#![allow(missing_docs)] // Integration-test crate (repo convention)
#![allow(clippy::unwrap_used, clippy::expect_used)] // Test code may panic on failure (repo convention)

use bw_clipboard::{ClipboardError, ClipboardManager};
use bw_crypto::DeviceId;
use bw_protocol::dispatcher::{DispatchError, MessageDispatcher};
use bw_protocol::message::{ClipboardEvent, ClipboardFormat, MessageType, ProtocolMessage};
use bw_protocol::routing::{MessageEnvelope, NodeId, Route, SessionId};
use bw_server::{apply_clipboard_event, register_clipboard_handler};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

fn make_node_id(val: u8) -> NodeId {
    NodeId(DeviceId::from_digest([val; 32]))
}

/// Wraps a protocol message in a directly-routed envelope.
fn wrap(message: ProtocolMessage) -> MessageEnvelope {
    MessageEnvelope {
        source: make_node_id(1),
        destination: make_node_id(2),
        session_id: SessionId([0u8; 16]),
        route: Route::Direct,
        message,
        routing_flags: 0,
    }
}

/// Serializes access to the global OS clipboard across tests in this process.
fn clipboard_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

/// Opens a clipboard manager, or returns `None` (skips the test) when no
/// clipboard is available in this environment.
fn open_clipboard() -> Option<ClipboardManager> {
    match ClipboardManager::new() {
        Ok(manager) => Some(manager),
        Err(ClipboardError::Unavailable(reason)) => {
            eprintln!("Skipping clipboard test: clipboard unavailable ({reason})");
            None
        }
        Err(e) => panic!("unexpected error opening clipboard: {e}"),
    }
}

/// Builds a dispatcher with the clipboard handler registered against a real
/// (or skipped) OS clipboard, returning the shared manager handle.
fn test_setup() -> Option<(MessageDispatcher, Arc<Mutex<ClipboardManager>>)> {
    let manager = open_clipboard()?;
    let clipboard = Arc::new(Mutex::new(manager));
    let dispatcher = MessageDispatcher::new();
    register_clipboard_handler(&dispatcher, clipboard.clone());
    Some((dispatcher, clipboard))
}

#[test]
fn test_text_clipboard_event_reaches_os_clipboard() {
    let _guard: MutexGuard<'_, ()> = clipboard_lock().lock().unwrap_or_else(|e| e.into_inner());
    let Some((dispatcher, clipboard)) = test_setup() else {
        return;
    };

    let event = ClipboardEvent {
        format: ClipboardFormat::Text,
        data: b"remote clipboard sync from dispatcher".to_vec(),
    };
    dispatcher
        .dispatch(wrap(ProtocolMessage::clipboard_event(event).unwrap()))
        .unwrap();

    let mut manager = clipboard.lock().unwrap_or_else(|e| e.into_inner());
    assert_eq!(
        manager.get_text().unwrap(),
        "remote clipboard sync from dispatcher"
    );
}

#[test]
fn test_image_clipboard_event_reaches_os_clipboard() {
    let _guard: MutexGuard<'_, ()> = clipboard_lock().lock().unwrap_or_else(|e| e.into_inner());
    let Some((dispatcher, clipboard)) = test_setup() else {
        return;
    };

    // 3x1 RGBA8 image: red, green, blue.
    let rgba = vec![
        255, 0, 0, 255, //
        0, 255, 0, 255, //
        0, 0, 255, 255, //
    ];
    let event = ClipboardEvent {
        format: ClipboardFormat::ImageRgba8 {
            width: 3,
            height: 1,
        },
        data: rgba,
    };
    dispatcher
        .dispatch(wrap(ProtocolMessage::clipboard_event(event).unwrap()))
        .unwrap();

    let mut manager = clipboard.lock().unwrap_or_else(|e| e.into_inner());
    let image = manager.get_image().unwrap();
    assert_eq!(image.width, 3);
    assert_eq!(image.height, 1);
    assert_eq!(
        image.bytes,
        vec![
            255, 0, 0, 255, //
            0, 255, 0, 255, //
            0, 0, 255, 255, //
        ]
    );
}

#[test]
fn test_undecodable_clipboard_payload_reports_handler_error() {
    let _guard: MutexGuard<'_, ()> = clipboard_lock().lock().unwrap_or_else(|e| e.into_inner());
    let Some((dispatcher, _clipboard)) = test_setup() else {
        return;
    };

    // A ClipboardData message whose payload is not valid CBOR for a
    // ClipboardEvent must surface as a handler error, not a panic.
    let envelope = wrap(ProtocolMessage {
        message_type: MessageType::ClipboardData,
        message_id: 0,
        flags: 0,
        payload: vec![0xde, 0xad, 0xbe, 0xef],
    });

    let err = dispatcher.dispatch(envelope).unwrap_err();
    assert!(matches!(err, DispatchError::Handler(_)));
}

#[test]
fn test_invalid_image_dimensions_rejected_by_handler() {
    let _guard: MutexGuard<'_, ()> = clipboard_lock().lock().unwrap_or_else(|e| e.into_inner());
    let Some((dispatcher, _clipboard)) = test_setup() else {
        return;
    };

    // Declared 3x1 (12 bytes) but only 4 bytes supplied → InvalidImage.
    let event = ClipboardEvent {
        format: ClipboardFormat::ImageRgba8 {
            width: 3,
            height: 1,
        },
        data: vec![0u8; 4],
    };
    let err = dispatcher
        .dispatch(wrap(ProtocolMessage::clipboard_event(event).unwrap()))
        .unwrap_err();
    assert!(matches!(err, DispatchError::Handler(_)));
}

#[test]
fn test_apply_clipboard_event_rejects_invalid_utf8() {
    // Pure mapping test — no OS clipboard needed.
    let manager = ClipboardManager::new().expect("clipboard should open on this machine");
    let mut manager = manager;
    let event = ClipboardEvent {
        format: ClipboardFormat::Text,
        data: vec![0xff, 0xfe, 0xfd], // invalid UTF-8
    };
    let err = apply_clipboard_event(&mut manager, &event).unwrap_err();
    assert!(matches!(err, DispatchError::Handler(_)));
}
