#![allow(missing_docs)] // Integration-test crate (repo convention)
#![allow(clippy::unwrap_used, clippy::expect_used)] // Test code may panic on failure (repo convention)

use bw_clipboard::{ClipboardError, ClipboardImage, ClipboardManager};
use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::sync::{Mutex, OnceLock};

/// Serializes access to the global OS clipboard across tests in this process.
///
/// Tests run in parallel by default, and arboard documents that parallel
/// clipboard operations may fail or clobber each other. Every test that
/// touches the real clipboard acquires this lock first.
fn clipboard_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

/// Returns a random 64-bit value seeded from the OS (via `RandomState`).
fn random_u64() -> u64 {
    let mut hasher = RandomState::new().build_hasher();
    hasher.write_u64(0);
    hasher.finish()
}

/// Builds a version-4-shaped UUID string without pulling in the `uuid` crate.
fn random_uuid() -> String {
    let a = random_u64();
    let b = random_u64();
    format!(
        "{:08x}-{:04x}-4{:03x}-{:04x}-{:012x}",
        (a >> 32) as u32,
        (a & 0xFFFF) as u16,
        ((b >> 44) & 0x0FFF) as u16,
        (0x8000 | ((b >> 28) & 0x0FFF)) as u16,
        b & 0xFFFF_FFFF_FFFF
    )
}

/// Opens the clipboard, or skips the test when no clipboard is available
/// (e.g. a headless CI session without a desktop).
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

#[test]
fn test_text_set_and_get_roundtrip() {
    let _guard = clipboard_lock().lock().unwrap_or_else(|e| e.into_inner());
    let Some(mut manager) = open_clipboard() else {
        return;
    };

    let id = random_uuid();
    match manager.set_text(&id) {
        Ok(()) => {}
        Err(ClipboardError::Unavailable(reason)) | Err(ClipboardError::Write(reason))
            if reason.contains("not accessible") || reason.contains("held by another") =>
        {
            eprintln!("Skipping clipboard test: clipboard busy ({reason})");
            return;
        }
        Err(e) => panic!("set_text failed: {e}"),
    }
    assert_eq!(manager.get_text().unwrap(), id);
}

#[test]
fn test_text_roundtrip_with_unicode() {
    let _guard = clipboard_lock().lock().unwrap_or_else(|e| e.into_inner());
    let Some(mut manager) = open_clipboard() else {
        return;
    };

    let text = "BLACKWING clipboard — 你好, zéro ✓";
    match manager.set_text(text) {
        Ok(()) => {}
        Err(ClipboardError::Unavailable(reason)) | Err(ClipboardError::Write(reason))
            if reason.contains("not accessible") || reason.contains("held by another") =>
        {
            eprintln!("Skipping clipboard test: clipboard busy ({reason})");
            return;
        }
        Err(e) => panic!("set_text failed: {e}"),
    }
    assert_eq!(manager.get_text().unwrap(), text);
}

#[test]
fn test_image_roundtrip() {
    let _guard = clipboard_lock().lock().unwrap_or_else(|e| e.into_inner());
    let Some(mut manager) = open_clipboard() else {
        return;
    };

    // A tiny 2x1 RGBA8 image: a red pixel and a green pixel.
    let image = ClipboardImage::new(
        2,
        1,
        vec![
            255, 0, 0, 255, // red
            0, 255, 0, 255, // green
        ],
    )
    .unwrap();
    match manager.set_image(&image) {
        Ok(()) => {}
        Err(ClipboardError::Unavailable(reason)) | Err(ClipboardError::Write(reason))
            if reason.contains("not accessible") || reason.contains("held by another") =>
        {
            eprintln!("Skipping clipboard test: clipboard busy ({reason})");
            return;
        }
        Err(e) => panic!("set_image failed: {e}"),
    }

    let read_back = manager.get_image().unwrap();
    assert_eq!(read_back.width, 2);
    assert_eq!(read_back.height, 1);
    assert_eq!(read_back.bytes, image.bytes);
}

#[test]
fn test_invalid_image_dimensions_rejected() {
    let err = ClipboardImage::new(2, 1, vec![0u8; 4]).unwrap_err(); // needs 8 bytes
    assert!(matches!(err, ClipboardError::InvalidImage { .. }));
}
