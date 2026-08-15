//! Error types for clipboard access.

use thiserror::Error;

/// Errors that can occur while reading or writing the OS clipboard.
#[derive(Debug, Error)]
pub enum ClipboardError {
    /// The clipboard could not be opened on this platform or environment.
    ///
    /// For example, headless Linux sessions (no Wayland/X11 display) or
    /// restricted desktop sessions cannot access the clipboard.
    #[error("clipboard is not available on this platform or environment: {0}")]
    Unavailable(String),

    /// Reading the clipboard failed.
    #[error("failed to read clipboard: {0}")]
    Read(String),

    /// Writing to the clipboard failed.
    #[error("failed to write clipboard: {0}")]
    Write(String),

    /// The image dimensions are inconsistent with the pixel data length.
    ///
    /// An RGBA8 image requires exactly `width * height * 4` bytes.
    #[error("image dimensions ({width}x{height}) do not match pixel data length {len}")]
    InvalidImage {
        /// Image width in pixels.
        width: usize,
        /// Image height in pixels.
        height: usize,
        /// Number of bytes supplied.
        len: usize,
    },
}
