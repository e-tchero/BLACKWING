//! The OS clipboard abstraction.
//!
//! [`ClipboardManager`] wraps an [`arboard::Clipboard`] so callers never touch
//! the platform-specific clipboard directly. Text is exchanged as UTF-8
//! strings; images are exchanged as tightly-packed RGBA8 pixels via
//! [`ClipboardImage`].

use crate::error::ClipboardError;

/// An owned RGBA8 image, the clipboard image representation used across
/// BLACKWING.
///
/// Pixels are stored row-major, four bytes per pixel (red, green, blue,
/// alpha), exactly matching `arboard::ImageData` and the protocol's
/// `ClipboardFormat::ImageRgba8`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClipboardImage {
    /// Image width in pixels.
    pub width: usize,
    /// Image height in pixels.
    pub height: usize,
    /// Tightly-packed RGBA8 pixels, exactly `width * height * 4` bytes.
    pub bytes: Vec<u8>,
}

impl ClipboardImage {
    /// Builds an image, validating that the pixel data length matches the
    /// declared dimensions.
    ///
    /// # Errors
    ///
    /// Returns [`ClipboardError::InvalidImage`] when `bytes.len()` is not
    /// exactly `width * height * 4`.
    pub fn new(width: usize, height: usize, bytes: Vec<u8>) -> Result<Self, ClipboardError> {
        let expected = width
            .checked_mul(height)
            .and_then(|area| area.checked_mul(4))
            .ok_or(ClipboardError::InvalidImage {
                width,
                height,
                len: bytes.len(),
            })?;
        if bytes.len() != expected {
            return Err(ClipboardError::InvalidImage {
                width,
                height,
                len: bytes.len(),
            });
        }
        Ok(Self {
            width,
            height,
            bytes,
        })
    }
}

/// Provides safe access to the OS clipboard.
///
/// `arboard` requires `&mut` for every operation (the clipboard may only be
/// opened by one thread at a time on Windows), so `ClipboardManager` exposes
/// the same mutating interface.
pub struct ClipboardManager {
    clipboard: arboard::Clipboard,
}

impl ClipboardManager {
    /// Opens the OS clipboard.
    ///
    /// # Errors
    ///
    /// Returns [`ClipboardError::Unavailable`] when the platform or desktop
    /// environment does not provide a clipboard (e.g. a headless session).
    pub fn new() -> Result<Self, ClipboardError> {
        arboard::Clipboard::new()
            .map(|clipboard| Self { clipboard })
            .map_err(|e| ClipboardError::Unavailable(e.to_string()))
    }

    /// Returns the current clipboard text, if the clipboard holds UTF-8 text.
    ///
    /// # Errors
    ///
    /// Returns [`ClipboardError::Read`] when the clipboard is empty, holds
    /// non-text content, or the platform cannot be read from.
    pub fn get_text(&mut self) -> Result<String, ClipboardError> {
        self.clipboard
            .get_text()
            .map_err(|e| ClipboardError::Read(e.to_string()))
    }

    /// Places UTF-8 text onto the clipboard.
    ///
    /// # Errors
    ///
    /// Returns [`ClipboardError::Write`] when the text cannot be stored.
    pub fn set_text(&mut self, text: &str) -> Result<(), ClipboardError> {
        self.clipboard
            .set_text(text)
            .map_err(|e| ClipboardError::Write(e.to_string()))
    }

    /// Returns the current clipboard image, if the clipboard holds one.
    ///
    /// # Errors
    ///
    /// Returns [`ClipboardError::Read`] when the clipboard is empty, holds
    /// non-image content, or the image format cannot be decoded.
    pub fn get_image(&mut self) -> Result<ClipboardImage, ClipboardError> {
        let image = self
            .clipboard
            .get_image()
            .map_err(|e| ClipboardError::Read(e.to_string()))?;
        let width = image.width;
        let height = image.height;
        let bytes = image.into_owned_bytes().into_owned();
        Ok(ClipboardImage {
            width,
            height,
            bytes,
        })
    }

    /// Places an RGBA8 image onto the clipboard.
    ///
    /// # Errors
    ///
    /// Returns [`ClipboardError::Write`] when the image cannot be stored, or
    /// [`ClipboardError::InvalidImage`] when the image dimensions are
    /// inconsistent with its pixel data.
    pub fn set_image(&mut self, image: &ClipboardImage) -> Result<(), ClipboardError> {
        let data = arboard::ImageData {
            width: image.width,
            height: image.height,
            bytes: std::borrow::Cow::Borrowed(&image.bytes),
        };
        self.clipboard
            .set_image(data)
            .map_err(|e| ClipboardError::Write(e.to_string()))
    }
}
