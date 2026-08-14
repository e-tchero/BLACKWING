//! Decoded frame types.

/// A decoded video frame in tightly-packed RGB8 format.
///
/// `rgb` holds `width * height * 3` bytes in row-major order, with three bytes
/// per pixel (R, G, B). This is the format the client renderer (`bw-client`,
/// TASK-104) feeds to the display surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedImage {
    /// Image width in pixels.
    pub width: u32,
    /// Image height in pixels.
    pub height: u32,
    /// RGB8 pixel data, `width * height * 3` bytes (R, G, B order).
    pub rgb: Vec<u8>,
}
