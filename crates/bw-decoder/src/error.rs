//! Error types for the H.264 decoder pipeline.

use bw_encoder::Codec;
use thiserror::Error;

/// Errors that can occur while decoding H.264 frames.
#[derive(Debug, Error)]
pub enum DecoderError {
    /// Failed to initialize the underlying OpenH264 decoder.
    #[error("Failed to initialize the OpenH264 decoder: {0}")]
    InitFailed(String),
    /// The underlying OpenH264 decoder rejected the bitstream as corrupted.
    #[error("Failed to decode H.264 payload: {0}")]
    DecodeFailed(String),
    /// The frame is not H.264 and cannot be decoded by this pipeline.
    #[error("Unsupported codec: {0:?}")]
    UnsupportedCodec(Codec),
    /// The frame carried an empty payload.
    #[error("Frame payload is empty")]
    EmptyPayload,
    /// The decoder produced an image with unusable dimensions.
    #[error("Decoder produced invalid dimensions {width}x{height}")]
    InvalidDimensions {
        /// Reported width in pixels.
        width: usize,
        /// Reported height in pixels.
        height: usize,
    },
}
