//! The OpenH264-backed decoder pipeline.

use crate::error::DecoderError;
use crate::image::DecodedImage;
use bw_encoder::{Codec, EncodedFrame};
use openh264::decoder::Decoder;
use openh264::formats::YUVSource;

/// Decodes H.264 [`EncodedFrame`]s into [`DecodedImage`]s.
///
/// The OpenH264 decoder is stateful: later frames (P-frames) reference earlier
/// keyframes in the stream, so a single pipeline instance must be used for the
/// lifetime of a video stream.
pub struct DecoderPipeline {
    decoder: Decoder,
}

impl DecoderPipeline {
    /// Creates a new decoder pipeline backed by an OpenH264 decoder.
    ///
    /// # Errors
    ///
    /// Returns [`DecoderError::InitFailed`] if the underlying OpenH264 decoder
    /// cannot be initialized.
    pub fn new() -> Result<Self, DecoderError> {
        let decoder = Decoder::new().map_err(|e| DecoderError::InitFailed(e.to_string()))?;
        Ok(Self { decoder })
    }

    /// Decodes a single encoded frame.
    ///
    /// Returns `Ok(Some(image))` when the frame (or an earlier frame in the
    /// stream) produced a decodable picture, and `Ok(None)` when the decoder
    /// needs more data before a picture is available (e.g. only SPS/PPS
    /// headers received so far).
    ///
    /// # Errors
    ///
    /// Returns [`DecoderError::UnsupportedCodec`] for non-H.264 frames,
    /// [`DecoderError::EmptyPayload`] for frames without a payload,
    /// [`DecoderError::DecodeFailed`] if the bitstream is corrupted, and
    /// [`DecoderError::InvalidDimensions`] if the decoder reports unusable
    /// dimensions.
    pub fn decode(&mut self, frame: &EncodedFrame) -> Result<Option<DecodedImage>, DecoderError> {
        if frame.codec != Codec::H264 {
            return Err(DecoderError::UnsupportedCodec(frame.codec));
        }
        if frame.payload.is_empty() {
            return Err(DecoderError::EmptyPayload);
        }

        let decoded = self
            .decoder
            .decode(&frame.payload)
            .map_err(|e| DecoderError::DecodeFailed(e.to_string()))?;

        let Some(yuv) = decoded else {
            return Ok(None);
        };

        let (width, height) = yuv.dimensions();
        if width == 0 || height == 0 {
            return Err(DecoderError::InvalidDimensions { width, height });
        }

        // Convert I420 YUV to tightly-packed RGB8 using OpenH264's built-in
        // converter. The converter requires I420 input, which is exactly what
        // `bw-encoder` produces.
        let mut rgb = vec![0u8; width * height * 3];
        yuv.write_rgb8(&mut rgb);

        Ok(Some(DecodedImage {
            width: width as u32,
            height: height as u32,
            rgb,
        }))
    }
}
