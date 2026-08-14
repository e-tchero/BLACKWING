//! The video decoder crate for BLACKWING.
//!
//! The client-side reverse of `bw-encoder`: receives H.264
//! [`bw_encoder::EncodedFrame`]s and decodes them into raw RGB pixel data via
//! OpenH264.
//!
//! # Architecture
//!
//! [`DecoderPipeline`] wraps an `openh264::Decoder`. Each call to
//! [`DecoderPipeline::decode`] feeds one encoded frame to OpenH264 and returns
//! the decoded image — converted to RGB8 with OpenH264's built-in converter —
//! when a picture is available, or `None` when the decoder needs more data
//! (e.g. only SPS/PPS headers received so far).

/// Error types for the decoder pipeline.
pub mod error;
/// Decoded frame types.
pub mod image;
/// The OpenH264-backed decoder pipeline.
pub mod pipeline;

pub use error::DecoderError;
pub use image::DecodedImage;
pub use pipeline::DecoderPipeline;
