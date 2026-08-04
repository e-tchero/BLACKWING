use crate::EncodedFrame;
use bw_capture::Frame;
use thiserror::Error;

/// Configuration for the video encoder.
#[derive(Debug, Clone)]
pub struct EncoderConfig {
    /// Target bitrate in bits per second.
    pub target_bitrate: u32,
    /// Target framerate.
    pub framerate: u32,
    /// Number of frames between forced IDR keyframes.
    pub keyframe_interval: u32,
}

impl Default for EncoderConfig {
    fn default() -> Self {
        Self {
            target_bitrate: 5_000_000, // 5 Mbps
            framerate: 60,
            keyframe_interval: 120, // Keyframe every 2 seconds at 60fps
        }
    }
}

/// Errors that can occur during encoding.
#[derive(Error, Debug)]
pub enum EncoderError {
    /// Initialization failed.
    #[error("Initialization failed: {0}")]
    InitFailed(String),
    /// Frame encoding failed.
    #[error("Encoding failed: {0}")]
    EncodeFailed(String),
    /// The encoder is stopped.
    #[error("Encoder stopped")]
    Stopped,
}

/// A backend trait for video encoding (e.g., OpenH264, NVENC).
pub trait EncoderBackend: Send {
    /// Starts the encoder backend for a given width and height, and configuration.
    fn start(&mut self, width: u32, height: u32, config: EncoderConfig)
    -> Result<(), EncoderError>;

    /// Encodes a raw captured frame and returns an encoded frame.
    fn encode_frame(&mut self, frame: &Frame, sequence: u64) -> Result<EncodedFrame, EncoderError>;

    /// Stops the encoder.
    fn stop(&mut self);
}
