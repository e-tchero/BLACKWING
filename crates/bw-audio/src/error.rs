//! Error types for audio capture, encoding, decoding and playback.

use thiserror::Error;

/// Errors that can occur in the audio pipeline.
#[derive(Debug, Error)]
pub enum AudioError {
    /// No audio output device is available on this system.
    #[error("no audio output device available")]
    NoOutputDevice,

    /// The audio device does not support the requested sample format.
    #[error("unsupported sample format: {0:?}")]
    UnsupportedSampleFormat(cpal::SampleFormat),

    /// Invalid codec parameters (sample rate, channel count or frame size).
    #[error("invalid audio parameters: {0}")]
    InvalidParameters(String),

    /// Opus encoding failed.
    #[error("opus encode failed: {0}")]
    Encode(String),

    /// Opus decoding failed.
    #[error("opus decode failed: {0}")]
    Decode(String),

    /// Building the audio stream failed.
    #[error("failed to build audio stream: {0}")]
    StreamBuild(String),

    /// Starting the audio stream failed.
    #[error("failed to start audio stream: {0}")]
    StreamPlay(String),
}
