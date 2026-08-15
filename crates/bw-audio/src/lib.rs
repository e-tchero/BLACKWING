//! Audio streaming for BLACKWING.
//!
//! Provides the low-latency audio pipeline: the host captures PCM from the
//! OS audio stack, encodes it into Opus packets ([`AudioEncoder`]), and the
//! client decodes ([`AudioDecoder`]) and plays them back.
//!
//! * [`AudioCapture`] — server side: captures the default output device via
//!   `cpal` (WASAPI loopback on Windows) and emits Opus packets on a channel.
//! * [`AudioPlayback`] — client side: receives Opus packets and writes PCM to
//!   the default output device.
//!
//! The codec is implemented with the pure-Rust `rusty_opus` crate, so no
//! system C library (libopus) or build toolchain (cmake/pkg-config) is needed.

pub mod capture;
pub mod codec;
pub mod error;
pub mod playback;

pub use capture::AudioCapture;
pub use codec::{AudioCodecConfig, AudioDecoder, AudioEncoder};
pub use error::AudioError;
pub use playback::AudioPlayback;
