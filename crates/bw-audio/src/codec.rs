//! The Opus codec layer.
//!
//! [`AudioEncoder`] and [`AudioDecoder`] wrap the pure-Rust `rusty_opus`
//! codec with a fixed [`AudioCodecConfig`] (sample rate, channels, 20 ms
//! frame size). Both sides derive the same frame size from the config, so a
//! packet produced by the encoder decodes correctly with a decoder built from
//! the same config — no frame size needs to travel on the wire.

use crate::error::AudioError;
use rusty_opus::{Application, OpusDecoder as RustyDecoder, OpusEncoder as RustyEncoder};

/// The largest possible Opus packet (RFC 6716 allows up to 1275 bytes per
/// frame; 4000 covers multi-frame packets with headroom).
const MAX_OPUS_PACKET: usize = 4000;

/// Describes the fixed format of a stream of Opus frames.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AudioCodecConfig {
    /// Sample rate in Hz (e.g. 48_000).
    pub sample_rate: u32,
    /// Number of interleaved channels (1 = mono, 2 = stereo).
    pub channels: u16,
    /// Samples per channel per frame (20 ms: `sample_rate / 50`).
    pub frame_size: usize,
}

impl AudioCodecConfig {
    /// Builds a config with a 20 ms frame size.
    ///
    /// # Errors
    ///
    /// Returns [`AudioError::InvalidParameters`] when the sample rate is not
    /// one of the Opus-supported rates (8, 12, 16, 24 or 48 kHz) or the
    /// channel count is outside the supported `1..=2` range.
    pub fn new(sample_rate: u32, channels: u16) -> Result<Self, AudioError> {
        if !matches!(sample_rate, 8_000 | 12_000 | 16_000 | 24_000 | 48_000) {
            return Err(AudioError::InvalidParameters(format!(
                "unsupported sample rate {sample_rate}; Opus supports 8, 12, 16, 24 or 48 kHz"
            )));
        }
        if !(1..=2).contains(&channels) {
            return Err(AudioError::InvalidParameters(
                "channel count must be 1 or 2".into(),
            ));
        }
        Ok(Self {
            sample_rate,
            channels,
            frame_size: (sample_rate / 50) as usize,
        })
    }
}

/// Encodes interleaved f32 PCM frames into Opus packets.
pub struct AudioEncoder {
    encoder: RustyEncoder,
    config: AudioCodecConfig,
    /// Total samples per frame (frame_size x channels).
    frame_len: usize,
}

impl AudioEncoder {
    /// Creates an encoder for the given format.
    ///
    /// # Errors
    ///
    /// Returns [`AudioError::Encode`] when the Opus encoder cannot be created
    /// for the requested sample rate / channels.
    pub fn new(config: AudioCodecConfig) -> Result<Self, AudioError> {
        let encoder = RustyEncoder::new(
            config.sample_rate as i32,
            config.channels as usize,
            Application::Voip,
        )
        .map_err(|e| AudioError::Encode(e.to_string()))?;
        let frame_len = config.frame_size * config.channels as usize;
        Ok(Self {
            encoder,
            config,
            frame_len,
        })
    }

    /// Returns the format this encoder was built for.
    pub fn config(&self) -> &AudioCodecConfig {
        &self.config
    }

    /// Encodes one PCM frame (exactly `frame_size * channels` interleaved f32
    /// samples) into a single Opus packet.
    ///
    /// # Errors
    ///
    /// Returns [`AudioError::InvalidParameters`] when `pcm` is not exactly one
    /// frame, or [`AudioError::Encode`] when the Opus encoder rejects the
    /// input.
    pub fn encode_frame(&mut self, pcm: &[f32]) -> Result<Vec<u8>, AudioError> {
        if pcm.len() != self.frame_len {
            return Err(AudioError::InvalidParameters(format!(
                "expected {} samples per frame, got {}",
                self.frame_len,
                pcm.len()
            )));
        }
        let mut out = vec![0u8; MAX_OPUS_PACKET];
        let written = self
            .encoder
            .encode(pcm, self.config.frame_size, &mut out)
            .map_err(|e| AudioError::Encode(e.to_string()))?;
        out.truncate(written);
        Ok(out)
    }
}

/// Decodes Opus packets back into interleaved f32 PCM frames.
pub struct AudioDecoder {
    decoder: RustyDecoder,
    config: AudioCodecConfig,
    /// Total samples per frame (frame_size x channels).
    frame_len: usize,
}

impl AudioDecoder {
    /// Creates a decoder for the given format.
    ///
    /// # Errors
    ///
    /// Returns [`AudioError::Decode`] when the Opus decoder cannot be created
    /// for the requested sample rate / channels.
    pub fn new(config: AudioCodecConfig) -> Result<Self, AudioError> {
        let decoder = RustyDecoder::new(config.sample_rate as i32, config.channels as usize)
            .map_err(|e| AudioError::Decode(e.to_string()))?;
        let frame_len = config.frame_size * config.channels as usize;
        Ok(Self {
            decoder,
            config,
            frame_len,
        })
    }

    /// Returns the format this decoder was built for.
    pub fn config(&self) -> &AudioCodecConfig {
        &self.config
    }

    /// Decodes one Opus packet into exactly `frame_size * channels`
    /// interleaved f32 samples.
    ///
    /// The underlying decoder reports the number of samples written **per
    /// channel**; the output buffer holds that many samples for each channel
    /// (interleaved). An empty packet is treated as a lost packet and decoded
    /// via packet-loss concealment (per Opus semantics), producing a full
    /// frame.
    ///
    /// # Errors
    ///
    /// Returns [`AudioError::Decode`] when the packet is malformed Opus data.
    pub fn decode_frame(&mut self, opus: &[u8]) -> Result<Vec<f32>, AudioError> {
        let mut out = vec![0.0f32; self.frame_len];
        let written = self
            .decoder
            .decode(opus, self.config.frame_size, &mut out)
            .map_err(|e| AudioError::Decode(e.to_string()))?;
        // `written` is per-channel; the interleaved buffer holds channels
        // copies of it (capped at the configured frame length).
        let interleaved = written
            .saturating_mul(self.config.channels as usize)
            .min(self.frame_len);
        out.truncate(interleaved);
        Ok(out)
    }
}
