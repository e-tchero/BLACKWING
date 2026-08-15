//! Client-side audio playback.
//!
//! [`AudioPlayback`] receives Opus packets ([`AudioPlayback::feed`]), decodes
//! them with [`AudioDecoder`], and queues the PCM for the output device. The
//! `cpal` output callback (audio thread) drains the queue, so decoding never
//! runs on the real-time thread.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};
use cpal::{FromSample, Sample, SampleFormat, SizedSample};

use crate::codec::{AudioCodecConfig, AudioDecoder};
use crate::error::AudioError;

/// Decodes and plays Opus packets on the default output device.
pub struct AudioPlayback {
    /// Decoder for the current stream format (recreated if the format
    /// changes between packets).
    decoder: Mutex<AudioDecoder>,
    /// Decoded f32 samples waiting for the output callback.
    pending: Arc<Mutex<VecDeque<f32>>>,
    /// Held so the playback stream keeps running until this is dropped.
    _stream: cpal::Stream,
}

impl AudioPlayback {
    /// Opens the default output device for playback and starts the stream.
    ///
    /// # Errors
    ///
    /// Returns [`AudioError::NoOutputDevice`] when no output device exists,
    /// [`AudioError::UnsupportedSampleFormat`] when the device format is not
    /// supported, or a stream error when the device rejects the requested
    /// format.
    pub fn new(config: AudioCodecConfig) -> Result<Self, AudioError> {
        let host = cpal::default_host();
        let device = host
            .default_output_device()
            .ok_or(AudioError::NoOutputDevice)?;
        let supported = device
            .default_output_config()
            .map_err(|e| AudioError::StreamBuild(format!("no default output config: {e}")))?;

        let decoder = AudioDecoder::new(config.clone())?;
        let pending = Arc::new(Mutex::new(VecDeque::new()));

        let stream_config = cpal::StreamConfig {
            channels: config.channels,
            sample_rate: config.sample_rate,
            buffer_size: cpal::BufferSize::Default,
        };

        let stream = match supported.sample_format() {
            SampleFormat::F32 => build_playback::<f32>(&device, &stream_config, pending.clone())?,
            SampleFormat::I16 => build_playback::<i16>(&device, &stream_config, pending.clone())?,
            SampleFormat::U16 => build_playback::<u16>(&device, &stream_config, pending.clone())?,
            other => return Err(AudioError::UnsupportedSampleFormat(other)),
        };
        stream
            .play()
            .map_err(|e| AudioError::StreamPlay(e.to_string()))?;

        Ok(Self {
            decoder: Mutex::new(decoder),
            pending,
            _stream: stream,
        })
    }

    /// Decodes an Opus packet and queues it for playback.
    ///
    /// The `channels`/`sample_rate` come from the received protocol payload;
    /// if they differ from the current decoder's config the decoder is
    /// recreated for the new format.
    ///
    /// # Errors
    ///
    /// Returns [`AudioError::Decode`] when the packet is not valid Opus data.
    pub fn feed(
        &self,
        channels: u16,
        sample_rate: u32,
        opus_data: &[u8],
    ) -> Result<(), AudioError> {
        let config = AudioCodecConfig::new(sample_rate, channels)?;
        let mut decoder = self.decoder.lock().unwrap_or_else(|e| e.into_inner());
        if decoder.config() != &config {
            *decoder = AudioDecoder::new(config)?;
        }
        let pcm = decoder.decode_frame(opus_data)?;
        self.pending
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .extend(pcm);
        Ok(())
    }
}

/// Builds a typed playback stream whose callback drains decoded samples from
/// the shared queue, writing silence when none are buffered.
fn build_playback<T>(
    device: &cpal::Device,
    stream_config: &cpal::StreamConfig,
    pending: Arc<Mutex<VecDeque<f32>>>,
) -> Result<cpal::Stream, AudioError>
where
    T: SizedSample + Sample + FromSample<f32>,
{
    device
        .build_output_stream(
            *stream_config,
            move |data: &mut [T], _: &cpal::OutputCallbackInfo| {
                let mut queue = pending.lock().unwrap_or_else(|e| e.into_inner());
                for out in data.iter_mut() {
                    *out = queue
                        .pop_front()
                        .map(T::from_sample)
                        .unwrap_or(T::EQUILIBRIUM);
                }
            },
            |err| eprintln!("audio playback stream error: {err}"),
            None,
        )
        .map_err(|e| AudioError::StreamBuild(e.to_string()))
}
