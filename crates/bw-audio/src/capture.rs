//! Server-side audio capture.
//!
//! [`AudioCapture`] captures PCM from the default output device via `cpal`.
//! On Windows this opens a WASAPI input stream on the render endpoint, which
//! captures **loopback** audio (everything the host is playing). Samples are
//! accumulated into 20 ms frames, encoded with [`AudioEncoder`], and pushed
//! as Opus packets onto a channel.

use std::sync::{Arc, Mutex, mpsc};

use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};
use cpal::{FromSample, Sample, SampleFormat, SizedSample};

use crate::codec::{AudioCodecConfig, AudioEncoder};
use crate::error::AudioError;

/// Internal state shared between the capture callback (audio thread) and the
/// capture handle.
struct CaptureState {
    encoder: AudioEncoder,
    /// Interleaved f32 samples not yet formed into a complete frame.
    pending: Vec<f32>,
    /// Total samples per frame (frame_size x channels).
    frame_len: usize,
    /// Opus packets are pushed here as frames complete.
    packets: mpsc::Sender<Vec<u8>>,
}

/// Captures the host's output audio and emits Opus-encoded frames.
pub struct AudioCapture {
    /// The format the capture is running at.
    config: AudioCodecConfig,
    /// Held so the capture stream keeps running until this is dropped.
    _stream: cpal::Stream,
}

impl AudioCapture {
    /// Opens a loopback capture on the default output device and starts it.
    ///
    /// Returns the capture handle and a channel of Opus packets (one per
    /// 20 ms frame).
    ///
    /// # Errors
    ///
    /// Returns [`AudioError::NoOutputDevice`] when no output device exists,
    /// [`AudioError::UnsupportedSampleFormat`] when the device format is not
    /// supported, or a stream error when capture cannot be opened (e.g. the
    /// platform/backend does not support loopback).
    pub fn new() -> Result<(Self, mpsc::Receiver<Vec<u8>>), AudioError> {
        let host = cpal::default_host();
        let device = host
            .default_output_device()
            .ok_or(AudioError::NoOutputDevice)?;
        let supported = device
            .default_output_config()
            .map_err(|e| AudioError::StreamBuild(format!("no default output config: {e}")))?;

        let channels = supported.channels().min(2) as u16;
        let sample_rate = supported.sample_rate();
        let config = AudioCodecConfig::new(sample_rate, channels)?;
        let encoder = AudioEncoder::new(config.clone())?;
        let frame_len = config.frame_size * config.channels as usize;

        let (tx, rx) = mpsc::channel();
        let state = Arc::new(Mutex::new(CaptureState {
            encoder,
            pending: Vec::with_capacity(frame_len),
            frame_len,
            packets: tx,
        }));

        let stream_config = cpal::StreamConfig {
            channels,
            sample_rate,
            buffer_size: cpal::BufferSize::Default,
        };

        let stream = match supported.sample_format() {
            SampleFormat::F32 => build_capture::<f32>(&device, &stream_config, state)?,
            SampleFormat::I16 => build_capture::<i16>(&device, &stream_config, state)?,
            SampleFormat::U16 => build_capture::<u16>(&device, &stream_config, state)?,
            other => return Err(AudioError::UnsupportedSampleFormat(other)),
        };
        stream
            .play()
            .map_err(|e| AudioError::StreamPlay(e.to_string()))?;

        Ok((
            Self {
                config,
                _stream: stream,
            },
            rx,
        ))
    }

    /// Returns the format this capture is running at.
    pub fn config(&self) -> &AudioCodecConfig {
        &self.config
    }
}

/// Builds a typed capture stream whose callback converts samples to f32,
/// frames them, and encodes them into Opus packets.
fn build_capture<T>(
    device: &cpal::Device,
    stream_config: &cpal::StreamConfig,
    state: Arc<Mutex<CaptureState>>,
) -> Result<cpal::Stream, AudioError>
where
    T: SizedSample + Sample,
    f32: FromSample<T>,
{
    device
        .build_input_stream(
            *stream_config,
            move |data: &[T], _: &cpal::InputCallbackInfo| {
                let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
                for sample in data {
                    s.pending.push(sample.to_sample());
                }
                while s.pending.len() >= s.frame_len {
                    let frame_len = s.frame_len;
                    let frame: Vec<f32> = s.pending.drain(..frame_len).collect();
                    if let Ok(packet) = s.encoder.encode_frame(&frame) {
                        let _ = s.packets.send(packet);
                    }
                }
            },
            |err| eprintln!("audio capture stream error: {err}"),
            None,
        )
        .map_err(|e| AudioError::StreamBuild(e.to_string()))
}
