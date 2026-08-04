#![allow(clippy::new_without_default)]

use crate::backend::{EncoderBackend, EncoderConfig, EncoderError};
use crate::{EncodedFrame, FrameType};
use bw_capture::Frame;
use openh264::encoder::Encoder;
use openh264::formats::YUVSource;

/// An encoder backend that uses Cisco's OpenH264 library.
pub struct OpenH264Backend {
    encoder: Option<Encoder>,
    width: u32,
    height: u32,
    config: EncoderConfig,
    frames_since_idr: u32,
}

impl OpenH264Backend {
    /// Creates a new OpenH264 backend.
    pub fn new() -> Self {
        Self {
            encoder: None,
            width: 0,
            height: 0,
            config: EncoderConfig::default(),
            frames_since_idr: 0,
        }
    }
}

impl EncoderBackend for OpenH264Backend {
    fn start(
        &mut self,
        width: u32,
        height: u32,
        config: EncoderConfig,
    ) -> Result<(), EncoderError> {
        let encoder = Encoder::new().map_err(|e| EncoderError::InitFailed(e.to_string()))?;

        // OpenH264 crate exposes limited config options without the raw API,
        // but it automatically configures basics. We could set bitrate via raw API if exposed.

        self.encoder = Some(encoder);
        self.width = width;
        self.height = height;
        self.config = config;
        self.frames_since_idr = 0;

        Ok(())
    }

    fn encode_frame(&mut self, frame: &Frame, sequence: u64) -> Result<EncodedFrame, EncoderError> {
        if self.encoder.is_none() || frame.width != self.width || frame.height != self.height {
            // Resolution changed or not started, re-initialize
            self.start(frame.width, frame.height, self.config.clone())?;
        }

        let encoder = self.encoder.as_mut().ok_or(EncoderError::Stopped)?;

        // Convert BGRA to YUV420p
        let yuv = bgra_to_yuv420p(&frame.buffer, frame.width, frame.height);

        // OpenH264 requires YUVSource implementation
        let yuv_source = BasicYuvSource {
            width: self.width as usize,
            height: self.height as usize,
            y: &yuv[0..(self.width * self.height) as usize],
            u: &yuv[(self.width * self.height) as usize
                ..(self.width * self.height + self.width * self.height / 4) as usize],
            v: &yuv[(self.width * self.height + self.width * self.height / 4) as usize..],
        };

        let encoded_bitstream = encoder
            .encode(&yuv_source)
            .map_err(|e| EncoderError::EncodeFailed(e.to_string()))?;

        // Extract NAL units
        let mut payload = Vec::new();
        encoded_bitstream.write_vec(&mut payload);

        let mut is_idr = false;
        // Simple NAL parsing to detect IDR (type 5)
        for i in 0..payload.len().saturating_sub(4) {
            if payload[i] == 0 && payload[i + 1] == 0 && payload[i + 2] == 0 && payload[i + 3] == 1
            {
                let nal_type = payload[i + 4] & 0x1F;
                if nal_type == 5 {
                    is_idr = true;
                    break;
                }
            } else if payload[i] == 0 && payload[i + 1] == 0 && payload[i + 2] == 1 {
                let nal_type = payload[i + 3] & 0x1F;
                if nal_type == 5 {
                    is_idr = true;
                    break;
                }
            }
        }

        if is_idr {
            self.frames_since_idr = 0;
        } else {
            self.frames_since_idr += 1;
            // Ideally force IDR via API here if frames_since_idr >= config.keyframe_interval
        }

        let frame_type = if is_idr {
            FrameType::IFrame
        } else {
            FrameType::PFrame
        };

        Ok(EncodedFrame {
            session_id: 0, // In real usage, this should come from a higher layer session context
            sequence,
            timestamp_us: frame.timestamp_us,
            frame_type,
            width: self.width,
            height: self.height,
            codec: crate::Codec::H264,
            payload,
        })
    }

    fn stop(&mut self) {
        self.encoder = None;
    }
}

/// Very simple BGRA to YUV420p conversion.
/// In production, this should be done on the GPU or using SIMD.
fn bgra_to_yuv420p(bgra: &[u8], width: u32, height: u32) -> Vec<u8> {
    let mut yuv = vec![0u8; (width * height + width * height / 2) as usize];
    let y_plane_size = (width * height) as usize;
    let u_plane_offset = y_plane_size;
    let v_plane_offset = y_plane_size + (width * height / 4) as usize;

    for y in 0..height {
        for x in 0..width {
            let i = ((y * width + x) * 4) as usize;
            let b = bgra[i] as f32;
            let g = bgra[i + 1] as f32;
            let r = bgra[i + 2] as f32;

            // BT.601 conversion
            let y_val = (0.299 * r + 0.587 * g + 0.114 * b) as u8;
            yuv[(y * width + x) as usize] = y_val;

            if y % 2 == 0 && x % 2 == 0 {
                let u_val = (-0.168736 * r - 0.331264 * g + 0.5 * b + 128.0) as u8;
                let v_val = (0.5 * r - 0.418688 * g - 0.081312 * b + 128.0) as u8;

                let uv_index = (y / 2 * width / 2 + x / 2) as usize;
                yuv[u_plane_offset + uv_index] = u_val;
                yuv[v_plane_offset + uv_index] = v_val;
            }
        }
    }
    yuv
}

struct BasicYuvSource<'a> {
    width: usize,
    height: usize,
    y: &'a [u8],
    u: &'a [u8],
    v: &'a [u8],
}

impl<'a> YUVSource for BasicYuvSource<'a> {
    fn dimensions(&self) -> (usize, usize) {
        (self.width, self.height)
    }
    fn strides(&self) -> (usize, usize, usize) {
        (self.width, self.width / 2, self.width / 2)
    }
    fn y(&self) -> &[u8] {
        self.y
    }
    fn u(&self) -> &[u8] {
        self.u
    }
    fn v(&self) -> &[u8] {
        self.v
    }
}
