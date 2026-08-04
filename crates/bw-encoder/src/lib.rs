//! The video encoder crate for BLACKWING.
//! This crate abstracts the video encoding pipeline for H.264 streaming.

/// Defines the encoder backend traits and errors.
pub mod backend;
/// Provides the OpenH264 encoding implementation.
pub mod h264;
/// Manages the asynchronous encoding pipeline.
pub mod pipeline;

pub use backend::{EncoderBackend, EncoderError};
pub use pipeline::EncoderPipeline;

/// Represents the type of an encoded video frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameType {
    /// An Intra-coded frame (keyframe).
    IFrame,
    /// A Predictive-coded frame (delta frame).
    PFrame,
    /// Unknown frame type.
    Unknown,
}

/// Supported video codecs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Codec {
    /// H.264 / AVC
    H264,
    /// Unknown or unsupported codec
    Unknown,
}

/// A fully encoded video frame ready for network transport.
#[derive(Debug, Clone)]
pub struct EncodedFrame {
    /// The logical session this frame belongs to.
    pub session_id: u64,
    /// The frame sequence number.
    pub sequence: u64,
    /// The capture timestamp in microseconds.
    pub timestamp_us: u64,
    /// The frame type.
    pub frame_type: FrameType,
    /// The width of the encoded frame.
    pub width: u32,
    /// The height of the encoded frame.
    pub height: u32,
    /// The codec used for this frame.
    pub codec: Codec,
    /// The encoded NAL unit payload.
    pub payload: Vec<u8>,
}

impl EncodedFrame {
    /// Serializes the frame into a binary format suitable for network transmission.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(42 + self.payload.len());
        buf.extend_from_slice(&self.session_id.to_be_bytes());
        buf.extend_from_slice(&self.sequence.to_be_bytes());
        buf.extend_from_slice(&self.timestamp_us.to_be_bytes());
        
        let ft = match self.frame_type {
            FrameType::IFrame => 1u8,
            FrameType::PFrame => 2u8,
            FrameType::Unknown => 0u8,
        };
        buf.push(ft);
        
        buf.extend_from_slice(&self.width.to_be_bytes());
        buf.extend_from_slice(&self.height.to_be_bytes());
        
        let cd = match self.codec {
            Codec::H264 => 1u8,
            Codec::Unknown => 0u8,
        };
        buf.push(cd);
        
        buf.extend_from_slice(&(self.payload.len() as u32).to_be_bytes());
        buf.extend_from_slice(&self.payload);
        
        buf
    }

    /// Deserializes a frame from binary network data.
    pub fn from_bytes(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() < 42 {
            return Err("Payload too short to contain header");
        }
        
        let session_id = u64::from_be_bytes(data[0..8].try_into().unwrap());
        let sequence = u64::from_be_bytes(data[8..16].try_into().unwrap());
        let timestamp_us = u64::from_be_bytes(data[16..24].try_into().unwrap());
        
        let frame_type = match data[24] {
            1 => FrameType::IFrame,
            2 => FrameType::PFrame,
            _ => FrameType::Unknown,
        };
        
        let width = u32::from_be_bytes(data[25..29].try_into().unwrap());
        let height = u32::from_be_bytes(data[29..33].try_into().unwrap());
        
        let codec = match data[33] {
            1 => Codec::H264,
            _ => Codec::Unknown,
        };
        
        if codec == Codec::Unknown {
            return Err("Unknown codec rejected");
        }
        
        let payload_len = u32::from_be_bytes(data[34..38].try_into().unwrap()) as usize;
        
        if data.len() < 38 + payload_len {
            return Err("Truncated payload");
        }
        if data.len() > 38 + payload_len {
            return Err("Trailing garbage in payload");
        }
        
        // Very basic malformed check: NAL units usually start with 00 00 00 01
        if payload_len > 4 {
            let p = &data[38..];
            if !(p[0] == 0 && p[1] == 0 && ((p[2] == 0 && p[3] == 1) || p[2] == 1)) {
                return Err("Malformed H.264 NAL unit");
            }
        }
        
        Ok(Self {
            session_id,
            sequence,
            timestamp_us,
            frame_type,
            width,
            height,
            codec,
            payload: data[38..38 + payload_len].to_vec(),
        })
    }
}
