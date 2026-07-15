//! Encoding and decoding logic.
//!
//! Provides zero-copy parsing of binary frames and exact-allocation serialization.

use crate::error::ProtocolError;
use crate::frame::ProtocolFrame;
use crate::header::PacketHeader;

/// Encodes a protocol frame into a raw byte vector.
///
/// Serializes the packet header and appends the payload. This function
/// allocates exactly once for the resulting buffer.
///
/// # Arguments
///
/// * `frame` - The protocol frame to encode.
///
/// # Returns
///
/// A vector containing the serialized frame.
pub fn encode_frame(frame: &ProtocolFrame<'_>) -> Vec<u8> {
    let header_size = std::mem::size_of::<PacketHeader>();
    let mut buffer = Vec::with_capacity(header_size + frame.payload.len());
    buffer.extend_from_slice(frame.header.as_bytes());
    buffer.extend_from_slice(frame.payload);
    buffer
}

/// Decodes a raw byte slice into a structured protocol frame.
///
/// Performs validation on the header boundaries, magic bytes, version compatibility,
/// and payload lengths before returning a zero-copy frame representation.
///
/// # Arguments
///
/// * `bytes` - The raw byte slice to decode from.
///
/// # Returns
///
/// Returns `Ok(ProtocolFrame)` if decoding and validation succeed, or a `ProtocolError` if a check fails.
pub fn decode_frame(bytes: &[u8]) -> Result<ProtocolFrame<'_>, ProtocolError> {
    let header_size = std::mem::size_of::<PacketHeader>();
    if bytes.len() < header_size {
        return Err(ProtocolError::BufferTooSmall);
    }

    let header = PacketHeader::try_from_bytes(bytes)?;
    let expected_len = header_size + header.payload_length as usize;

    if bytes.len() < expected_len {
        return Err(ProtocolError::BufferTooSmall);
    }

    if bytes.len() > expected_len {
        return Err(ProtocolError::InvalidPayloadLength);
    }

    let payload = &bytes[header_size..expected_len];
    Ok(ProtocolFrame {
        header: *header,
        payload,
    })
}
