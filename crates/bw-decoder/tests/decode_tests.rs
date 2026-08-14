#![allow(missing_docs)] // Integration-test crate (repo convention)
#![allow(clippy::unwrap_used, clippy::expect_used)] // Test code may panic on failure (repo convention)

use bw_decoder::{DecodedImage, DecoderError, DecoderPipeline};
use bw_encoder::{Codec, EncodedFrame, FrameType};
use openh264::encoder::Encoder;
use openh264::formats::YUVBuffer;

const WIDTH: u32 = 64;
const HEIGHT: u32 = 64;

fn make_frame(payload: Vec<u8>) -> EncodedFrame {
    EncodedFrame {
        session_id: 1,
        sequence: 0,
        timestamp_us: 0,
        frame_type: FrameType::IFrame,
        width: WIDTH,
        height: HEIGHT,
        codec: Codec::H264,
        payload,
    }
}

/// Encodes a synthetic solid-color frame with the OpenH264 encoder and returns
/// the raw H.264 bitstream.
fn encode_synthetic_frame() -> Vec<u8> {
    let mut encoder = Encoder::new().unwrap();
    let yuv = YUVBuffer::new(WIDTH as usize, HEIGHT as usize);
    let bitstream = encoder.encode(&yuv).unwrap();
    let mut payload = Vec::new();
    bitstream.write_vec(&mut payload);
    assert!(!payload.is_empty(), "encoder produced an empty bitstream");
    payload
}

#[test]
fn test_decoder_initializes() {
    let _pipeline = DecoderPipeline::new().unwrap();
}

#[test]
fn test_rejects_non_h264_codec() {
    let mut pipeline = DecoderPipeline::new().unwrap();
    let frame = EncodedFrame {
        codec: Codec::Unknown,
        ..make_frame(vec![0u8; 16])
    };
    let err = pipeline.decode(&frame).unwrap_err();
    assert!(matches!(
        err,
        DecoderError::UnsupportedCodec(Codec::Unknown)
    ));
}

#[test]
fn test_rejects_empty_payload() {
    let mut pipeline = DecoderPipeline::new().unwrap();
    let frame = make_frame(Vec::new());
    let err = pipeline.decode(&frame).unwrap_err();
    assert!(matches!(err, DecoderError::EmptyPayload));
}

#[test]
fn test_malformed_payload_returns_decode_error() {
    let mut pipeline = DecoderPipeline::new().unwrap();
    // Deterministic garbage: no Annex-B start codes, not a valid H.264 stream.
    // OpenH264 rejects the corrupted bitstream with a native decoding error,
    // which the pipeline surfaces as `DecoderError::DecodeFailed`.
    let frame = make_frame(vec![0xde; 256]);
    let err = pipeline.decode(&frame).unwrap_err();
    assert!(matches!(err, DecoderError::DecodeFailed(_)));
}

#[test]
fn test_round_trip_encode_decode() {
    let mut pipeline = DecoderPipeline::new().unwrap();
    let payload = encode_synthetic_frame();

    let frame = make_frame(payload);
    let image: DecodedImage = pipeline
        .decode(&frame)
        .unwrap()
        .expect("a valid encoded frame must produce a picture");

    assert_eq!(image.width, WIDTH);
    assert_eq!(image.height, HEIGHT);
    assert_eq!(image.rgb.len(), (WIDTH * HEIGHT * 3) as usize);
}
#[test]
fn test_truncated_stream_needs_more_data() {
    let mut pipeline = DecoderPipeline::new().unwrap();
    let payload = encode_synthetic_frame();
    // Truncate the stream to roughly a third — SPS/PPS may survive but no
    // complete picture can be recovered, so the decoder reports that more
    // data is required (`Ok(None)`), not an error.
    let truncated = payload[..payload.len() / 3].to_vec();
    let frame = make_frame(truncated);
    assert!(pipeline.decode(&frame).unwrap().is_none());
}
