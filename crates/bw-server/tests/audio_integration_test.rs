#![allow(missing_docs)] // Integration-test crate (repo convention)
#![allow(clippy::unwrap_used, clippy::expect_used)] // Test code may panic on failure (repo convention)

use bw_audio::{AudioCodecConfig, AudioDecoder, AudioEncoder};
use bw_protocol::message::{AudioPayload, MessageType};
use bw_server::audio_packet_message;

/// Exercises the server's exact audio-forwarding path (TASK-114): encode a
/// PCM frame with the Opus encoder, wrap the packet via
/// [`audio_packet_message`] into an outbound `AudioData` protocol message,
/// then recover the packet and decode it back.
#[test]
fn test_audio_packet_message_roundtrip() {
    let config = AudioCodecConfig::new(48_000, 2).unwrap();
    let mut encoder = AudioEncoder::new(config.clone()).unwrap();
    let mut decoder = AudioDecoder::new(config.clone()).unwrap();

    // One frame of silence (stereo).
    let frame = vec![0.0f32; config.frame_size * 2];
    let packet = encoder.encode_frame(&frame).unwrap();

    // The production wrapping path.
    let message =
        audio_packet_message(config.channels, config.sample_rate, packet.clone()).unwrap();

    assert_eq!(message.message_type, MessageType::AudioData);
    assert!(message.validate().is_ok());

    let payload = message.as_audio_data().expect("audio payload decodable");
    assert_eq!(payload.channels, 2);
    assert_eq!(payload.sample_rate, 48_000);
    assert_eq!(payload.opus_data, packet);

    // The recovered packet must decode back to a full frame.
    let decoded = decoder.decode_frame(&payload.opus_data).unwrap();
    assert_eq!(decoded.len(), config.frame_size * 2);
}

/// The audio payload survives a full wire round-trip (serialize → deserialize),
/// preserving format metadata and the encoded bytes.
#[test]
fn test_audio_message_wire_roundtrip() {
    let config = AudioCodecConfig::new(16_000, 1).unwrap();
    let mut encoder = AudioEncoder::new(config.clone()).unwrap();

    let frame = vec![0.1f32; config.frame_size];
    let packet = encoder.encode_frame(&frame).unwrap();
    let message = audio_packet_message(config.channels, config.sample_rate, packet).unwrap();

    let bytes = message.serialize().unwrap();
    let decoded_msg = bw_protocol::message::ProtocolMessage::deserialize(&bytes).unwrap();
    assert_eq!(decoded_msg.message_type, MessageType::AudioData);

    let payload: AudioPayload = decoded_msg
        .as_audio_data()
        .expect("audio payload decodable");
    assert_eq!(payload.channels, 1);
    assert_eq!(payload.sample_rate, 16_000);
    assert!(!payload.opus_data.is_empty());
}
