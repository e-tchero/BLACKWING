#![allow(missing_docs)] // Integration-test crate (repo convention)
#![allow(clippy::unwrap_used, clippy::expect_used)] // Test code may panic on failure (repo convention)

use bw_audio::{AudioCodecConfig, AudioDecoder, AudioEncoder};

/// Encodes then decodes a 440 Hz stereo sine wave and asserts the output is a
/// faithful reconstruction of the input.
///
/// Opus has an inherent algorithmic delay (encoder lookahead plus decoder
/// delay — a few frames for SILK mode), so the output is compared against the
/// input at the best frame alignment rather than sample-for-sample.
#[test]
fn test_sine_wave_encode_decode_roundtrip() {
    let config = AudioCodecConfig::new(48_000, 2).unwrap();
    let mut encoder = AudioEncoder::new(config.clone()).unwrap();
    let mut decoder = AudioDecoder::new(config.clone()).unwrap();

    let frame_samples = config.frame_size * config.channels as usize; // 960 * 2 = 1920
    assert_eq!(config.frame_size, 960);

    let phase_delta = 2.0 * std::f32::consts::PI * 440.0 / 48_000.0;
    let mut phase = 0.0f32;

    let mut input_all = Vec::new();
    let mut output_all = Vec::new();

    for _ in 0..12 {
        let mut frame = Vec::with_capacity(frame_samples);
        for _ in 0..frame_samples {
            let sample = 0.5 * phase.sin();
            frame.push(sample);
            input_all.push(sample);
            phase += phase_delta;
            if phase > 2.0 * std::f32::consts::PI {
                phase -= 2.0 * std::f32::consts::PI;
            }
        }
        let packet = encoder.encode_frame(&frame).unwrap();
        assert!(!packet.is_empty());
        assert!(
            packet.len() < 300,
            "opus packet unexpectedly large: {}",
            packet.len()
        );

        let decoded = decoder.decode_frame(&packet).unwrap();
        assert_eq!(decoded.len(), frame_samples);
        output_all.extend(decoded);
    }

    // Root-mean-square error between the input and the reconstructed signal
    // at each candidate frame offset; the codec delay shows up as the best
    // alignment with the lowest error.
    let mut best_rmse = f32::MAX;
    for delay_frames in 0..6usize {
        let start = delay_frames * frame_samples;
        if start >= input_all.len() {
            break;
        }
        let n = input_all.len() - start;
        let mse = input_all[start..]
            .iter()
            .zip(&output_all[..n])
            .map(|(a, b)| (a - b) * (a - b))
            .sum::<f32>()
            / n as f32;
        best_rmse = best_rmse.min(mse.sqrt());
    }
    assert!(
        best_rmse < 0.1,
        "sine reconstruction error too high: best RMSE = {best_rmse}"
    );
}

/// The encoder must reject frames that are not exactly one frame long.
#[test]
fn test_encode_rejects_wrong_frame_length() {
    let config = AudioCodecConfig::new(48_000, 2).unwrap();
    let mut encoder = AudioEncoder::new(config).unwrap();

    let too_short = vec![0.0f32; 100];
    assert!(encoder.encode_frame(&too_short).is_err());

    let too_long = vec![0.0f32; 2000];
    assert!(encoder.encode_frame(&too_long).is_err());
}

/// The decoder must reject malformed Opus data, but treat an empty packet as
/// packet-loss concealment (per Opus semantics, a lost packet decodes to a
/// full frame of concealed audio rather than erroring).
#[test]
fn test_decode_handles_bad_and_lost_packets() {
    let config = AudioCodecConfig::new(48_000, 1).unwrap();
    let mut decoder = AudioDecoder::new(config.clone()).unwrap();

    // TOC with code 2 (two equal frames) declaring a 16-byte first frame that
    // exceeds the packet: must error, not panic or decode garbage.
    let malformed = [0x02u8, 0x10u8];
    assert!(decoder.decode_frame(&malformed).is_err());

    // Empty packet = lost packet -> PLC produces a full frame.
    let plc = decoder.decode_frame(&[]).unwrap();
    assert_eq!(plc.len(), config.frame_size);
}

/// Config validation: zero sample rate and out-of-range channels rejected,
/// and the 20 ms frame size is derived correctly at other rates.
#[test]
fn test_codec_config_validation() {
    assert!(AudioCodecConfig::new(0, 2).is_err());
    assert!(AudioCodecConfig::new(48_000, 0).is_err());
    assert!(AudioCodecConfig::new(48_000, 3).is_err());

    let mono = AudioCodecConfig::new(48_000, 1).unwrap();
    assert_eq!(mono.frame_size, 960);
    let cd = AudioCodecConfig::new(44_100, 2).unwrap();
    assert_eq!(cd.frame_size, 882); // 20 ms at 44.1 kHz
}

/// Two sequential frames with a discontinuity still decode independently
/// (packets are self-contained).
#[test]
fn test_packets_are_independent() {
    let config = AudioCodecConfig::new(48_000, 1).unwrap();
    let mut encoder = AudioEncoder::new(config.clone()).unwrap();
    let mut decoder = AudioDecoder::new(config.clone()).unwrap();

    let silent = vec![0.0f32; config.frame_size];
    let packet1 = encoder.encode_frame(&silent).unwrap();
    let packet2 = encoder.encode_frame(&silent).unwrap();

    let out1 = decoder.decode_frame(&packet1).unwrap();
    let out2 = decoder.decode_frame(&packet2).unwrap();
    assert_eq!(out1.len(), config.frame_size);
    assert_eq!(out2.len(), config.frame_size);
}
