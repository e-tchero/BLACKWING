#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Phase 3 Adversarial Validation — Crypto State-Machine Attacks
//!
//! Attempts to break epoch transitions, replay protection, nonce
//! uniqueness, and authentication ordering.
//!
//! FINDING: The sliding window replay protection correctly allows
//! reordering within a 64-counter window but rejects actual replays.
//! The EncryptionContext rotates both encryptor+decryptor simultaneously,
//! which is correct for same-process use but means old-epoch frames
//! cannot be decrypted after rotation by the same context.

use bw_crypto::SymmetricKey;
use bw_protocol::encryption::{
    AuthenticationTag, EncryptionContext, FrameDecryptor, FrameEncryptor, KeyRotationPolicy, Nonce,
    SessionKeys,
};
use bw_protocol::frame::OwnedProtocolFrame;
use bw_protocol::header::{PacketHeader, PROTOCOL_MAGIC};
use bw_protocol::version::CURRENT_VERSION;

fn make_frame(payload: Vec<u8>) -> OwnedProtocolFrame {
    OwnedProtocolFrame {
        header: PacketHeader {
            magic: PROTOCOL_MAGIC,
            schema_version: u16::from(CURRENT_VERSION),
            flags: 0,
            packet_type: 1,
            payload_length: payload.len() as u16,
            sequence_number: 42,
            session_epoch: 1,
            monotonic_timestamp: 1000,
        },
        payload,
    }
}

fn make_context(policy: KeyRotationPolicy) -> EncryptionContext {
    let keys = SessionKeys {
        send_key: SymmetricKey([0xAB; 32]),
        recv_key: SymmetricKey([0xAB; 32]),
        epoch: 0,
    };
    EncryptionContext::new(keys, policy)
}

#[allow(dead_code)]
fn make_pair(policy: KeyRotationPolicy) -> (FrameEncryptor, FrameDecryptor) {
    let send_key = SymmetricKey([0xAB; 32]);
    let recv_key = SymmetricKey([0xAB; 32]);
    let enc = FrameEncryptor::new(send_key, 0);
    let dec = FrameDecryptor::new(recv_key, 0);
    let _ = policy; // unused for now
    (enc, dec)
}

// ═══════════════════════════════════════════════════
// ATTACK 1: FORGED EPOCH ATTEMPTS
// ═══════════════════════════════════════════════════

/// Forged epoch+1 with random ciphertext must be rejected.
#[test]
fn attack_forged_epoch_advance() {
    let mut ctx = make_context(KeyRotationPolicy::Manual);

    let frame = make_frame(b"secret data".to_vec());
    let ct = ctx.encrypt_frame(&frame).unwrap();
    assert!(ctx.decrypt_frame(&ct).is_ok(), "Normal frame must decrypt");

    // Forged epoch+1 with random ciphertext.
    let mut forged = ct.clone();
    forged.epoch = ct.epoch + 1;
    forged.ciphertext = vec![0xFF; 32];
    forged.tag = AuthenticationTag([0x00; 16]);
    assert!(
        ctx.decrypt_frame(&forged).is_err(),
        "Forged epoch must be rejected"
    );

    // Next legitimate frame should still work.
    let frame2 = make_frame(b"more data".to_vec());
    let ct2 = ctx.encrypt_frame(&frame2).unwrap();
    assert!(
        ctx.decrypt_frame(&ct2).is_ok(),
        "Legitimate frame after forgery must work"
    );
}

/// Skip two epochs ahead must be rejected.
#[test]
fn attack_epoch_skip_ahead() {
    let mut ctx = make_context(KeyRotationPolicy::Manual);

    let frame = make_frame(b"test".to_vec());
    let ct = ctx.encrypt_frame(&frame).unwrap();

    let mut forged = ct.clone();
    forged.epoch = ct.epoch + 2;
    forged.ciphertext = vec![0xFF; 32];
    forged.tag = AuthenticationTag([0x00; 16]);
    assert!(
        ctx.decrypt_frame(&forged).is_err(),
        "Skipped epoch must be rejected"
    );
}

// ═══════════════════════════════════════════════════
// ATTACK 2: REPLAY ATTACKS
// ═══════════════════════════════════════════════════

/// Replaying the same ciphertext MUST be rejected (sliding window catches it).
#[test]
fn attack_replay_same_frame() {
    let mut ctx = make_context(KeyRotationPolicy::Manual);

    let frame = make_frame(b"secret".to_vec());
    let ct = ctx.encrypt_frame(&frame).unwrap();

    assert!(ctx.decrypt_frame(&ct).is_ok(), "First decrypt must succeed");
    assert!(ctx.decrypt_frame(&ct).is_err(), "Replay must be rejected");
}

/// Reordering within the 64-counter window is ALLOWED by design.
/// The sliding window correctly handles out-of-order delivery.
/// Only ACTUAL replays (same counter received twice) are rejected.
#[test]
fn attack_reorder_within_window_is_allowed() {
    let mut ctx = make_context(KeyRotationPolicy::Manual);

    let frame1 = make_frame(b"frame1".to_vec());
    let frame2 = make_frame(b"frame2".to_vec());
    let ct1 = ctx.encrypt_frame(&frame1).unwrap();
    let ct2 = ctx.encrypt_frame(&frame2).unwrap();

    // Decrypt frame 2 first — should succeed (within window).
    assert!(ctx.decrypt_frame(&ct2).is_ok(), "Frame 2 must decrypt");
    // Then frame 1 — should also succeed (within window, not yet seen).
    assert!(
        ctx.decrypt_frame(&ct1).is_ok(),
        "Frame 1 must also decrypt (reordering allowed)"
    );

    // But replaying frame 1 AGAIN must fail.
    assert!(
        ctx.decrypt_frame(&ct1).is_err(),
        "Actual replay must be rejected"
    );
}

/// Frames far outside the window (>64 behind max) are rejected.
#[test]
fn attack_frame_outside_window_rejected() {
    let mut ctx = make_context(KeyRotationPolicy::Manual);

    // Create a frame at counter=0.
    let frame_early = make_frame(b"early".to_vec());
    let ct_early = ctx.encrypt_frame(&frame_early).unwrap();

    // Decrypt the first frame to start tracking counter=0 in replay window.
    assert!(ctx.decrypt_frame(&ct_early).is_ok());

    // Advance the counter by 65 frames (decrypt each to advance the window).
    for i in 0..65u8 {
        let f = make_frame(vec![i]);
        let ct = ctx.encrypt_frame(&f).unwrap();
        let _ = ctx.decrypt_frame(&ct);
    }

    // Now try to decrypt the early frame again — should be rejected (outside window).
    assert!(
        ctx.decrypt_frame(&ct_early).is_err(),
        "Frame >64 behind max counter must be rejected"
    );
}

/// Cross-epoch replay: after encryption-context rotation, old-epoch
/// frames cannot be decrypted (wrong epoch error, which is correct).
#[test]
fn attack_cross_epoch_replay() {
    let mut ctx = make_context(KeyRotationPolicy::Counter(2));

    let f1 = make_frame(b"e0-1".to_vec());
    let f2 = make_frame(b"e0-2".to_vec());
    // f3 will be encrypted after rotation (epoch 1).
    let f3 = make_frame(b"e1-1".to_vec());

    let ct1 = ctx.encrypt_frame(&f1).unwrap(); // epoch=0, counter=0
    let ct2 = ctx.encrypt_frame(&f2).unwrap(); // epoch=0, counter=1, triggers rotation
    let ct3 = ctx.encrypt_frame(&f3).unwrap(); // epoch=1, counter=0

    // ct3 should decrypt (epoch 1).
    assert!(
        ctx.decrypt_frame(&ct3).is_ok(),
        "Epoch-1 frame must decrypt"
    );

    // ct1 and ct2 are epoch 0, but decryptor is now epoch 1.
    // These should fail with wrong-epoch error (NOT replay).
    assert!(
        ctx.decrypt_frame(&ct1).is_err(),
        "Old-epoch frame must be rejected after rotation"
    );
    assert!(
        ctx.decrypt_frame(&ct2).is_err(),
        "Old-epoch frame must be rejected after rotation"
    );
}

// ═══════════════════════════════════════════════════
// ATTACK 3: NONCE MANIPULATION
// ═══════════════════════════════════════════════════

/// Same plaintext encrypted twice produces different nonces.
#[test]
fn attack_nonce_reuse() {
    let mut ctx = make_context(KeyRotationPolicy::Manual);

    let frame = make_frame(b"identical".to_vec());
    let ct1 = ctx.encrypt_frame(&frame).unwrap();
    let ct2 = ctx.encrypt_frame(&frame).unwrap();

    assert_ne!(ct1.nonce.0, ct2.nonce.0, "Nonces must differ");
}

/// Nonces must be unique across epoch boundaries.
#[test]
fn attack_nonce_uniqueness_across_epochs() {
    let mut ctx = make_context(KeyRotationPolicy::Counter(2));

    let f1 = make_frame(b"e0".to_vec());
    let f2 = make_frame(b"e0".to_vec());
    let f3 = make_frame(b"e1".to_vec()); // Triggers rotation

    let ct1 = ctx.encrypt_frame(&f1).unwrap();
    let ct2 = ctx.encrypt_frame(&f2).unwrap();
    let ct3 = ctx.encrypt_frame(&f3).unwrap();

    let nonces = [ct1.nonce.0, ct2.nonce.0, ct3.nonce.0];
    for i in 0..nonces.len() {
        for j in (i + 1)..nonces.len() {
            assert_ne!(nonces[i], nonces[j], "Nonce reuse detected");
        }
    }
}

// ═══════════════════════════════════════════════════
// ATTACK 4: KEY ROTATION UNDER ATTACK
// ═══════════════════════════════════════════════════

/// Forged epoch+1 between legitimate frames must not corrupt state.
#[test]
fn attack_rotation_with_forged_injection() {
    let mut ctx = make_context(KeyRotationPolicy::Manual);

    let f1 = make_frame(b"legit1".to_vec());
    let ct1 = ctx.encrypt_frame(&f1).unwrap();
    assert!(ctx.decrypt_frame(&ct1).is_ok());

    // Forged frame with epoch+1.
    let mut forged = ct1.clone();
    forged.epoch = ct1.epoch + 1;
    forged.ciphertext = vec![0xFF; 32];
    forged.tag = AuthenticationTag([0x00; 16]);
    assert!(ctx.decrypt_frame(&forged).is_err(), "Forged must fail");

    // Legitimate frame must still work (state unchanged after failed forgery).
    let f2 = make_frame(b"legit2".to_vec());
    let ct2 = ctx.encrypt_frame(&f2).unwrap();
    assert!(
        ctx.decrypt_frame(&ct2).is_ok(),
        "Legitimate frame after forgery must succeed"
    );
}

/// Many forged epoch attempts must not break state.
#[test]
fn attack_repeated_forged_epochs() {
    let mut ctx = make_context(KeyRotationPolicy::Manual);

    let frame = make_frame(b"test".to_vec());
    let ct = ctx.encrypt_frame(&frame).unwrap();
    assert!(ctx.decrypt_frame(&ct).is_ok());

    for i in 0..10u32 {
        let mut forged = ct.clone();
        forged.epoch = ct.epoch + 1;
        forged.ciphertext = vec![0xFF; 32];
        forged.tag = AuthenticationTag([0x00; 16]);
        assert!(
            ctx.decrypt_frame(&forged).is_err(),
            "Forged frame {} must be rejected",
            i
        );
    }

    let frame2 = make_frame(b"still works".to_vec());
    let ct2 = ctx.encrypt_frame(&frame2).unwrap();
    assert!(
        ctx.decrypt_frame(&ct2).is_ok(),
        "Legitimate frame after attacks must work"
    );
}

// ═══════════════════════════════════════════════════
// ATTACK 5: COUNTER EXHAUSTION
// ═══════════════════════════════════════════════════

#[test]
fn attack_counter_exhaustion() {
    let mut ctx = make_context(KeyRotationPolicy::Manual);

    for i in 0..1000u32 {
        let data = format!("frame-{}", i);
        let frame = make_frame(data.as_bytes().to_vec());
        let ct = ctx.encrypt_frame(&frame).unwrap();
        let pt = ctx.decrypt_frame(&ct).unwrap();
        assert_eq!(pt.payload, data.as_bytes());
    }
}

// ═══════════════════════════════════════════════════
// ATTACK 6: EMPTY PAYLOADS
// ═══════════════════════════════════════════════════

#[test]
fn attack_empty_plaintext() {
    let mut ctx = make_context(KeyRotationPolicy::Manual);

    let frame = make_frame(vec![]);
    let ct = ctx.encrypt_frame(&frame).unwrap();
    let pt = ctx.decrypt_frame(&ct).unwrap();
    assert!(pt.payload.is_empty(), "Empty plaintext should roundtrip");
}

#[test]
fn attack_single_byte_plaintext() {
    let mut ctx = make_context(KeyRotationPolicy::Manual);

    let frame = make_frame(vec![0x42]);
    let ct = ctx.encrypt_frame(&frame).unwrap();
    let pt = ctx.decrypt_frame(&ct).unwrap();
    assert_eq!(pt.payload, &[0x42]);
}

// ═══════════════════════════════════════════════════
// ATTACK 7: CORRUPTED CIPHERTEXT
// ═══════════════════════════════════════════════════

#[test]
fn attack_corrupted_ciphertext() {
    let mut ctx = make_context(KeyRotationPolicy::Manual);

    let frame = make_frame(b"secret".to_vec());
    let mut ct = ctx.encrypt_frame(&frame).unwrap();
    if let Some(byte) = ct.ciphertext.first_mut() {
        *byte ^= 0x01;
    }
    assert!(
        ctx.decrypt_frame(&ct).is_err(),
        "Corrupted ciphertext must be rejected"
    );
}

#[test]
fn attack_corrupted_tag() {
    let mut ctx = make_context(KeyRotationPolicy::Manual);

    let frame = make_frame(b"secret".to_vec());
    let mut ct = ctx.encrypt_frame(&frame).unwrap();
    ct.tag.0[0] ^= 0xFF;
    assert!(
        ctx.decrypt_frame(&ct).is_err(),
        "Corrupted tag must be rejected"
    );
}

#[test]
fn attack_corrupted_nonce() {
    let mut ctx = make_context(KeyRotationPolicy::Manual);

    let frame = make_frame(b"secret".to_vec());
    let mut ct = ctx.encrypt_frame(&frame).unwrap();
    let mut nonce_bytes = ct.nonce.0;
    nonce_bytes[0] ^= 0xFF;
    ct.nonce = Nonce(nonce_bytes);
    assert!(
        ctx.decrypt_frame(&ct).is_err(),
        "Corrupted nonce must be rejected"
    );
}

// ═══════════════════════════════════════════════════
// ATTACK 8: FORCED ROTATION + REPLAY
// ═══════════════════════════════════════════════════

/// Rotate with Counter(2), then try to decrypt old-epoch frames.
/// After rotation, old-epoch frames must fail (wrong epoch, not replay).
#[test]
fn attack_old_epoch_frames_after_rotation() {
    let mut ctx = make_context(KeyRotationPolicy::Counter(2));

    let f1 = make_frame(b"old".to_vec());
    let ct1 = ctx.encrypt_frame(&f1).unwrap(); // epoch=0
    let f2 = make_frame(b"triggers".to_vec());
    let _ct2 = ctx.encrypt_frame(&f2).unwrap(); // epoch=0, triggers rotation
    let f3 = make_frame(b"new".to_vec());
    let ct3 = ctx.encrypt_frame(&f3).unwrap(); // epoch=1

    // Decrypt new-epoch frame first.
    assert!(ctx.decrypt_frame(&ct3).is_ok());

    // Old-epoch frame should fail (decryptor is now at epoch 1).
    assert!(
        ctx.decrypt_frame(&ct1).is_err(),
        "Old-epoch frame rejected after rotation"
    );
}
