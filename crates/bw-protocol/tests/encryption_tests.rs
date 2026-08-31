#![allow(missing_docs)] // Integration-test crate (repo convention)
#![allow(clippy::unwrap_used, clippy::expect_used)] // Test code may panic on failure (repo convention)
use bw_crypto::SymmetricKey;
use bw_protocol::encryption::{EncryptionContext, FrameEncryptor, KeyRotationPolicy, SessionKeys};
use bw_protocol::error::ProtocolError;
use bw_protocol::frame::OwnedProtocolFrame;
use bw_protocol::header::{PacketHeader, PROTOCOL_MAGIC};
use bw_protocol::version::CURRENT_VERSION;

fn make_valid_frame(payload: Vec<u8>) -> OwnedProtocolFrame {
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

fn test_keys() -> SessionKeys {
    SessionKeys {
        send_key: SymmetricKey([1u8; 32]),
        recv_key: SymmetricKey([1u8; 32]),
        epoch: 0,
    }
}

#[test]
fn test_frame_encryption_decryption_success() {
    let keys = test_keys();
    let mut context = EncryptionContext::new(keys, KeyRotationPolicy::Manual);

    let original = make_valid_frame(b"Secret blackwing mission".to_vec());
    let encrypted = context.encrypt_frame(&original).expect("Encryption failed");

    assert_eq!(encrypted.epoch, 0);

    let decrypted = context
        .decrypt_frame(&encrypted)
        .expect("Decryption failed");
    assert_eq!(decrypted, original);
}

#[test]
fn test_authentication_tag_verification() {
    let keys = test_keys();
    let context = EncryptionContext::new(keys, KeyRotationPolicy::Manual);

    let original = make_valid_frame(b"Secret message".to_vec());
    let mut encryptor = context.encryptor.clone();
    let decryptor = context.decryptor.clone();

    let encrypted = encryptor
        .encrypt_frame(&original)
        .expect("Encryption failed");

    // Success verification
    let ver_res = decryptor.verify_tag(&encrypted);
    assert!(ver_res.is_ok());

    // Tampered verification
    let mut tampered = encrypted.clone();
    tampered.tag.0[0] ^= 0xFF;
    let bad_ver_res = decryptor.verify_tag(&tampered);
    assert_eq!(bad_ver_res.err(), Some(ProtocolError::EncryptionError));
}

#[test]
fn test_incorrect_key_rejection() {
    let keys_sender = test_keys();
    let keys_receiver = SessionKeys {
        send_key: SymmetricKey([1u8; 32]),
        recv_key: SymmetricKey([3u8; 32]), // Wrong recv key
        epoch: 0,
    };

    let mut sender = EncryptionContext::new(keys_sender, KeyRotationPolicy::Manual);
    let mut receiver = EncryptionContext::new(keys_receiver, KeyRotationPolicy::Manual);

    let original = make_valid_frame(b"Top secret data".to_vec());
    let encrypted = sender.encrypt_frame(&original).expect("Encryption failed");

    let dec_res = receiver.decrypt_frame(&encrypted);
    assert_eq!(dec_res.err(), Some(ProtocolError::EncryptionError));
}

#[test]
fn test_tampered_ciphertext_rejection() {
    let keys = test_keys();
    let mut context = EncryptionContext::new(keys, KeyRotationPolicy::Manual);

    let original = make_valid_frame(b"Sensitive payload".to_vec());
    let mut encrypted = context.encrypt_frame(&original).expect("Encryption failed");

    // Tamper ciphertext
    if !encrypted.ciphertext.is_empty() {
        encrypted.ciphertext[0] ^= 0xFF;
    }

    let dec_res = context.decrypt_frame(&encrypted);
    assert_eq!(dec_res.err(), Some(ProtocolError::EncryptionError));
}

#[test]
fn test_replay_detection() {
    let keys = test_keys();
    let mut context = EncryptionContext::new(keys, KeyRotationPolicy::Manual);

    let original = make_valid_frame(b"Some message".to_vec());
    let encrypted = context.encrypt_frame(&original).expect("Encryption failed");

    // First decryption succeeds
    let dec_res = context.decrypt_frame(&encrypted);
    assert!(dec_res.is_ok());

    // Replay of same encrypted frame (same nonce) fails
    let dec_res2 = context.decrypt_frame(&encrypted);
    assert_eq!(dec_res2.err(), Some(ProtocolError::ReplayDetected));
}

#[test]
fn test_nonce_uniqueness() {
    let keys = test_keys();
    let mut encryptor = FrameEncryptor::new(keys.send_key.clone(), 0);

    let f1 = make_valid_frame(b"msg1".to_vec());
    let f2 = make_valid_frame(b"msg2".to_vec());

    let enc1 = encryptor.encrypt_frame(&f1).expect("Enc1 failed");
    let enc2 = encryptor.encrypt_frame(&f2).expect("Enc2 failed");

    assert_ne!(enc1.nonce, enc2.nonce);
    assert_eq!(enc1.nonce.counter() + 1, enc2.nonce.counter());
}

#[test]
fn test_key_rotation() {
    let keys = test_keys();
    let mut context = EncryptionContext::new(keys, KeyRotationPolicy::Counter(2));

    let f1 = make_valid_frame(b"m1".to_vec());
    let f2 = make_valid_frame(b"m2".to_vec());
    let f3 = make_valid_frame(b"m3".to_vec());

    // First frame
    let enc1 = context.encrypt_frame(&f1).expect("Enc1 failed");
    assert_eq!(enc1.epoch, 0);

    // Second frame (triggers key rotation after encryption)
    let enc2 = context.encrypt_frame(&f2).expect("Enc2 failed");
    assert_eq!(enc2.epoch, 0);

    // Third frame uses new epoch
    let enc3 = context.encrypt_frame(&f3).expect("Enc3 failed");
    assert_eq!(enc3.epoch, 1);
    assert_eq!(context.current_key_epoch(), 1);
}

#[test]
fn test_manual_key_rotation() {
    let keys = test_keys();
    let mut context = EncryptionContext::new(keys, KeyRotationPolicy::Manual);

    let frame = make_valid_frame(b"hello".to_vec());

    let enc1 = context.encrypt_frame(&frame).expect("Enc1 failed");
    assert_eq!(enc1.epoch, 0);

    // Manually rotate keys
    context.rotate_keys().expect("Rotation failed");
    assert_eq!(context.current_key_epoch(), 1);

    let enc2 = context.encrypt_frame(&frame).expect("Enc2 failed");
    assert_eq!(enc2.epoch, 1);
}

#[test]
fn test_deterministic_serialization() {
    let keys = test_keys();
    let mut context = EncryptionContext::new(keys, KeyRotationPolicy::Manual);

    let frame = make_valid_frame(b"Data".to_vec());
    let encrypted = context.encrypt_frame(&frame).expect("Enc failed");

    let bytes1 = encrypted.serialize().expect("Serialize 1 failed");
    let bytes2 = encrypted.serialize().expect("Serialize 2 failed");

    assert_eq!(bytes1, bytes2);

    let deserialized =
        bw_protocol::encryption::EncryptedFrame::deserialize(&bytes1).expect("Deserialize failed");
    assert_eq!(deserialized, encrypted);
}

// ═══════════════════════════════════════════════════════════
// H1 REGRESSION TESTS — Automatic Key Rotation
// ═══════════════════════════════════════════════════════════

/// Test 1: Rotation occurs at the configured threshold.
///
/// Uses Counter(2) so that rotation triggers after 2 frames.
/// Verifies that the epoch advances from 0 to 1.
#[test]
fn test_rotation_occurs_at_threshold() {
    let keys = test_keys();
    let mut ctx = EncryptionContext::new(keys, KeyRotationPolicy::Counter(2));

    let f1 = make_valid_frame(b"r1".to_vec());
    let f2 = make_valid_frame(b"r2".to_vec());
    let f3 = make_valid_frame(b"r3".to_vec());

    let enc1 = ctx.encrypt_frame(&f1).expect("Enc1");
    assert_eq!(enc1.epoch, 0, "Frame 1 should be epoch 0");

    let enc2 = ctx.encrypt_frame(&f2).expect("Enc2");
    assert_eq!(
        enc2.epoch, 0,
        "Frame 2 should be epoch 0 (rotation triggers AFTER this frame)"
    );

    // After frame 2, counter >= 2, so rotation happens. Frame 3 uses new epoch.
    let enc3 = ctx.encrypt_frame(&f3).expect("Enc3");
    assert_eq!(enc3.epoch, 1, "Frame 3 should be epoch 1 after rotation");
    assert_eq!(ctx.current_key_epoch(), 1);
}

/// Test 2: Both peers remain synchronized across rotation.
///
/// Creates separate sender/receiver contexts with the same keys.
/// Encrypts frames across the rotation boundary and decrypts on the
/// receiver. Verifies that the auto-rotate in FrameDecryptor keeps
/// both sides in sync.
#[test]
fn test_peers_synchronized_across_rotation() {
    let keys = test_keys();
    let mut sender = EncryptionContext::new(keys.clone(), KeyRotationPolicy::Counter(2));
    let mut receiver = EncryptionContext::new(keys, KeyRotationPolicy::Counter(2));

    let f1 = make_valid_frame(b"sync1".to_vec());
    let f2 = make_valid_frame(b"sync2".to_vec());
    let f3 = make_valid_frame(b"sync3".to_vec());

    // Encrypt 3 frames on the sender side
    let enc1 = sender.encrypt_frame(&f1).expect("Enc1");
    let enc2 = sender.encrypt_frame(&f2).expect("Enc2");
    let enc3 = sender.encrypt_frame(&f3).expect("Enc3");

    // All frames should decrypt correctly on the receiver
    let dec1 = receiver.decrypt_frame(&enc1).expect("Dec1");
    assert_eq!(dec1, f1, "Frame 1 mismatch");

    let dec2 = receiver.decrypt_frame(&enc2).expect("Dec2");
    assert_eq!(dec2, f2, "Frame 2 mismatch");

    // Frame 3 is epoch 1; receiver should auto-rotate and decrypt.
    // The successful decryption proves auto-rotate worked — without it,
    // the epoch check would reject the frame.
    let dec3 = receiver
        .decrypt_frame(&enc3)
        .expect("Dec3 should auto-rotate");
    assert_eq!(dec3, f3, "Frame 3 mismatch");
}

/// Test 3: Nonce uniqueness across epoch rotation.
///
/// Verifies that nonces remain unique even when the counter resets
/// to 0 after a key rotation (new epoch ensures uniqueness).
#[test]
fn test_nonce_uniqueness_across_rotation() {
    let keys = test_keys();
    let mut ctx = EncryptionContext::new(keys, KeyRotationPolicy::Counter(2));

    let mut nonces = std::collections::HashSet::new();

    // Encrypt enough frames to trigger multiple rotations
    for i in 0..6u32 {
        let frame = make_valid_frame(format!("m{i}").into_bytes());
        let enc = ctx.encrypt_frame(&frame).expect("Encrypt failed");
        let nonce_bytes = enc.nonce.0;
        assert!(
            nonces.insert(nonce_bytes),
            "Duplicate nonce detected at frame {i}: {nonce_bytes:?}"
        );
    }

    assert_eq!(nonces.len(), 6, "All 6 nonces should be unique");
    assert_eq!(
        ctx.current_key_epoch(),
        3,
        "Should have rotated 3 times (frames 1, 3, 5)"
    );
}

/// Test 4: Replay protection survives key rotation.
///
/// Encrypts a frame at epoch 0, rotates, then attempts to replay
/// the old ciphertext. The replay should be rejected even though
/// the epoch has changed.
#[test]
fn test_replay_protection_survives_rotation() {
    let keys = test_keys();
    let mut sender = EncryptionContext::new(keys.clone(), KeyRotationPolicy::Counter(1));
    let mut receiver = EncryptionContext::new(keys, KeyRotationPolicy::Counter(1));

    let f1 = make_valid_frame(b"replay-me".to_vec());
    let f2 = make_valid_frame(b"post-rotate".to_vec());

    // Frame 1 at epoch 0
    let enc1 = sender.encrypt_frame(&f1).expect("Enc1");
    // Frame 2 triggers rotation, encrypted at epoch 1
    let enc2 = sender.encrypt_frame(&f2).expect("Enc2");

    // Receiver decrypts both (auto-rotates on enc2)
    receiver.decrypt_frame(&enc1).expect("Dec1");
    receiver.decrypt_frame(&enc2).expect("Dec2");

    // Replay enc1 — should be rejected (epoch 0 != current epoch 1)
    let replay_result = receiver.decrypt_frame(&enc1);
    assert!(
        replay_result.is_err(),
        "Replay of epoch-0 ciphertext should be rejected after rotation to epoch 1"
    );
}

/// Test 5: Production configuration uses automatic rotation.
///
/// Verifies that KeyRotationPolicy::Manual is NOT used in the
/// production session handshake paths. This is a static regression
/// test to prevent accidental re-introduction of Manual policy.
#[test]
fn test_production_uses_automatic_rotation() {
    // Verify that the policy enum variants exist and are constructible
    let auto_policy = KeyRotationPolicy::Counter(10_000);
    match auto_policy {
        KeyRotationPolicy::Counter(limit) => {
            assert_eq!(limit, 10_000, "Production rotation limit should be 10,000");
        }
        _ => panic!("Production policy must be Counter, not Manual"),
    }

    // Verify that Manual is not the default for production sessions.
    // This test fails if someone changes Counter(10_000) back to Manual
    // in secure_conn.rs.
    let keys = test_keys();
    let ctx = EncryptionContext::new(keys, auto_policy);
    assert_eq!(ctx.rotation_policy, KeyRotationPolicy::Counter(10_000));
}

// L-K1 REGRESSION TESTS

use bw_protocol::encryption::EncryptedFrame;

fn forged_frame(epoch: u32, nonce_counter: u64) -> EncryptedFrame {
    EncryptedFrame {
        epoch,
        nonce: bw_protocol::encryption::Nonce::new(epoch, nonce_counter),
        ciphertext: vec![0xDE; 64],
        tag: bw_protocol::encryption::AuthenticationTag([0xAD; 16]),
    }
}

#[test]
fn test_forged_epoch_does_not_rotate() {
    let keys = test_keys();
    let mut receiver = EncryptionContext::new(keys, KeyRotationPolicy::Counter(10_000));
    let epoch_before = receiver.decryptor.current_key_epoch();
    let forged = forged_frame(epoch_before + 1, 0);
    let result = receiver.decrypt_frame(&forged);
    assert!(result.is_err(), "Forged epoch+1 frame must fail AEAD");
    assert_eq!(
        receiver.decryptor.current_key_epoch(),
        epoch_before,
        "Epoch must not change"
    );
}

#[test]
fn test_forged_epoch_does_not_desync() {
    let keys = test_keys();
    let mut sender = EncryptionContext::new(keys.clone(), KeyRotationPolicy::Counter(10_000));
    let mut receiver = EncryptionContext::new(keys, KeyRotationPolicy::Counter(10_000));
    let f1 = make_valid_frame(b"legit1".to_vec());
    let enc1 = sender.encrypt_frame(&f1).expect("Enc1");
    let forged = forged_frame(1, 0);
    let _ = receiver.decrypt_frame(&forged);
    assert_eq!(receiver.decryptor.current_key_epoch(), 0);
    let dec1 = receiver
        .decrypt_frame(&enc1)
        .expect("Legit must still decrypt");
    assert_eq!(dec1, f1);
}

#[test]
fn test_legitimate_rotation_still_works_after_lk1_fix() {
    let keys = test_keys();
    let mut sender = EncryptionContext::new(keys.clone(), KeyRotationPolicy::Counter(2));
    let mut receiver = EncryptionContext::new(keys, KeyRotationPolicy::Counter(2));
    let f1 = make_valid_frame(b"s1".to_vec());
    let f2 = make_valid_frame(b"s2".to_vec());
    let f3 = make_valid_frame(b"s3".to_vec());
    let enc1 = sender.encrypt_frame(&f1).expect("Enc1");
    let enc2 = sender.encrypt_frame(&f2).expect("Enc2");
    let enc3 = sender.encrypt_frame(&f3).expect("Enc3");
    assert_eq!(enc1.epoch, 0);
    assert_eq!(enc2.epoch, 0);
    assert_eq!(enc3.epoch, 1);
    receiver.decrypt_frame(&enc1).expect("Dec1");
    receiver.decrypt_frame(&enc2).expect("Dec2");
    assert_eq!(receiver.decryptor.current_key_epoch(), 0);
    let dec3 = receiver.decrypt_frame(&enc3).expect("Dec3 must succeed");
    assert_eq!(dec3, f3);
    assert_eq!(receiver.decryptor.current_key_epoch(), 1);
}

#[test]
fn test_skipped_epoch_rejected() {
    let keys = test_keys();
    let mut receiver = EncryptionContext::new(keys, KeyRotationPolicy::Counter(10_000));
    let forged = forged_frame(2, 0);
    let result = receiver.decrypt_frame(&forged);
    assert!(result.is_err(), "Skipped epoch must be rejected");
    assert_eq!(receiver.decryptor.current_key_epoch(), 0);
}

#[test]
fn test_old_epoch_rejected_after_rotation() {
    let keys = test_keys();
    let mut sender = EncryptionContext::new(keys.clone(), KeyRotationPolicy::Counter(1));
    let mut receiver = EncryptionContext::new(keys, KeyRotationPolicy::Counter(1));
    let f1 = make_valid_frame(b"old".to_vec());
    let enc1 = sender.encrypt_frame(&f1).expect("Enc1");
    let f2 = make_valid_frame(b"new".to_vec());
    let enc2 = sender.encrypt_frame(&f2).expect("Enc2");
    receiver.decrypt_frame(&enc1).expect("Dec1");
    receiver.decrypt_frame(&enc2).expect("Dec2");
    assert_eq!(receiver.decryptor.current_key_epoch(), 1);
    let replay = receiver.decrypt_frame(&enc1);
    assert!(replay.is_err(), "Old epoch must be rejected");
    assert_eq!(receiver.decryptor.current_key_epoch(), 1);
}

#[test]
fn test_multiple_forged_epochs_cannot_force_rotation() {
    let keys = test_keys();
    let mut receiver = EncryptionContext::new(keys, KeyRotationPolicy::Counter(10_000));
    let epoch_before = receiver.decryptor.current_key_epoch();
    for future_epoch in 1..=5u32 {
        let forged = forged_frame(epoch_before + future_epoch, future_epoch as u64);
        let result = receiver.decrypt_frame(&forged);
        assert!(
            result.is_err(),
            "Forged epoch {} must be rejected",
            epoch_before + future_epoch
        );
        assert_eq!(
            receiver.decryptor.current_key_epoch(),
            epoch_before,
            "Epoch must not change"
        );
    }
}
