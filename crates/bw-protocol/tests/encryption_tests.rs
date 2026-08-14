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
