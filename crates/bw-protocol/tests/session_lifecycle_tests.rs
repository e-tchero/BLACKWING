use bw_crypto::SymmetricKey;
use bw_protocol::encryption::KeyRotationPolicy;
use bw_protocol::error::ProtocolError;
use bw_protocol::frame::OwnedProtocolFrame;
use bw_protocol::header::{PacketHeader, PROTOCOL_MAGIC};
use bw_protocol::routing::SessionId;
use bw_protocol::session::SessionManager;
use bw_protocol::version::CURRENT_VERSION;
use std::sync::Arc;
use std::thread;

fn make_valid_frame(payload: Vec<u8>, sequence_number: u32) -> OwnedProtocolFrame {
    OwnedProtocolFrame {
        header: PacketHeader {
            magic: PROTOCOL_MAGIC,
            schema_version: u16::from(CURRENT_VERSION),
            flags: 0,
            packet_type: 1,
            payload_length: payload.len() as u16,
            sequence_number,
            session_epoch: 0,
            monotonic_timestamp: 1000,
        },
        payload,
    }
}

#[test]
fn test_end_to_end_secure_session_happy_path() {
    let manager = SessionManager::new();
    let client_sess = SessionId([11u8; 16]);
    let server_sess = SessionId([12u8; 16]);

    let master_secret = SymmetricKey([0xAA; 32]);
    let client_nonce = [0x01; 16];
    let server_nonce = [0x02; 16];

    // 1. Client derives keys: client sends on client-key (send), client receives on server-key (recv)
    assert!(manager
        .create_session_from_handshake(
            client_sess,
            &master_secret,
            &client_nonce,
            &server_nonce,
            KeyRotationPolicy::Manual
        )
        .is_ok());

    // 2. Server derives keys: server sends on server-key (send), server receives on client-key (recv)
    // To match client's send_key (client-key), server's recv_key must be client-key.
    // By deriving keys with client and server nonces, the derived SessionKeys are:
    // send_key = client-key, recv_key = server-key.
    // So for the server side, the keys are swapped: send_key = server-key, recv_key = client-key.
    let client_keys =
        bw_protocol::handshake::derive_session_keys(&master_secret, &client_nonce, &server_nonce)
            .unwrap();
    let server_keys = bw_protocol::encryption::SessionKeys {
        send_key: client_keys.recv_key.clone(),
        recv_key: client_keys.send_key.clone(),
        epoch: 0,
    };
    assert!(manager
        .create_session_with_context(
            server_sess,
            bw_protocol::encryption::EncryptionContext::new(server_keys, KeyRotationPolicy::Manual)
        )
        .is_ok());

    // 3. Client encrypts outbound frame (mutates counter in place)
    let frame1 = make_valid_frame(b"Message 1".to_vec(), 0);
    let encrypted1 = manager
        .with_session_context(&client_sess, |ctx| ctx.encrypt_frame(&frame1))
        .expect("Encryption lookup failed")
        .expect("Encryption failed");

    // Nonce counter should be 0 for the first frame
    assert_eq!(encrypted1.nonce.counter(), 0);

    // 4. Server decrypts inbound frame (updates replay window)
    let decrypted1 = manager
        .with_session_context(&server_sess, |ctx| ctx.decrypt_frame(&encrypted1))
        .expect("Decryption lookup failed")
        .expect("Decryption failed");

    assert_eq!(decrypted1, frame1);

    // 5. Cleanup
    assert!(manager.close_session(&client_sess).unwrap());
    assert!(manager.close_session(&server_sess).unwrap());
}

#[test]
fn test_session_lifecycle_failure_paths() {
    let manager = SessionManager::new();
    let session_id = SessionId([22u8; 16]);

    let master_secret = SymmetricKey([0xBB; 32]);
    let client_nonce = [0x03; 16];
    let server_nonce = [0x04; 16];

    // Establish initial session
    assert!(manager
        .create_session_from_handshake(
            session_id,
            &master_secret,
            &client_nonce,
            &server_nonce,
            KeyRotationPolicy::Manual
        )
        .is_ok());

    // Re-registration of duplicate session fails
    let dup_res = manager.create_session_from_handshake(
        session_id,
        &master_secret,
        &client_nonce,
        &server_nonce,
        KeyRotationPolicy::Manual,
    );
    assert_eq!(dup_res.err(), Some(ProtocolError::SessionDuplicate));

    // Encryption with incorrect key (invalid server secret decryption)
    let bad_secret = SymmetricKey([0xCC; 32]);
    let bad_session_id = SessionId([33u8; 16]);
    assert!(manager
        .create_session_from_handshake(
            bad_session_id,
            &bad_secret,
            &client_nonce,
            &server_nonce,
            KeyRotationPolicy::Manual
        )
        .is_ok());

    let frame = make_valid_frame(b"Secret".to_vec(), 0);
    let encrypted_good = manager
        .with_session_context(&session_id, |ctx| ctx.encrypt_frame(&frame))
        .unwrap()
        .unwrap();

    // Trying to decrypt the good frame on the bad session (mismatched keys) fails
    let decrypt_bad =
        manager.with_session_context(&bad_session_id, |ctx| ctx.decrypt_frame(&encrypted_good));
    assert_eq!(
        decrypt_bad.unwrap().err(),
        Some(ProtocolError::EncryptionError)
    );
}

#[test]
fn test_session_state_mutation_and_replay_protection() {
    let manager = SessionManager::new();
    let session_id = SessionId([44u8; 16]);

    // Use symmetric keys (send_key == recv_key) for self-decryption loopback testing
    let keys = bw_protocol::encryption::SessionKeys {
        send_key: SymmetricKey([0xDD; 32]),
        recv_key: SymmetricKey([0xDD; 32]),
        epoch: 0,
    };
    assert!(manager
        .create_session_with_context(
            session_id,
            bw_protocol::encryption::EncryptionContext::new(keys, KeyRotationPolicy::Manual)
        )
        .is_ok());

    let frame = make_valid_frame(b"Replay test payload".to_vec(), 0);
    let encrypted = manager
        .with_session_context(&session_id, |ctx| ctx.encrypt_frame(&frame))
        .unwrap()
        .unwrap();

    // Successful first decryption
    let dec1 = manager
        .with_session_context(&session_id, |ctx| ctx.decrypt_frame(&encrypted))
        .unwrap();
    assert!(dec1.is_ok());

    // Replay of the exact same frame fails
    let dec2 = manager
        .with_session_context(&session_id, |ctx| ctx.decrypt_frame(&encrypted))
        .unwrap();
    assert_eq!(dec2.err(), Some(ProtocolError::ReplayDetected));

    // Try decrypting an out-of-order counter frame that is too old (e.g. counter difference >= 64)
    let fut_frame = make_valid_frame(b"Future".to_vec(), 100);
    let encrypted_fut = manager
        .with_session_context(&session_id, |ctx| ctx.encrypt_frame(&fut_frame))
        .unwrap()
        .unwrap();

    let dec_fut = manager
        .with_session_context(&session_id, |ctx| ctx.decrypt_frame(&encrypted_fut))
        .unwrap();
    assert!(dec_fut.is_ok());

    // An old frame with counter = 0 should now be rejected as too old
    let old_dec = manager
        .with_session_context(&session_id, |ctx| ctx.decrypt_frame(&encrypted))
        .unwrap();
    assert_eq!(old_dec.err(), Some(ProtocolError::ReplayDetected));
}

#[test]
fn test_session_concurrency_and_thread_safety() {
    let manager = Arc::new(SessionManager::new());
    let sess_1 = SessionId([1u8; 16]);
    let sess_2 = SessionId([2u8; 16]);

    let keys1 = bw_protocol::encryption::SessionKeys {
        send_key: SymmetricKey([0xEE; 32]),
        recv_key: SymmetricKey([0xEE; 32]),
        epoch: 0,
    };
    let keys2 = bw_protocol::encryption::SessionKeys {
        send_key: SymmetricKey([0xFF; 32]),
        recv_key: SymmetricKey([0xFF; 32]),
        epoch: 0,
    };

    manager
        .create_session_with_context(
            sess_1,
            bw_protocol::encryption::EncryptionContext::new(keys1, KeyRotationPolicy::Manual),
        )
        .unwrap();

    manager
        .create_session_with_context(
            sess_2,
            bw_protocol::encryption::EncryptionContext::new(keys2, KeyRotationPolicy::Manual),
        )
        .unwrap();

    // 1. Thread safety: Parallel access to different sessions
    let m1 = Arc::clone(&manager);
    let handle1 = thread::spawn(move || {
        for i in 0..50 {
            let frame = make_valid_frame(b"thread 1 payload".to_vec(), i);
            let encrypted = m1
                .with_session_context(&sess_1, |ctx| ctx.encrypt_frame(&frame))
                .unwrap()
                .unwrap();
            let decrypted = m1
                .with_session_context(&sess_1, |ctx| ctx.decrypt_frame(&encrypted))
                .unwrap()
                .unwrap();
            assert_eq!(decrypted, frame);
        }
    });

    let m2 = Arc::clone(&manager);
    let handle2 = thread::spawn(move || {
        for i in 0..50 {
            let frame = make_valid_frame(b"thread 2 payload".to_vec(), i);
            let encrypted = m2
                .with_session_context(&sess_2, |ctx| ctx.encrypt_frame(&frame))
                .unwrap()
                .unwrap();
            let decrypted = m2
                .with_session_context(&sess_2, |ctx| ctx.decrypt_frame(&encrypted))
                .unwrap()
                .unwrap();
            assert_eq!(decrypted, frame);
        }
    });

    handle1.join().unwrap();
    handle2.join().unwrap();

    // 2. Thread safety: Serialized concurrent access to the exact same session
    let m3 = Arc::clone(&manager);
    let sess_shared = sess_1;
    let handle3 = thread::spawn(move || {
        for _ in 0..20 {
            let _ = m3.with_session_context(&sess_shared, |ctx| ctx.current_key_epoch());
        }
    });

    let m4 = Arc::clone(&manager);
    let handle4 = thread::spawn(move || {
        for _ in 0..20 {
            let _ = m4.with_session_context(&sess_shared, |ctx| ctx.current_key_epoch());
        }
    });

    handle3.join().unwrap();
    handle4.join().unwrap();
}
