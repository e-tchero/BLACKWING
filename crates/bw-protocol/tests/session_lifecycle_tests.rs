use bw_crypto::SymmetricKey;
use bw_protocol::encryption::{EncryptionContext, KeyRotationPolicy, SessionKeys};
use bw_protocol::error::ProtocolError;
use bw_protocol::frame::OwnedProtocolFrame;
use bw_protocol::header::{PacketHeader, PROTOCOL_MAGIC};
use bw_protocol::routing::SessionId;
use bw_protocol::session::SessionManager;
use bw_protocol::version::CURRENT_VERSION;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

fn make_test_context() -> EncryptionContext {
    EncryptionContext::new(
        SessionKeys {
            send_key: SymmetricKey([0xAA; 32]),
            recv_key: SymmetricKey([0xBB; 32]),
            epoch: 0,
        },
        KeyRotationPolicy::Manual,
    )
}

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

// ── Existing Tests ──────────────────────────────────────────────────────────

#[test]
fn test_end_to_end_secure_session_happy_path() {
    let manager = SessionManager::new();
    let client_sess = SessionId([11u8; 16]);
    let server_sess = SessionId([12u8; 16]);

    let master_secret = SymmetricKey([0xAA; 32]);
    let client_nonce = [0x01; 16];
    let server_nonce = [0x02; 16];

    // 1. Client derives keys
    assert!(manager
        .create_session_from_handshake(
            client_sess,
            &master_secret,
            &client_nonce,
            &server_nonce,
            KeyRotationPolicy::Manual
        )
        .is_ok());

    // 2. Server derives keys (swapped send/recv)
    let client_keys =
        bw_protocol::handshake::derive_session_keys(&master_secret, &client_nonce, &server_nonce)
            .unwrap();
    let server_keys = bw_protocol::encryption::SessionKeys {
        send_key: client_keys.recv_key.clone(),
        recv_key: client_keys.send_key.clone(),
        epoch: 0,
    };
    assert!(manager
        .create_session(
            server_sess,
            bw_protocol::encryption::EncryptionContext::new(server_keys, KeyRotationPolicy::Manual)
        )
        .is_ok());

    // 3. Client encrypts
    let frame1 = make_valid_frame(b"Message 1".to_vec(), 0);
    let encrypted1 = manager
        .with_session_context(&client_sess, |ctx| ctx.encrypt_frame(&frame1))
        .expect("Encryption lookup failed")
        .expect("Encryption failed");

    assert_eq!(encrypted1.nonce.counter(), 0);

    // 4. Server decrypts
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

    assert!(manager
        .create_session_from_handshake(
            session_id,
            &master_secret,
            &client_nonce,
            &server_nonce,
            KeyRotationPolicy::Manual
        )
        .is_ok());

    let dup_res = manager.create_session_from_handshake(
        session_id,
        &master_secret,
        &client_nonce,
        &server_nonce,
        KeyRotationPolicy::Manual,
    );
    assert_eq!(dup_res.err(), Some(ProtocolError::SessionDuplicate));

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

    let keys = bw_protocol::encryption::SessionKeys {
        send_key: SymmetricKey([0xDD; 32]),
        recv_key: SymmetricKey([0xDD; 32]),
        epoch: 0,
    };
    assert!(manager
        .create_session(
            session_id,
            bw_protocol::encryption::EncryptionContext::new(keys, KeyRotationPolicy::Manual)
        )
        .is_ok());

    let frame = make_valid_frame(b"Replay test payload".to_vec(), 0);
    let encrypted = manager
        .with_session_context(&session_id, |ctx| ctx.encrypt_frame(&frame))
        .unwrap()
        .unwrap();

    let dec1 = manager
        .with_session_context(&session_id, |ctx| ctx.decrypt_frame(&encrypted))
        .unwrap();
    assert!(dec1.is_ok());

    let dec2 = manager
        .with_session_context(&session_id, |ctx| ctx.decrypt_frame(&encrypted))
        .unwrap();
    assert_eq!(dec2.err(), Some(ProtocolError::ReplayDetected));

    let fut_frame = make_valid_frame(b"Future".to_vec(), 100);
    let encrypted_fut = manager
        .with_session_context(&session_id, |ctx| ctx.encrypt_frame(&fut_frame))
        .unwrap()
        .unwrap();

    let dec_fut = manager
        .with_session_context(&session_id, |ctx| ctx.decrypt_frame(&encrypted_fut))
        .unwrap();
    assert!(dec_fut.is_ok());

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
        .create_session(
            sess_1,
            bw_protocol::encryption::EncryptionContext::new(keys1, KeyRotationPolicy::Manual),
        )
        .unwrap();

    manager
        .create_session(
            sess_2,
            bw_protocol::encryption::EncryptionContext::new(keys2, KeyRotationPolicy::Manual),
        )
        .unwrap();

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

// ── Session Expiry Tests ────────────────────────────────────────────────────

#[test]
fn test_session_expires_after_ttl() {
    // Use a short TTL (50ms) — long enough that creation + validation completes
    // within the TTL, but short enough that a 100ms sleep exceeds it.
    let manager = SessionManager::with_ttl(Duration::from_millis(50));
    let id = SessionId([0xAA; 16]);

    manager
        .create_session(id, make_test_context())
        .expect("create must succeed");

    // Session should be valid right after creation
    assert!(
        manager.validate_session(&id).unwrap(),
        "Session should be valid immediately after creation"
    );

    // Wait for TTL to elapse
    thread::sleep(Duration::from_millis(100));

    // Session should now be expired and invisible to validators
    assert!(
        !manager.validate_session(&id).unwrap(),
        "Session should be expired after TTL"
    );
}

#[test]
fn test_lookup_of_expired_returns_not_found() {
    let manager = SessionManager::with_ttl(Duration::from_millis(1));
    let id = SessionId([0xBB; 16]);

    manager
        .create_session(id, make_test_context())
        .expect("create must succeed");

    thread::sleep(Duration::from_millis(10));

    // lookup_session should return SessionNotFound for expired sessions
    let result = manager.lookup_session(&id);
    assert_eq!(
        result.err(),
        Some(ProtocolError::SessionNotFound),
        "Expired session should not be found"
    );
}

#[test]
fn test_with_session_context_of_expired_returns_not_found() {
    let manager = SessionManager::with_ttl(Duration::from_millis(1));
    let id = SessionId([0xCC; 16]);

    manager
        .create_session(
            id,
            bw_protocol::encryption::EncryptionContext::new(
                bw_protocol::encryption::SessionKeys {
                    send_key: SymmetricKey([0x11; 32]),
                    recv_key: SymmetricKey([0x22; 32]),
                    epoch: 0,
                },
                KeyRotationPolicy::Manual,
            ),
        )
        .expect("create with context must succeed");

    thread::sleep(Duration::from_millis(10));

    let result: Result<u32, ProtocolError> =
        manager.with_session_context(&id, |ctx| ctx.current_key_epoch());
    assert_eq!(
        result.err(),
        Some(ProtocolError::SessionNotFound),
        "Expired session should return SessionNotFound from with_session_context"
    );
}

#[test]
fn test_expire_stale_removes_expired_only() {
    let manager = SessionManager::with_ttl(Duration::from_millis(1));
    let expired_id = SessionId([0xDD; 16]);
    let valid_id = SessionId([0xEE; 16]);

    // Create both sessions with the same short TTL
    manager
        .create_session(expired_id, make_test_context())
        .unwrap();
    manager
        .create_session(valid_id, make_test_context())
        .unwrap();

    // Change the TTL for the valid session by creating a new manager...
    // Actually, we need a different approach. Let's use two managers.
    drop(manager);

    let manager = SessionManager::with_ttl(Duration::from_millis(1));

    // Create the session that will expire
    manager
        .create_session(expired_id, make_test_context())
        .unwrap();

    // Wait for expiry
    thread::sleep(Duration::from_millis(10));
    assert_eq!(
        manager.expire_stale().unwrap(),
        1,
        "Should expire 1 session"
    );

    // Create a fresh session — should not be expired
    manager
        .create_session(valid_id, make_test_context())
        .unwrap();
    assert!(
        manager.validate_session(&valid_id).unwrap(),
        "Fresh session should be valid"
    );

    // expire_stale should not remove the valid session
    assert_eq!(
        manager.expire_stale().unwrap(),
        0,
        "Should not expire valid session"
    );
}

#[tokio::test]
async fn test_sweeper_cleans_expired_sessions() {
    let manager = Arc::new(SessionManager::with_ttl(Duration::from_millis(1)));
    let id = SessionId([0xFF; 16]);

    manager.create_session(id, make_test_context()).unwrap();

    // Start the sweeper with a 5ms interval
    let _sweeper_handle = manager.start_sweeper(Duration::from_millis(5));

    // Wait long enough for TTL + sweeper interval
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Session should be gone
    assert!(
        !manager.validate_session(&id).unwrap(),
        "Sweeper should have cleaned expired session"
    );
}
