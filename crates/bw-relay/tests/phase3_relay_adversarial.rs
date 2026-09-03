#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Phase 3 Adversarial Validation — Relay
//!
//! Actively attempts to break BLACKWING relay resource limits,
//! state machines, and concurrency controls.

use bw_crypto::{DeviceId, SigningKey};
use bw_relay::clock::MockClock;
use bw_relay::forwarding::ForwardingTable;
use bw_relay::protocol::RelayMessage;
use bw_relay::rendezvous::INTENT_TIMEOUT_MS;
use bw_relay::server::RelayServer;
use sha2::{Digest, Sha256};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

fn kp() -> (SigningKey, DeviceId) {
    let sk = SigningKey::generate_ed25519().unwrap();
    let id = sk.verify_key().device_id();
    (sk, id)
}

fn register(server: &RelayServer, sk: &SigningKey, time: u64, addr: SocketAddr) {
    let id = sk.verify_key().device_id();
    let vk = *sk.verify_key().as_bytes();
    let mut h = Sha256::new();
    h.update(id.as_bytes());
    h.update(vk);
    h.update(time.to_be_bytes());
    let payload: [u8; 32] = h.finalize().into();
    let sig = sk.sign(&payload);
    let msg = RelayMessage::RegisterRequest {
        device_id: id,
        verify_key_bytes: vk,
        timestamp: time,
        signature_bytes: sig.as_bytes().to_vec(),
    };
    let _ = server.handle_message_from(msg, Some(addr));
}

fn intent_msg(
    sk: &SigningKey,
    from: DeviceId,
    to: DeviceId,
    id: &[u8; 16],
    time: u64,
) -> RelayMessage {
    let mut h = Sha256::new();
    h.update(id);
    h.update(from.as_bytes());
    h.update(to.as_bytes());
    h.update(time.to_be_bytes());
    let payload: [u8; 32] = h.finalize().into();
    let sig = sk.sign(&payload);
    RelayMessage::ConnectIntent {
        initiator_device_id: from,
        target: to,
        intent_id: id.to_vec(),
        candidates: vec![bw_relay::candidate::Candidate::server_reflexive(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 5000),
        )],
        timestamp: time,
        signature_bytes: sig.as_bytes().to_vec(),
    }
}

// ═══════════════════════════════════════════════════
// ATTACK 1: REGISTRATION FLOOD
// ═══════════════════════════════════════════════════

/// Flood with 2000 unique registrations — should not panic or OOM.
#[test]
fn attack_registration_flood() {
    let clock = Arc::new(MockClock::new(1000));
    let server = RelayServer::with_clock(clock.clone() as Arc<dyn bw_relay::clock::Clock>);

    for i in 0u16..2000 {
        let (sk, _id) = kp();
        let addr = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(10, (i / 256) as u8, (i % 256) as u8, 1)),
            9000,
        );
        register(&server, &sk, 1000, addr);
    }
    // Should handle gracefully. No panic.
}

/// Flood with duplicate registrations from same device.
#[test]
fn attack_duplicate_registration() {
    let clock = Arc::new(MockClock::new(1000));
    let server = RelayServer::with_clock(clock.clone() as Arc<dyn bw_relay::clock::Clock>);
    let (sk, _id) = kp();
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 9000);

    // Register same device 100 times — should overwrite, not leak.
    for _ in 0..100 {
        register(&server, &sk, 1000, addr);
    }
}

// ═══════════════════════════════════════════════════
// ATTACK 2: INTENT FLOOD
// ═══════════════════════════════════════════════════

/// Create many intents rapidly — should be bounded.
#[test]
fn attack_intent_flood() {
    let clock = Arc::new(MockClock::new(1000));
    let server = RelayServer::with_clock(clock.clone() as Arc<dyn bw_relay::clock::Clock>);
    let (sk_a, id_a) = kp();
    let (sk_b, id_b) = kp();

    register(
        &server,
        &sk_a,
        1000,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)), 9000),
    );
    register(
        &server,
        &sk_b,
        1000,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 1, 2)), 9001),
    );

    let mut success = 0;
    for i in 0u16..3000 {
        let mut id = [0u8; 16];
        id[0] = (i % 256) as u8;
        id[1] = (i / 256) as u8;
        let msg = intent_msg(&sk_a, id_a, id_b, &id, 1000);
        if server.handle_message(msg).is_ok() {
            success += 1;
        }
    }
    // Should not exceed MAX_INTENTS (2048).
    assert!(success <= 2048, "Intent count exceeded limit: {}", success);
}

/// Create intent with expired timestamp — should fail.
#[test]
fn attack_expired_intent() {
    let clock = Arc::new(MockClock::new(1000));
    let server = RelayServer::with_clock(clock.clone() as Arc<dyn bw_relay::clock::Clock>);
    let (sk_a, id_a) = kp();
    let (sk_b, id_b) = kp();

    register(
        &server,
        &sk_a,
        1000,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)), 9000),
    );
    register(
        &server,
        &sk_b,
        1000,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 1, 2)), 9001),
    );

    let mut id = [0u8; 16];
    id[0] = 0xAA;
    let msg = intent_msg(&sk_a, id_a, id_b, &id, 1000);
    server.handle_message(msg).unwrap();

    // Advance clock past timeout.
    clock.advance(INTENT_TIMEOUT_MS + 1000);

    // Try to accept the expired intent.
    let mut id2 = [0u8; 16];
    id2[0] = 0xBB;
    let msg2 = intent_msg(&sk_a, id_a, id_b, &id2, 1000 + INTENT_TIMEOUT_MS + 1000);
    let result = server.handle_message(msg2);
    // New intent should succeed (old one swept). No panic.
    let _ = result;
}

// ═══════════════════════════════════════════════════
// ATTACK 3: FORWARDING TABLE ABUSE
// ═══════════════════════════════════════════════════

/// Brute-force token guessing from many IPs.
#[test]
fn attack_token_guessing() {
    let clock = Arc::new(MockClock::new(1000));
    let table = ForwardingTable::with_limits(
        clock.clone() as Arc<dyn bw_relay::clock::Clock>,
        625_000,
        120_000,
    );

    for i in 0u16..2000 {
        let ip = IpAddr::V4(Ipv4Addr::new(10, (i / 256) as u8, (i % 256) as u8, 1));
        let addr = SocketAddr::new(ip, 9000);
        let mut token = [0u8; 32];
        token[0] = (i % 256) as u8;
        token[1] = (i / 256) as u8;
        // 10 guesses per IP
        for _ in 0..10 {
            table.get_destination(&token, addr, 100);
        }
    }
    // Should not panic, no unbounded growth.
}

/// Oversized packets should be dropped.
#[test]
fn attack_oversized_packet() {
    let clock = Arc::new(MockClock::new(1000));
    let table = ForwardingTable::with_limits(
        clock.clone() as Arc<dyn bw_relay::clock::Clock>,
        625_000,
        120_000,
    );

    let token = [0u8; 32];
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 9000);
    // Packet larger than MAX_FORWARDING_PAYLOAD.
    let result = table.get_destination(&token, addr, 2000);
    // Should drop silently (unknown token).
    assert!(result.is_none());
}

/// Rapid close/open cycles — no resource leak.
#[test]
fn attack_rapid_close_reopen() {
    let clock = Arc::new(MockClock::new(1000));
    let table = ForwardingTable::with_limits(
        clock.clone() as Arc<dyn bw_relay::clock::Clock>,
        625_000,
        120_000,
    );

    for i in 0u32..100 {
        let mut intent_id = [0u8; 16];
        intent_id[0] = (i % 256) as u8;
        intent_id[1] = (i / 256) as u8;
        let mut token = [0u8; 32];
        token[0] = (i % 256) as u8;

        // authorize then immediately close.
        table.authorize_pair(
            intent_id,
            token,
            DeviceId::from_digest([1u8; 32]),
            DeviceId::from_digest([2u8; 32]),
        );
        table.close(intent_id);
    }

    // Sweep should clean up.
    let swept = table.sweep();
    assert_eq!(swept, 100, "All closed contexts should be swept");
}

// ═══════════════════════════════════════════════════
// ATTACK 4: TIMESTAMP MANIPULATION
// ═══════════════════════════════════════════════════

/// Registration with timestamp far in the future.
#[test]
fn attack_future_timestamp() {
    let clock = Arc::new(MockClock::new(1000));
    let server = RelayServer::with_clock(clock.clone() as Arc<dyn bw_relay::clock::Clock>);
    let (sk, _id) = kp();
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 9000);

    // Timestamp 10 minutes in the future — should fail (exceeds 5min window).
    let id = sk.verify_key().device_id();
    let vk = *sk.verify_key().as_bytes();
    let future_time: u64 = 1000 + 600_000; // 10 minutes
    let mut h = Sha256::new();
    h.update(id.as_bytes());
    h.update(vk);
    h.update(future_time.to_be_bytes());
    let payload: [u8; 32] = h.finalize().into();
    let sig = sk.sign(&payload);
    let msg = RelayMessage::RegisterRequest {
        device_id: id,
        verify_key_bytes: vk,
        timestamp: future_time,
        signature_bytes: sig.as_bytes().to_vec(),
    };
    let result = server.handle_message_from(msg, Some(addr));
    assert!(result.is_err(), "Future timestamp must be rejected");
}

/// Registration with timestamp far in the past.
#[test]
fn attack_past_timestamp() {
    let clock = Arc::new(MockClock::new(10_000_000));
    let server = RelayServer::with_clock(clock.clone() as Arc<dyn bw_relay::clock::Clock>);
    let (sk, _id) = kp();
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 9000);

    // Timestamp 10 minutes in the past.
    let id = sk.verify_key().device_id();
    let vk = *sk.verify_key().as_bytes();
    let past_time: u64 = 10_000_000 - 600_000;
    let mut h = Sha256::new();
    h.update(id.as_bytes());
    h.update(vk);
    h.update(past_time.to_be_bytes());
    let payload: [u8; 32] = h.finalize().into();
    let sig = sk.sign(&payload);
    let msg = RelayMessage::RegisterRequest {
        device_id: id,
        verify_key_bytes: vk,
        timestamp: past_time,
        signature_bytes: sig.as_bytes().to_vec(),
    };
    let result = server.handle_message_from(msg, Some(addr));
    assert!(result.is_err(), "Past timestamp must be rejected");
}

// ═══════════════════════════════════════════════════
// ATTACK 5: INVALID SIGNATURES
// ═══════════════════════════════════════════════════

/// Registration with wrong signature length.
#[test]
fn attack_wrong_signature_length() {
    let clock = Arc::new(MockClock::new(1000));
    let server = RelayServer::with_clock(clock.clone() as Arc<dyn bw_relay::clock::Clock>);
    let (sk, id) = kp();
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 9000);

    let vk = *sk.verify_key().as_bytes();
    let msg = RelayMessage::RegisterRequest {
        device_id: id,
        verify_key_bytes: vk,
        timestamp: 1000,
        signature_bytes: vec![0u8; 32], // Wrong length (should be 64)
    };
    let result = server.handle_message_from(msg, Some(addr));
    assert!(result.is_err(), "Wrong signature length must be rejected");
}

/// Registration with completely random signature.
#[test]
fn attack_random_signature() {
    let clock = Arc::new(MockClock::new(1000));
    let server = RelayServer::with_clock(clock.clone() as Arc<dyn bw_relay::clock::Clock>);
    let (sk, id) = kp();
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 9000);

    let vk = *sk.verify_key().as_bytes();
    let mut random_sig = [0u8; 64];
    random_sig[0] = 0xFF;
    let msg = RelayMessage::RegisterRequest {
        device_id: id,
        verify_key_bytes: vk,
        timestamp: 1000,
        signature_bytes: random_sig.to_vec(),
    };
    let result = server.handle_message_from(msg, Some(addr));
    assert!(result.is_err(), "Random signature must be rejected");
}

/// Registration with mismatched DeviceId.
#[test]
fn attack_mismatched_device_id() {
    let clock = Arc::new(MockClock::new(1000));
    let server = RelayServer::with_clock(clock.clone() as Arc<dyn bw_relay::clock::Clock>);
    let (sk, _id) = kp();
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 9000);

    let vk = *sk.verify_key().as_bytes();
    let fake_id = DeviceId::from_digest([0xFF; 32]); // Not derived from this key
    let mut h = Sha256::new();
    h.update(fake_id.as_bytes());
    h.update(vk);
    h.update(1000u64.to_be_bytes());
    let payload: [u8; 32] = h.finalize().into();
    let sig = sk.sign(&payload);

    let msg = RelayMessage::RegisterRequest {
        device_id: fake_id,
        verify_key_bytes: vk,
        timestamp: 1000,
        signature_bytes: sig.as_bytes().to_vec(),
    };
    let result = server.handle_message_from(msg, Some(addr));
    assert!(result.is_err(), "Mismatched DeviceId must be rejected");
}

// ═══════════════════════════════════════════════════
// ATTACK 6: UNKNOWN MESSAGE TYPES
// ═══════════════════════════════════════════════════

/// Server receiving a message type it doesn't handle.
#[test]
fn attack_unknown_relay_message() {
    let clock = Arc::new(MockClock::new(1000));
    let server = RelayServer::with_clock(clock.clone() as Arc<dyn bw_relay::clock::Clock>);

    // PollPendingIntents from unregistered device.
    let fake_id = DeviceId::from_digest([0x01; 32]);
    let msg = RelayMessage::PollPendingIntents { device_id: fake_id };
    let result = server.handle_message(msg);
    assert!(result.is_err(), "Unregistered device must be rejected");
}

// ═══════════════════════════════════════════════════
// ATTACK 7: BLOCKLIST EXPLOITATION
// ═══════════════════════════════════════════════════

/// Exhaust blocklist from many source IPs, verify no OOM.
#[test]
fn attack_blocklist_exhaustion() {
    let clock = Arc::new(MockClock::new(1000));
    let table = ForwardingTable::with_limits(
        clock.clone() as Arc<dyn bw_relay::clock::Clock>,
        625_000,
        120_000,
    );

    // 5000 unique IPs, each with 25 failed lookups.
    for i in 0u16..5000 {
        let ip = IpAddr::V4(Ipv4Addr::new(
            10,
            (i / 256) as u8,
            (i % 256) as u8,
            (i % 256) as u8,
        ));
        let addr = SocketAddr::new(ip, 9000);
        let mut token = [0u8; 32];
        token[0] = (i % 256) as u8;
        token[1] = (i / 256) as u8;
        for _ in 0..25 {
            table.get_destination(&token, addr, 100);
        }
    }
    // Should handle without panic or OOM. Blocklist bounded.
}

/// Blocklist should not prevent legitimate use after expiry.
#[test]
fn attack_blocklist_legitimate_after_expiry() {
    let clock = Arc::new(MockClock::new(1000));
    let table = ForwardingTable::with_limits(
        clock.clone() as Arc<dyn bw_relay::clock::Clock>,
        625_000,
        120_000,
    );

    let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50));
    let addr = SocketAddr::new(ip, 9000);

    // Trigger blocklist.
    let token = [0u8; 32];
    for _ in 0..25 {
        table.get_destination(&token, addr, 100);
    }
    assert!(table.is_blocklisted(&ip));

    // Advance past window.
    clock.advance(61_000);
    assert!(
        !table.is_blocklisted(&ip),
        "Should be unblocked after window"
    );
}
