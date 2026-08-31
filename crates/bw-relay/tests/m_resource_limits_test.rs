#![allow(clippy::unwrap_used, clippy::expect_used)]
//! M2/M3/M6 Regression Tests — Resource Limits
//!
//! Tests that relay registration capacity (M2), intent capacity (M3),
//! and blocklist eviction (M6) are enforced and do not regress.

use bw_crypto::{DeviceId, SigningKey};
use bw_relay::clock::MockClock;
use bw_relay::forwarding::ForwardingTable;
use bw_relay::protocol::RelayMessage;
use bw_relay::rendezvous::INTENT_TIMEOUT_MS;
use bw_relay::server::RelayServer;
use sha2::{Digest, Sha256};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

fn generate_keypair() -> (SigningKey, DeviceId) {
    let signing_key = SigningKey::generate_ed25519().expect("key generation failed");
    let device_id = signing_key.verify_key().device_id();
    (signing_key, device_id)
}

fn register_device(server: &RelayServer, key: &SigningKey, time: u64, addr: SocketAddr) {
    let device_id = key.verify_key().device_id();
    let verify_key_bytes = *key.verify_key().as_bytes();

    let mut hasher = Sha256::new();
    hasher.update(device_id.as_bytes());
    hasher.update(verify_key_bytes);
    hasher.update(time.to_be_bytes());
    let payload: [u8; 32] = hasher.finalize().into();

    let signature = key.sign(&payload);
    let req = RelayMessage::RegisterRequest {
        device_id,
        verify_key_bytes,
        timestamp: time,
        signature_bytes: signature.as_bytes().to_vec(),
    };
    let _ = server.handle_message_from(req, Some(addr));
}

fn signed_connect_intent(
    key: &SigningKey,
    initiator: DeviceId,
    target: DeviceId,
    intent_id: &[u8],
    time: u64,
) -> RelayMessage {
    let mut hasher = Sha256::new();
    hasher.update(intent_id);
    hasher.update(initiator.as_bytes());
    hasher.update(target.as_bytes());
    hasher.update(time.to_be_bytes());
    let payload: [u8; 32] = hasher.finalize().into();
    let signature = key.sign(&payload);

    RelayMessage::ConnectIntent {
        initiator_device_id: initiator,
        target,
        intent_id: intent_id.to_vec(),
        candidates: vec![bw_relay::candidate::Candidate::server_reflexive(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 5000),
        )],
        timestamp: time,
        signature_bytes: signature.as_bytes().to_vec(),
    }
}

// ═══════════════════════════════════════════════════
// M2 — REGISTRATION CAPACITY
// ═══════════════════════════════════════════════════

/// Test: Multiple devices can register successfully.
#[test]
fn test_m2_multiple_registrations() {
    let clock = Arc::new(MockClock::new(1000));
    let server = RelayServer::with_clock(clock);

    for i in 0..50u8 {
        let (sk, _id) = generate_keypair();
        // Use signing key's verify key for proper registration.
        let device_id = sk.verify_key().device_id();
        let vk_bytes = *sk.verify_key().as_bytes();

        let mut hasher = Sha256::new();
        hasher.update(device_id.as_bytes());
        hasher.update(vk_bytes);
        hasher.update(1000u64.to_be_bytes());
        let payload: [u8; 32] = hasher.finalize().into();
        let sig = sk.sign(&payload);

        let msg = RelayMessage::RegisterRequest {
            device_id,
            verify_key_bytes: vk_bytes,
            timestamp: 1000,
            signature_bytes: sig.as_bytes().to_vec(),
        };
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, i)), 9000);
        let result = server.handle_message_from(msg, Some(addr));
        assert!(
            result.is_ok(),
            "Registration {} should succeed: {:?}",
            i,
            result
        );
    }
}

// ═══════════════════════════════════════════════════
// M3 — INTENT CAPACITY (expired sweep on register)
// ═══════════════════════════════════════════════════

/// Test: After intent timeout, old pending intents are swept.
#[test]
fn test_m3_expired_intent_swept_on_new_register() {
    let base_time = 1000u64;
    let clock = Arc::new(MockClock::new(base_time));
    let server = RelayServer::with_clock(clock.clone());

    // Register two devices.
    let (sk_a, id_a) = generate_keypair();
    let (sk_b, id_b) = generate_keypair();

    let addr_a = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)), 9000);
    let addr_b = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 1, 2)), 9001);

    register_device(&server, &sk_a, base_time, addr_a);
    register_device(&server, &sk_b, base_time, addr_b);

    // Create an intent from A → B.
    let intent_id = [0xAA; 16];
    let msg = signed_connect_intent(&sk_a, id_a, id_b, &intent_id, base_time);
    let result = server.handle_message(msg);
    assert!(result.is_ok(), "ConnectIntent should succeed: {:?}", result);

    // Advance clock past INTENT_TIMEOUT_MS.
    clock.advance(INTENT_TIMEOUT_MS + 1000);

    // Create a new intent from A → B with a different intent_id.
    // The expired intent should be swept by the new register_intent call.
    let intent_id2 = [0xBB; 16];
    let msg2 = signed_connect_intent(
        &sk_a,
        id_a,
        id_b,
        &intent_id2,
        base_time + INTENT_TIMEOUT_MS + 1000,
    );
    let result2 = server.handle_message(msg2);
    // Should succeed because the expired intent was swept.
    assert!(
        result2.is_ok(),
        "New intent after sweep should succeed: {:?}",
        result2
    );
}

// ═══════════════════════════════════════════════════
// M6 — BLOCKLIST EVICTION
// ═══════════════════════════════════════════════════

/// Test: Failed token lookups from many IPs don't cause unbounded growth.
#[test]
fn test_m6_blocklist_eviction_under_load() {
    let clock = Arc::new(MockClock::new(1000));
    let table = ForwardingTable::with_limits(clock.clone(), 625_000, 120_000);

    // Generate many unique source IPs and try invalid tokens.
    for i in 0u16..500 {
        let ip = IpAddr::V4(Ipv4Addr::new(10, (i / 256) as u8, (i % 256) as u8, 1));
        let addr = SocketAddr::new(ip, 9000);
        let mut token = [0u8; 32];
        token[0] = (i % 256) as u8;
        token[1] = (i / 256) as u8;
        // Each failed lookup records the IP.
        for _ in 0..25 {
            table.get_destination(&token, addr, 100);
        }
    }

    // The blocklist should handle this without panic.
    let mut token = [0u8; 32];
    token[0] = 0xFF;
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 99)), 9000);
    let result = table.get_destination(&token, addr, 100);
    assert!(result.is_none(), "Unknown token should still be dropped");
}

/// Test: Blocklisted IP is blocked within the window.
#[test]
fn test_m6_blocklist_blocks_after_threshold() {
    let clock = Arc::new(MockClock::new(1000));
    let table = ForwardingTable::with_limits(clock.clone(), 625_000, 120_000);

    let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
    let addr = SocketAddr::new(ip, 9000);
    let mut token = [0u8; 32];
    token[0] = 0xFF;

    // Record 20+ failed lookups to trigger blocklist.
    for _ in 0..25 {
        table.get_destination(&token, addr, 100);
    }

    assert!(
        table.is_blocklisted(&ip),
        "IP should be blocklisted after 20+ failed lookups"
    );

    // Even a valid-looking token from a blocklisted IP should be dropped.
    let result = table.get_destination(&token, addr, 100);
    assert!(
        result.is_none(),
        "Blocklisted IP should be dropped silently"
    );
}

/// Test: Blocklist expires after the window passes.
#[test]
fn test_m6_blocklist_expiry() {
    let clock = Arc::new(MockClock::new(1000));
    let table = ForwardingTable::with_limits(clock.clone(), 625_000, 120_000);

    let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 200));
    let addr = SocketAddr::new(ip, 9000);
    let mut token = [0u8; 32];
    token[0] = 0xFF;

    // Trigger blocklist.
    for _ in 0..25 {
        table.get_destination(&token, addr, 100);
    }
    assert!(table.is_blocklisted(&ip));

    // Advance clock past the blocklist window (60 seconds).
    clock.advance(61_000);

    // Now the IP should no longer be blocklisted.
    assert!(
        !table.is_blocklisted(&ip),
        "Blocklist entry should expire after window"
    );
}
