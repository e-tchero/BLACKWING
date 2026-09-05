#![allow(clippy::unwrap_used, clippy::expect_used)]
//! RT-002 regression tests — expired ConnectIntents are filtered before
//! delivery.
//!
//! Regression for RT-002: `pending_for` must never deliver an intent past
//! `INTENT_TIMEOUT_MS`, so a stale intent can never reach a target's
//! polling loop and trigger a fatal acceptance error. A subsequent valid
//! intent is still discovered and serviced.

use bw_crypto::{DeviceId, SigningKey};
use bw_relay::clock::{Clock, MockClock};
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
        candidates: vec![],
        timestamp: time,
        signature_bytes: sig.as_bytes().to_vec(),
    }
}

fn poll_intents(
    server: &RelayServer,
    device: DeviceId,
    addr: SocketAddr,
) -> Vec<([u8; 16], DeviceId)> {
    let msg = RelayMessage::PollPendingIntents { device_id: device };
    let resp = server.handle_message_from(msg, Some(addr)).unwrap();
    match resp {
        RelayMessage::PendingIntents { intents } => intents
            .into_iter()
            .map(|i| {
                let mut id = [0u8; 16];
                let n = i.intent_id.len().min(16);
                id[..n].copy_from_slice(&i.intent_id[..n]);
                (id, i.from)
            })
            .collect(),
        other => panic!("expected PendingIntents, got {other:?}"),
    }
}

/// An expired intent is never delivered; a subsequent fresh intent is.
#[test]
fn expired_intent_not_delivered_and_fresh_intent_served() {
    let clock = Arc::new(MockClock::new(1000));
    let server = RelayServer::with_clock(clock.clone() as Arc<dyn bw_relay::clock::Clock>);
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 5000);

    let (attacker_sk, attacker_id) = kp();
    let (victim_sk, victim_id) = kp();
    register(&server, &attacker_sk, 1000, addr);
    register(&server, &victim_sk, 1000, addr);

    // Attacker seeds an intent at t=2000.
    let stale = [0xAA; 16];
    let resp = server
        .handle_message_from(
            intent_msg(&attacker_sk, attacker_id, victim_id, &stale, 2000),
            Some(addr),
        )
        .unwrap();
    assert!(matches!(resp, RelayMessage::ConnectInvite { .. }));

    // Advance past expiry; no further inserts occur, so no sweep runs.
    clock.advance(INTENT_TIMEOUT_MS + 5000);

    // RT-002: the expired intent must NOT be delivered.
    let pending = poll_intents(&server, victim_id, addr);
    assert!(
        pending.is_empty(),
        "expired intent must not be delivered by pending_for, got {pending:?}"
    );

    // A fresh intent is still discovered and serviced.
    let fresh = [0xBB; 16];
    let resp = server
        .handle_message_from(
            intent_msg(&attacker_sk, attacker_id, victim_id, &fresh, clock.now_ms()),
            Some(addr),
        )
        .unwrap();
    assert!(matches!(resp, RelayMessage::ConnectInvite { .. }));

    let pending = poll_intents(&server, victim_id, addr);
    assert_eq!(pending.len(), 1, "fresh intent must be delivered");
    assert_eq!(
        pending[0].0, fresh,
        "the fresh intent id must be the one delivered"
    );
}

/// Multiple sequential fresh intents are all delivered; an expired one in
/// between never surfaces.
#[test]
fn multiple_sequential_fresh_intents_serviced() {
    let clock = Arc::new(MockClock::new(1000));
    let server = RelayServer::with_clock(clock.clone() as Arc<dyn bw_relay::clock::Clock>);
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 5000);

    let (attacker_sk, attacker_id) = kp();
    let (victim_sk, victim_id) = kp();
    register(&server, &attacker_sk, 1000, addr);
    register(&server, &victim_sk, 1000, addr);

    // First intent expires silently.
    let first = [0x11; 16];
    let _ = server
        .handle_message_from(
            intent_msg(&attacker_sk, attacker_id, victim_id, &first, 2000),
            Some(addr),
        )
        .unwrap();
    clock.advance(INTENT_TIMEOUT_MS + 1000);

    // Second intent is fresh and delivered.
    let second = [0x22; 16];
    let _ = server
        .handle_message_from(
            intent_msg(
                &attacker_sk,
                attacker_id,
                victim_id,
                &second,
                clock.now_ms(),
            ),
            Some(addr),
        )
        .unwrap();
    let pending = poll_intents(&server, victim_id, addr);
    assert_eq!(pending.len(), 1, "only the fresh intent must be delivered");
    assert_eq!(pending[0].0, second);

    // Third intent is also delivered (sequential servicing works).
    let third = [0x33; 16];
    let _ = server
        .handle_message_from(
            intent_msg(&attacker_sk, attacker_id, victim_id, &third, clock.now_ms()),
            Some(addr),
        )
        .unwrap();
    let pending = poll_intents(&server, victim_id, addr);
    assert_eq!(
        pending.len(),
        2,
        "second + third intents must both be delivered"
    );
    let ids: Vec<[u8; 16]> = pending.iter().map(|(id, _)| *id).collect();
    assert!(ids.contains(&second) && ids.contains(&third));
}
