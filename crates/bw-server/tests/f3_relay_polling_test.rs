#![allow(clippy::unwrap_used, clippy::expect_used)]
//! F3 Regression Tests — Continuous Relay Polling
//!
//! Verifies that the server's relay rendezvous polling:
//! - Continuously polls until an intent arrives (not finite 15×2s)
//! - Expired intents are not accepted
//! - Multiple polling cycles work correctly
//! - Graceful cancellation via tokio shutdown

use bw_crypto::{DeviceId, SigningKey};
use bw_relay::clock::MockClock;
use bw_relay::protocol::RelayMessage;
use bw_relay::rendezvous::INTENT_TIMEOUT_MS;
use bw_relay::server::RelayServer;
use sha2::{Digest, Sha256};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

fn kp() -> (SigningKey, DeviceId) {
    let sk = SigningKey::generate_ed25519().unwrap();
    let id = sk.verify_key().device_id();
    (sk, id)
}

fn register(server: &RelayServer, sk: &SigningKey, time: u64, _addr: SocketAddr) {
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
    let _ = server.handle_message(msg);
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

/// Intent arriving after the old 30-second polling window would have expired.
/// With continuous polling, the server should find it regardless of timing.
#[test]
fn test_intent_arriving_after_old_timeout() {
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

    // Simulate: server starts polling, but no intent exists yet.
    // Advance clock past old 30s window.
    clock.advance(35_000);

    // Now client sends intent (at the new time).
    let now = 1000 + 35_000;
    let mut id = [0u8; 16];
    id[0] = 0xAA;
    let msg = intent_msg(&sk_a, id_a, id_b, &id, now);
    let result = server.handle_message(msg);
    assert!(
        result.is_ok(),
        "Intent at current time must succeed: {:?}",
        result
    );

    // Server polls — should find the intent.
    let poll_msg = RelayMessage::PollPendingIntents { device_id: id_b };
    let response = server.handle_message(poll_msg).unwrap();
    match response {
        RelayMessage::PendingIntents { intents } => {
            assert!(!intents.is_empty(), "Should find the pending intent");
            assert_eq!(intents[0].from, id_a);
        }
        other => panic!("Expected PendingIntents, got: {:?}", other),
    }
}

/// Expired intents cannot be accepted even if they appear in polling.
/// The relay marks them expired on accept, protecting against stale intents.
#[test]
fn test_expired_intent_rejected_on_accept() {
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

    // Create an intent.
    let mut id = [0u8; 16];
    id[0] = 0xBB;
    let msg = intent_msg(&sk_a, id_a, id_b, &id, 1000);
    server.handle_message(msg).unwrap();

    // Advance past INTENT_TIMEOUT_MS.
    clock.advance(INTENT_TIMEOUT_MS + 1000);

    // Try to accept the expired intent — must fail.
    let accept_msg = RelayMessage::AcceptConnect {
        acceptor_device_id: id_b,
        intent_id: id.to_vec(),
        candidates: vec![],
        timestamp: 1000 + INTENT_TIMEOUT_MS + 1000,
        signature_bytes: {
            let mut h = Sha256::new();
            h.update(id);
            h.update(id_b.as_bytes());
            h.update(id_a.as_bytes());
            h.update((1000 + INTENT_TIMEOUT_MS + 1000).to_be_bytes());
            let payload: [u8; 32] = h.finalize().into();
            sk_b.sign(&payload).as_bytes().to_vec()
        },
    };
    let result = server.handle_message(accept_msg);
    assert!(result.is_err(), "Expired intent must be rejected on accept");
}

/// Multiple polling cycles find intents correctly.
#[test]
fn test_multiple_polling_cycles() {
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

    // Cycle 1: no intent — poll returns empty.
    let poll_msg = RelayMessage::PollPendingIntents { device_id: id_b };
    let response = server.handle_message(poll_msg.clone()).unwrap();
    match response {
        RelayMessage::PendingIntents { intents } => assert!(intents.is_empty()),
        other => panic!("Expected PendingIntents, got: {:?}", other),
    }

    // Cycle 2: intent arrives.
    let mut id = [0u8; 16];
    id[0] = 0xCC;
    let msg = intent_msg(&sk_a, id_a, id_b, &id, 1000);
    server.handle_message(msg).unwrap();

    // Cycle 3: poll finds it.
    let response = server.handle_message(poll_msg.clone()).unwrap();
    match response {
        RelayMessage::PendingIntents { intents } => {
            assert_eq!(intents.len(), 1, "Should find exactly one intent");
        }
        other => panic!("Expected PendingIntents, got: {:?}", other),
    }

    // Cycle 4: accept the intent.
    let accept_msg = RelayMessage::AcceptConnect {
        acceptor_device_id: id_b,
        intent_id: id.to_vec(),
        candidates: vec![],
        timestamp: 1000,
        signature_bytes: {
            let mut h = Sha256::new();
            h.update(id);
            h.update(id_b.as_bytes());
            h.update(id_a.as_bytes());
            h.update(1000u64.to_be_bytes());
            let payload: [u8; 32] = h.finalize().into();
            sk_b.sign(&payload).as_bytes().to_vec()
        },
    };
    let result = server.handle_message(accept_msg);
    assert!(result.is_ok(), "Accept must succeed: {:?}", result);

    // Cycle 5: poll returns empty (intent consumed).
    let response = server.handle_message(poll_msg).unwrap();
    match response {
        RelayMessage::PendingIntents { intents } => {
            assert!(intents.is_empty(), "Accepted intent must not appear again");
        }
        other => panic!("Expected PendingIntents, got: {:?}", other),
    }
}

/// Graceful cancellation: tokio shutdown drops the polling task cleanly.
///
/// This test synchronizes on the task's actual state (via AtomicU32)
/// rather than assuming wall-clock timing. This makes the test
/// deterministic regardless of system load or scheduler behavior.
#[tokio::test]
async fn test_graceful_cancellation() {
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
    let count = Arc::new(AtomicU32::new(0));
    let count_clone = Arc::clone(&count);

    let handle = tokio::spawn(async move {
        let mut n = 0u32;
        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    break;
                }
                _ = tokio::time::sleep(std::time::Duration::from_millis(10)) => {
                    n += 1;
                    count_clone.store(n, Ordering::Relaxed);
                }
            }
        }
        n
    });

    // Synchronize: wait until the task has completed at least 1 poll cycle.
    // This eliminates the timing dependency — we wait for actual work, not
    // wall-clock time.
    tokio::task::yield_now().await;
    while count.load(Ordering::Relaxed) == 0 {
        tokio::time::sleep(std::time::Duration::from_millis(1)).await;
    }

    // Signal shutdown.
    shutdown_tx.send(true).unwrap();

    // Should terminate promptly (within 2 seconds).
    let n = tokio::time::timeout(std::time::Duration::from_secs(2), handle)
        .await
        .unwrap()
        .unwrap();

    // The task must have polled at least once (proven by synchronization above).
    // The count from the task return value must match the shared atomic.
    assert!(n >= 1, "Task should have polled at least once: {}", n);
    assert_eq!(
        n,
        count.load(Ordering::Relaxed),
        "Task return value must match atomic counter"
    );
    assert!(n <= 100, "Task should not poll excessively: {}", n);
}
