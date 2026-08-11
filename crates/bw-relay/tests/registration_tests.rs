//! Tests for bw-relay registration and rendezvous.

use bw_crypto::{DeviceId, SigningKey};
use bw_relay::candidate::Candidate;
use bw_relay::checker::{ConnectivityChecker, DirectConnector};
use bw_relay::protocol::RelayMessage;
use bw_relay::server::RelayServer;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn current_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn generate_keypair() -> (SigningKey, DeviceId) {
    let signing_key = SigningKey::generate_ed25519().expect("key generation failed");
    let device_id = signing_key.verify_key().device_id();
    (signing_key, device_id)
}

fn register_device(server: &RelayServer, key: &SigningKey) -> (DeviceId, u64) {
    let device_id = key.verify_key().device_id();
    let timestamp = current_time_ms();
    let verify_key_bytes = *key.verify_key().as_bytes();

    let mut hasher = Sha256::new();
    hasher.update(device_id.as_bytes());
    hasher.update(verify_key_bytes);
    hasher.update(timestamp.to_be_bytes());
    let payload: [u8; 32] = hasher.finalize().into();

    let signature = key.sign(&payload);
    let mut signature_bytes = Vec::new();
    signature_bytes.extend_from_slice(signature.as_bytes());

    let req = RelayMessage::RegisterRequest {
        device_id,
        verify_key_bytes,
        timestamp,
        signature_bytes,
    };

    let peer_addr: SocketAddr = "192.168.1.100:12345".parse().unwrap();
    let resp = server.handle_message_from(req, Some(peer_addr)).unwrap();

    match resp {
        RelayMessage::RegisterAck {
            relay_session_id, ..
        } => (device_id, relay_session_id),
        _ => panic!("Expected RegisterAck"),
    }
}

// ── Phase 1 Tests ────────────────────────────────────────────────────────

#[test]
fn test_registration_and_discovery_success() {
    let server = RelayServer::new();
    let (sk1, device_id1) = generate_keypair();
    let (_sk2, device_id2) = generate_keypair();

    register_device(&server, &sk1);

    // Discover registered device
    let req = RelayMessage::DiscoverRequest { target: device_id1 };
    let resp = server.handle_message(req).unwrap();
    match resp {
        RelayMessage::DiscoverResponse { target, is_online } => {
            assert_eq!(target, device_id1);
            assert!(is_online);
        }
        _ => panic!("Expected DiscoverResponse"),
    }

    // Discover unregistered device
    let req = RelayMessage::DiscoverRequest { target: device_id2 };
    let resp = server.handle_message(req).unwrap();
    match resp {
        RelayMessage::DiscoverResponse { target, is_online } => {
            assert_eq!(target, device_id2);
            assert!(!is_online);
        }
        _ => panic!("Expected DiscoverResponse"),
    }
}

#[test]
fn test_registration_replay_protection() {
    let server = RelayServer::new();
    let (sk1, device_id1) = generate_keypair();

    let timestamp = current_time_ms() - 600_000; // 10 minutes ago
    let verify_key_bytes = *sk1.verify_key().as_bytes();

    let mut hasher = Sha256::new();
    hasher.update(device_id1.as_bytes());
    hasher.update(verify_key_bytes);
    hasher.update(timestamp.to_be_bytes());
    let payload: [u8; 32] = hasher.finalize().into();

    let signature = sk1.sign(&payload);
    let mut signature_bytes = Vec::new();
    signature_bytes.extend_from_slice(signature.as_bytes());

    let req = RelayMessage::RegisterRequest {
        device_id: device_id1,
        verify_key_bytes,
        timestamp,
        signature_bytes,
    };

    assert!(server.handle_message(req).is_err());
}

#[test]
fn test_registration_identity_mismatch() {
    let server = RelayServer::new();
    let (sk1, _device_id1) = generate_keypair();
    let (_sk2, device_id2) = generate_keypair();

    let timestamp = current_time_ms();
    let verify_key_bytes = *sk1.verify_key().as_bytes();

    let mut hasher = Sha256::new();
    hasher.update(device_id2.as_bytes());
    hasher.update(verify_key_bytes);
    hasher.update(timestamp.to_be_bytes());
    let payload: [u8; 32] = hasher.finalize().into();

    let signature = sk1.sign(&payload);
    let mut signature_bytes = Vec::new();
    signature_bytes.extend_from_slice(signature.as_bytes());

    let req = RelayMessage::RegisterRequest {
        device_id: device_id2, // Claiming device_id2 but using sk1
        verify_key_bytes,
        timestamp,
        signature_bytes,
    };

    assert!(server.handle_message(req).is_err());
}

#[test]
fn test_registration_invalid_signature() {
    let server = RelayServer::new();
    let (sk1, device_id1) = generate_keypair();

    let timestamp = current_time_ms();
    let verify_key_bytes = *sk1.verify_key().as_bytes();

    let signature_bytes = vec![0u8; 64]; // Invalid signature

    let req = RelayMessage::RegisterRequest {
        device_id: device_id1,
        verify_key_bytes,
        timestamp,
        signature_bytes,
    };

    assert!(server.handle_message(req).is_err());
}

// ── Phase 2 Tests (Rendezvous & Connection checks) ───────────────────────

#[test]
fn test_rendezvous_happy_path() {
    let server = RelayServer::new();
    let (sk_a, dev_a) = generate_keypair();
    let (sk_b, dev_b) = generate_keypair();

    register_device(&server, &sk_a);
    register_device(&server, &sk_b);

    let intent_id = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    let ts = current_time_ms();

    // 1. A sends ConnectIntent
    let mut hasher = Sha256::new();
    hasher.update(&intent_id);
    hasher.update(dev_a.as_bytes());
    hasher.update(dev_b.as_bytes());
    hasher.update(ts.to_be_bytes());
    let payload: [u8; 32] = hasher.finalize().into();
    let mut sig_a = Vec::new();
    sig_a.extend_from_slice(sk_a.sign(&payload).as_bytes());

    let candidates_a = vec![Candidate::host("10.0.0.1:5000".parse().unwrap())];

    let intent_req = RelayMessage::ConnectIntent {
        initiator_device_id: dev_a,
        target: dev_b,
        intent_id: intent_id.clone(),
        candidates: candidates_a.clone(),
        timestamp: ts,
        signature_bytes: sig_a,
    };

    let invite_resp = server.handle_message(intent_req).unwrap();
    match invite_resp {
        RelayMessage::ConnectInvite {
            from,
            intent_id: id,
        } => {
            assert_eq!(from, dev_a);
            assert_eq!(id, intent_id);
        }
        _ => panic!("Expected ConnectInvite"),
    }

    // 2. B sends AcceptConnect
    let ts_b = current_time_ms();
    let mut hasher_b = Sha256::new();
    hasher_b.update(&intent_id);
    hasher_b.update(dev_b.as_bytes());
    hasher_b.update(dev_a.as_bytes());
    hasher_b.update(ts_b.to_be_bytes());
    let payload_b: [u8; 32] = hasher_b.finalize().into();
    let mut sig_b = Vec::new();
    sig_b.extend_from_slice(sk_b.sign(&payload_b).as_bytes());

    let candidates_b = vec![Candidate::host("10.0.0.2:6000".parse().unwrap())];

    let accept_req = RelayMessage::AcceptConnect {
        acceptor_device_id: dev_b,
        intent_id: intent_id.clone(),
        candidates: candidates_b.clone(),
        timestamp: ts_b,
        signature_bytes: sig_b,
    };

    let accept_resp = server.handle_message(accept_req).unwrap();
    match accept_resp {
        RelayMessage::CandidateExchange {
            intent_id: id,
            candidates,
        } => {
            assert_eq!(id, intent_id);
            assert_eq!(candidates.len(), 1);
            assert_eq!(
                candidates[0].addr,
                "10.0.0.1:5000".parse::<SocketAddr>().unwrap()
            );
        }
        _ => panic!("Expected CandidateExchange"),
    }

    // 3. A requests target candidates
    let get_cand_req = RelayMessage::GetCandidates {
        requester_device_id: dev_a,
        intent_id: intent_id.clone(),
    };

    let get_cand_resp = server.handle_message(get_cand_req).unwrap();
    match get_cand_resp {
        RelayMessage::CandidateExchange {
            intent_id: id,
            candidates,
        } => {
            assert_eq!(id, intent_id);
            assert_eq!(candidates.len(), 1);
            assert_eq!(
                candidates[0].addr,
                "10.0.0.2:6000".parse::<SocketAddr>().unwrap()
            );
        }
        _ => panic!("Expected CandidateExchange"),
    }
}

#[test]
fn test_rendezvous_target_offline() {
    let server = RelayServer::new();
    let (sk_a, dev_a) = generate_keypair();
    let (_sk_b, dev_b) = generate_keypair();

    register_device(&server, &sk_a);
    // B is NOT registered

    let intent_id = vec![0; 16];
    let ts = current_time_ms();

    let mut hasher = Sha256::new();
    hasher.update(&intent_id);
    hasher.update(dev_a.as_bytes());
    hasher.update(dev_b.as_bytes());
    hasher.update(ts.to_be_bytes());
    let payload: [u8; 32] = hasher.finalize().into();
    let mut sig_a = Vec::new();
    sig_a.extend_from_slice(sk_a.sign(&payload).as_bytes());

    let intent_req = RelayMessage::ConnectIntent {
        initiator_device_id: dev_a,
        target: dev_b,
        intent_id,
        candidates: vec![],
        timestamp: ts,
        signature_bytes: sig_a,
    };

    let resp = server.handle_message(intent_req).unwrap();
    match resp {
        RelayMessage::ConnectRejected { target, reason } => {
            assert_eq!(target, dev_b);
            assert_eq!(reason, "Target device is not registered");
        }
        _ => panic!("Expected ConnectRejected"),
    }
}

#[test]
fn test_get_candidates_unauthorized() {
    let server = RelayServer::new();
    let (sk_a, dev_a) = generate_keypair();
    let (sk_b, dev_b) = generate_keypair();
    let (sk_c, dev_c) = generate_keypair();

    register_device(&server, &sk_a);
    register_device(&server, &sk_b);
    register_device(&server, &sk_c);

    let intent_id = vec![1; 16];
    let ts = current_time_ms();

    // A -> B
    let mut hasher = Sha256::new();
    hasher.update(&intent_id);
    hasher.update(dev_a.as_bytes());
    hasher.update(dev_b.as_bytes());
    hasher.update(ts.to_be_bytes());
    let payload: [u8; 32] = hasher.finalize().into();
    let mut sig_a = Vec::new();
    sig_a.extend_from_slice(sk_a.sign(&payload).as_bytes());

    server
        .handle_message(RelayMessage::ConnectIntent {
            initiator_device_id: dev_a,
            target: dev_b,
            intent_id: intent_id.clone(),
            candidates: vec![],
            timestamp: ts,
            signature_bytes: sig_a,
        })
        .unwrap();

    // B accepts
    let ts_b = current_time_ms();
    let mut hasher_b = Sha256::new();
    hasher_b.update(&intent_id);
    hasher_b.update(dev_b.as_bytes());
    hasher_b.update(dev_a.as_bytes());
    hasher_b.update(ts_b.to_be_bytes());
    let payload_b: [u8; 32] = hasher_b.finalize().into();
    let mut sig_b = Vec::new();
    sig_b.extend_from_slice(sk_b.sign(&payload_b).as_bytes());

    server
        .handle_message(RelayMessage::AcceptConnect {
            acceptor_device_id: dev_b,
            intent_id: intent_id.clone(),
            candidates: vec![],
            timestamp: ts_b,
            signature_bytes: sig_b,
        })
        .unwrap();

    // C tries to get candidates for A's intent
    let req = RelayMessage::GetCandidates {
        requester_device_id: dev_c,
        intent_id: intent_id.clone(),
    };
    assert!(server.handle_message(req).is_err());
}

#[test]
fn test_rendezvous_intent_timeout() {
    use bw_relay::clock::MockClock;
    use std::sync::Arc;

    let base_time = current_time_ms();
    let clock = Arc::new(MockClock::new(base_time));
    let server = RelayServer::with_clock(clock.clone());

    let (sk_a, dev_a) = generate_keypair();
    let (sk_b, dev_b) = generate_keypair();

    // Re-implement register_device inline to use the same timestamp for simplicity,
    // or just let it use the system time since the server's MockClock starts near system time.
    register_device(&server, &sk_a);
    register_device(&server, &sk_b);

    let intent_id = vec![2; 16];
    let ts = current_time_ms();

    let mut hasher = Sha256::new();
    hasher.update(&intent_id);
    hasher.update(dev_a.as_bytes());
    hasher.update(dev_b.as_bytes());
    hasher.update(ts.to_be_bytes());
    let payload: [u8; 32] = hasher.finalize().into();
    let mut sig_a = Vec::new();
    sig_a.extend_from_slice(sk_a.sign(&payload).as_bytes());

    server
        .handle_message(RelayMessage::ConnectIntent {
            initiator_device_id: dev_a,
            target: dev_b,
            intent_id: intent_id.clone(),
            candidates: vec![],
            timestamp: ts,
            signature_bytes: sig_a,
        })
        .unwrap();

    // 1. Advance clock by 10s (within 30s timeout). Intent should still be active.
    clock.advance(10_000);

    // B accepts just fine at 10s? No, wait. Let's just create a completely different intent to show they don't affect each other, but the requirement says:
    // - A valid rendezvous remains active before the 30-second intent timeout.
    // - The rendezvous expires after the configured timeout.
    // - An expired rendezvous cannot proceed to candidate exchange.
    // - Expiration does not affect unrelated active rendezvous.
    // - Clock behavior cannot be abused to extend an authorization indefinitely.

    // Let's create intent 2
    let intent_id2 = vec![3; 16];
    let ts2 = current_time_ms();
    let mut hasher2 = Sha256::new();
    hasher2.update(&intent_id2);
    hasher2.update(dev_a.as_bytes());
    hasher2.update(dev_b.as_bytes());
    hasher2.update(ts2.to_be_bytes());
    let payload2: [u8; 32] = hasher2.finalize().into();
    let mut sig_a2 = Vec::new();
    sig_a2.extend_from_slice(sk_a.sign(&payload2).as_bytes());

    server
        .handle_message(RelayMessage::ConnectIntent {
            initiator_device_id: dev_a,
            target: dev_b,
            intent_id: intent_id2.clone(),
            candidates: vec![],
            timestamp: ts2,
            signature_bytes: sig_a2,
        })
        .unwrap();

    // Advance clock past the first intent's timeout (created at T0). Total advance = 30_001.
    // Since intent 2 was created at T+10s, it has only aged 20s.
    clock.advance(20_001);

    // Try to accept intent 1 -> Should fail because it expired.
    let ts_b1 = current_time_ms();
    let mut hasher_b1 = Sha256::new();
    hasher_b1.update(&intent_id);
    hasher_b1.update(dev_b.as_bytes());
    hasher_b1.update(dev_a.as_bytes());
    hasher_b1.update(ts_b1.to_be_bytes());
    let payload_b1: [u8; 32] = hasher_b1.finalize().into();
    let mut sig_b1 = Vec::new();
    sig_b1.extend_from_slice(sk_b.sign(&payload_b1).as_bytes());

    let res = server.handle_message(RelayMessage::AcceptConnect {
        acceptor_device_id: dev_b,
        intent_id: intent_id.clone(),
        candidates: vec![],
        timestamp: ts_b1,
        signature_bytes: sig_b1,
    });
    assert!(res.is_err());
    assert_eq!(
        res.unwrap_err().to_string(),
        "Internal error: Intent has expired"
    );

    // Try to accept intent 2 -> Should succeed because it has only aged 20s.
    let ts_b2 = current_time_ms();
    let mut hasher_b2 = Sha256::new();
    hasher_b2.update(&intent_id2);
    hasher_b2.update(dev_b.as_bytes());
    hasher_b2.update(dev_a.as_bytes());
    hasher_b2.update(ts_b2.to_be_bytes());
    let payload_b2: [u8; 32] = hasher_b2.finalize().into();
    let mut sig_b2 = Vec::new();
    sig_b2.extend_from_slice(sk_b.sign(&payload_b2).as_bytes());

    let res2 = server.handle_message(RelayMessage::AcceptConnect {
        acceptor_device_id: dev_b,
        intent_id: intent_id2.clone(),
        candidates: vec![],
        timestamp: ts_b2,
        signature_bytes: sig_b2,
    });
    assert!(res2.is_ok());
}

// ── Client-side Checker Tests ─────────────────────────────────────────────

struct MockConnector {
    reachable: SocketAddr,
    attempts: Arc<Mutex<HashMap<SocketAddr, u32>>>,
}

impl DirectConnector for MockConnector {
    fn try_connect(&self, addr: SocketAddr, _timeout: Duration) -> bool {
        *self.attempts.lock().unwrap().entry(addr).or_insert(0) += 1;
        addr == self.reachable
    }
}

#[test]
fn test_checker_priority_and_retry() {
    let target_addr: SocketAddr = "10.0.0.1:443".parse().unwrap();
    let bad_host: SocketAddr = "192.168.1.1:443".parse().unwrap();

    let attempts = Arc::new(Mutex::new(HashMap::new()));
    let connector = MockConnector {
        reachable: target_addr,
        attempts: attempts.clone(),
    };

    let checker = ConnectivityChecker::with_params(connector, 3, Duration::from_millis(1));

    let candidates = vec![
        Candidate::server_reflexive(target_addr),
        Candidate::host(bad_host),
    ];

    let result = checker.find_direct_path(candidates);

    assert_eq!(result, Some(target_addr));

    let stats = attempts.lock().unwrap();
    // Host (bad_host) has higher priority (30000 > 20000), so it gets tried first
    assert_eq!(*stats.get(&bad_host).unwrap(), 3); // Failed all 3 retries
    assert_eq!(*stats.get(&target_addr).unwrap(), 1); // Succeeded on 1st try
}

#[test]
fn test_checker_all_fail() {
    let bad_host1: SocketAddr = "192.168.1.1:443".parse().unwrap();
    let bad_host2: SocketAddr = "192.168.1.2:443".parse().unwrap();

    let attempts = Arc::new(Mutex::new(HashMap::new()));
    let connector = MockConnector {
        reachable: "127.0.0.1:0".parse().unwrap(),
        attempts: attempts.clone(),
    };

    let checker = ConnectivityChecker::with_params(connector, 2, Duration::from_millis(1));

    let candidates = vec![
        Candidate::host(bad_host1),
        Candidate::server_reflexive(bad_host2),
    ];

    let result = checker.find_direct_path(candidates);

    assert_eq!(result, None);

    let stats = attempts.lock().unwrap();
    assert_eq!(*stats.get(&bad_host1).unwrap(), 2);
    assert_eq!(*stats.get(&bad_host2).unwrap(), 2);
}
