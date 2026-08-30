#![allow(clippy::unwrap_used, clippy::expect_used)]
//! C1 regression tests: relay token security.
//!
//! These tests verify that the relay token mechanism is properly scoped,
//! session-bound, and resistant to replay and unauthorized access.

use bw_crypto::{DeviceId, SigningKey};
use bw_relay::protocol::RelayMessage;
use bw_relay::server::RelayServer;
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

fn current_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn generate_keypair() -> (SigningKey, DeviceId) {
    let signing_key = SigningKey::generate_ed25519().expect("key generation failed");
    let device_id = signing_key.verify_key().device_id();
    (signing_key, device_id)
}

fn register_device(server: &RelayServer, key: &SigningKey) -> DeviceId {
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
    let _ = server.handle_message_from(req, Some(peer_addr));
    device_id
}

fn signed_connect_intent(
    key: &SigningKey,
    initiator: DeviceId,
    target: DeviceId,
    intent_id: &[u8],
) -> RelayMessage {
    let ts = current_time_ms();
    let mut hasher = Sha256::new();
    hasher.update(intent_id);
    hasher.update(initiator.as_bytes());
    hasher.update(target.as_bytes());
    hasher.update(ts.to_be_bytes());
    let payload: [u8; 32] = hasher.finalize().into();
    let sig = key.sign(&payload);

    RelayMessage::ConnectIntent {
        initiator_device_id: initiator,
        target,
        intent_id: intent_id.to_vec(),
        candidates: vec![],
        timestamp: ts,
        signature_bytes: sig.as_bytes().to_vec(),
    }
}

fn signed_accept_connect(
    key: &SigningKey,
    acceptor: DeviceId,
    initiator: DeviceId,
    intent_id: &[u8],
) -> RelayMessage {
    let ts = current_time_ms();
    let mut hasher = Sha256::new();
    hasher.update(intent_id);
    hasher.update(acceptor.as_bytes());
    hasher.update(initiator.as_bytes());
    hasher.update(ts.to_be_bytes());
    let payload: [u8; 32] = hasher.finalize().into();
    let sig = key.sign(&payload);

    RelayMessage::AcceptConnect {
        acceptor_device_id: acceptor,
        intent_id: intent_id.to_vec(),
        candidates: vec![],
        timestamp: ts,
        signature_bytes: sig.as_bytes().to_vec(),
    }
}

// ══ C1 TESTS ══════════════════════════════════════════════════════════

#[test]
fn c1_no_hardcoded_relay_token_in_server_source() {
    let server_src =
        std::fs::read_to_string("../bw-server/src/main.rs").expect("failed to read server main.rs");
    assert!(
        !server_src.contains("let token = [0xABu8; 32]"),
        "Server still contains hardcoded relay token [0xAB; 32]"
    );
}

#[test]
fn c1_no_hardcoded_relay_token_in_client_source() {
    let client_src =
        std::fs::read_to_string("../bw-client/src/main.rs").expect("failed to read client main.rs");
    assert!(
        !client_src.contains("[0xABu8; 32]"),
        "Client still contains hardcoded relay token [0xAB; 32]"
    );
}

#[test]
fn c1_two_sessions_receive_different_tokens() {
    let server = RelayServer::new();
    let (sk_a, dev_a) = generate_keypair();
    let (sk_b, dev_b) = generate_keypair();
    let (sk_c, dev_c) = generate_keypair();

    register_device(&server, &sk_a);
    register_device(&server, &sk_b);
    register_device(&server, &sk_c);

    // Session 1: A -> B
    let intent_id1 = [1u8; 16];
    let msg1 = signed_connect_intent(&sk_a, dev_a, dev_b, &intent_id1);
    server.handle_message(msg1).unwrap();

    let accept1 = signed_accept_connect(&sk_b, dev_b, dev_a, &intent_id1);
    let token1 = match server.handle_message(accept1).unwrap() {
        RelayMessage::CandidateExchange { relay_token, .. } => relay_token,
        _ => panic!("Expected CandidateExchange for session 1"),
    };

    // Session 2: A -> C
    let intent_id2 = [2u8; 16];
    let msg2 = signed_connect_intent(&sk_a, dev_a, dev_c, &intent_id2);
    server.handle_message(msg2).unwrap();

    let accept2 = signed_accept_connect(&sk_c, dev_c, dev_a, &intent_id2);
    let token2 = match server.handle_message(accept2).unwrap() {
        RelayMessage::CandidateExchange { relay_token, .. } => relay_token,
        _ => panic!("Expected CandidateExchange for session 2"),
    };

    assert_ne!(token1, token2, "Two sessions must receive different tokens");
}

#[test]
fn c1_same_session_both_endpoints_get_same_token() {
    let server = RelayServer::new();
    let (sk_a, dev_a) = generate_keypair();
    let (sk_b, dev_b) = generate_keypair();

    register_device(&server, &sk_a);
    register_device(&server, &sk_b);

    let intent_id = [5u8; 16];

    // A sends ConnectIntent
    let msg = signed_connect_intent(&sk_a, dev_a, dev_b, &intent_id);
    server.handle_message(msg).unwrap();

    // B accepts — gets token
    let accept = signed_accept_connect(&sk_b, dev_b, dev_a, &intent_id);
    let token_b = match server.handle_message(accept).unwrap() {
        RelayMessage::CandidateExchange { relay_token, .. } => relay_token,
        _ => panic!("Expected CandidateExchange for B"),
    };

    // A gets candidates — gets same token
    let token_a = match server
        .handle_message(RelayMessage::GetCandidates {
            requester_device_id: dev_a,
            intent_id: intent_id.to_vec(),
        })
        .unwrap()
    {
        RelayMessage::CandidateExchange { relay_token, .. } => relay_token,
        _ => panic!("Expected CandidateExchange for A"),
    };

    assert_eq!(
        token_a, token_b,
        "Both endpoints must receive the same token"
    );
}

#[test]
fn c1_wrong_token_rejected_on_data_plane() {
    let table = bw_relay::forwarding::ForwardingTable::new(Arc::new(bw_relay::clock::SystemClock));

    let (_sk_a, dev_a) = generate_keypair();
    let (_sk_b, dev_b) = generate_keypair();

    let intent_id = [7u8; 16];
    let real_token = [0x42u8; 32];
    let fake_token = [0x99u8; 32];

    table.authorize_pair(intent_id, real_token, dev_a, dev_b);

    let init_addr: SocketAddr = "10.0.0.1:5000".parse().unwrap();
    let targ_addr: SocketAddr = "10.0.0.2:6000".parse().unwrap();

    table.update_binding(intent_id, dev_a, init_addr).unwrap();
    table.update_binding(intent_id, dev_b, targ_addr).unwrap();

    // Real token works
    assert!(table.get_destination(&real_token, init_addr, 100).is_some());
    // Fake token is rejected
    assert!(table.get_destination(&fake_token, init_addr, 100).is_none());
}

#[test]
fn c1_unauthorized_initiator_rejected() {
    let server = RelayServer::new();
    let (sk_a, dev_a) = generate_keypair();
    let (sk_b, dev_b) = generate_keypair();
    let (sk_c, dev_c) = generate_keypair();

    register_device(&server, &sk_a);
    register_device(&server, &sk_b);
    register_device(&server, &sk_c);

    let intent_id = [9u8; 16];
    let msg = signed_connect_intent(&sk_a, dev_a, dev_b, &intent_id);
    server.handle_message(msg).unwrap();

    let accept = signed_accept_connect(&sk_b, dev_b, dev_a, &intent_id);
    server.handle_message(accept).unwrap();

    // C (unauthorized) tries to get candidates for A's intent
    let result = server.handle_message(RelayMessage::GetCandidates {
        requester_device_id: dev_c,
        intent_id: intent_id.to_vec(),
    });
    assert!(
        result.is_err(),
        "Unauthorized device must not retrieve candidates"
    );
}

#[test]
fn c1_expired_intent_rejected() {
    use bw_relay::clock::MockClock;

    let base_time = current_time_ms();
    let clock = Arc::new(MockClock::new(base_time));
    let server = RelayServer::with_clock(clock.clone());

    let (sk_a, dev_a) = generate_keypair();
    let (sk_b, dev_b) = generate_keypair();

    register_device(&server, &sk_a);
    register_device(&server, &sk_b);

    let intent_id = [11u8; 16];
    let msg = signed_connect_intent(&sk_a, dev_a, dev_b, &intent_id);
    server.handle_message(msg).unwrap();

    // Advance past the 30-second intent timeout
    clock.advance(31_000);

    let accept = signed_accept_connect(&sk_b, dev_b, dev_a, &intent_id);
    let result = server.handle_message(accept);
    assert!(result.is_err(), "Expired intent must be rejected");
}

#[test]
fn c1_replay_of_accept_connect_rejected() {
    let server = RelayServer::new();
    let (sk_a, dev_a) = generate_keypair();
    let (sk_b, dev_b) = generate_keypair();

    register_device(&server, &sk_a);
    register_device(&server, &sk_b);

    let intent_id = [13u8; 16];
    let msg = signed_connect_intent(&sk_a, dev_a, dev_b, &intent_id);
    server.handle_message(msg).unwrap();

    // First accept succeeds
    let accept = signed_accept_connect(&sk_b, dev_b, dev_a, &intent_id);
    assert!(
        server.handle_message(accept).is_ok(),
        "First accept must succeed"
    );

    // Replay the same accept — must fail
    let accept_replay = signed_accept_connect(&sk_b, dev_b, dev_a, &intent_id);
    assert!(
        server.handle_message(accept_replay).is_err(),
        "Replayed AcceptConnect must be rejected"
    );
}

#[test]
fn c1_tokens_never_logged_in_server() {
    let server_src =
        std::fs::read_to_string("../bw-relay/src/server.rs").expect("failed to read server.rs");

    for (i, line) in server_src.lines().enumerate() {
        if line.contains("eprintln!") || line.contains("println!") || line.contains("log::") {
            assert!(
                !line.contains("relay_token") && !line.contains("token"),
                "Line {} in server.rs appears to log a token: {}",
                i + 1,
                line.trim()
            );
        }
    }
}
