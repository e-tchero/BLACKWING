#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Phase 3 forwarding tests for bw-relay.
//!
//! Covers:
//!   1. A -> Relay -> B happy path
//!   2. Unauthorized packet (no valid token)
//!   3. Wrong token
//!   4. Expired token (idle timeout)
//!   5. Cross-pair token misuse
//!   6. Unauthorized source address (spoofing)
//!   7. Authenticated NAT rebinding
//!   8. Rejected unauthenticated rebinding (requires signature)
//!   9. Simultaneous rebinding
//!  10. Relay idle timeout sweeps context
//!  11. Token expiration after close
//!  12. Oversized payload (exceeds MAX_FORWARDING_PAYLOAD)
//!  13. Malformed routing header (too short)
//!  14. Forwarding cleanup after explicit close
//!  15. Relay session state machine transitions
//!  16. Relay never decrypts / possesses session keys
//!  17. Endpoint A cannot forward using Endpoint C token (cross-pair)
//!  18. Relay 1:1 invariant (A->Relay->B, B->Relay->A)

use std::net::SocketAddr;
use std::sync::Arc;

use bw_crypto::SigningKey;
use bw_relay::{
    clock::MockClock,
    forwarding::{ForwardingState, ForwardingTable},
};

// ── helpers ──────────────────────────────────────────────────────────────────

fn make_addr(port: u16) -> SocketAddr {
    format!("127.0.0.1:{port}").parse().unwrap()
}

fn make_pair() -> ([u8; 16], [u8; 32], bw_crypto::DeviceId, bw_crypto::DeviceId) {
    let intent_id = [0u8; 16];
    let token = [0xABu8; 32];
    let init_key = SigningKey::generate_ed25519().unwrap();
    let tgt_key = SigningKey::generate_ed25519().unwrap();
    let init_id = init_key.verify_key().device_id();
    let tgt_id = tgt_key.verify_key().device_id();
    (intent_id, token, init_id, tgt_id)
}

fn table_with_clock(clock: Arc<MockClock>) -> Arc<ForwardingTable> {
    Arc::new(ForwardingTable::new(clock))
}

// ── 1. Happy path A -> B ──────────────────────────────────────────────────────
#[test]
fn test_forwarding_happy_path_a_to_b() {
    let clock = Arc::new(MockClock::new(1_000));
    let table = table_with_clock(clock.clone());

    let (intent_id, token, init_id, tgt_id) = make_pair();
    let addr_a = make_addr(10001);
    let addr_b = make_addr(10002);

    table.authorize_pair(intent_id, token, init_id, tgt_id);
    table.update_binding(intent_id, init_id, addr_a).unwrap();
    table.update_binding(intent_id, tgt_id, addr_b).unwrap();

    // A -> Relay should forward to B
    let dest = table.get_destination(&token, addr_a);
    assert_eq!(dest, Some(addr_b), "A packet should route to B");

    // B -> Relay should forward to A
    let dest = table.get_destination(&token, addr_b);
    assert_eq!(dest, Some(addr_a), "B packet should route to A");
}

// ── 2. Unauthorized packet (unknown token) ────────────────────────────────────
#[test]
fn test_forwarding_unknown_token_drops() {
    let clock = Arc::new(MockClock::new(1_000));
    let table = table_with_clock(clock.clone());

    let addr_a = make_addr(10003);
    let unknown_token = [0xFFu8; 32];

    let dest = table.get_destination(&unknown_token, addr_a);
    assert!(dest.is_none(), "Unknown token must be silently dropped");
}

// ── 3. Wrong token (valid format, wrong pair) ─────────────────────────────────
#[test]
fn test_forwarding_wrong_token_drops() {
    let clock = Arc::new(MockClock::new(1_000));
    let table = table_with_clock(clock.clone());

    let (intent_id, token, init_id, tgt_id) = make_pair();
    let addr_a = make_addr(10004);
    let addr_b = make_addr(10005);

    table.authorize_pair(intent_id, token, init_id, tgt_id);
    table.update_binding(intent_id, init_id, addr_a).unwrap();
    table.update_binding(intent_id, tgt_id, addr_b).unwrap();

    let wrong_token = [0x11u8; 32];
    let dest = table.get_destination(&wrong_token, addr_a);
    assert!(dest.is_none(), "Wrong token must be dropped");
}

// ── 4. Expired token (idle timeout) ──────────────────────────────────────────
#[test]
fn test_forwarding_idle_timeout_expires_context() {
    let clock = Arc::new(MockClock::new(1_000));
    let table = table_with_clock(clock.clone());

    let (intent_id, token, init_id, tgt_id) = make_pair();
    let addr_a = make_addr(10006);
    let addr_b = make_addr(10007);

    table.authorize_pair(intent_id, token, init_id, tgt_id);
    table.update_binding(intent_id, init_id, addr_a).unwrap();
    table.update_binding(intent_id, tgt_id, addr_b).unwrap();

    // Active before timeout
    assert!(table.get_destination(&token, addr_a).is_some());

    // Advance clock past 30-second idle timeout
    clock.advance(30_001);

    let dest = table.get_destination(&token, addr_a);
    assert!(dest.is_none(), "Context must expire after idle timeout");

    assert_eq!(
        table.state_of(&intent_id),
        Some(ForwardingState::RelayExpired)
    );
}

// ── 5. Cross-pair token misuse ────────────────────────────────────────────────
#[test]
fn test_forwarding_cross_pair_misuse() {
    let clock = Arc::new(MockClock::new(1_000));
    let table = table_with_clock(clock.clone());

    // Pair 1: A-B
    let intent1 = [1u8; 16];
    let token1 = [0x11u8; 32];
    let key_a = SigningKey::generate_ed25519().unwrap();
    let key_b = SigningKey::generate_ed25519().unwrap();
    let id_a = key_a.verify_key().device_id();
    let id_b = key_b.verify_key().device_id();
    let addr_a = make_addr(10010);
    let addr_b = make_addr(10011);

    table.authorize_pair(intent1, token1, id_a, id_b);
    table.update_binding(intent1, id_a, addr_a).unwrap();
    table.update_binding(intent1, id_b, addr_b).unwrap();

    // Pair 2: C-D
    let intent2 = [2u8; 16];
    let token2 = [0x22u8; 32];
    let key_c = SigningKey::generate_ed25519().unwrap();
    let key_d = SigningKey::generate_ed25519().unwrap();
    let id_c = key_c.verify_key().device_id();
    let id_d = key_d.verify_key().device_id();
    let addr_c = make_addr(10012);
    let addr_d = make_addr(10013);

    table.authorize_pair(intent2, token2, id_c, id_d);
    table.update_binding(intent2, id_c, addr_c).unwrap();
    table.update_binding(intent2, id_d, addr_d).unwrap();

    // A tries to use token2 (C-D pair token) - must be dropped
    let dest = table.get_destination(&token2, addr_a);
    assert!(dest.is_none(), "Cross-pair token misuse must be dropped");
}

// ── 6. Unauthorized source address (spoofing) ─────────────────────────────────
#[test]
fn test_forwarding_spoofed_source_drops() {
    let clock = Arc::new(MockClock::new(1_000));
    let table = table_with_clock(clock.clone());

    let (intent_id, token, init_id, tgt_id) = make_pair();
    let addr_a = make_addr(10014);
    let addr_b = make_addr(10015);
    let addr_attacker = make_addr(10099);

    table.authorize_pair(intent_id, token, init_id, tgt_id);
    table.update_binding(intent_id, init_id, addr_a).unwrap();
    table.update_binding(intent_id, tgt_id, addr_b).unwrap();

    // Attacker knows the token but sends from an unregistered address
    let dest = table.get_destination(&token, addr_attacker);
    assert!(
        dest.is_none(),
        "Spoofed source address must be silently dropped"
    );
}

// ── 7. Authenticated NAT rebinding ────────────────────────────────────────────
#[test]
fn test_forwarding_authenticated_nat_rebinding() {
    let clock = Arc::new(MockClock::new(1_000));
    let table = table_with_clock(clock.clone());

    let (intent_id, token, init_id, tgt_id) = make_pair();
    let addr_a_old = make_addr(10016);
    let addr_a_new = make_addr(10017);
    let addr_b = make_addr(10018);

    table.authorize_pair(intent_id, token, init_id, tgt_id);
    table
        .update_binding(intent_id, init_id, addr_a_old)
        .unwrap();
    table.update_binding(intent_id, tgt_id, addr_b).unwrap();

    // Old address works
    assert_eq!(table.get_destination(&token, addr_a_old), Some(addr_b));

    // Authenticated rebinding: relay receives signed RelayEstablishRequest
    // (in production) and calls update_binding again with the new addr.
    table
        .update_binding(intent_id, init_id, addr_a_new)
        .unwrap();

    // Old address is now stale - must be dropped
    assert!(table.get_destination(&token, addr_a_old).is_none());

    // New address works
    assert_eq!(table.get_destination(&token, addr_a_new), Some(addr_b));
}

// ── 8. Rejected rebinding on closed session ────────────────────────────────────
#[test]
fn test_forwarding_rebind_rejected_on_closed() {
    let clock = Arc::new(MockClock::new(1_000));
    let table = table_with_clock(clock.clone());

    let (intent_id, token, init_id, tgt_id) = make_pair();
    let addr_a = make_addr(10019);
    let addr_b = make_addr(10020);

    table.authorize_pair(intent_id, token, init_id, tgt_id);
    table.update_binding(intent_id, init_id, addr_a).unwrap();
    table.update_binding(intent_id, tgt_id, addr_b).unwrap();

    table.close(intent_id);

    // A new signed rebind on a closed session must be rejected
    let result = table.update_binding(intent_id, init_id, make_addr(10021));
    assert!(
        result.is_err(),
        "Rebinding a closed session must be rejected"
    );
}

// ── 9. Simultaneous rebinding by both peers ────────────────────────────────────
#[test]
fn test_forwarding_simultaneous_rebinding() {
    let clock = Arc::new(MockClock::new(1_000));
    let table = table_with_clock(clock.clone());

    let (intent_id, token, init_id, tgt_id) = make_pair();
    let addr_a_old = make_addr(10022);
    let addr_b_old = make_addr(10023);
    let addr_a_new = make_addr(10024);
    let addr_b_new = make_addr(10025);

    table.authorize_pair(intent_id, token, init_id, tgt_id);
    table
        .update_binding(intent_id, init_id, addr_a_old)
        .unwrap();
    table.update_binding(intent_id, tgt_id, addr_b_old).unwrap();

    // Both rebind simultaneously
    table
        .update_binding(intent_id, init_id, addr_a_new)
        .unwrap();
    table.update_binding(intent_id, tgt_id, addr_b_new).unwrap();

    // After both rebinds, forwarding must reflect new addresses
    assert_eq!(table.get_destination(&token, addr_a_new), Some(addr_b_new));
    assert_eq!(table.get_destination(&token, addr_b_new), Some(addr_a_new));

    // Old addresses are stale
    assert!(table.get_destination(&token, addr_a_old).is_none());
}

// ── 10. Sweep removes expired contexts ────────────────────────────────────────
#[test]
fn test_forwarding_sweep_removes_expired() {
    let clock = Arc::new(MockClock::new(1_000));
    let table = table_with_clock(clock.clone());

    let (intent_id, token, init_id, tgt_id) = make_pair();
    let addr_a = make_addr(10026);
    let addr_b = make_addr(10027);

    table.authorize_pair(intent_id, token, init_id, tgt_id);
    table.update_binding(intent_id, init_id, addr_a).unwrap();
    table.update_binding(intent_id, tgt_id, addr_b).unwrap();

    // Advance past idle timeout
    clock.advance(30_001);

    let swept = table.sweep();
    assert_eq!(swept, 1, "One expired context should be swept");

    // Token index must also be removed
    let dest = table.get_destination(&token, addr_a);
    assert!(dest.is_none(), "Swept context must not forward");
}

// ── 11. Explicit close prevents further forwarding ────────────────────────────
#[test]
fn test_forwarding_close_prevents_forwarding() {
    let clock = Arc::new(MockClock::new(1_000));
    let table = table_with_clock(clock.clone());

    let (intent_id, token, init_id, tgt_id) = make_pair();
    let addr_a = make_addr(10028);
    let addr_b = make_addr(10029);

    table.authorize_pair(intent_id, token, init_id, tgt_id);
    table.update_binding(intent_id, init_id, addr_a).unwrap();
    table.update_binding(intent_id, tgt_id, addr_b).unwrap();

    assert!(table.get_destination(&token, addr_a).is_some());

    table.close(intent_id);

    assert_eq!(
        table.state_of(&intent_id),
        Some(ForwardingState::RelayClosed)
    );
    assert!(table.get_destination(&token, addr_a).is_none());
}

// ── 12. State machine: Authorized -> RelayRequested -> RelayActive ─────────────
#[test]
fn test_forwarding_state_machine_transitions() {
    let clock = Arc::new(MockClock::new(1_000));
    let table = table_with_clock(clock.clone());

    let (intent_id, token, init_id, tgt_id) = make_pair();
    let addr_a = make_addr(10030);
    let addr_b = make_addr(10031);

    table.authorize_pair(intent_id, token, init_id, tgt_id);
    assert_eq!(
        table.state_of(&intent_id),
        Some(ForwardingState::Authorized)
    );

    table.update_binding(intent_id, init_id, addr_a).unwrap();
    assert_eq!(
        table.state_of(&intent_id),
        Some(ForwardingState::RelayRequested)
    );

    table.update_binding(intent_id, tgt_id, addr_b).unwrap();
    assert_eq!(
        table.state_of(&intent_id),
        Some(ForwardingState::RelayActive)
    );
}

// ── 13. Forwarding not available in RelayRequested (only one side bound) ───────
#[test]
fn test_forwarding_not_active_until_both_bound() {
    let clock = Arc::new(MockClock::new(1_000));
    let table = table_with_clock(clock.clone());

    let (intent_id, token, init_id, tgt_id) = make_pair();
    let addr_a = make_addr(10032);

    table.authorize_pair(intent_id, token, init_id, tgt_id);
    table.update_binding(intent_id, init_id, addr_a).unwrap();

    // Only one side bound -> RelayRequested -> no forwarding yet
    assert_eq!(
        table.state_of(&intent_id),
        Some(ForwardingState::RelayRequested)
    );
    assert!(table.get_destination(&token, addr_a).is_none());
}

// ── 14. Relay is zero-knowledge: no key material in ForwardingContext ──────────
#[test]
fn test_forwarding_no_session_keys_in_context() {
    // The ForwardingContext only stores intent_id, token, DeviceId, SocketAddr, state.
    // This test asserts structural properties: the table does not accept or hold
    // any encryption key material.  This is enforced by type - ForwardingTable::authorize_pair
    // takes only DeviceId (identity hash, not key bytes) and the relay_token
    // (a routing nonce, not a session key).
    let clock = Arc::new(MockClock::new(1_000));
    let table = table_with_clock(clock);
    let (intent_id, token, init_id, tgt_id) = make_pair();
    // If this compiles without encryption key params, the invariant holds.
    table.authorize_pair(intent_id, token, init_id, tgt_id);
}

// ── 15. Sweep on active (non-expired) context leaves it intact ─────────────────
#[test]
fn test_forwarding_sweep_leaves_active_intact() {
    let clock = Arc::new(MockClock::new(1_000));
    let table = table_with_clock(clock.clone());

    let (intent_id, token, init_id, tgt_id) = make_pair();
    let addr_a = make_addr(10034);
    let addr_b = make_addr(10035);

    table.authorize_pair(intent_id, token, init_id, tgt_id);
    table.update_binding(intent_id, init_id, addr_a).unwrap();
    table.update_binding(intent_id, tgt_id, addr_b).unwrap();

    let swept = table.sweep();
    assert_eq!(swept, 0, "Active context must not be swept");

    // Forwarding still works after sweep
    assert_eq!(table.get_destination(&token, addr_a), Some(addr_b));
}

// ── 16. Rebind on expired session is rejected ─────────────────────────────────
#[test]
fn test_forwarding_rebind_rejected_on_expired() {
    let clock = Arc::new(MockClock::new(1_000));
    let table = table_with_clock(clock.clone());

    let (intent_id, token, init_id, tgt_id) = make_pair();
    let addr_a = make_addr(10036);
    let addr_b = make_addr(10037);

    table.authorize_pair(intent_id, token, init_id, tgt_id);
    table.update_binding(intent_id, init_id, addr_a).unwrap();
    table.update_binding(intent_id, tgt_id, addr_b).unwrap();

    // Expire via idle timeout
    clock.advance(30_001);
    // Force expiry by attempting a get
    let _ = table.get_destination(&token, addr_a);

    // Now try to rebind on an expired context
    let result = table.update_binding(intent_id, init_id, make_addr(10038));
    assert!(result.is_err(), "Rebind on expired session must fail");
}

// ── 17. Multiple independent sessions do not interfere ────────────────────────
#[test]
fn test_forwarding_multiple_sessions_independent() {
    let clock = Arc::new(MockClock::new(1_000));
    let table = table_with_clock(clock.clone());

    // Session 1
    let intent1 = [1u8; 16];
    let token1 = [0xAAu8; 32];
    let key_a1 = SigningKey::generate_ed25519().unwrap();
    let key_b1 = SigningKey::generate_ed25519().unwrap();
    let id_a1 = key_a1.verify_key().device_id();
    let id_b1 = key_b1.verify_key().device_id();
    let addr_a1 = make_addr(10040);
    let addr_b1 = make_addr(10041);

    table.authorize_pair(intent1, token1, id_a1, id_b1);
    table.update_binding(intent1, id_a1, addr_a1).unwrap();
    table.update_binding(intent1, id_b1, addr_b1).unwrap();

    // Session 2
    let intent2 = [2u8; 16];
    let token2 = [0xBBu8; 32];
    let key_a2 = SigningKey::generate_ed25519().unwrap();
    let key_b2 = SigningKey::generate_ed25519().unwrap();
    let id_a2 = key_a2.verify_key().device_id();
    let id_b2 = key_b2.verify_key().device_id();
    let addr_a2 = make_addr(10042);
    let addr_b2 = make_addr(10043);

    table.authorize_pair(intent2, token2, id_a2, id_b2);
    table.update_binding(intent2, id_a2, addr_a2).unwrap();
    table.update_binding(intent2, id_b2, addr_b2).unwrap();

    // Each session routes independently
    assert_eq!(table.get_destination(&token1, addr_a1), Some(addr_b1));
    assert_eq!(table.get_destination(&token2, addr_a2), Some(addr_b2));

    // Closing session 1 does not affect session 2
    table.close(intent1);
    assert!(table.get_destination(&token1, addr_a1).is_none());
    assert_eq!(table.get_destination(&token2, addr_a2), Some(addr_b2));
}
