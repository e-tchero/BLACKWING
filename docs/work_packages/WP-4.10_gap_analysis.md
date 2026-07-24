# WP-4.10 — Gap Analysis

> Based on a verbatim audit of every source file, test file, and dependency in `bw-protocol` at commit `2a82c7d`.

---

## Current Capability Inventory

| Module | What exists | Lines | Tests |
|--------|-------------|-------|-------|
| [error.rs](file:///C:/BLACKWING/crates/bw-protocol/src/error.rs) | `ProtocolError` enum with 15 variants | 68 | — |
| [frame.rs](file:///C:/BLACKWING/crates/bw-protocol/src/frame.rs) | `ProtocolFrame<'a>` (borrowed), `OwnedProtocolFrame` (owned), `borrow()` | 34 | 7 |
| [header.rs](file:///C:/BLACKWING/crates/bw-protocol/src/header.rs) | `PacketHeader` (32-byte, `#[repr(C)]`, bytemuck), `try_from_bytes`, `validate` | 84 | 5 |
| [version.rs](file:///C:/BLACKWING/crates/bw-protocol/src/version.rs) | `ProtocolVersion`, `CURRENT_VERSION`, `is_compatible_with`, `u16` conversions | 45 | — |
| [codec.rs](file:///C:/BLACKWING/crates/bw-protocol/src/codec.rs) | `encode_frame`, `decode_frame` | 64 | (covered by frame_tests) |
| [handshake.rs](file:///C:/BLACKWING/crates/bw-protocol/src/handshake.rs) | `Capabilities`, `HandshakeRequest`, `HandshakeResponse`, `HandshakeStatus`, `negotiate_capabilities` | 128 | 9 |
| [message.rs](file:///C:/BLACKWING/crates/bw-protocol/src/message.rs) | `MessageType` (8 variants), `ProtocolMessage` with serialize/deserialize/validate | 80 | 5 |
| [routing.rs](file:///C:/BLACKWING/crates/bw-protocol/src/routing.rs) | `NodeId`, `SessionId([u8; 16])`, `Route` (Direct/Broadcast/Loopback/Relay), `MessageEnvelope` | 118 | 7 |
| [session.rs](file:///C:/BLACKWING/crates/bw-protocol/src/session.rs) | `SessionManager` wrapping `Mutex<HashSet<SessionId>>` with create/close/validate/lookup | 83 | (covered by routing_tests) |
| [transport.rs](file:///C:/BLACKWING/crates/bw-protocol/src/transport.rs) | `Transport` trait (boxed futures), `MockTransport`, `ConnectionState` | 126 | 2 |
| [dispatcher.rs](file:///C:/BLACKWING/crates/bw-protocol/src/dispatcher.rs) | `MessageDispatcher` with `dispatch` (validates envelope) and `run` (receives from transport) | 46 | (covered by transport_tests) |
| [reliability.rs](file:///C:/BLACKWING/crates/bw-protocol/src/reliability.rs) | `SequenceNumber`, `SlidingWindow`, `DuplicateFilter`, `OrderedAssembler`, `ReliableSender`, `ReliableReceiver`, `AckFrame`, `ReliableFrame`, `TimeoutPolicy`, `RetransmissionEntry`, `DeliveryState` | 344 | 6 |
| [encryption.rs](file:///C:/BLACKWING/crates/bw-protocol/src/encryption.rs) | `Nonce`, `AuthenticationTag`, `EncryptedFrame`, `SessionKeys`, `ReplayProtection`, `KeyRotationPolicy`, `FrameEncryptor`, `FrameDecryptor`, `EncryptionContext` | 335 | 9 |

**Total tests: 50 test functions across 8 test files.**

---

## Missing Capabilities (Verified Gaps)

### Gap 1: `session.rs` has no connection to `encryption.rs`

**What exists:**
- `SessionManager` tracks `SessionId` membership in a `HashSet`.
- `EncryptionContext` holds a `FrameEncryptor` + `FrameDecryptor` + `KeyRotationPolicy`.
- These two systems are completely independent.

**What is missing:**
- No mechanism to associate an `EncryptionContext` with a `SessionId`.
- No way to look up encryption state by session.
- No way to create a session that has keys.

**Evidence:**
- [session.rs](file:///C:/BLACKWING/crates/bw-protocol/src/session.rs) imports only `crate::error::ProtocolError` and `crate::routing::SessionId`.
- [encryption.rs](file:///C:/BLACKWING/crates/bw-protocol/src/encryption.rs) has no concept of `SessionId`.

---

### Gap 2: `handshake.rs` output does not feed into session or encryption creation

**What exists:**
- `HandshakeResponse` contains `session_id: [u8; 16]`, `server_nonce: [u8; 16]`.
- `HandshakeRequest` contains `nonce: [u8; 16]`.
- `SessionKeys` exists with `send_key`, `recv_key`, `epoch`.

**What is missing:**
- No function that takes a completed handshake (client nonce + server nonce + shared secret) and produces `SessionKeys`.
- No function that takes a `HandshakeResponse` and creates a session in the `SessionManager`.
- The nonces exchanged during handshake are unused after validation.

**Evidence:**
- `handshake.rs` does not import `encryption`, `session`, or `bw_crypto::hkdf_derive`.
- `encryption.rs` does not import `handshake`.

---

### Gap 3: No per-session key derivation

**What exists:**
- `bw_crypto::hkdf_derive` is available and used inside `FrameEncryptor::rotate_keys` / `FrameDecryptor::rotate_keys` for epoch rotation.
- `SessionKeys` requires externally constructed `SymmetricKey` values.

**What is missing:**
- No function derives distinct per-session keys from a master secret or handshake material.
- Callers must manually construct `SessionKeys` with raw key bytes.

**Evidence:**
- The only call sites for `hkdf_derive` are in `FrameEncryptor::rotate_keys` (line 180) and `FrameDecryptor::rotate_keys` (line 260), both using `send-epoch-{N}` / `recv-epoch-{N}` info strings for rotation — not for initial derivation.

---

### Gap 4: No session expiry or lifecycle management

**What exists:**
- `SessionManager::create_session` inserts a `SessionId`.
- `SessionManager::close_session` removes a `SessionId`.

**What is missing:**
- No timestamp or TTL associated with a session.
- No mechanism to expire stale sessions.
- No session state beyond "exists" or "does not exist".

**Evidence:**
- `SessionManager` field is `active_sessions: Mutex<HashSet<SessionId>>` — a bare set with no metadata per session.

---

### Gap 5: `dispatcher.rs` does not actually route messages

**What exists:**
- `MessageDispatcher::dispatch` calls `envelope.validate()` and returns `Ok(())`.
- `MessageDispatcher::run` loops receiving frames, decoding them, but the decoded frames are not dispatched anywhere.

**What is missing:**
- No handler registration or callback mechanism.
- No routing of messages to session-specific handlers.
- `dispatch` is effectively a no-op after validation.

**Evidence:**
- `MessageDispatcher` is an empty struct: `pub struct MessageDispatcher {}`.
- `dispatch` body (after validation) is just `Ok(())`.

---

### Gap 6: `reliability.rs` and `encryption.rs` are not composed

**What exists:**
- `ReliableSender` produces `ReliableFrame` (with sequence number + payload).
- `FrameEncryptor` encrypts `OwnedProtocolFrame`.

**What is missing:**
- No pipeline that takes a message, wraps it in a `ReliableFrame`, then encrypts it as an `EncryptedFrame`.
- No pipeline that decrypts an `EncryptedFrame`, then feeds the result into `ReliableReceiver`.
- The two layers operate on different types with no adapter.

**Evidence:**
- `reliability.rs` does not import `encryption`.
- `encryption.rs` does not import `reliability`.

---

### Gap 7: Constant-time comparison is not used for security-sensitive equality

**What exists:**
- `SessionId`, `Nonce`, `AuthenticationTag`, handshake nonces all derive `PartialEq`.
- Standard `==` (byte-by-byte, short-circuiting) is used for all comparisons.

**What is missing:**
- No use of `subtle::ConstantTimeEq` or equivalent anywhere in the crate.
- Token and nonce comparisons are vulnerable to timing side-channels.

**Evidence:**
- `grep` for `subtle`, `ConstantTimeEq`, `constant_time` returns zero results across all source files.

---

### Gap 8: `zeroize` is declared but never used

**What exists:**
- `zeroize = { workspace = true }` in `Cargo.toml`.

**What is missing:**
- No `use zeroize` statement in any source file.
- `SessionKeys`, `FrameEncryptor`, `FrameDecryptor` hold `SymmetricKey` values but do not implement `ZeroizeOnDrop` or call `zeroize()`.
- Dropped keys remain in memory.

**Evidence:**
- Zero occurrences of `zeroize` in any `.rs` file under `src/`.

---

### Gap 9: `bw-core` is declared but never used

**What exists:**
- `bw-core = { path = "../bw-core" }` in `Cargo.toml`.

**What is missing:**
- No `use bw_core` statement in any source file.
- This is a dead dependency.

**Evidence:**
- Zero occurrences of `bw_core` in any `.rs` file under `src/`.

---

### Gap 10: No session resumption mechanism

**What exists:**
- Handshake can establish a new session.
- `SessionManager` can check if a session exists.

**What is missing:**
- No way to resume a previously established session without repeating the full handshake.
- No resumption token or session ticket mechanism.

**Evidence:**
- `SessionManager` has only `create_session`, `close_session`, `validate_session`, `lookup_session`.
- No method accepts prior session state for resumption.

---

## Summary Table

| Gap | Category | Severity |
|-----|----------|----------|
| 1. Session ↔ Encryption binding | Integration | **High** — sessions exist without keys |
| 2. Handshake → Session creation | Integration | **High** — handshake output is unused |
| 3. Per-session key derivation | Cryptographic | **High** — keys must be manually constructed |
| 4. Session expiry/lifecycle | State management | **Medium** — no TTL, no cleanup |
| 5. Dispatcher routing | Message delivery | **Medium** — dispatch is a no-op |
| 6. Reliability ↔ Encryption composition | Integration | **Medium** — two layers don't connect |
| 7. Constant-time comparison | Security | **High** — timing side-channel risk |
| 8. Zeroize on drop | Security | **Medium** — keys linger in memory |
| 9. Unused `bw-core` dependency | Hygiene | **Low** — dead dependency |
| 10. Session resumption | Feature | **Low** — not critical for initial operation |

---

## WP-4.10 Scope (Derived from Gaps)

WP-4.10 addresses the following **high-severity integration and security gaps** that prevent the existing modules from functioning as a coherent protocol stack:

- **Gap 1: Session ↔ Encryption Context association.** Provide a way to associate encryption contexts with session identifiers.
- **Gap 2: Handshake → Session flow.** Consume nonces and handshake results to create session states.
- **Gap 3: Per-session key derivation.** Integrate key derivation from handshake secrets/nonces.
- **Gap 7: Constant-time comparison.** Hard check sensitive byte identifiers for timing attacks.
- **Gap 8: Zeroize on drop.** Ensure keys are wiped when session contexts are dropped.
- **Gap 9: Unused `bw-core` dependency.** Clean up dependency declaration.

All other medium and low severity gaps are deferred as design options or future features.
