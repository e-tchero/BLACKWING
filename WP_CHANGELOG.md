# Work Package & Architecture Changelog

**Last Updated:** 2026-08-21
**Phase:** Full-stack implementation complete

This document tracks every structural, architectural, and work package change made to PROJECT BLACKWING. It is written so that any engineer or AI agent can understand exactly what happened, in what order, and why.

---

## Milestone 0: Repository Triage (Completed)

### What was found
The repository had no functioning Cargo workspace. The only `Cargo.toml` that existed was `crates/bw-crypto/cargo.toml` (lowercase), and it was incorrectly written as a workspace manifest pointing to itself — a self-referential loop that made it impossible for Cargo to resolve dependencies or compile anything.

Additional problems found:
- No root `Cargo.toml` workspace manifest.
- The MSVC toolchain was the default but the machine has no Visual Studio Build Tools or Windows SDK — so the linker would fail.
- `DalekVerifyKey` struct was referenced in the codebase but never defined anywhere.
- `secret.rs` was an orphan file — not declared in `lib.rs` and would not compile standalone.
- TPM backend methods were entirely absent.
- `proptest!` macro blocks had incorrect `Result<(), TestCaseError>` return types.

### What was fixed

| Fix | Detail |
|---|---|
| Created root `Cargo.toml` | Workspace manifest with `resolver = "2"` |
| Replaced `bw-crypto/cargo.toml` | Proper `[package]` manifest with all dependencies |
| Switched toolchain to GNU | `stable-x86_64-pc-windows-gnu`. Installed MinGW via `scoop install mingw`. |
| Added `DalekVerifyKey` struct | Defined in `src/backend/dalek.rs` |
| Fixed `proptest!` macro bodies | Removed `Result<(), TestCaseError>` return types |
| Fixed borrow checker errors | Changed `prop_assert_eq!(s1, s2)` to `prop_assert_eq!(&s1, &s2)` |
| Created `.gitignore` | Excludes `/target`, `*.rs.bk` |

**Result:** `cargo check` ✅, `cargo test` ✅ (13/13), `cargo fmt` ✅, `cargo clippy` ✅.
**Tagged:** `recovery-baseline-v0.1`

---

## Milestone 1: Architecture Audit (Completed)

A full read-only engineering audit was performed. No files were modified.

### Audit Findings
- Single active crate: `bw-crypto`
- 3 recovered source files in `archive/` awaiting migration
- 18+ `.docx` specification documents organized into `docs/`
- No CI pipeline
- No ADRs beyond ADR-001 (Device Identifier)

**Report saved:** `BLACKWING_ENGINEERING_BASELINE.md`

---

## Milestone 1.5: Repository Hard Freeze (Completed)

### Changes Made

| Action | Detail |
|---|---|
| Renamed `archive/recovery/` | → `archive/recovered_sources/` |
| Created `docs/REPOSITORY_MAP.md` | Physical layout of the workspace |
| Created `docs/WORKSPACE_VISION.md` | Dependency direction rules, public API freeze policy |
| Created ADR-002 through ADR-008 | Workspace structure, crate boundaries, memory allocation, crypto backends, error handling, async runtime, logging |
| Tagged | `git tag architecture-baseline-v0.2` |

---

## Work Package 3.1: `bw-core` Crate Bootstrap (Completed)

**Objective:** Create a production-ready empty crate scaffold.

### Files Created

| File | Detail |
|---|---|
| `crates/bw-core/Cargo.toml` | Only dependency: `thiserror = "1"` |
| `crates/bw-core/src/lib.rs` | `#![forbid(unsafe_code)]`, `#![deny(missing_docs)]` |
| `crates/bw-core/src/error.rs` | `BwError` enum via thiserror |
| `crates/bw-core/src/logging.rs` | `LogEvent`, `Severity`, `HealthReport` |
| `crates/bw-core/src/memory.rs` | Zero-allocation buffer pool |
| `crates/bw-core/src/pool.rs` | `StaticSlotPool` with const generics |

**Tagged:** `wp-3.1-complete`

---

## Work Packages 3.2–3.9: `bw-core` Implementation (Completed)

Implemented all core primitives:
- `BwError` enum with `thiserror` integration
- `LogEvent` with severity levels, stacktraces, and serde support
- `HealthReport` for system health monitoring
- `ZeroAllocationPool` — pre-allocated slot pool with atomic CAS
- `StaticSlotPool` — const-generic, type-safe pool with ABA protection
- Property-based tests for all pool behaviors

---

## Work Packages 4.1–4.6: `bw-protocol` Foundation (Completed)

Implemented the wire protocol layer:
- `PacketHeader` — 32-byte, 8-byte aligned, zero-copy via bytemuck
- `ProtocolFrame` / `OwnedProtocolFrame` — wire framing
- `ProtocolMessage` — CBOR serialization with 12 message types (Input, Video, Audio, Clipboard, ICE, etc.)
- `MessageEnvelope` — routing envelope with sender/receiver addresses
- `MessageType` enum — all message categories
- `decode_frame` / `encode_frame` — codec functions

---

## Work Package 4.7: Safety Correction (Completed)

Resolved unsafe lifetime issues in the protocol layer. Ensured all references are properly bounded and no dangling pointers exist in the frame/message pipeline.

---

## Work Package 4.8: Reliable Delivery Layer (Completed)

Implemented reliability primitives:
- Sequence numbers and duplicate detection
- ACK processing and sliding window
- Retransmission scheduling with configurable timeouts
- Ordered delivery with out-of-order buffering
- Comprehensive test suite (6 tests)

---

## Work Package 4.9: Encryption Pipeline (Completed)

Implemented end-to-end encryption:
- `EncryptionContext` — AES-256-GCM encryption/decryption
- Nonce management with uniqueness guarantees
- Replay detection via nonce tracking
- Key rotation with `KeyRotationPolicy`
- `SessionKeys` — send/recv key pair with epoch
- HKDF key derivation from master secrets
- Authentication tag verification
- Comprehensive test suite (9 tests)

---

## Work Package 4.10: Session Integration (Completed)

Bound session lifecycle to encryption:
- `SessionManager` — session creation, lookup, expiry, TTL-based sweeping
- `create_session_from_handshake()` — full handshake → key derivation → session registration
- `with_session_context()` — borrows `EncryptionContext` mutably for atomic state updates
- Session encryption binding — each session has its own encryption context
- End-to-end secure session tests (4 tests)

---

## Work Package 4.11: Dispatcher Routing & Composition (Completed)

Implemented the message routing system:
- `MessageDispatcher` — handler registry with `HashMap<MessageType, Vec<Box<dyn MessageHandler>>>`
- `MessageHandler` trait — `handle(&self, envelope) -> Result<(), ProtocolError>`
- `register_handler()` / `unregister_handlers()` — dynamic handler management
- `dispatch()` — validates envelope, looks up handlers, dispatches to all matching handlers
- `run()` — async loop: `transport.receive()` → deserialize → `dispatch()`
- DRR (Deficit Round Robin) priority scheduler for QUIC stream multiplexing
- Integration with `bw-net` receive loop
- Comprehensive test suite (8 dispatcher tests + 6 scheduler tests)

---

## Work Package 5.0: Network Bootstrap (Completed)

Bootstrapped the `bw-net` crate:
- `UdpTransport` — Tokio `UdpSocket` wrapper implementing `Transport` trait
- `run_receive_loop()` — core receive loop: reads datagrams, decodes frames, dispatches to protocol layer
- `ConnectionManager` — spawns and manages connection tasks with cancellation tokens
- `ConnectionHandle` — opaque handle with automatic cleanup on drop
- Oversized datagram detection, error handling, graceful shutdown
- Integration test: UDP receive → frame decode → message dispatch

---

## Work Package 6.0–6.2: QUIC Transport (Completed)

Implemented QUIC transport layer:
- `QuicClient` / `QuicServer` — QUIC endpoint management
- `ProtocolTransportAdapter` — bridges `bw-protocol::Transport` to `bw-net::Transport`
- Secure connection lifecycle with certificate management
- `RelayUdpSocket` — QUIC over relay
- E2E tests: QUIC handshake and data exchange

---

## Work Package 7.0: Screen Capture (Completed)

Implemented screen capture pipeline:
- DXGI capture backend (Windows Desktop Duplication API)
- Windows Graphics Capture (WGC) backend
- Frame buffer management with dirty rect tracking
- Cursor overlay and position tracking
- Monitor enumeration and selection
- Lifecycle management (start/stop)

---

## Work Package 8.0: Relay Server (Completed)

Implemented the relay infrastructure:
- Token-based forwarding with expiry and session quotas
- Rendezvous protocol for NAT traversal
- Rate limiting with configurable thresholds
- Brute-force blocklist protection
- Spoofed source detection
- Session sweep for expired connections
- Comprehensive test suite (33 tests)

---

## Work Package 9.0: Video Encoding (Completed)

Implemented video encoding:
- H.264 encoding pipeline via OpenH264
- Frame fragmentation for MTU compliance
- End-to-end streaming test

---

## Work Package 10.0: Full-Stack Integration (Completed)

Integrated all subsystems into working client/server applications:
- `bw-input` — Win32 `SendInput` injection, keyboard/mouse mapping from winit keycodes
- `bw-clipboard` — clipboard polling, text/image roundtrip via arboard
- `bw-audio` — Opus audio capture/playback via cpal
- `bw-client` — winit rendering loop, video decoding, input event capture
- `bw-server` — dispatcher wiring, input injection, audio capture, clipboard handling
- End-to-end interactivity tests, ICE signaling tests, session wire tests

---

## Architectural Principles Established (Locked)

These decisions are locked. Do not reverse without creating a new ADR.

| Principle | Detail |
|---|---|
| Dependency direction | `bw-core` → `bw-crypto` → `bw-protocol` → `bw-net` → applications |
| Default visibility | `pub(crate)`. Only `pub` after ADR review. |
| No unsafe in `bw-core` | `#![forbid(unsafe_code)]` enforced at compiler level. |
| No panics in library code | Workspace lints deny `unwrap_used` and `expect_used`. |
| No virtualisation in hot paths | Enum dispatch, not trait objects. |
| Zeroize on Drop | All secret-bearing types implement `ZeroizeOnDrop`. |
| DeviceId format | `bw-id-` prefix + 64 lowercase hex chars (32 bytes SHA-256 of Ed25519 public key). |
| Quality gates mandatory | All five gates must pass before any WP is tagged complete. |
| Workspace lint policy | All crates inherit `[lints] workspace = true`. |
| No attributions in commits | Never include AI agent signatures, robot emojis (🤖), Co-authored-by lines, or any attribution footer in git commit messages unless explicitly requested. |

---

## Current Status Summary

| Metric | Value |
|---|---|
| Workspace crates | 17 |
| Source modules | 80+ |
| Tests | 228 (0 failures) |
| Benchmark binaries | 21 |
| `unsafe` blocks | 0 |
| `unimplemented!()` calls | 0 |
| `todo!()` calls | 0 |
| `unwrap()` in library code | 0 |
| `expect()` in library code | 0 |
