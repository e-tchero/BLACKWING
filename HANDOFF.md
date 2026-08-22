# PROJECT BLACKWING — Master Handoff Document

> **CRITICAL:** If you are a new AI agent reading this, read this document top-to-bottom BEFORE touching any file or running any command. This document is the single source of truth for the current state of this project.
>
> **Last Updated:** 2026-08-21
> **Repository Root:** `C:\BLACKWING`
> **Current Phase:** Full-stack implementation complete. Production hardening and CI/CD in progress.

---

## 0. How to Read This Document

1. Read sections 1-4 to understand what this project is and where it stands.
2. Read section 5 to understand the toolchain constraints — this is the most critical environmental fact.
3. Read section 6 to understand the current build status.
4. Read section 7 to understand the workspace structure.
5. Read sections 8-9 to understand what was done and the quality gates.
6. Never skip the quality gate checks described in section 9.

---

## 1. Project Summary

**PROJECT BLACKWING** is a remote desktop and device-management platform built in Rust. It is a monorepo structured as a Cargo workspace with 17 crates covering cryptography, protocol, networking, transport, relay, capture, encoding, input injection, clipboard, audio, ICE/STUN, authentication, and client/server applications.

The project is similar in scope to RustDesk but with a focus on enterprise cryptographic identity, zero-allocation memory primitives, QUIC transport, OPAQUE PAKE authentication, and a clean multi-crate workspace architecture.

---

## 2. Architectural Philosophy (agreed with the user)

The following principles were explicitly discussed and adopted. **Do not contradict them.**

- **No virtual dispatch in hot paths.** Use enum dispatch instead of trait objects.
- **No unsafe code in `bw-core`.** `lib.rs` enforces `#![forbid(unsafe_code)]`.
- **No allocation in pool hot paths.** Memory pools pre-allocate and use atomic CAS.
- **Zeroize on Drop** for all types that hold secrets.
- **No circular dependencies** between crates. Flow is strictly top-down.
- **Default visibility is `pub(crate)`.** Only expose `pub` after an explicit ADR review.
- **No panics in library code.** Workspace lints deny `unwrap_used` and `expect_used`.
- **Every public API decision is traceable to an ADR.**
- **Workspace-wide lint policy.** All crates inherit `[lints] workspace = true`.
- **No attributions in commits.** Never include AI agent signatures, robot emojis (🤖), Co-authored-by lines, or any attribution footer in git commit messages unless the user explicitly requests it.

---

## 3. Dependency Direction (strictly enforced)

```text
bw-core          ← bottom of the stack, no dependencies on other bw-* crates
   ↓
bw-crypto        ← depends on bw-core only
   ↓
bw-protocol      ← depends on bw-crypto only (no bw-net dependency)
   ↓
bw-net           ← depends on bw-protocol only
   ↓
bw-session       ← depends on bw-protocol, bw-crypto
bw-transport     ← depends on bw-protocol, bw-crypto, bw-net
bw-auth          ← depends on bw-crypto
   ↓
bw-capture / bw-relay / bw-ice  ← depend on bw-net and below
bw-encoder / bw-decoder         ← depend on bw-core, bw-crypto
bw-audio / bw-clipboard / bw-input  ← depend on bw-protocol, bw-core
   ↓
bw-client / bw-server  ← top-level applications
```

**Forbidden:** Any upward or sideways dependency (e.g., `bw-core` depending on `bw-protocol`).

---

## 4. Toolchain — CRITICAL ENVIRONMENTAL FACT

> Do NOT attempt to build with the MSVC toolchain. It will fail.

| Fact | Detail |
|---|---|
| **Active Rust toolchain** | `stable-x86_64-pc-windows-gnu` |
| **Rustc version** | `1.96.1` |
| **Why GNU?** | The machine has no Visual Studio Build Tools / Windows SDK installed. MSVC toolchain needs `link.exe`, `kernel32.lib`, etc. GNU uses MinGW GCC and does not need them. |
| **MinGW location** | Installed via `scoop install mingw` (non-admin) |
| **MinGW path** | `C:\Users\ETCHE\scoop\apps\mingw\current\bin` |

**All cargo commands must be run as:**
```powershell
$env:PATH = "C:\Users\ETCHE\scoop\apps\mingw\current\bin;" + $env:PATH
cargo +stable-x86_64-pc-windows-gnu <command>
```

Or simply:
```powershell
cargo <command>   # if the default toolchain is already set to GNU
```

---

## 5. Current Build Status

| Command | Status |
|---|---|
| `cargo fmt --check` | ✅ Clean (exit 0) |
| `cargo check --workspace` | ✅ 0 errors, 0 warnings |
| `cargo test --workspace` | ✅ **228/228 tests pass** |
| `cargo clippy --workspace -- -D warnings` | ✅ 0 warnings |
| `cargo bench --no-run --workspace` | ✅ 21 benchmark binaries compile |

---

## 6. Workspace Members (17 crates)

```toml
# C:\BLACKWING\Cargo.toml
[workspace]
resolver = "2"
members = [
    "crates/bw-core",
    "crates/bw-crypto",
    "crates/bw-protocol",
    "crates/bw-net",
    "crates/bw-session",
    "crates/bw-transport",
    "crates/bw-auth",
    "crates/bw-capture",
    "crates/bw-encoder",
    "crates/bw-decoder",
    "crates/bw-relay",
    "crates/bw-ice",
    "crates/bw-input",
    "crates/bw-clipboard",
    "crates/bw-audio",
    "crates/bw-client",
    "crates/bw-server",
]
```

### Crate Responsibilities

| Crate | Responsibility | Status | Tests |
|---|---|---|---|
| **bw-core** | Error types, logging, zero-alloc memory pools | ✅ Complete | 17 |
| **bw-crypto** | Ed25519 identity, HMAC-SHA256, HKDF, symmetric encryption | ✅ Complete | 13 |
| **bw-protocol** | Wire protocol: frames, headers, CBOR messages, codec, dispatcher, encryption, reliability, session management, handshake, routing, scheduler | ✅ Complete | 83 |
| **bw-net** | UDP transport, receive loop, connection manager, protocol adapter | ✅ Complete | 5 |
| **bw-session** | Session lifecycle, secure connection, wire protocol bridge | ✅ Complete | 4 |
| **bw-transport** | QUIC client/server, ICE socket binding, relay socket, certificate management, protocol adapter | ✅ Complete | 6 |
| **bw-auth** | OPAQUE PAKE authentication (RFC 9381), client/server | ✅ Complete | 4 |
| **bw-capture** | DXGI/WGC screen capture, frame buffers, cursor tracking | ✅ Complete | 9 |
| **bw-encoder** | H.264 video encoding pipeline | ✅ Complete | 1 |
| **bw-decoder** | H.264 video decoding pipeline | ✅ Complete | 6 |
| **bw-relay** | Relay server, forwarding, rendezvous, NAT traversal, rate limiting | ✅ Complete | 33 |
| **bw-ice** | ICE/STUN agent wrapping webrtc-ice | ✅ Complete | 4 |
| **bw-input** | Win32 SendInput injection, keyboard/mouse mapping | ✅ Complete | 9 |
| **bw-clipboard** | Clipboard polling, text/image roundtrip | ✅ Complete | 7 |
| **bw-audio** | Opus audio capture/playback via cpal | ✅ Complete | 5 |
| **bw-client** | Desktop client application (winit rendering loop) | ✅ Complete | 5 |
| **bw-server** | Host server (dispatcher, input injection, audio, clipboard) | ✅ Complete | 16 |

---

## 7. Protocol Layer Detail (bw-protocol — 15 source modules)

| Module | Responsibility | Complete |
|---|---|---|
| `version.rs` | `ProtocolVersion` enum, compatibility checking | ✅ |
| `header.rs` | 32-byte `PacketHeader` with zero-copy via bytemuck | ✅ |
| `frame.rs` | `ProtocolFrame` / `OwnedProtocolFrame` wire framing | ✅ |
| `message.rs` | `ProtocolMessage` with CBOR serialization, 12 message types | ✅ |
| `codec.rs` | `encode_frame` / `decode_frame` codec functions | ✅ |
| `dispatcher.rs` | `MessageDispatcher` with handler registry and async dispatch loop | ✅ |
| `routing.rs` | `MessageEnvelope`, `RouteType`, `SessionManager` | ✅ |
| `session.rs` | Session creation, TTL expiry, key derivation, encryption binding | ✅ |
| `encryption.rs` | `EncryptionContext`, AES-256-GCM, nonce management, key rotation | ✅ |
| `reliability.rs` | Reliable delivery: sequence numbers, ACKs, retransmission, ordered delivery | ✅ |
| `handshake.rs` | `HandshakeRequest`/`HandshakeResponse`, capability negotiation | ✅ |
| `transport.rs` | `MockTransport` for testing | ✅ |
| `scheduler.rs` | DRR (Deficit Round Robin) priority scheduler for QUIC streams | ✅ |
| `error.rs` | `ProtocolError` enum | ✅ |
| `lib.rs` | Crate root, re-exports | ✅ |

---

## 8. Network Layer Detail (bw-net — 5 source modules)

| Module | Responsibility | Complete |
|---|---|---|
| `udp.rs` | `UdpTransport`, `run_receive_loop` — core receive loop wiring | ✅ |
| `transport.rs` | `Transport` trait, `BoxFuture`, `BoxTransport` | ✅ |
| `connection.rs` | `ConnectionManager`, `ConnectionHandle`, task lifecycle | ✅ |
| `error.rs` | `NetError` enum | ✅ |
| `lib.rs` | Crate root | ✅ |

---

## 9. Repository Tag History (Git)

| Tag | Meaning |
|---|---|
| `recovery-baseline-v0.1` | First buildable state. `cargo test` passes. |
| `architecture-baseline-v0.2` | ADRs, REPOSITORY_MAP, WORKSPACE_VISION added. |
| `wp-3.1-complete` | `bw-core` crate bootstrap complete. |
| `wp-4.10-complete` | Protocol core logic, crypto integration, session management. |
| `wp-5.0-complete` | Network bootstrap, UDP transport, receive loop. |
| `wp-6.x-complete` | QUIC transport, protocol adapter, secure connection lifecycle. |
| `wp-7.0-complete` | Screen capture pipeline (DXGI/WGC). |
| `wp-8.0-complete` | Relay server, forwarding, rendezvous, NAT traversal. |
| `wp-9.0-complete` | H.264 video encoding. |
| `wp-10.0-complete` | Input injection, clipboard, audio, client/server applications. |

---

## 10. Work Package History

### Completed

| WP | Description | Outcome |
|---|---|---|
| WP-3.1 | `bw-core` bootstrap | Empty scaffold, quality gates green |
| WP-3.2–3.9 | `bw-core` implementation | Error types, logging, memory pools |
| WP-4.1–4.6 | `bw-protocol` foundation | Frames, headers, codec, messages |
| WP-4.7 | Safety correction | Resolve unsafe lifetime issues |
| WP-4.8 | Reliable delivery layer | Sequence numbers, ACKs, retransmission |
| WP-4.9 | Encryption pipeline | AES-256-GCM, nonce management, key rotation |
| WP-4.10 | Session integration | Session creation, key derivation, encryption binding |
| WP-4.11 | Dispatcher routing | Handler registry, async dispatch loop, DRR scheduler |
| WP-5.0 | Network bootstrap | UDP transport, receive loop, connection manager |
| WP-6.0–6.2 | QUIC transport | QUIC client/server, protocol adapter, secure connection |
| WP-7.0 | Screen capture | DXGI/WGC capture, frame buffers, cursor tracking |
| WP-8.0 | Relay server | Forwarding, rendezvous, NAT traversal, rate limiting |
| WP-9.0 | Video encoding | H.264 encoding pipeline |
| WP-10.0 | Full-stack integration | Input injection, clipboard, audio, client/server apps |

### Current State

**All planned work packages through WP-10.0 are complete.** The codebase has:
- 17 workspace crates
- 228 passing tests (0 failures)
- 21 benchmark binaries
- Zero `unimplemented!()`, `todo!()`, `unsafe`, or `unwrap()` in library code
- Workspace-wide lint enforcement (`unsafe_code = "forbid"`, `clippy::unwrap_used = "deny"`)
- No CI/CD pipeline yet (GitHub Actions workflow needed)

---

## 11. Quality Gate Checklist (Run After Every WP)

Run this sequence after EVERY work package completes. Do not skip any step.

```powershell
cargo fmt --check
# Expected: exit 0 (no diffs)

cargo check --workspace
# Expected: 0 errors, 0 warnings

cargo test --workspace
# Expected: all tests pass, 0 failures

cargo clippy --workspace -- -D warnings
# Expected: 0 warnings

cargo bench --no-run --workspace
# Expected: all benchmark binaries compile
```

---

## 12. Open Questions

| Question | Context | Priority |
|---|---|---|
| CI/CD pipeline | No GitHub Actions workflow exists. Needed before external contributors. | High |
| Production QUIC configuration | Current QUIC defaults are functional but not tuned for production (MTU, congestion control). | Medium |
| Cross-platform support | Currently Windows-only (DXGI, Win32 SendInput). Linux/macOS backends needed. | Medium |

---

## 13. Commands Quick Reference

```powershell
# Navigate to repo
cd C:\BLACKWING

# All cargo commands require this PATH if not already set
$env:PATH = "C:\Users\ETCHE\scoop\apps\mingw\current\bin;" + $env:PATH

# Core build commands
cargo fmt --check
cargo check --workspace
cargo test --workspace
cargo clippy --workspace -- -D warnings
cargo bench --no-run --workspace

# View dependency tree
cargo tree

# View workspace metadata
cargo metadata --format-version 1

# Git
git log --oneline          # brief history
git status                 # verify clean working tree
git tag                    # list all tags
```

---

*This document is the canonical handoff document. Update it after every work package completion.*
