# PROJECT BLACKWING — Repository Map

This is the first document every contributor reads. It outlines the physical structure of the workspace.

Last Updated: 2026-08-21

```text
BLACKWING/
├── archive/
│   └── recovered_sources/        # Historical source artifacts (do not modify)
│
├── crates/                       # Active Rust Workspace (17 crates)
│   │
│   ├── bw-core/                  # Core primitives: errors, logging, memory pools
│   │   ├── src/
│   │   │   ├── lib.rs            # #![forbid(unsafe_code)] #![deny(missing_docs)]
│   │   │   ├── error.rs          # BwError enum (thiserror)
│   │   │   ├── logging.rs        # LogEvent, Severity, HealthReport
│   │   │   ├── memory.rs         # ZeroAllocationPool
│   │   │   └── pool.rs           # StaticSlotPool<SLOT_SIZE, POOL_SIZE>
│   │   └── tests/                # 2 test files, 17 tests
│   │
│   ├── bw-crypto/                # Cryptography & Identity
│   │   ├── src/
│   │   │   ├── lib.rs            # Re-exports DeviceId, Signature, SigningKey, VerifyKey
│   │   │   ├── error.rs          # CryptoError enum
│   │   │   ├── identity.rs       # DeviceId (SHA-256 of ed25519 pubkey), Signature, SigningKey, VerifyKey
│   │   │   ├── random.rs         # SecureRandom trait + OsRandom
│   │   │   ├── symmetric.rs      # HMAC-SHA256, HKDF, SymmetricKey
│   │   │   └── backend/
│   │   │       ├── mod.rs        # SigningKeyInner + VerifyKeyInner enum dispatch
│   │   │       └── dalek.rs      # Ed25519 (ed25519-dalek) implementation
│   │   └── tests/                # 1 test file, 13 property-based tests (proptest)
│   │
│   ├── bw-protocol/              # Wire protocol (15 source modules)
│   │   ├── src/
│   │   │   ├── lib.rs            # Crate root
│   │   │   ├── version.rs        # ProtocolVersion enum
│   │   │   ├── header.rs         # 32-byte PacketHeader (bytemuck zero-copy)
│   │   │   ├── frame.rs          # ProtocolFrame / OwnedProtocolFrame
│   │   │   ├── message.rs        # ProtocolMessage, MessageType (12 types), CBOR serde
│   │   │   ├── codec.rs          # encode_frame / decode_frame
│   │   │   ├── dispatcher.rs     # MessageDispatcher, handler registry, async dispatch
│   │   │   ├── routing.rs        # MessageEnvelope, RouteType, SessionManager
│   │   │   ├── session.rs        # Session lifecycle, TTL expiry, key derivation
│   │   │   ├── encryption.rs     # EncryptionContext, AES-256-GCM, nonce mgmt
│   │   │   ├── reliability.rs    # Reliable delivery, ACKs, retransmission
│   │   │   ├── handshake.rs      # HandshakeRequest/Response, capability negotiation
│   │   │   ├── scheduler.rs      # DRR priority scheduler for QUIC streams
│   │   │   ├── transport.rs      # MockTransport for testing
│   │   │   └── error.rs          # ProtocolError enum
│   │   ├── tests/                # 11 test files, 83 tests
│   │   └── benches/              # 2 bench files (crypto_bench, placeholder)
│   │
│   ├── bw-net/                   # Network I/O layer
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── udp.rs            # UdpTransport, run_receive_loop
│   │   │   ├── transport.rs      # Transport trait, BoxFuture
│   │   │   ├── connection.rs     # ConnectionManager, ConnectionHandle
│   │   │   └── error.rs          # NetError enum
│   │   └── tests/                # 4 test files, 5 tests
│   │
│   ├── bw-session/               # Session lifecycle & wire protocol bridge
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── lifecycle.rs      # Session lifecycle management
│   │   │   ├── secure_conn.rs    # Secure connection handling
│   │   │   └── wire.rs           # Wire protocol bridge
│   │   └── tests/                # 2 test files, 4 tests
│   │
│   ├── bw-transport/             # QUIC transport layer
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── client.rs         # QuicClient
│   │   │   ├── server.rs         # QuicServer
│   │   │   ├── adapter.rs        # ProtocolTransportAdapter
│   │   │   ├── cert.rs           # Certificate management
│   │   │   ├── ice_socket.rs     # ICE socket binding
│   │   │   └── relay_socket.rs   # RelayUdpSocket
│   │   └── tests/                # 4 test files, 6 tests
│   │
│   ├── bw-auth/                  # OPAQUE PAKE authentication (RFC 9381)
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── client.rs         # Client-side OPAQUE
│   │   │   ├── server.rs         # Server-side OPAQUE
│   │   │   ├── store.rs          # Credential store
│   │   │   └── error.rs
│   │   └── tests/                # 1 test file, 4 tests
│   │
│   ├── bw-capture/               # Screen capture (DXGI/WGC)
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── backend.rs        # Capture backend abstraction
│   │   │   ├── frame.rs          # Frame buffer, dirty rect tracking
│   │   │   ├── cursor.rs         # Cursor overlay
│   │   │   ├── monitor.rs        # Monitor enumeration
│   │   │   ├── thread.rs         # Capture thread management
│   │   │   └── windows/          # DXGI and WGC backends
│   │   └── tests/                # 1 test file, 9 tests
│   │
│   ├── bw-encoder/               # H.264 video encoding
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── backend.rs        # Encoding backend
│   │   │   ├── h264.rs           # H.264 via OpenH264
│   │   │   └── pipeline.rs       # Encoding pipeline
│   │   └── tests/                # 1 test file, 1 test
│   │
│   ├── bw-decoder/               # H.264 video decoding
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── image.rs          # Image frame output
│   │   │   ├── pipeline.rs       # Decoding pipeline
│   │   │   └── error.rs
│   │   └── tests/                # 1 test file, 6 tests
│   │
│   ├── bw-relay/                 # Relay server & NAT traversal
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── bin/relay.rs      # Relay binary entry point
│   │   │   ├── forwarding.rs     # Token-based forwarding
│   │   │   ├── rendezvous.rs     # Rendezvous protocol
│   │   │   ├── candidate.rs      # Candidate management
│   │   │   ├── checker.rs        # Health checking
│   │   │   ├── clock.rs          # Time management
│   │   │   ├── protocol.rs       # Relay protocol
│   │   │   └── server.rs         # Relay server
│   │   └── tests/                # 2 test files, 33 tests
│   │
│   ├── bw-ice/                   # ICE/STUN agent (wraps webrtc-ice)
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── manager.rs        # ICE agent management
│   │   │   ├── signaling.rs      # ICE signaling
│   │   │   └── error.rs
│   │   └── tests/                # 1 test file, 4 tests
│   │
│   ├── bw-input/                 # Win32 input injection
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── inject.rs         # SendInput wrapper
│   │   │   ├── input.rs          # Input event types
│   │   │   └── error.rs
│   │   └── tests/                # 1 test file, 9 tests
│   │
│   ├── bw-clipboard/             # Clipboard management
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── manager.rs        # Clipboard operations
│   │   │   ├── poller.rs         # Change detection
│   │   │   └── error.rs
│   │   └── tests/                # 1 test file, 7 tests
│   │
│   ├── bw-audio/                 # Audio capture/playback (cpal + Opus)
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── capture.rs        # Audio capture
│   │   │   ├── playback.rs       # Audio playback
│   │   │   ├── codec.rs          # Opus codec
│   │   │   └── error.rs
│   │   └── tests/                # 1 test file, 5 tests
│   │
│   ├── bw-client/                # Desktop client application
│   │   ├── src/
│   │   │   └── main.rs           # winit rendering loop, video decode, input capture
│   │   └── tests/                # 5 inline tests
│   │
│   └── bw-server/                # Host server application
│       ├── src/
│       │   ├── lib.rs
│       │   └── main.rs           # Dispatcher, input injection, audio, clipboard
│       └── tests/                # 4 test files, 16 tests
│
├── docs/                         # Specifications & ADRs
│   ├── REPOSITORY_MAP.md         # This file
│   ├── WORKSPACE_VISION.md       # Dependency rules, API freeze policy
│   └── adr/                      # Architecture Decision Records
│       ├── ADR-002_Workspace_Structure.md
│       ├── ADR-003_Crate_Boundaries.md
│       ├── ADR-004_Memory_Allocation_Policy.md
│       ├── ADR-005_Cryptographic_Backend_Strategy.md
│       ├── ADR-006_Error_Handling_Policy.md
│       ├── ADR-007_Async_Runtime_Policy.md
│       └── ADR-008_Logging_Strategy.md
│
├── Cargo.toml                    # Workspace root (17 members, workspace lints)
├── Cargo.lock                    # Committed (reproducible builds)
├── HANDOFF.md                    # Master handoff document (this file's companion)
├── WP_CHANGELOG.md               # Work package history
├── BLACKWING_ENGINEERING_BASELINE.md
└── README.md
```

## Workspace Lint Policy

All crates inherit these lints from the workspace root:

```toml
[workspace.lints.rust]
unsafe_code = "forbid"
missing_docs = "deny"

[workspace.lints.clippy]
unwrap_used = "deny"
expect_used = "deny"
todo = "deny"
dbg_macro = "deny"
```

Each crate opts in with `[lints] workspace = true` in its `Cargo.toml`.

## Quality Gate Summary

| Metric | Value |
|---|---|
| Workspace crates | 17 |
| Source modules | 80+ |
| Integration test files | 38 |
| Tests | 228 (0 failures) |
| Benchmark binaries | 21 |
| `unsafe` blocks | 0 |
| `unimplemented!()` | 0 |
| `todo!()` | 0 |
| `unwrap()` in library code | 0 |
