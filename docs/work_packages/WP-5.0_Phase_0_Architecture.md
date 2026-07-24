# WP-5.0 Phase 0: Network Bootstrap Architecture Freeze

This document defines the complete architectural specification for the `bw-net` crate. It serves as the design contract that must be reviewed and approved prior to any implementation.

---

## 1. Crate Responsibilities

To maintain strict boundary discipline, responsibilities are explicitly divided:

**Belongs in `bw-net`:**
- Socket creation, binding, and lifecycle management (UDP/TCP).
- Asynchronous polling of OS network primitives.
- NAT traversal logic (ICE, STUN, TURN candidate gathering and testing).
- Peer endpoint discovery and raw connection establishment.
- Multiplexing raw byte streams across threads/tasks.

**Must remain in `bw-protocol`:**
- Handshake negotiation and cryptographic validation.
- Message serialization/deserialization.
- Frame encryption and decryption (`EncryptionContext`).
- Reliability mechanisms (sequence numbers, sliding windows, retransmissions, ACKs).
- Session state tracking (`SessionManager`) and message routing (`MessageDispatcher`).

**Must remain in `bw-crypto`:**
- All cryptographic primitives (Ed25519, AES-GCM, HKDF, RNG).
- Constant-time equality checks and zeroization.

**Dependency Rules:**
- `bw-net` **must** depend on `bw-protocol` (and by extension `bw-crypto`).
- `bw-protocol` **must never** depend on `bw-net`.
- Circular dependencies are strictly forbidden.

**Public API Boundaries:**
- `bw-net` exposes opaque `Connection` builders and standard Tokio-compatible Streams/Sinks for reading and writing raw protocol frames. It does not expose its internal OS-level socket types.

---

## 2. Network Stack

The stack enforces top-down dependency flow. Ownership transitions clearly at each boundary.

```text
Application
      │    (Owns: High-level application logic, UI, File Transfers, Screen capture streams)
      ↓    (Passes: Structured Rust structs/enums representing application intent)
Dispatcher
      │    (Owns: Routing registry, Handler mappings. Part of `bw-protocol`)
      ↓    (Passes: `MessageEnvelope` to specific session state machines)
bw-protocol
      │    (Owns: Encryption, ACKs, Framing, Handshakes)
      ↓    (Passes: Serialized, encrypted byte arrays representing raw `ProtocolFrame`s)
bw-net
      │    (Owns: Sockets, async tasks, STUN/TURN bindings)
      ↓    (Passes: Raw bytes via syscalls)
QUIC / UDP / TCP
      │
      ↓
Operating System
```

---

## 3. Connection Lifecycle

The connection state machine governs the physical network path, distinct from the protocol's logical session state.

```text
       Disconnected
            │
            ↓
 Listening / Resolving (DNS lookup, ICE candidate gathering)
            │
            ↓
      Candidate Testing (Pinging STUN/TURN/Direct paths)
            │
            ↓
         Connecting (Raw UDP/TCP path verified and open)
            │
            ↓  (Control hands over to `bw-protocol` for crypto)
         Handshake
            │
            ↓  (Master secret established)
       Authenticated
            │
            ↓  (Per-session keys derived)
       Session Active (Multiplexed data transfer occurs here)
            │
            ↓  (Timeout, I/O Error, or explicit application termination)
          Closing (Flushing buffers, sending connection close frame)
            │
            ↓
          Closed (Sockets dropped, tasks cancelled, keys zeroized)
```

---

## 4. Transport Abstraction

`bw-net` must provide an abstraction over the underlying socket to ensure the protocol layer remains agnostic to UDP, TCP, or future transports like QUIC. 

*(Note: No implementation is provided here, only the structural contract)*

```rust
use async_trait::async_trait;

/// The fundamental abstraction for network operations.
#[async_trait]
pub trait Transport: Send + Sync {
    /// Send a serialized protocol frame over the transport.
    async fn send(&self, frame_bytes: &[u8]) -> Result<(), NetError>;
    
    /// Receive a serialized protocol frame from the transport.
    async fn receive(&self) -> Result<Vec<u8>, NetError>;
    
    /// Gracefully terminate the transport connection.
    async fn disconnect(&self) -> Result<(), NetError>;
}
```

---

## 5. Session Ownership

Ownership is strictly demarcated to prevent lock contention and memory leaks:

| Resource | Owning Crate | Notes |
| :--- | :--- | :--- |
| **Sockets (UDP/TCP)** | `bw-net` | Dropped when connection tasks terminate. |
| **Peer State (IP, Port, ICE)** | `bw-net` | Transparent to the protocol. |
| **Session IDs** | `bw-protocol` | Tracked in `SessionManager`. |
| **Encryption Contexts** | `bw-protocol` | Bound to Session IDs. Contains `zeroize` material. |
| **Routing / Dispatch** | `bw-protocol` | Owned by `MessageDispatcher`. |
| **Retransmission State** | `bw-protocol` | `reliability.rs` sliding windows and queues. |

---

## 6. Threading Model

`bw-net` is heavily async and relies on Tokio. 

- **Tokio Task Layout:** Each active connection spawns exactly two lightweight tasks: one `receiver_task` reading from the socket, and one `sender_task` writing to the socket.
- **Channel Ownership:** `bw-net` owns bounded `tokio::sync::mpsc` channels that bridge the socket tasks to the protocol dispatcher.
- **Cancellation Model:** Every connection task wraps a `tokio::select!` block listening to a `CancellationToken`. Dropping the `ConnectionHandle` struct automatically fires the token, tearing down the tasks and dropping the sockets.
- **Shutdown Sequence:** Graceful shutdown uses a broadcast channel to signal shutdown, allowing tasks to flush pending egress buffers before yielding.
- **Back-Pressure:** `mpsc` channels are strictly bounded. If the protocol layer processes packets too slowly and the channel fills, the network layer will exert back-pressure or drop the connection to prevent out-of-memory (OOM) exploits.

---

## 7. Error Flow

Errors must be translated at boundaries to preserve encapsulation.

```text
Operating System
      │   (std::io::Error: Connection Reset by Peer)
      ↓
bw-net
      │   (Translates to `NetError::Io(ConnectionReset)`)
      ↓
bw-protocol
      │   (Translates to `ProtocolError::TransportClosed`)
      ↓
Application
      │   (Handles explicit `Event::PeerDisconnected`)
```

---

## 8. Future Compatibility

This architecture secures future extensibility without breaking public APIs:

- **QUIC / TCP / UDP:** By passing opaque `Arc<dyn Transport>` (or equivalent generic bounds) to `bw-protocol`, we can seamlessly swap out UDP for QUIC implementations internally within `bw-net`.
- **ICE / STUN / TURN:** NAT traversal occurs purely inside `bw-net` during the `Listening` -> `Connecting` lifecycle phase. The protocol layer simply waits for a socket that implements `Transport` to be yielded.
- **Relay Servers:** A relay server is just an implementation of `Transport` that encapsulates routing headers; the `bw-protocol` cryptographic guarantees remain unbroken end-to-end.
- **Multi-peer Sessions:** `bw-net` handles multiple multiplexed `Transport` instances, feeding them into the shared `MessageDispatcher` which routes by `SessionId`.

---

## 9. Success Criteria

Phase 0 is complete when this document is approved.

WP-5.0 (Implementation) will be considered successfully bootstrapped when:
1. The `bw-net` crate exists and compiles with 0 errors.
2. The `Transport` trait is finalized and implemented for raw UDP.
3. A functional test demonstrates connecting two endpoints over loopback, transmitting 10,000 frames using `bw-net`, without crashing or deadlocking.
4. The workspace dependency tree `cargo tree` confirms `bw-net` depends on `bw-protocol`, and no upstream cyclic dependencies exist.
5. All `clippy` warnings and standard quality gates pass cleanly.
