# PROJECT BLACKWING — Workspace Vision & Rules

> **Historical vs current:** §1 below is the **original planning vision** from the
> architecture phase. It is historical — several crates were renamed, split, or never
> created. For the **actual current workspace (verified 2026-09-03)**, see §1a.
> The canonical project-state document is `BLACKWING_SOURCE_OF_TRUTH.md`.

## 1. Original Planning Vision (historical)

This outlines the intended final shape of the Project Blackwing workspace as originally planned. Planning and scoping become significantly easier when the target crate graph is defined upfront, even if many of these crates remain empty today.

> Historical note: `bw-video` was later split into `bw-encoder` + `bw-decoder`;
> `bw-agent` → `bw-server`; `bw-console` → `bw-client`; `bw-cli` and `bw-update`
> were never created. `bw-session`, `bw-transport`, `bw-auth`, `bw-ice`,
> `bw-input`, and `bw-clipboard` were added beyond the original vision.

```text
BLACKWING
└── crates/
    ├── bw-core      (Fundamental types, memory pooling, locks, basic traits)
    ├── bw-crypto    (Identity, cryptographic verification, signing, keys)
    ├── bw-protocol  (Wire formats, packet framing, codecs)
    ├── bw-net       (Transport layers, connection management, sockets)
    ├── bw-capture   (Screen capture, OS windowing interfaces)
    ├── bw-video     (Video encoding pipeline, compression)
    ├── bw-audio     (Audio capture, encoding, mixing)
    ├── bw-relay     (Relay server & control plane routing logic)
    ├── bw-agent     (Endpoint daemon / service payload)
    ├── bw-console   (Admin/User TUI or GUI interface)
    ├── bw-cli       (Command-line tools for operators)
    └── bw-update    (Over-the-air update mechanisms, staging, verification)
```

---

## 1a. Current Workspace (verified 2026-09-03)

The actual workspace contains **17 crates**:

```text
crates/
├── bw-core       (Errors, logging, zero-alloc memory pools)          — bottom of stack
├── bw-crypto     (Ed25519 identity, ChaCha20-Poly1305 AEAD, HKDF, HMAC-SHA256)
├── bw-protocol   (Wire protocol: frames, CBOR messages, codec, encryption, routing, dispatcher, DRR scheduler)
├── bw-net        (UDP transport, receive loop, connection manager)
├── bw-session    (Session lifecycle, secure connection — OPAQUE-authenticated)
├── bw-transport  (QUIC client/server, cert management, ICE/relay sockets)
├── bw-auth       (OPAQUE PAKE authentication — RFC 9381)
├── bw-capture    (DXGI/WGC screen capture, cursor tracking, frame timer)
├── bw-encoder    (H.264 encoding pipeline — OpenH264)
├── bw-decoder    (H.264 decoding pipeline — OpenH264)
├── bw-relay      (Relay server, forwarding, rendezvous, NAT traversal)
├── bw-ice        (ICE/STUN agent — webrtc-ice)
├── bw-input      (Win32 SendInput injection, keyboard/mouse mapping)
├── bw-clipboard  (Bidirectional clipboard sync — arboard)
├── bw-audio      (Opus audio capture/playback — cpal)
├── bw-client     (Desktop client application — winit)
└── bw-server     (Host server application)
```

Current status: full-stack vertical slice complete; security hardening
(C1/C2/C3, H1, L-K1, H3, H5/H6, M1/M2/M3/M6) complete; F3 relay polling
CLOSED (`1fd53e9`); 364 tests, 0 failures.

---

## 2. Dependency Rules

To prevent spaghetti architecture and circular dependencies, the dependency flow must strictly be top-down. 

**Permitted Flow Example:**
```text
bw-core
   ↓
bw-crypto
   ↓
bw-protocol
   ↓
bw-net
```

**Forbidden:**
- `bw-core` CANNOT depend on `bw-protocol`.
- `bw-crypto` CANNOT depend on `bw-net`.
- Circular dependencies are absolutely forbidden by policy. 
- Higher-level crates (like `bw-agent` or `bw-relay`) depend on lower-level crates, but never the reverse.

## 3. Public API Freeze Policy

To prevent API sprawl, the boundaries of the following foundational crates are frozen.

### Frozen Public APIs:
- **`bw-core`**
- **`bw-crypto`**
- **`bw-protocol`**

### Rule:
Anything that does not explicitly need to be consumed externally by a downstream workspace member **must** remain `pub(crate)`. If a feature is only needed within the boundaries of `bw-protocol`, it should not leak into the global namespace via `pub`.
