# ADR-001: Selection of Core Transport Layer Protocol

## Status
Proposed (Pending Review)

## Context
Project Blackwing requires a foundational network transport layer capable of handling ultra-low-latency real-time video streams, highly interactive input coordinate synchronization, and reliable asynchronous file/clipboard transfers under volatile WAN conditions. 

We evaluated WebRTC, QUIC (RFC 9000), and Custom TLS-wrapped transport architectures against a strict 9-point weighted scoring model.

## Decision
We select QUIC as the primary transport protocol, to be implemented via the pure-Rust `quinn` crate ecosystem. 

Time-sensitive data streams (video frames, mouse telemetry) will utilize QUIC Datagrams (RFC 9221). Ordered transactional data streams (file structures, authentication requests) will utilize native QUIC bidirectional streams.

## Rationale
1. Native TLS 1.3 encryption eliminates cryptographic implementation drift.
2. Independent stream multiplexing solves the Head-of-Line blocking vulnerability inherent in TCP solutions.
3. Native Connection Migration natively satisfies our NFR for network adaptation and seamless reconnection under mobile or cellular handoffs.
4. Structural complexity and binary footprint are significantly smaller than the WebRTC runtime footprint.

## Consequences
- Positive: Predictable memory footprints, exceptional concurrency performance via `tokio`, and structural code safety via Rust.
- Negative: Blackwing engineering must manually implement the STUN/ICE hole-punching lifecycle on the raw UDP socket before initializing the QUIC handshakes, rather than inheriting it natively from a WebRTC framework.
- Fallback: If outbound UDP traffic is blocked by enterprise firewalls, a fallback layer to WebSocket-over-TLS (TCP) must be systematically triggered.