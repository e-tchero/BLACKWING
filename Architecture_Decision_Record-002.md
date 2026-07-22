# ADR-002: Session Establishment & NAT Traversal Strategy

## Status
Under Review (Tightly coupled with ADR-001)

## Context
Project Blackwing requires a reliable, performant, and secure mechanism to establish network connections between a Console and an Agent located behind arbitrary, residential, or corporate NAT firewalls. The architecture must guarantee connection initialization while minimizing infrastructure routing costs and latency bloat.

## Decision
We adopt a custom, lightweight ICE-Lite implementation integrated directly with the QUIC transport pipeline defined in ADR-001. 

Endpoints use Ed25519 keys for identity verification and use a stateless Rendezvous Service solely for control-plane signaling. Direct P2P UDP hole-punching via STUN will act as the aggressive default path. Dual-Symmetric NAT topologies or UDP-blocked corporate environments will systematically drop down to a high-throughput Blackwing TURN Relay, migrating to a Reliable Relay Transport over TCP/TLS if UDP is entirely blocked. BBR is designated as the primary candidate for transport congestion control.

## Rationale
1. ICE-Lite over raw UDP limits binary dependency bloat compared to importing full WebRTC libraries, while preserving a deterministic traversal matrix.
2. BBR congestion control ensures smooth frame pacing and minimizes latency spikes on lossy, modern networks.
3. Strict separation of signaling and payload data guarantees absolute operational privacy.

## Consequences
- Positive: Zero-Trust identity verification before connection optimization; exceptional connection success rate (≥99.9%); optimal latency paths via direct P2P.
- Negative: Requires engineering a custom STUN socket binding layout within the Rust `tokio` async network engine to coordinate hole-punching prior to the `quinn` engine takeover.