//! bw-relay: BLACKWING relay server and client-side rendezvous for WP-8.0.
//!
//! This crate provides:
//! - The signaling protocol (`protocol`) for registration, discovery, and rendezvous.
//! - The relay server (`server`) that authenticates endpoints and mediates candidate exchange.
//! - The rendezvous state machine (`rendezvous`) managing connect-intent lifecycle.
//! - Candidate types (`candidate`) for NAT traversal path selection.
//! - The connectivity checker (`checker`) for client-side direct-path validation.
//!
//! # Security Model
//!
//! The relay server operates purely on the **control plane**. It never handles
//! `bw-session` encryption keys, `bw-encoder` media, or `bw-protocol` frames.
//! All identity is rooted in the device's long-term Ed25519 signing key from `bw-crypto`.

/// Candidate types for NAT traversal path selection.
pub mod candidate;
/// Connectivity checker for client-side direct-path validation.
pub mod checker;
/// Time abstraction for deterministic testing.
pub mod clock;
/// Signaling protocol for registration, discovery, and rendezvous.
pub mod protocol;
/// Rendezvous state machine managing connect-intent lifecycle.
pub mod rendezvous;
/// Relay server that authenticates endpoints and mediates candidate exchange.
pub mod server;
