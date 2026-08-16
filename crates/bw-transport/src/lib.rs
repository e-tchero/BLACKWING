//! Transport layer: Quinn QUIC endpoints with optional relay routing.
//!
//! Provides `QuicClient`/`QuicServer` endpoints (direct or relay-routed via
//! `RelayUdpSocket`), the `QuicProtocolAdapter` frame-codec glue, and
//! self-signed certificate helpers.

/// QUIC protocol frame adapter.
pub mod adapter;
/// Self-signed certificate helpers for QUIC TLS.
pub mod cert;
/// QUIC client endpoint.
pub mod client;
/// ICE-backed async UDP socket adapter for Quinn.
pub mod ice_socket;
/// Relay-aware async UDP socket wrapper for Quinn.
pub mod relay_socket;
/// QUIC server endpoint.
pub mod server;

pub use adapter::{AdapterError, QuicProtocolAdapter};
pub use client::{QuicClient, QuicClientError};
pub use ice_socket::IceUdpSocket;
pub use relay_socket::RelayUdpSocket;
pub use server::{QuicServer, QuicServerError};
