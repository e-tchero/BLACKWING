//! # bw-net
//!
//! Network I/O layer for Project Blackwing.
//!
//! This crate owns sockets, connection management, and the async transport
//! abstraction. It is the only crate permitted to interact with OS-level
//! networking primitives.
//!
//! ## Architectural Boundaries
//!
//! - `bw-net` owns: sockets, peer addresses, raw byte I/O, NAT traversal.
//! - `bw-protocol` owns: frame decoding, session state, encryption, dispatch.
//! - `bw-crypto` owns: all cryptographic primitives.
//!
//! `bw-net` depends on `bw-protocol`. The reverse is explicitly forbidden.

pub mod connection;
pub mod error;
pub mod protocol_adapter;
pub mod transport;
pub mod udp;
