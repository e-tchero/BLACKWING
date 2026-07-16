#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! # bw-protocol
//!
//! Serialization formats and core protocol definitions for Project Blackwing.

pub mod codec;
pub mod dispatcher;
pub mod error;
pub mod frame;
pub mod handshake;
pub mod header;
pub mod message;
pub mod reliability;
pub mod routing;
pub mod session;
pub mod transport;
pub mod version;
