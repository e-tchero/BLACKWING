#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! # bw-protocol
//!
//! Serialization formats and core protocol definitions for Project Blackwing.

pub mod codec;
pub mod error;
pub mod frame;
pub mod header;
pub mod version;
