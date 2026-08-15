//! Clipboard synchronization for BLACKWING.
//!
//! Wraps the [`arboard`](https://docs.rs/arboard) crate to provide safe,
//! cross-platform access to the OS clipboard for both text and RGBA8 images.
//! The [`ClipboardManager`] is the single entry point used by `bw-server` and
//! `bw-client` to read and write the local clipboard, and the protocol layer
//! (`bw-protocol`'s `ClipboardData` message) carries the contents across the
//! wire.

pub mod error;
pub mod manager;

pub use error::ClipboardError;
pub use manager::{ClipboardImage, ClipboardManager};
