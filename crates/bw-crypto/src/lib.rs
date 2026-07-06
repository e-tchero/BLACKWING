#![allow(dead_code)]

// Internal implementation details
mod backend;
mod random;

// Public API
pub mod error;
pub mod identity;

// Re-exports for a clean public surface
pub use crate::error::{CryptoError, Result};
pub use crate::identity::{DeviceId, Signature, SigningKey, VerifyKey};
