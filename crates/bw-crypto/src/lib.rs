//! Cryptographic identity primitives for Project Blackwing.
//!
//! Provides [`DeviceId`], [`SigningKey`], [`VerifyKey`], and [`Signature`]
//! backed by an enum-dispatched cryptographic backend (Ed25519 or TPM).

// JUSTIFIED: TPM backend and OsRandom are structural stubs awaiting
// implementation in a future work package. Dead code is expected at
// this stage of the recovery baseline.
#![allow(dead_code)]
// Temporarily allow missing docs in recovery crates to unblock build.
#![allow(missing_docs)]

// Internal implementation details
mod backend;
mod random;

// Public API
pub mod error;
pub mod identity;

// Re-exports for a clean public surface
pub use crate::error::{CryptoError, Result};
pub use crate::identity::{DeviceId, Signature, SigningKey, VerifyKey};
