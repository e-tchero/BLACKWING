#![deny(clippy::unwrap_used, clippy::expect_used)]

//! # Cryptographic Identity Primitives (Milestone 3.1 Core)
//!
//! This module defines the core, backend-agnostic identity types for PROJECT BLACKWING:
//! `DeviceId`, `Signature`, `SigningKey`, and `VerifyKey`.
//!
//! ### Key Design Decisions (ADR-001 & ADR-002)
//! 1. **No Virtual Dispatch / Heap Allocations:** Concrete key wrappers wrap the private enums
//!    `SigningKeyInner` and `VerifyKeyInner` directly, yielding zero runtime heap allocations
//!    and exhaustive compile-time routing.
//! 2. **Authoritative vs. Protocol Boundaries:** `DeviceId` is represented internally as a raw
//!    32-byte binary digest. Creation is restricted to authoritative derivation from a `VerifyKey`
//!    or internal protocol-decoding reconstruction (`from_digest`).
//! 3. **Cryptographic Zeroization:** Any secret-bearing type (such as `SigningKey`) implements
//!    mandatory zeroization on `Drop` to prevent RAM-scraping vulnerability vectors.
//! 4. **Constant-Time Validation:** Type-safe comparisons of signatures are handled strictly via
//!    constant-time equality primitives to eliminate microarchitectural timing analysis channels.

use sha2::{Digest, Sha256};
use std::fmt;
use std::str::FromStr;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::backend::{SigningKeyInner, VerifyKeyInner};
use crate::error::Result;

// =========================================================================
// Constant Constraints (ADR-001 Specifications)
// =========================================================================

pub const DEVICE_ID_BYTES: usize = 32;
pub const DEVICE_ID_HEX_LEN: usize = 64;
pub const DEVICE_ID_PREFIX: &str = "bw-id-";
pub const DEVICE_ID_STR_LEN: usize = DEVICE_ID_PREFIX.len() + DEVICE_ID_HEX_LEN;

// =========================================================================
// 1. DeviceId Definition & Serialization Rules
// =========================================================================

/// Represents an immutable, platform-agnostic system participant identity.
/// Derived as: SHA-256(Raw_Ed25519_Public_Key_Bytes)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DeviceId([u8; DEVICE_ID_BYTES]);

/// Standardized parsing failures for DeviceId.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceIdParseError {
    InvalidPrefix,
    InvalidLength,
    InvalidHex,
    UppercaseNotAllowed,
}

impl fmt::Display for DeviceIdParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPrefix => write!(f, "Device ID must start with literal prefix 'bw-id-'"),
            Self::InvalidLength => write!(f, "Device ID string must be exactly 70 characters long"),
            Self::InvalidHex => write!(f, "Device ID contains invalid non-hexadecimal characters"),
            Self::UppercaseNotAllowed => write!(f, "Device ID must be strictly lowercase hex only"),
        }
    }
}

impl std::error::Error for DeviceIdParseError {}

impl DeviceId {
    /// Returns the raw binary representation of the identity digest.
    #[inline]
    pub fn as_bytes(&self) -> &[u8; DEVICE_ID_BYTES] {
        &self.0
    }

    /// Internal: Deterministically derives a DeviceId from a public verification key.
    /// This is the only valid construction path for fresh identities.
    pub(crate) fn derive(key: &VerifyKey) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(key.as_bytes());
        let mut digest = [0u8; DEVICE_ID_BYTES];
        digest.copy_from_slice(&hasher.finalize());
        Self(digest)
    }

    /// Public: Reconstructs a DeviceId from a pre-validated protocol digest.
    /// Required for external integration/fuzz tests and packet decoders.
    #[inline]
    pub fn from_digest(digest: [u8; DEVICE_ID_BYTES]) -> Self {
        Self(digest)
    }
}

// Memory mapping traits for zero-copy compatibility
impl AsRef<[u8]> for DeviceId {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8; DEVICE_ID_BYTES]> for DeviceId {
    #[inline]
    fn as_ref(&self) -> &[u8; DEVICE_ID_BYTES] {
        &self.0
    }
}

impl fmt::Display for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", DEVICE_ID_PREFIX)?;
        for byte in &self.0 {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

impl FromStr for DeviceId {
    type Err = DeviceIdParseError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        if !s.starts_with(DEVICE_ID_PREFIX) {
            return Err(DeviceIdParseError::InvalidPrefix);
        }
        if s.len() != DEVICE_ID_STR_LEN {
            return Err(DeviceIdParseError::InvalidLength);
        }

        let hex_body = &s[DEVICE_ID_PREFIX.len()..];
        if hex_body.chars().any(|c| c.is_ascii_uppercase()) {
            return Err(DeviceIdParseError::UppercaseNotAllowed);
        }

        let mut bytes = [0u8; DEVICE_ID_BYTES];
        for (i, byte) in bytes.iter_mut().enumerate() {
            let start = i * 2;
            let byte_str = &hex_body[start..start + 2];
            *byte = u8::from_str_radix(byte_str, 16).map_err(|_| DeviceIdParseError::InvalidHex)?;
        }

        Ok(Self(bytes))
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for DeviceId {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(&self.to_string())
        } else {
            serializer.serialize_bytes(&self.0)
        }
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for DeviceId {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct DeviceIdVisitor;

        impl<'de> serde::de::Visitor<'de> for DeviceIdVisitor {
            type Value = DeviceId;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a 70-character lowercase hex string or a 32-byte binary array")
            }

            fn visit_str<E>(self, v: &str) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                DeviceId::from_str(v).map_err(E::custom)
            }

            fn visit_bytes<E>(self, v: &[u8]) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if v.len() != DEVICE_ID_BYTES {
                    return Err(E::invalid_length(v.len(), &"exactly 32 bytes"));
                }
                let mut digest = [0u8; DEVICE_ID_BYTES];
                digest.copy_from_slice(v);
                Ok(DeviceId::from_digest(digest))
            }
        }

        if deserializer.is_human_readable() {
            deserializer.deserialize_str(DeviceIdVisitor)
        } else {
            deserializer.deserialize_bytes(DeviceIdVisitor)
        }
    }
}

// =========================================================================
// 2. Type-Safe Signature Implementations & Hardening
// =========================================================================

/// A type-safe signature wrapper to prevent mix-ups with raw byte slices.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Signature([u8; 64]);

impl Signature {
    /// Creates a type-safe signature wrapper from a raw 64-byte array.
    pub fn from_bytes(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }

    /// Exposes a shared reference to the raw 64-byte array.
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }

    /// Performs constant-time signature comparison to prevent timing leaks.
    pub fn ct_eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Signature([u8; 64])")
    }
}

// =========================================================================
// 3. Concrete Asymmetric Key Primitives
// =========================================================================

/// Concrete, backend-agnostic long-term signing key wrapper.
/// Custom Drop automatically sanitizes underlying secret RAM sectors securely.
pub struct SigningKey {
    pub(crate) inner: SigningKeyInner,
}

impl Zeroize for SigningKey {
    fn zeroize(&mut self) {
        match &mut self.inner {
            SigningKeyInner::Dalek(k) => k.zeroize(),
            SigningKeyInner::Tpm(_) => {} // Hardware references are non-extractable
        }
    }
}

impl Drop for SigningKey {
    #[inline]
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl SigningKey {
    /// Generates a fresh Ed25519 signing key using OS entropy.
    pub fn generate_ed25519() -> crate::error::Result<Self> {
        use crate::random::SecureRandom;
        let mut secret = [0u8; 32];
        let mut rng = crate::random::OsRandom;
        rng.fill(&mut secret)?;
        Ok(Self {
            inner: crate::backend::SigningKeyInner::Dalek(
                crate::backend::dalek::DalekSigningKey::from_secret(secret),
            ),
        })
    }

    /// Extracts the associated public verification key.
    /// This path executes purely via static enum-matching dispatch.
    pub fn verify_key(&self) -> VerifyKey {
        match &self.inner {
            SigningKeyInner::Dalek(k) => VerifyKey {
                inner: VerifyKeyInner::Dalek(k.get_verify_key()),
            },
            SigningKeyInner::Tpm(k) => VerifyKey {
                inner: VerifyKeyInner::Tpm(k.get_verify_key()),
            },
        }
    }

    /// Sign the provided message payload.
    pub fn sign(&self, message: &[u8]) -> Signature {
        match &self.inner {
            SigningKeyInner::Dalek(k) => Signature(k.sign(message)),
            SigningKeyInner::Tpm(k) => Signature(k.sign(message)),
        }
    }

    /// Returns the raw 32-byte Ed25519 secret key for persistence.
    ///
    /// The returned bytes must be kept secret. They can be loaded back via
    /// SigningKey::from_secret_bytes to restore the same identity.
    pub fn to_bytes(&self) -> [u8; 32] {
        match &self.inner {
            SigningKeyInner::Dalek(k) => k.to_bytes(),
            SigningKeyInner::Tpm(_) => panic!("TPM keys cannot be serialized to bytes"),
        }
    }

    /// Restores a signing key from raw 32-byte secret bytes previously
    /// obtained via SigningKey::to_bytes.
    pub fn from_secret_bytes(bytes: [u8; 32]) -> crate::error::Result<Self> {
        Ok(Self {
            inner: crate::backend::SigningKeyInner::Dalek(
                crate::backend::dalek::DalekSigningKey::from_secret(bytes),
            ),
        })
    }
}

/// Concrete, backend-agnostic public verification key wrapper.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyKey {
    pub(crate) inner: VerifyKeyInner,
}

impl VerifyKey {
    /// Deserializes a VerifyKey from a 32-byte array (assuming Dalek/Ed25519 backend).
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self> {
        let dalek_key = crate::backend::dalek::DalekVerifyKey::from_bytes(&bytes)?;
        Ok(Self {
            inner: VerifyKeyInner::Dalek(dalek_key),
        })
    }

    /// Deterministically derives the versioned canonical DeviceId from this verify key.
    pub fn device_id(&self) -> DeviceId {
        DeviceId::derive(self)
    }

    /// Verifies an asymmetric signature against the public verification key.
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<()> {
        match &self.inner {
            VerifyKeyInner::Dalek(k) => k.verify(message, signature.as_bytes()),
            VerifyKeyInner::Tpm(k) => k.verify(message, signature.as_bytes()),
        }
    }

    /// Exposes a shared reference to the raw canonical 32-byte compressed Ed25519 representation.
    pub fn as_bytes(&self) -> &[u8; 32] {
        match &self.inner {
            VerifyKeyInner::Dalek(k) => k.as_bytes(),
            VerifyKeyInner::Tpm(k) => k.as_bytes(),
        }
    }
}
