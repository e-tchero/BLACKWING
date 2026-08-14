//! OPAQUE PAKE authentication (RFC 9381).
//!
//! Implements the OPAQUE password-authenticated key exchange protocol using
//! the ristretto255 group for the OPRF and key exchange, replacing the
//! pre-shared symmetric key previously used for authentication.
//!
//! # Cipher suite
//!
//! - OPRF group / key exchange: ristretto255
//! - Key exchange: TripleDH with SHA-512
//! - Key stretching function: [`opaque_ke::ksf::Identity`]
//!
//! The identity KSF is used because the shared secret this crate
//! authenticates (the replacement for the 32-byte pre-shared key) is
//! high-entropy. For low-entropy human passwords, enable the `argon2`
//! feature on `opaque-ke` and switch the cipher suite's `Ksf` to Argon2.

pub mod client;
pub mod error;
pub mod server;

pub use error::AuthError;

use opaque_ke::CipherSuite;
use sha2::Sha512;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// The BLACKWING OPAQUE cipher suite.
///
/// Uses ristretto255 for both the OPRF and the TripleDH key exchange, SHA-512
/// for hashing, and the identity key-stretching function (see the crate
/// documentation for the rationale).
pub struct DefaultCipherSuite;

impl CipherSuite for DefaultCipherSuite {
    type OprfCs = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::TripleDh<opaque_ke::Ristretto255, Sha512>;
    type Ksf = opaque_ke::ksf::Identity;
}

/// A session key produced by a successful OPAQUE login.
///
/// Shared between the client and the server; zeroized on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SessionKey(Vec<u8>);

impl SessionKey {
    /// Returns the session key bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for SessionKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl PartialEq for SessionKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_slice() == other.0.as_slice()
    }
}

impl std::fmt::Debug for SessionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SessionKey(***)")
    }
}
