//! Symmetric cryptographic primitives for PROJECT BLACKWING.
//!
//! Exposes AEAD (ChaCha20Poly1305) and HKDF-SHA256 operations.

use crate::error::{CryptoError, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305,
};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A symmetric key wrapper that automatically zeroizes on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SymmetricKey(pub [u8; 32]);

impl std::fmt::Debug for SymmetricKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SymmetricKey(***)")
    }
}

/// Derives a 32-byte symmetric key from input key material using HKDF-SHA256.
pub fn hkdf_derive(salt: Option<&[u8]>, ikm: &[u8], info: Option<&[u8]>) -> Result<SymmetricKey> {
    let hk = Hkdf::<Sha256>::new(salt, ikm);
    let mut okm = [0u8; 32];
    hk.expand(info.unwrap_or(&[]), &mut okm)
        .map_err(|_| CryptoError::InvalidKey)?;
    Ok(SymmetricKey(okm))
}

/// Encrypts plaintext with ChaCha20Poly1305.
///
/// Returns the ciphertext and the 16-byte authentication tag separately.
pub fn encrypt_aead(
    key: &SymmetricKey,
    nonce: &[u8; 12],
    plaintext: &[u8],
    associated_data: &[u8],
) -> Result<(Vec<u8>, [u8; 16])> {
    let cipher = ChaCha20Poly1305::new(
        chacha20poly1305::aead::generic_array::GenericArray::from_slice(&key.0),
    );
    let payload = Payload {
        msg: plaintext,
        aad: associated_data,
    };
    let ciphertext_with_tag = cipher
        .encrypt(
            chacha20poly1305::aead::generic_array::GenericArray::from_slice(nonce),
            payload,
        )
        .map_err(|_| CryptoError::VerificationFailed)?;

    if ciphertext_with_tag.len() < 16 {
        return Err(CryptoError::VerificationFailed);
    }

    let tag_start = ciphertext_with_tag.len() - 16;
    let ciphertext = ciphertext_with_tag[..tag_start].to_vec();
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&ciphertext_with_tag[tag_start..]);

    Ok((ciphertext, tag))
}

/// Decrypts ciphertext with ChaCha20Poly1305.
pub fn decrypt_aead(
    key: &SymmetricKey,
    nonce: &[u8; 12],
    ciphertext: &[u8],
    tag: &[u8; 16],
    associated_data: &[u8],
) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(
        chacha20poly1305::aead::generic_array::GenericArray::from_slice(&key.0),
    );

    let mut combined = Vec::with_capacity(ciphertext.len() + 16);
    combined.extend_from_slice(ciphertext);
    combined.extend_from_slice(tag);

    let payload = Payload {
        msg: &combined,
        aad: associated_data,
    };

    let plaintext = cipher
        .decrypt(
            chacha20poly1305::aead::generic_array::GenericArray::from_slice(nonce),
            payload,
        )
        .map_err(|_| CryptoError::VerificationFailed)?;

    Ok(plaintext)
}
