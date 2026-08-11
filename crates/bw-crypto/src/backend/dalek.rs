use crate::error::Result;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct DalekSigningKey {
    // Explicit wrapper for robustness against version changes
    secret: [u8; 32],
}

impl DalekSigningKey {
    pub(crate) fn from_secret(secret: [u8; 32]) -> Self {
        Self { secret }
    }

    pub(crate) fn sign(&self, message: &[u8]) -> [u8; 64] {
        use ed25519_dalek::{Signer, SigningKey};
        let key = SigningKey::from_bytes(&self.secret);
        key.sign(message).to_bytes()
    }

    pub(crate) fn get_verify_key(&self) -> DalekVerifyKey {
        use ed25519_dalek::SigningKey;
        let key = SigningKey::from_bytes(&self.secret);
        DalekVerifyKey {
            public: key.verifying_key(),
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) struct DalekVerifyKey {
    pub(crate) public: ed25519_dalek::VerifyingKey,
}

impl DalekVerifyKey {
    pub(crate) fn from_bytes(bytes: &[u8; 32]) -> Result<Self> {
        let public = ed25519_dalek::VerifyingKey::from_bytes(bytes)
            .map_err(|_| crate::error::CryptoError::VerificationFailed)?;
        Ok(Self { public })
    }

    pub(crate) fn verify(&self, message: &[u8], signature: &[u8; 64]) -> Result<()> {
        use ed25519_dalek::Verifier;
        let sig = ed25519_dalek::Signature::from_bytes(signature);
        self.public
            .verify(message, &sig)
            .map_err(|_| crate::error::CryptoError::VerificationFailed)
    }

    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        self.public.as_bytes()
    }
}
