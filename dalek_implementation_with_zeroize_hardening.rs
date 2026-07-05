use crate::error::Result;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct DalekSigningKey {
    // Explicit wrapper for robustness against version changes
    secret: [u8; 32], 
}

impl DalekSigningKey {
    pub(crate) fn sign(&self, message: &[u8]) -> [u8; 64] {
        use ed25519_dalek::{SigningKey, Signer};
        let key = SigningKey::from_bytes(&self.secret);
        key.sign(message).to_bytes()
    }
    
    pub(crate) fn get_verify_key(&self) -> super::DalekVerifyKey {
        use ed25519_dalek::SigningKey;
        let key = SigningKey::from_bytes(&self.secret);
        super::DalekVerifyKey { public: key.verifying_key() }
    }
}