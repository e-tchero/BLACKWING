/// A lightweight TPM 2.0 key reference, holding a session handle for signing
/// while maintaining public verification structures locally in fast RAM.
pub(crate) struct TpmSigningKey {
    pub(crate) key_handle: u32,
}

#[derive(Clone)]
pub(crate) struct TpmVerifyKey {
    pub(crate) public_bytes: [u8; 32],
}

impl TpmVerifyKey {
    #[inline]
    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.public_bytes
    }
}