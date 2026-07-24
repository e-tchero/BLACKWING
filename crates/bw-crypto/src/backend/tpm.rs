/// A lightweight TPM 2.0 key reference, holding a session handle for signing
/// while maintaining public verification structures locally in fast RAM.
pub(crate) struct TpmSigningKey {
    pub(crate) key_handle: u32,
}

impl TpmSigningKey {
    pub(crate) fn sign(&self, _message: &[u8]) -> [u8; 64] {
        unimplemented!("TPM signing not yet implemented")
    }

    pub(crate) fn get_verify_key(&self) -> TpmVerifyKey {
        unimplemented!("TPM get_verify_key not yet implemented")
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) struct TpmVerifyKey {
    pub(crate) public_bytes: [u8; 32],
}

impl TpmVerifyKey {
    pub(crate) fn verify(
        &self,
        _message: &[u8],
        _signature: &[u8; 64],
    ) -> crate::error::Result<()> {
        unimplemented!("TPM verify not yet implemented")
    }

    #[inline]
    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.public_bytes
    }
}
