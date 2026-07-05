pub(crate) mod dalek;
pub(crate) mod tpm;

pub(crate) enum SigningKeyInner {
    Dalek(dalek::DalekSigningKey),
    Tpm(tpm::TpmSigningKey),
}

pub(crate) enum VerifyKeyInner {
    Dalek(dalek::DalekVerifyKey),
    Tpm(tpm::TpmVerifyKey),
}