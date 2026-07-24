pub(crate) mod dalek;
pub(crate) mod tpm;

pub(crate) enum SigningKeyInner {
    Dalek(dalek::DalekSigningKey),
    Tpm(tpm::TpmSigningKey),
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) enum VerifyKeyInner {
    Dalek(dalek::DalekVerifyKey),
    Tpm(tpm::TpmVerifyKey),
}
