use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::sync::Arc;
use thiserror::Error;

/// Errors produced while generating or configuring TLS certificates.
#[derive(Debug, Error)]
pub enum CertError {
    /// Certificate generation failed (rcgen error).
    #[error("Failed to generate certificate: {0}")]
    Rcgen(#[from] rcgen::Error),
    /// The generated key could not be parsed into a rustls key.
    #[error("Failed to parse private key")]
    KeyParseError,
}

/// A self-signed X.509 certificate and its private key.
pub struct SelfSignedCert {
    /// DER-encoded certificate.
    pub cert: CertificateDer<'static>,
    /// Private key material in PKCS#8 form.
    pub key: PrivateKeyDer<'static>,
}

impl SelfSignedCert {
    /// Generates a self-signed certificate for the given subject alternative names (SANs).
    pub fn generate(subject_alt_names: Vec<String>) -> Result<Self, CertError> {
        let cert = rcgen::generate_simple_self_signed(subject_alt_names)?;

        let cert_der = cert.cert.der().clone();
        let key_der = PrivateKeyDer::Pkcs8(cert.key_pair.serialize_der().into());

        Ok(Self {
            cert: cert_der,
            key: key_der,
        })
    }
}

/// Generates a rustls ServerConfig configured with a self-signed certificate.
pub fn generate_server_config(
    subject_alt_names: Vec<String>,
) -> Result<rustls::ServerConfig, CertError> {
    let self_signed = SelfSignedCert::generate(subject_alt_names)?;

    let mut server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![self_signed.cert], self_signed.key)
        .map_err(|_| CertError::KeyParseError)?;

    server_config.alpn_protocols = vec![b"blackwing-v1".to_vec()];

    Ok(server_config)
}

/// Generates a rustls ClientConfig that skips server certificate verification.
/// WARNING: This is for development/testing only. In production, use standard PKI or
/// pin the server's certificate.
pub fn generate_client_config() -> rustls::ClientConfig {
    #[derive(Debug)]
    struct SkipServerVerification;

    impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &rustls::pki_types::ServerName<'_>,
            _ocsp_response: &[u8],
            _now: rustls::pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            vec![
                rustls::SignatureScheme::RSA_PKCS1_SHA256,
                rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
                rustls::SignatureScheme::ED25519,
            ]
        }
    }

    let mut client_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
        .with_no_client_auth();

    client_config.alpn_protocols = vec![b"blackwing-v1".to_vec()];

    client_config
}
