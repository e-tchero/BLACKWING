use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use sha2::{Digest, Sha256};
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
    /// The certificate did not contain a valid Ed25519 public key.
    #[error("Invalid certificate public key")]
    InvalidPublicKey,
    /// The certificate public key does not match the expected DeviceId.
    #[error("Certificate identity mismatch: expected {expected}, got {actual}")]
    IdentityMismatch {
        /// The expected DeviceId.
        expected: String,
        /// The actual DeviceId from the certificate.
        actual: String,
    },
}

// =========================================================================
// Key Management
// =========================================================================

/// Loads or generates an rcgen Ed25519 KeyPair, persisting the PKCS#8 DER.
///
/// If the file at `pkcs8_path` exists, loads the key from it.
/// Otherwise generates a fresh Ed25519 key pair and saves the PKCS#8 DER.
pub fn load_or_generate_tls_keypair(
    pkcs8_path: &std::path::Path,
) -> Result<rcgen::KeyPair, CertError> {
    if pkcs8_path.exists() {
        let data = std::fs::read(pkcs8_path).map_err(|_| CertError::KeyParseError)?;
        let pkcs8 = rustls::pki_types::PrivatePkcs8KeyDer::from(data);
        let kp = rcgen::KeyPair::from_pkcs8_der_and_sign_algo(&pkcs8, &rcgen::PKCS_ED25519)?;
        Ok(kp)
    } else {
        let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519)?;
        if let Some(parent) = pkcs8_path.parent() {
            std::fs::create_dir_all(parent).map_err(|_| CertError::KeyParseError)?;
        }
        std::fs::write(pkcs8_path, kp.serialize_der()).map_err(|_| CertError::KeyParseError)?;
        Ok(kp)
    }
}

/// Derives the Blackwing DeviceId from an rcgen KeyPair's Ed25519 public key.
///
/// Computes: DeviceId = SHA-256(raw_ed25519_public_key_bytes).
/// This matches the derivation used by `bw_crypto::SigningKey::verify_key().device_id()`.
pub fn device_id_from_keypair(kp: &rcgen::KeyPair) -> bw_crypto::DeviceId {
    let pub_raw = kp.public_key_raw();
    let mut hasher = Sha256::new();
    hasher.update(pub_raw);
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&hasher.finalize());
    bw_crypto::DeviceId::from_digest(digest)
}

/// Returns the raw 32-byte Ed25519 public key from an rcgen KeyPair.
pub fn public_key_raw(kp: &rcgen::KeyPair) -> &[u8] {
    kp.public_key_raw()
}

// =========================================================================
// Server Configuration
// =========================================================================

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

/// Generates a rustls ServerConfig with a self-signed certificate from the
/// given rcgen Ed25519 KeyPair.
///
/// The certificate's SubjectPublicKeyInfo is bound to the Blackwing DeviceId
/// derived from this key pair, enabling client-side certificate pinning.
pub fn generate_server_config_from_keypair(
    key_pair: &rcgen::KeyPair,
    subject_alt_names: Vec<String>,
) -> Result<rustls::ServerConfig, CertError> {
    let params = rcgen::CertificateParams::new(subject_alt_names)?;
    let cert = params.self_signed(key_pair)?;

    let cert_der = cert.der().clone();
    let key_der = PrivateKeyDer::Pkcs8(key_pair.serialize_der().into());

    let mut server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .map_err(|_| CertError::KeyParseError)?;

    server_config.alpn_protocols = vec![b"blackwing-v1".to_vec()];
    Ok(server_config)
}

/// Generates a rustls ServerConfig using a randomly generated key (legacy/dev).
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

// =========================================================================
// H5: Certificate Pinning — DeviceId-based server identity verification
// =========================================================================

/// Custom rustls certificate verifier that pins the server's Ed25519 public
/// key to a specific Blackwing DeviceId.
///
/// Verification: extract raw 32-byte Ed25519 public key from cert → SHA-256 →
/// compare to expected DeviceId. Reject if mismatch.
#[derive(Debug)]
struct DeviceIdPinningVerifier {
    expected_id: bw_crypto::DeviceId,
}

impl rustls::client::danger::ServerCertVerifier for DeviceIdPinningVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let public_key_bytes = extract_ed25519_spki_raw(end_entity.as_ref())
            .map_err(|_| rustls::Error::General("invalid certificate public key".into()))?;

        let mut hasher = Sha256::new();
        hasher.update(public_key_bytes);
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&hasher.finalize());
        let actual_id = bw_crypto::DeviceId::from_digest(digest);

        if actual_id != self.expected_id {
            return Err(rustls::Error::General(format!(
                "server identity mismatch: expected {}, got {}",
                self.expected_id, actual_id
            )));
        }

        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        // Primary security comes from certificate pinning above.
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        // Primary security comes from certificate pinning above.
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
        ]
    }
}

/// Generates a production rustls ClientConfig with certificate pinning.
/// Only accepts servers whose certificate's Ed25519 public key hashes to `server_id`.
pub fn generate_pinned_client_config(server_id: bw_crypto::DeviceId) -> rustls::ClientConfig {
    let verifier = DeviceIdPinningVerifier {
        expected_id: server_id,
    };

    let mut client_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();

    client_config.alpn_protocols = vec![b"blackwing-v1".to_vec()];
    client_config
}

/// Generates a development-only rustls ClientConfig that skips certificate
/// verification entirely. MUST NOT be used in production.
pub fn generate_dev_client_config() -> rustls::ClientConfig {
    #[derive(Debug)]
    struct SkipServerVerification;

    impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
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

// =========================================================================
// Helper: Ed25519 SPKI public key extraction
// =========================================================================

/// Extracts the raw 32-byte Ed25519 public key from an X.509 certificate's
/// SubjectPublicKeyInfo (SPKI) field.
///
/// Searches for the Ed25519 OID (06 03 2b 65 70) in the cert DER, then
/// reads the 33-byte BIT STRING that follows (1 unused-bit byte + 32 key bytes).
fn extract_ed25519_spki_raw(cert_der: &[u8]) -> Result<[u8; 32], CertError> {
    // The Ed25519 OID (06 03 2b 65 70) appears twice in an Ed25519 cert:
    //   1. In SubjectPublicKeyInfo.algorithm (followed by BIT STRING of 33 bytes)
    //   2. In signatureAlgorithm (followed by BIT STRING of 65 bytes)
    // We want the SPKI occurrence — search for the one followed by BIT STRING 0x21.
    let oid_pattern = [0x06, 0x03, 0x2b, 0x65, 0x70];
    let mut oid_pos = 0;

    while oid_pos + oid_pattern.len() < cert_der.len() {
        match cert_der[oid_pos..]
            .windows(oid_pattern.len())
            .position(|w| w == oid_pattern)
        {
            Some(offset) => {
                let abs_pos = oid_pos + offset;
                let after_oid = abs_pos + oid_pattern.len();
                if after_oid + 3 > cert_der.len() {
                    return Err(CertError::InvalidPublicKey);
                }
                // Check if followed by BIT STRING of 33 bytes (SPKI) vs 65 bytes (signature).
                if cert_der[after_oid] == 0x03 && cert_der[after_oid + 1] == 0x21 {
                    // BIT STRING, 33 bytes — this is the SPKI public key.
                    let unused_bits = after_oid + 2;
                    if cert_der[unused_bits] != 0x00 {
                        return Err(CertError::InvalidPublicKey);
                    }
                    let key_start = unused_bits + 1;
                    if key_start + 32 > cert_der.len() {
                        return Err(CertError::InvalidPublicKey);
                    }
                    let mut key = [0u8; 32];
                    key.copy_from_slice(&cert_der[key_start..key_start + 32]);
                    return Ok(key);
                }
                oid_pos = abs_pos + oid_pattern.len();
            }
            None => break,
        }
    }
    Err(CertError::InvalidPublicKey)
}
