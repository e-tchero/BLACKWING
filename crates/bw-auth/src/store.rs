//! Server-side OPAQUE enrollment store.
//!
//! Persists the OPAQUE server setup plus one password file per registered
//! identifier, and runs the one-shot registration flow (client + server steps
//! in-process) so an operator can enroll a device without a separate client.

use crate::{client, server, AuthError, DefaultCipherSuite, ServerRegistration, ServerSetup};
use std::collections::HashMap;
use std::path::Path;
use thiserror::Error;

/// Errors produced by the enrollment store.
#[derive(Debug, Error)]
pub enum StoreError {
    /// An OPAQUE protocol step failed.
    #[error("authentication error: {0}")]
    Auth(#[from] AuthError),
    /// Reading or writing an enrollment file failed.
    #[error("enrollment file I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// The data directory does not contain a server setup.
    #[error("no server setup found in {0} — run with --register first")]
    MissingSetup(String),
    /// The identifier attempted to log in but has no enrollment.
    #[error("identifier is not enrolled")]
    NotEnrolled,
}

/// Server-side OPAQUE credential store.
///
/// Holds the [`ServerSetup`] and a password file per identifier. Registration
/// runs the full OPAQUE registration flow in-process; logins are served by
/// [`EnrollmentStore::start_login`] / [`EnrollmentStore::finish_login`].
pub struct EnrollmentStore {
    setup: ServerSetup<DefaultCipherSuite>,
    enrollments: HashMap<Vec<u8>, ServerRegistration<DefaultCipherSuite>>,
}

impl Default for EnrollmentStore {
    fn default() -> Self {
        Self::new()
    }
}

impl EnrollmentStore {
    /// Creates an empty store with a freshly generated server setup.
    pub fn new() -> Self {
        Self {
            setup: server::new_setup(),
            enrollments: HashMap::new(),
        }
    }

    /// Enrolls a device: runs the full OPAQUE registration flow in-process so
    /// the server can authenticate logins for `identifier` with `password`.
    pub fn register(&mut self, identifier: &[u8], password: &[u8]) -> Result<(), StoreError> {
        let reg_start = client::start_registration(password)?;
        let reg_resp = server::start_registration(&self.setup, reg_start.request, identifier)?;
        let reg_upload = client::finish_registration(reg_start.state, reg_resp, password)?;
        let password_file = server::finish_registration(reg_upload);
        self.enrollments.insert(identifier.to_vec(), password_file);
        Ok(())
    }

    /// Returns the stored password file for `identifier`, if enrolled.
    pub fn get(&self, identifier: &[u8]) -> Option<&ServerRegistration<DefaultCipherSuite>> {
        self.enrollments.get(identifier)
    }

    /// Returns the server setup used for all registrations and logins.
    pub fn setup(&self) -> &ServerSetup<DefaultCipherSuite> {
        &self.setup
    }

    /// Whether `identifier` is enrolled.
    pub fn contains(&self, identifier: &[u8]) -> bool {
        self.enrollments.contains_key(identifier)
    }

    /// Starts a server-side login for `identifier` with a client credential
    /// request, returning the serialized credential response to send back.
    ///
    /// The returned login state must be passed to [`EnrollmentStore::finish_login`]
    /// once the client's finalization arrives.
    pub fn start_login(
        &self,
        identifier: &[u8],
        credential_request: &[u8],
    ) -> Result<(crate::server::ServerLoginStart, Vec<u8>), StoreError> {
        let request =
            crate::CredentialRequest::<DefaultCipherSuite>::deserialize(credential_request)
                .map_err(AuthError::from)?;
        let password_file = self.get(identifier).ok_or(StoreError::NotEnrolled)?.clone();
        let login = server::start_login(&self.setup, password_file, request, identifier)?;
        let response = login.response.serialize().to_vec();
        Ok((login, response))
    }

    /// Finishes a server-side login, returning the shared session key.
    pub fn finish_login(
        &self,
        login: crate::server::ServerLoginStart,
        finalization: &[u8],
    ) -> Result<crate::SessionKey, StoreError> {
        let finalization =
            crate::CredentialFinalization::<DefaultCipherSuite>::deserialize(finalization)
                .map_err(AuthError::from)?;
        Ok(server::finish_login(login.state, finalization)?)
    }

    /// Persists the setup and all password files to `dir`.
    pub fn save_to_dir(&self, dir: &Path) -> Result<(), StoreError> {
        std::fs::create_dir_all(dir)?;
        std::fs::write(
            dir.join("setup.opaque"),
            server::serialize_setup(&self.setup),
        )?;
        for (identifier, registration) in &self.enrollments {
            let name = hex(identifier);
            std::fs::write(
                dir.join(format!("{name}.opaque")),
                server::serialize_registration(registration),
            )?;
        }
        Ok(())
    }

    /// Loads a store previously written by [`EnrollmentStore::save_to_dir`].
    pub fn load_from_dir(dir: &Path) -> Result<Self, StoreError> {
        let setup_path = dir.join("setup.opaque");
        let setup_bytes = std::fs::read(&setup_path)
            .map_err(|_| StoreError::MissingSetup(dir.display().to_string()))?;
        let setup = server::deserialize_setup(&setup_bytes)?;

        let mut enrollments = HashMap::new();
        let entries = std::fs::read_dir(dir)?;
        for entry in entries {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().to_string();
            if name == "setup.opaque" || !name.ends_with(".opaque") {
                continue;
            }
            let Some(hex_id) = name.strip_suffix(".opaque") else {
                continue;
            };
            let identifier = unhex(hex_id);
            if let Ok(bytes) = std::fs::read(entry.path()) {
                if let Ok(registration) = server::deserialize_registration(&bytes) {
                    enrollments.insert(identifier, registration);
                }
            }
        }

        Ok(Self { setup, enrollments })
    }

    /// Returns the number of enrolled identifiers.
    pub fn len(&self) -> usize {
        self.enrollments.len()
    }

    /// Whether the store has no enrollments.
    pub fn is_empty(&self) -> bool {
        self.enrollments.is_empty()
    }
}

/// Lowercase hex of a byte slice (used for enrollment file names).
fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Decodes a lowercase hex string into bytes.
fn unhex(hex: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(hex.len() / 2);
    let bytes = hex.as_bytes();
    let mut i = 0;
    while i + 1 < bytes.len() {
        let hi = (bytes[i] as char).to_digit(16).unwrap_or(0) as u8;
        let lo = (bytes[i + 1] as char).to_digit(16).unwrap_or(0) as u8;
        out.push((hi << 4) | lo);
        i += 2;
    }
    out
}
