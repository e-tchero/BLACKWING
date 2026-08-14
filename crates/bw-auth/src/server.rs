//! OPAQUE server-side registration and login flows.

use crate::{AuthError, DefaultCipherSuite, SessionKey};
use opaque_ke::{
    CredentialFinalization, CredentialRequest, CredentialResponse, RegistrationRequest,
    RegistrationResponse, RegistrationUpload, ServerLogin, ServerLoginParameters,
    ServerRegistration, ServerSetup,
};
use rand::rngs::OsRng;

/// The server-side login start: the credential response to send back to the
/// client and the state to keep until the finalization arrives.
pub struct ServerLoginStart {
    /// The credential response to send to the client.
    pub response: CredentialResponse<DefaultCipherSuite>,
    /// State retained by the server until [`finish_login`] is called.
    pub state: ServerLogin<DefaultCipherSuite>,
}

/// Creates a fresh server setup.
///
/// The setup must be persisted by the server (see [`serialize_setup`] and
/// [`deserialize_setup`]) and reused across registrations and logins.
pub fn new_setup() -> ServerSetup<DefaultCipherSuite> {
    let mut rng = OsRng;
    ServerSetup::<DefaultCipherSuite>::new(&mut rng)
}

/// Starts OPAQUE registration from the server side.
///
/// Consumes the client's [`RegistrationRequest`] and returns the
/// [`RegistrationResponse`] to send back to the client.
pub fn start_registration(
    setup: &ServerSetup<DefaultCipherSuite>,
    request: RegistrationRequest<DefaultCipherSuite>,
    credential_identifier: &[u8],
) -> Result<RegistrationResponse<DefaultCipherSuite>, AuthError> {
    let result =
        ServerRegistration::<DefaultCipherSuite>::start(setup, request, credential_identifier)?;
    Ok(result.message)
}

/// Finishes OPAQUE registration from the server side.
///
/// Consumes the client's [`RegistrationUpload`] and returns the password file
/// ([`ServerRegistration`]) to store for later logins.
pub fn finish_registration(
    upload: RegistrationUpload<DefaultCipherSuite>,
) -> ServerRegistration<DefaultCipherSuite> {
    ServerRegistration::<DefaultCipherSuite>::finish(upload)
}

/// Starts OPAQUE login from the server side.
///
/// Consumes the stored password file from [`finish_registration`] and the
/// client's [`CredentialRequest`], returning the [`CredentialResponse`] to
/// send back to the client together with the server state required to finish
/// the login.
pub fn start_login(
    setup: &ServerSetup<DefaultCipherSuite>,
    password_file: ServerRegistration<DefaultCipherSuite>,
    request: CredentialRequest<DefaultCipherSuite>,
    credential_identifier: &[u8],
) -> Result<ServerLoginStart, AuthError> {
    let mut rng = OsRng;
    let result = ServerLogin::<DefaultCipherSuite>::start(
        &mut rng,
        setup,
        Some(password_file),
        request,
        credential_identifier,
        ServerLoginParameters::default(),
    )?;
    Ok(ServerLoginStart {
        response: result.message,
        state: result.state,
    })
}

/// Finishes OPAQUE login from the server side.
///
/// Consumes the server state from [`start_login`] and the client's
/// [`CredentialFinalization`], returning the shared session key. On a wrong
/// password this returns `AuthError::Protocol(ProtocolError::InvalidLoginError)`.
pub fn finish_login(
    state: ServerLogin<DefaultCipherSuite>,
    finalization: CredentialFinalization<DefaultCipherSuite>,
) -> Result<SessionKey, AuthError> {
    let result = state.finish(finalization, ServerLoginParameters::default())?;
    Ok(SessionKey(result.session_key.as_slice().to_vec()))
}

/// Serializes a [`ServerSetup`] for persistence.
pub fn serialize_setup(setup: &ServerSetup<DefaultCipherSuite>) -> Vec<u8> {
    setup.serialize().as_slice().to_vec()
}

/// Deserializes a [`ServerSetup`] previously written by [`serialize_setup`].
pub fn deserialize_setup(bytes: &[u8]) -> Result<ServerSetup<DefaultCipherSuite>, AuthError> {
    ServerSetup::<DefaultCipherSuite>::deserialize(bytes).map_err(AuthError::from)
}

/// Serializes a [`ServerRegistration`] password file for persistence.
pub fn serialize_registration(registration: &ServerRegistration<DefaultCipherSuite>) -> Vec<u8> {
    registration.serialize().as_slice().to_vec()
}

/// Deserializes a [`ServerRegistration`] previously written by
/// [`serialize_registration`].
pub fn deserialize_registration(
    bytes: &[u8],
) -> Result<ServerRegistration<DefaultCipherSuite>, AuthError> {
    ServerRegistration::<DefaultCipherSuite>::deserialize(bytes).map_err(AuthError::from)
}
