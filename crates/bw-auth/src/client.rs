//! OPAQUE client-side registration and login flows.

use crate::{AuthError, DefaultCipherSuite, SessionKey};
use opaque_ke::{
    ClientLogin, ClientLoginFinishParameters, ClientLoginStartResult, ClientRegistration,
    ClientRegistrationFinishParameters, ClientRegistrationStartResult, CredentialRequest,
    CredentialResponse, RegistrationRequest, RegistrationResponse, RegistrationUpload,
};
use rand::rngs::OsRng;

/// The client-side registration start: the message to send to the server and
/// the state to keep until the response arrives.
pub struct ClientRegistrationStart {
    /// The registration request to send to the server.
    pub request: RegistrationRequest<DefaultCipherSuite>,
    /// State retained by the client until [`finish_registration`] is called.
    pub state: ClientRegistration<DefaultCipherSuite>,
}

/// The client-side login start: the credential request to send to the server
/// and the state to keep until the response arrives.
pub struct ClientLoginStart {
    /// The credential request to send to the server.
    pub request: CredentialRequest<DefaultCipherSuite>,
    /// State retained by the client until [`finish_login`] is called.
    pub state: ClientLogin<DefaultCipherSuite>,
}

/// The client-side login finish: the finalization message for the server and
/// the shared session key.
pub struct ClientLoginFinish {
    /// The credential finalization to send to the server.
    pub finalization: opaque_ke::CredentialFinalization<DefaultCipherSuite>,
    /// The shared session key, matching the server's on success.
    pub session_key: SessionKey,
}

/// Starts OPAQUE registration from the client side.
///
/// Returns the [`RegistrationRequest`] to send to the server and the client
/// state required to finish registration once the server responds.
pub fn start_registration(password: &[u8]) -> Result<ClientRegistrationStart, AuthError> {
    let mut rng = OsRng;
    let result: ClientRegistrationStartResult<DefaultCipherSuite> =
        ClientRegistration::<DefaultCipherSuite>::start(&mut rng, password)?;
    Ok(ClientRegistrationStart {
        request: result.message,
        state: result.state,
    })
}

/// Finishes OPAQUE registration from the client side.
///
/// Consumes the client state from [`start_registration`] and the server's
/// [`RegistrationResponse`], returning the [`RegistrationUpload`] to send back
/// to the server.
pub fn finish_registration(
    state: ClientRegistration<DefaultCipherSuite>,
    response: RegistrationResponse<DefaultCipherSuite>,
    password: &[u8],
) -> Result<RegistrationUpload<DefaultCipherSuite>, AuthError> {
    let mut rng = OsRng;
    let result = state.finish(
        &mut rng,
        password,
        response,
        ClientRegistrationFinishParameters::default(),
    )?;
    Ok(result.message)
}

/// Deserializes a server credential response received over the wire.
pub fn deserialize_credential_response(
    bytes: &[u8],
) -> Result<CredentialResponse<DefaultCipherSuite>, AuthError> {
    CredentialResponse::deserialize(bytes).map_err(AuthError::from)
}

/// Starts OPAQUE login from the client side.
///
/// Returns the [`CredentialRequest`] to send to the server and the client
/// state required to finish login once the server responds.
pub fn start_login(password: &[u8]) -> Result<ClientLoginStart, AuthError> {
    let mut rng = OsRng;
    let result: ClientLoginStartResult<DefaultCipherSuite> =
        ClientLogin::<DefaultCipherSuite>::start(&mut rng, password)?;
    Ok(ClientLoginStart {
        request: result.message,
        state: result.state,
    })
}

/// Finishes OPAQUE login from the client side.
///
/// Consumes the client state from [`start_login`] and the server's
/// [`CredentialResponse`]. On a wrong password this returns
/// `AuthError::Protocol(ProtocolError::InvalidLoginError)`; on success it
/// returns the credential finalization for the server and the shared session
/// key.
pub fn finish_login(
    state: ClientLogin<DefaultCipherSuite>,
    response: CredentialResponse<DefaultCipherSuite>,
    password: &[u8],
) -> Result<ClientLoginFinish, AuthError> {
    let mut rng = OsRng;
    let result = state.finish(
        &mut rng,
        password,
        response,
        ClientLoginFinishParameters::default(),
    )?;
    Ok(ClientLoginFinish {
        finalization: result.message,
        session_key: SessionKey(result.session_key.as_slice().to_vec()),
    })
}
