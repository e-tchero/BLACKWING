//! Integration tests for the OPAQUE registration and login flows.

#![allow(clippy::unwrap_used, clippy::expect_used)]
#![allow(missing_docs)]

use bw_auth::client;
use bw_auth::error::AuthError;
use bw_auth::server;
use bw_auth::DefaultCipherSuite;
use opaque_ke::errors::ProtocolError;
use opaque_ke::{ServerRegistration, ServerSetup};

const PASSWORD: &[u8] = b"correct horse battery staple";
const IDENTIFIER: &[u8] = b"alice@example.com";

/// Runs a complete 4-message registration, returning the server's password file.
fn register(
    setup: &ServerSetup<DefaultCipherSuite>,
    identifier: &[u8],
    password: &[u8],
) -> ServerRegistration<DefaultCipherSuite> {
    // Message 1: client -> server
    let start = client::start_registration(password).unwrap();
    let (request, state) = (start.request, start.state);
    // Message 2: server -> client
    let response = server::start_registration(setup, request, identifier).unwrap();
    // Message 3: client -> server
    let upload = client::finish_registration(state, response, password).unwrap();
    // Message 4: server stores the password file
    server::finish_registration(upload)
}

#[test]
fn test_full_registration_and_login() {
    let setup = server::new_setup();
    let password_file = register(&setup, IDENTIFIER, PASSWORD);

    // Message 1: client -> server
    let client_start = client::start_login(PASSWORD).unwrap();
    let (client_request, client_state) = (client_start.request, client_start.state);
    // Message 2: server -> client
    let server_start =
        server::start_login(&setup, password_file, client_request, IDENTIFIER).unwrap();
    let (server_response, server_state) = (server_start.response, server_start.state);
    // Message 3: client -> server
    let client_finish = client::finish_login(client_state, server_response, PASSWORD).unwrap();
    // Message 4: server finishes
    let server_key = server::finish_login(server_state, client_finish.finalization).unwrap();

    assert_eq!(client_finish.session_key, server_key);
}

#[test]
fn test_wrong_password_rejected() {
    let setup = server::new_setup();
    let password_file = register(&setup, IDENTIFIER, PASSWORD);

    let client_start = client::start_login(b"wrong password").unwrap();
    let (client_request, client_state) = (client_start.request, client_start.state);
    let server_start =
        server::start_login(&setup, password_file, client_request, IDENTIFIER).unwrap();

    // Client detects the mismatch when finishing login.
    let result = client::finish_login(client_state, server_start.response, b"wrong password");
    assert!(result.is_err());
    assert!(matches!(
        result.err().unwrap(),
        AuthError::Protocol(ProtocolError::InvalidLoginError)
    ));
}

#[test]
fn test_session_keys_match() {
    let setup = server::new_setup();
    let password_file = register(&setup, IDENTIFIER, PASSWORD);

    let client_start = client::start_login(PASSWORD).unwrap();
    let (client_request, client_state) = (client_start.request, client_start.state);
    let server_start =
        server::start_login(&setup, password_file, client_request, IDENTIFIER).unwrap();
    let (server_response, server_state) = (server_start.response, server_start.state);
    let client_finish = client::finish_login(client_state, server_response, PASSWORD).unwrap();
    let server_key = server::finish_login(server_state, client_finish.finalization).unwrap();

    // Both parties derive the same session key.
    assert_eq!(client_finish.session_key.as_bytes(), server_key.as_bytes());
    assert!(!client_finish.session_key.as_bytes().is_empty());
}

#[test]
fn test_session_keys_are_unique() {
    let setup = server::new_setup();
    let password_file = register(&setup, IDENTIFIER, PASSWORD);

    // First login.
    let client_start = client::start_login(PASSWORD).unwrap();
    let (client_request, client_state) = (client_start.request, client_start.state);
    let server_start =
        server::start_login(&setup, password_file.clone(), client_request, IDENTIFIER).unwrap();
    let (server_response, server_state) = (server_start.response, server_start.state);
    let client_finish = client::finish_login(client_state, server_response, PASSWORD).unwrap();
    let server_key = server::finish_login(server_state, client_finish.finalization).unwrap();
    let first_key = client_finish.session_key;
    // Sanity: client and server agree on the first session key.
    assert_eq!(first_key.as_bytes(), server_key.as_bytes());

    // Second login with the same password file and password.
    let client_start = client::start_login(PASSWORD).unwrap();
    let (client_request, client_state) = (client_start.request, client_start.state);
    let server_start =
        server::start_login(&setup, password_file, client_request, IDENTIFIER).unwrap();
    let (server_response, server_state) = (server_start.response, server_start.state);
    let client_finish = client::finish_login(client_state, server_response, PASSWORD).unwrap();
    let second_key = client_finish.session_key;
    let second_server_key = server::finish_login(server_state, client_finish.finalization).unwrap();
    assert_eq!(second_key.as_bytes(), second_server_key.as_bytes());

    // Forward secrecy: each login derives a fresh, distinct session key.
    assert_ne!(first_key.as_bytes(), second_key.as_bytes());
    assert_ne!(server_key.as_bytes(), second_server_key.as_bytes());
}
