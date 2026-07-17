use bw_crypto::DeviceId;
use bw_protocol::error::ProtocolError;
use bw_protocol::handshake::{
    negotiate_capabilities, Capabilities, HandshakeRequest, HandshakeResponse, HandshakeStatus,
};
use bw_protocol::version::{ProtocolVersion, CURRENT_VERSION};

fn make_mock_device_id() -> DeviceId {
    DeviceId::from_digest([7u8; 32])
}

#[test]
fn test_capabilities_negotiation() {
    // Both support compression and encryption
    let client_caps = Capabilities(
        Capabilities::COMPRESSION | Capabilities::ENCRYPTION | Capabilities::STREAMING,
    );
    let server_caps =
        Capabilities(Capabilities::ENCRYPTION | Capabilities::STREAMING | Capabilities::HEARTBEAT);

    let negotiated = negotiate_capabilities(client_caps, server_caps).unwrap();
    assert!(negotiated.contains(Capabilities::ENCRYPTION));
    assert!(negotiated.contains(Capabilities::STREAMING));
    assert!(!negotiated.contains(Capabilities::COMPRESSION));
    assert!(!negotiated.contains(Capabilities::HEARTBEAT));
}

#[test]
fn test_capabilities_negotiation_missing_encryption() {
    let client_caps = Capabilities(Capabilities::COMPRESSION);
    let server_caps = Capabilities(Capabilities::ENCRYPTION);

    let result = negotiate_capabilities(client_caps, server_caps);
    assert_eq!(result.err(), Some(ProtocolError::IncompatibleCapabilities));
}

#[test]
fn test_handshake_request_validation_compatible() {
    let req = HandshakeRequest {
        client_version: CURRENT_VERSION,
        supported_capabilities: Capabilities(Capabilities::ENCRYPTION),
        device_id: make_mock_device_id(),
        nonce: [0u8; 16],
        timestamp: 1000,
    };

    assert!(req.validate().is_ok());
}

#[test]
fn test_handshake_request_validation_downgrade_prevention() {
    let incompatible_version = ProtocolVersion::new(CURRENT_VERSION.major + 1, 0);
    let req = HandshakeRequest {
        client_version: incompatible_version,
        supported_capabilities: Capabilities(Capabilities::ENCRYPTION),
        device_id: make_mock_device_id(),
        nonce: [0u8; 16],
        timestamp: 1000,
    };

    let result = req.validate();
    assert_eq!(
        result.err(),
        Some(ProtocolError::InvalidVersion(u16::from(
            incompatible_version
        )))
    );
}

#[test]
fn test_handshake_request_validation_invalid_handshake_no_encryption() {
    let req = HandshakeRequest {
        client_version: CURRENT_VERSION,
        supported_capabilities: Capabilities(Capabilities::COMPRESSION),
        device_id: make_mock_device_id(),
        nonce: [0u8; 16],
        timestamp: 1000,
    };

    let result = req.validate();
    assert_eq!(result.err(), Some(ProtocolError::InvalidHandshake));
}

#[test]
fn test_unknown_capability_flags() {
    // Bit 31 is unknown, but should be preserved during roundtrip
    let unknown_bit = 1 << 31;
    let caps = Capabilities(Capabilities::ENCRYPTION | unknown_bit);

    assert!(caps.contains(Capabilities::ENCRYPTION));
    assert!(caps.contains(unknown_bit));

    let mut encoded = Vec::new();
    ciborium::ser::into_writer(&caps, &mut encoded).unwrap();

    let decoded: Capabilities = ciborium::de::from_reader(encoded.as_slice()).unwrap();
    assert_eq!(decoded, caps);
}

#[test]
fn test_cbor_handshake_request_roundtrip() {
    let req = HandshakeRequest {
        client_version: CURRENT_VERSION,
        supported_capabilities: Capabilities(Capabilities::ENCRYPTION | Capabilities::COMPRESSION),
        device_id: make_mock_device_id(),
        nonce: [1u8; 16],
        timestamp: 99999,
    };

    let mut encoded = Vec::new();
    ciborium::ser::into_writer(&req, &mut encoded).unwrap();

    let decoded: HandshakeRequest = ciborium::de::from_reader(encoded.as_slice()).unwrap();
    assert_eq!(decoded, req);
}

#[test]
fn test_cbor_handshake_response_roundtrip() {
    let res = HandshakeResponse {
        accepted_version: CURRENT_VERSION,
        negotiated_capabilities: Capabilities(Capabilities::ENCRYPTION),
        server_nonce: [2u8; 16],
        session_id: [3u8; 16],
        status: HandshakeStatus::Accepted,
    };

    let mut encoded = Vec::new();
    ciborium::ser::into_writer(&res, &mut encoded).unwrap();

    let decoded: HandshakeResponse = ciborium::de::from_reader(encoded.as_slice()).unwrap();
    assert_eq!(decoded, res);
}

#[test]
fn test_malformed_packets() {
    let malformed_bytes = b"not a valid cbor handshake request";
    let result: Result<HandshakeRequest, _> = ciborium::de::from_reader(malformed_bytes.as_slice());
    assert!(result.is_err());
}

#[test]
fn test_session_key_derivation() {
    let master = bw_crypto::SymmetricKey([5u8; 32]);
    let client_nonce = [1u8; 16];
    let server_nonce = [2u8; 16];

    let keys = bw_protocol::handshake::derive_session_keys(&master, &client_nonce, &server_nonce)
        .expect("Derivation failed");

    assert_eq!(keys.epoch, 0);
    // Keys should be derived and distinct
    assert_ne!(keys.send_key.0, master.0);
    assert_ne!(keys.recv_key.0, master.0);
    assert_ne!(keys.send_key.0, keys.recv_key.0);
}
