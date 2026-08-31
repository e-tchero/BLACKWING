#![allow(clippy::unwrap_used, clippy::expect_used)]
#![allow(missing_docs)]

//! H5+H6 regression tests for certificate pinning and SNI handling.

use bw_transport::cert;
use bw_transport::{QuicClient, QuicServer};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

/// Helper: generate a server TLS keypair and its DeviceId.
fn make_server_identity() -> (rcgen::KeyPair, bw_crypto::DeviceId) {
    let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let device_id = cert::device_id_from_keypair(&kp);
    (kp, device_id)
}

/// Test 1: Valid production certificate accepted.
#[tokio::test]
async fn test_valid_production_identity_accepted() {
    let (kp, server_id) = make_server_identity();

    let server_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));
    let server = QuicServer::bind(server_addr, None, &kp, vec!["127.0.0.1".into()]).unwrap();
    let bound_addr = server.endpoint.local_addr().unwrap();
    let connect_addr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), bound_addr.port());

    let client = QuicClient::bind(None, server_id).unwrap();

    let server_task = tokio::spawn(async move {
        let conn = server.accept().await.expect("server should accept");
        let (mut send, mut recv) = conn.accept_bi().await.expect("should accept bi");
        let mut buf = vec![0u8; 4];
        recv.read_exact(&mut buf).await.expect("should read");
        assert_eq!(&buf, b"ping");
        send.write_all(b"pong").await.expect("should write");
        send.finish().expect("should finish");
        conn.closed().await;
    });

    let conn = client.connect(connect_addr).await.expect("should connect");
    let (mut send, mut recv) = conn.open_bi().await.expect("should open bi");
    send.write_all(b"ping").await.expect("should write");
    send.finish().expect("should finish");
    let mut buf = vec![0u8; 4];
    recv.read_exact(&mut buf).await.expect("should read");
    assert_eq!(&buf, b"pong");
    server_task.await.unwrap();
}

/// Test 2: Wrong server identity rejected.
#[tokio::test]
async fn test_wrong_identity_rejected() {
    let (kp_a, _server_a_id) = make_server_identity();
    let (_kp_b, client_expected_id) = make_server_identity();

    let server_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));
    let server = QuicServer::bind(server_addr, None, &kp_a, vec!["127.0.0.1".into()]).unwrap();
    let bound_addr = server.endpoint.local_addr().unwrap();
    let connect_addr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), bound_addr.port());

    let client = QuicClient::bind(None, client_expected_id).unwrap();

    let result = client.connect(connect_addr).await;
    assert!(
        result.is_err(),
        "connection should fail when identity mismatches"
    );
}

/// Test 3: Dev client connects to dev server.
#[tokio::test]
async fn test_dev_mode_bypass_works() {
    let server_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));
    let server = QuicServer::bind_dev(server_addr, None).unwrap();
    let bound_addr = server.endpoint.local_addr().unwrap();
    let connect_addr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), bound_addr.port());

    let client = QuicClient::bind_dev(None).unwrap();

    let server_task = tokio::spawn(async move {
        let conn = server.accept().await.expect("server should accept");
        let (mut send, _) = conn.accept_bi().await.expect("should accept bi");
        send.write_all(b"ok").await.expect("should write");
        send.finish().expect("should finish");
        conn.closed().await;
    });

    let conn = client
        .connect(connect_addr)
        .await
        .expect("dev should connect");
    let (_, mut recv) = conn.open_bi().await.expect("should open bi");
    let mut buf = vec![0u8; 2];
    recv.read_exact(&mut buf).await.expect("should read");
    assert_eq!(&buf, b"ok");
    server_task.await.unwrap();
}

/// Test 4: Certificate generation from KeyPair produces valid config.
#[test]
fn test_cert_generation_from_keypair() {
    let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let config = cert::generate_server_config_from_keypair(&kp, vec!["localhost".into()]).unwrap();
    assert_eq!(config.alpn_protocols, vec![b"blackwing-v1".to_vec()]);
}

/// Test 5: Dev client config exists.
#[test]
fn test_dev_client_config_exists() {
    let config = cert::generate_dev_client_config();
    assert_eq!(config.alpn_protocols, vec![b"blackwing-v1".to_vec()]);
}

/// Test 6: Pinned client config creation.
#[test]
fn test_pinned_client_config_creation() {
    let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let device_id = cert::device_id_from_keypair(&kp);
    let config = cert::generate_pinned_client_config(device_id);
    assert_eq!(config.alpn_protocols, vec![b"blackwing-v1".to_vec()]);
}

/// Test 7: Production client rejects dev server.
#[tokio::test]
async fn test_production_client_rejects_dev_server() {
    let (_kp, expected_id) = make_server_identity();

    let server_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));
    let server = QuicServer::bind_dev(server_addr, None).unwrap();
    let bound_addr = server.endpoint.local_addr().unwrap();
    let connect_addr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), bound_addr.port());

    let client = QuicClient::bind(None, expected_id).unwrap();

    let result = client.connect(connect_addr).await;
    assert!(
        result.is_err(),
        "production client should reject dev server"
    );
}

/// Test 8: Dev client connects to production server.
#[tokio::test]
async fn test_dev_client_connects_to_production_server() {
    let (kp, _server_id) = make_server_identity();

    let server_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));
    let server = QuicServer::bind(server_addr, None, &kp, vec!["127.0.0.1".into()]).unwrap();
    let bound_addr = server.endpoint.local_addr().unwrap();
    let connect_addr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), bound_addr.port());

    let client = QuicClient::bind_dev(None).unwrap();

    let server_task = tokio::spawn(async move {
        let conn = server.accept().await.expect("server should accept");
        let (mut send, _) = conn.accept_bi().await.expect("should accept bi");
        send.write_all(b"ok").await.expect("should write");
        send.finish().expect("should finish");
        conn.closed().await;
    });

    let conn = client
        .connect(connect_addr)
        .await
        .expect("dev should connect to prod server");
    let (_, mut recv) = conn.open_bi().await.expect("should open bi");
    let mut buf = vec![0u8; 2];
    recv.read_exact(&mut buf).await.expect("should read");
    assert_eq!(&buf, b"ok");
    server_task.await.unwrap();
}

/// Test 9: DeviceId is consistent between KeyPair and raw key extraction.
#[test]
fn test_device_id_consistency() {
    let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let device_id = cert::device_id_from_keypair(&kp);

    // Extract raw public key and verify DeviceId derivation matches.
    let pub_raw = cert::public_key_raw(&kp);
    assert_eq!(pub_raw.len(), 32);

    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(pub_raw);
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&hasher.finalize());
    let manual_id = bw_crypto::DeviceId::from_digest(digest);

    assert_eq!(device_id, manual_id);
}
