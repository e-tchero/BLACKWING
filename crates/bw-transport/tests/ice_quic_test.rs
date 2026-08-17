//! End-to-end test: a QUIC connection established entirely over an
//! ICE-negotiated P2P socket (no direct UDP bind, no relay).
//!
//! Two local ICE agents connect over `127.0.0.1`, each side's negotiated
//! socket is wrapped in an `IceUdpSocket`, and Quinn endpoints are built on
//! top. A full QUIC handshake plus a hello/world stream exchange proves the
//! complete P2P path.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use bw_ice::{IceConfig, IceManager};
use bw_transport::{QuicClient, QuicServer};
use std::time::Duration;
use tokio::time::timeout;

/// Establishes a P2P ICE connection between two local agents.
async fn establish_ice_pair() -> (bw_ice::IceConnection, bw_ice::IceConnection) {
    let controlling = IceManager::new(IceConfig {
        is_controlling: true,
        include_loopback: true,
        ..IceConfig::default()
    })
    .await
    .unwrap();
    let controlled = IceManager::new(IceConfig {
        is_controlling: false,
        include_loopback: true,
        ..IceConfig::default()
    })
    .await
    .unwrap();

    let (c_ufrag, c_pwd) = controlling.local_credentials().await;
    let (d_ufrag, d_pwd) = controlled.local_credentials().await;
    controlled.set_remote_credentials(&c_ufrag, &c_pwd).await;
    controlling.set_remote_credentials(&d_ufrag, &d_pwd).await;

    let mut c_rx = controlling.gather_candidates().await.unwrap();
    let mut d_rx = controlled.gather_candidates().await.unwrap();
    let c_collect = tokio::spawn(async move {
        let mut out = Vec::new();
        while let Some(s) = c_rx.recv().await {
            out.push(s);
        }
        out
    });
    let d_collect = tokio::spawn(async move {
        let mut out = Vec::new();
        while let Some(s) = d_rx.recv().await {
            out.push(s);
        }
        out
    });
    let (c_cands, d_cands) = timeout(Duration::from_secs(30), async {
        tokio::join!(c_collect, d_collect)
    })
    .await
    .expect("ICE candidate gathering timed out");
    let c_cands = c_cands.unwrap();
    let d_cands = d_cands.unwrap();
    assert!(
        !c_cands.is_empty(),
        "controlling agent gathered no candidates"
    );
    assert!(
        !d_cands.is_empty(),
        "controlled agent gathered no candidates"
    );

    for cand in &c_cands {
        controlled.add_remote_candidate(cand).await.unwrap();
    }
    for cand in &d_cands {
        controlling.add_remote_candidate(cand).await.unwrap();
    }

    let (c_conn, d_conn) = timeout(Duration::from_secs(30), async {
        tokio::join!(
            controlling.establish_connection(),
            controlled.establish_connection()
        )
    })
    .await
    .expect("ICE connection establishment timed out");

    (c_conn.unwrap(), d_conn.unwrap())
}

#[tokio::test]
async fn quic_handshake_and_data_over_ice() {
    // 1. Negotiate the P2P path.
    let (client_ice, server_ice) = establish_ice_pair().await;

    // 2. Build Quinn endpoints on top of the ICE sockets.
    let server = QuicServer::bind_with_ice(server_ice).expect("server should bind over ICE");
    let server_addr = server.endpoint.local_addr().expect("server has local addr");
    let client = QuicClient::bind_with_ice(client_ice).expect("client should bind over ICE");

    // 3. Full QUIC handshake + stream exchange over the ICE path.
    let server_task = tokio::spawn(async move {
        let conn = server
            .accept()
            .await
            .expect("server should accept over ICE");
        let (mut send_stream, mut recv_stream) =
            conn.accept_bi().await.expect("should accept bi stream");

        let mut buf = vec![0u8; 5];
        recv_stream
            .read_exact(&mut buf)
            .await
            .expect("should read hello");
        assert_eq!(&buf, b"hello");

        send_stream
            .write_all(b"world")
            .await
            .expect("should write world");
        send_stream.finish().expect("should finish stream");

        conn.closed().await;
    });

    let conn = client
        .connect(server_addr)
        .await
        .expect("client should connect over ICE");

    let (mut send_stream, mut recv_stream) = conn.open_bi().await.expect("should open bi stream");
    send_stream
        .write_all(b"hello")
        .await
        .expect("should write hello");
    send_stream.finish().expect("should finish client stream");

    let mut buf = vec![0u8; 5];
    recv_stream
        .read_exact(&mut buf)
        .await
        .expect("should read world");
    assert_eq!(&buf, b"world");

    server_task.await.expect("server task should complete");
}
