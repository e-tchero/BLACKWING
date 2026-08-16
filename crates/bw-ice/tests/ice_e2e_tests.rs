//! End-to-end ICE tests: two local agents establish a direct connection over
//! `127.0.0.1`, plus error-path coverage.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::Duration;

use bw_ice::{IceConfig, IceError, IceManager};
use tokio::time::timeout;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const DATA_TIMEOUT: Duration = Duration::from_secs(10);

/// Two local agents (one controlling, one controlled) gather candidates,
/// exchange them, and establish a direct connection over `127.0.0.1`.
#[tokio::test]
async fn local_agents_establish_direct_connection() {
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

    // Exchange ICE credentials (normally done out-of-band, e.g. over the relay).
    let (c_ufrag, c_pwd) = controlling.local_credentials().await;
    let (d_ufrag, d_pwd) = controlled.local_credentials().await;
    controlled.set_remote_credentials(&c_ufrag, &c_pwd).await;
    controlling.set_remote_credentials(&d_ufrag, &d_pwd).await;

    // Gather candidates on both sides; the streams end when gathering completes.
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
    let (c_cands, d_cands) = tokio::join!(c_collect, d_collect);
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

    // Exchange candidates.
    for cand in &c_cands {
        controlled.add_remote_candidate(cand).await.unwrap();
    }
    for cand in &d_cands {
        controlling.add_remote_candidate(cand).await.unwrap();
    }

    // Establish connections on both sides concurrently.
    let (c_conn, d_conn) = timeout(CONNECT_TIMEOUT, async {
        tokio::join!(
            controlling.establish_connection(),
            controlled.establish_connection()
        )
    })
    .await
    .expect("ICE connection establishment timed out");
    let c_conn = c_conn.unwrap();
    let d_conn = d_conn.unwrap();

    // The negotiated socket carries real addresses.
    let _ = c_conn.local_addr().unwrap();
    assert!(c_conn.remote_addr().is_some());

    // Bidirectional data over the direct path.
    c_conn.send(b"ping-from-controlling").await.unwrap();
    let mut buf = [0u8; 64];
    let n = timeout(DATA_TIMEOUT, d_conn.recv(&mut buf))
        .await
        .expect("controlled side timed out waiting for data")
        .unwrap();
    assert_eq!(&buf[..n], b"ping-from-controlling");

    d_conn.send(b"pong-from-controlled").await.unwrap();
    let n = timeout(DATA_TIMEOUT, c_conn.recv(&mut buf))
        .await
        .expect("controlling side timed out waiting for data")
        .unwrap();
    assert_eq!(&buf[..n], b"pong-from-controlled");

    // Clean shutdown.
    controlling.close().await.unwrap();
    controlled.close().await.unwrap();
}

/// A malformed remote candidate string is rejected with a parse error.
#[tokio::test]
async fn rejects_malformed_remote_candidate() {
    let manager = IceManager::new(IceConfig::default()).await.unwrap();
    let err = manager
        .add_remote_candidate("this is not an ICE candidate")
        .await;
    assert!(matches!(err, Err(IceError::InvalidCandidate(_, _))));
}

/// Establishing a connection without remote credentials fails fast.
#[tokio::test]
async fn establish_connection_without_credentials_fails() {
    let manager = IceManager::new(IceConfig::default()).await.unwrap();
    let err = manager.establish_connection().await;
    assert!(matches!(err, Err(IceError::MissingRemoteCredentials)));
}

/// Gathering candidates twice is rejected.
#[tokio::test]
async fn gathering_twice_fails() {
    let manager = IceManager::new(IceConfig::default()).await.unwrap();
    let _rx = manager.gather_candidates().await.unwrap();
    let err = manager.gather_candidates().await;
    assert!(matches!(err, Err(IceError::AlreadyGathered)));
    manager.close().await.unwrap();
}
