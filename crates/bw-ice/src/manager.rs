//! High-level ICE manager wrapping a [`webrtc_ice::Agent`].

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::sync::{Mutex, mpsc};
use webrtc_ice::agent::Agent;
use webrtc_ice::agent::agent_config::AgentConfig;
use webrtc_ice::candidate::Candidate;
use webrtc_ice::candidate::candidate_base::unmarshal_candidate;
use webrtc_ice::mdns::MulticastDnsMode;
use webrtc_ice::network_type::NetworkType;
use webrtc_ice::url::Url;
use webrtc_util::Conn;

use crate::error::IceError;

/// Configuration for an [`IceManager`].
#[derive(Debug, Clone)]
pub struct IceConfig {
    /// STUN/TURN server URLs used for candidate gathering, e.g.
    /// `"stun:stun.l.google.com:19302"`. Empty for host-only gathering.
    pub urls: Vec<String>,

    /// Whether this agent is the ICE *controlling* agent (the side that
    /// nominates candidate pairs). Exactly one side of a connection must be
    /// controlling; the other is *controlled*.
    pub is_controlling: bool,

    /// Include loopback addresses in candidate gathering. Required for local
    /// tests over `127.0.0.1`; leave disabled in production.
    pub include_loopback: bool,
}

impl Default for IceConfig {
    fn default() -> Self {
        Self {
            urls: vec!["stun:stun.l.google.com:19302".to_string()],
            is_controlling: false,
            include_loopback: false,
        }
    }
}

/// A connected ICE transport: a datagram socket bound to the selected
/// candidate pair after connectivity checks succeed.
///
/// This is a thin wrapper around the [`Conn`] trait from `webrtc-util`, which
/// is the connection type returned by `webrtc-ice` 0.17's `dial`/`accept`.
#[derive(Clone)]
pub struct IceConnection {
    conn: Arc<dyn Conn + Send + Sync>,
}

impl IceConnection {
    /// Sends a datagram to the remote peer.
    pub async fn send(&self, buf: &[u8]) -> Result<usize, IceError> {
        self.conn
            .send(buf)
            .await
            .map_err(|e| IceError::ConnectFailed(e.to_string()))
    }

    /// Receives the next datagram into `buf`, returning the number of bytes
    /// read.
    pub async fn recv(&self, buf: &mut [u8]) -> Result<usize, IceError> {
        self.conn
            .recv(buf)
            .await
            .map_err(|e| IceError::ConnectFailed(e.to_string()))
    }

    /// Returns the local socket address of the selected candidate pair.
    pub fn local_addr(&self) -> Result<SocketAddr, IceError> {
        self.conn
            .local_addr()
            .map_err(|e| IceError::ConnectFailed(e.to_string()))
    }

    /// Returns the remote socket address of the selected candidate pair.
    pub fn remote_addr(&self) -> Option<SocketAddr> {
        self.conn.remote_addr()
    }

    /// Closes the connection, releasing the underlying socket.
    pub async fn close(&self) -> Result<(), IceError> {
        self.conn
            .close()
            .await
            .map_err(|e| IceError::ConnectFailed(e.to_string()))
    }

    /// Returns the underlying datagram connection, for transport layers that
    /// need to adapt the ICE socket to their own abstraction (e.g. Quinn).
    pub fn inner(&self) -> Arc<dyn Conn + Send + Sync> {
        Arc::clone(&self.conn)
    }
}

/// Wraps a [`webrtc_ice::Agent`] behind a simplified API for gathering
/// candidates and establishing a direct connection.
pub struct IceManager {
    agent: Arc<Agent>,
    is_controlling: bool,
    remote_credentials: Mutex<Option<(String, String)>>,
    gathered: AtomicBool,
}

impl IceManager {
    /// Creates a new ICE agent with the given configuration.
    pub async fn new(config: IceConfig) -> Result<Self, IceError> {
        let mut urls = Vec::with_capacity(config.urls.len());
        for raw in &config.urls {
            let url = Url::parse_url(raw)
                .map_err(|e| IceError::InvalidUrl(raw.clone(), e.to_string()))?;
            urls.push(url);
        }

        let agent = Agent::new(AgentConfig {
            urls,
            network_types: vec![NetworkType::Udp4],
            multicast_dns_mode: MulticastDnsMode::Disabled,
            include_loopback: config.include_loopback,
            ..Default::default()
        })
        .await
        .map_err(|e| IceError::Agent(e.to_string()))?;

        Ok(Self {
            agent: Arc::new(agent),
            is_controlling: config.is_controlling,
            remote_credentials: Mutex::new(None),
            gathered: AtomicBool::new(false),
        })
    }

    /// Returns this agent's local ICE username fragment and password. The
    /// remote peer needs these to authenticate connectivity checks.
    pub async fn local_credentials(&self) -> (String, String) {
        self.agent.get_local_user_credentials().await
    }

    /// Stores the remote peer's ICE credentials. Must be called before
    /// [`IceManager::establish_connection`].
    pub async fn set_remote_credentials(&self, ufrag: &str, pwd: &str) {
        *self.remote_credentials.lock().await = Some((ufrag.to_string(), pwd.to_string()));
    }

    /// Starts gathering local candidates and returns a stream of candidate
    /// strings (SDP-style ICE candidate attributes, e.g.
    /// `candidate:1 1 UDP 2130706431 192.168.0.10 54321 typ host`).
    ///
    /// The receiver should be forwarded to the remote peer (for example as a
    /// [`crate`] protocol message over the relay). The stream ends when
    /// gathering completes, so `recv()` returning `None` signals completion.
    ///
    /// This method may only be called once per manager.
    pub async fn gather_candidates(&self) -> Result<mpsc::Receiver<String>, IceError> {
        if self.gathered.swap(true, Ordering::SeqCst) {
            return Err(IceError::AlreadyGathered);
        }

        let (tx, rx) = mpsc::channel(64);
        let shared: Arc<Mutex<Option<mpsc::Sender<String>>>> = Arc::new(Mutex::new(Some(tx)));
        let shared_clone = Arc::clone(&shared);

        self.agent.on_candidate(Box::new(
            move |candidate: Option<Arc<dyn Candidate + Send + Sync>>| {
                let shared = Arc::clone(&shared_clone);
                Box::pin(async move {
                    match candidate {
                        Some(c) => {
                            let guard = shared.lock().await;
                            if let Some(tx) = guard.as_ref() {
                                let _ = tx.send(c.marshal()).await;
                            }
                        }
                        // Gathering finished: drop the sender so the receiver
                        // observes the end of the candidate stream.
                        None => {
                            *shared.lock().await = None;
                        }
                    }
                })
            },
        ));

        self.agent
            .gather_candidates()
            .map_err(|e| IceError::Agent(e.to_string()))?;
        Ok(rx)
    }

    /// Adds a remote candidate received from the peer.
    pub async fn add_remote_candidate(&self, candidate: &str) -> Result<(), IceError> {
        let c = unmarshal_candidate(candidate)
            .map_err(|e| IceError::InvalidCandidate(candidate.to_string(), e.to_string()))?;
        let c: Arc<dyn Candidate + Send + Sync> = Arc::new(c);
        self.agent
            .add_remote_candidate(&c)
            .map_err(|e| IceError::Agent(e.to_string()))
    }

    /// Runs connectivity checks and blocks until a candidate pair is selected,
    /// returning the established [`IceConnection`].
    ///
    /// The agent plays its configured role: a controlling agent calls `dial`,
    /// a controlled agent calls `accept`.
    pub async fn establish_connection(&self) -> Result<IceConnection, IceError> {
        let (remote_ufrag, remote_pwd) = self
            .remote_credentials
            .lock()
            .await
            .clone()
            .ok_or(IceError::MissingRemoteCredentials)?;

        let (_cancel_tx, cancel_rx) = mpsc::channel(1);
        let conn: Arc<dyn Conn + Send + Sync> = if self.is_controlling {
            self.agent
                .dial(cancel_rx, remote_ufrag, remote_pwd)
                .await
                .map_err(|e| IceError::ConnectFailed(e.to_string()))?
        } else {
            self.agent
                .accept(cancel_rx, remote_ufrag, remote_pwd)
                .await
                .map_err(|e| IceError::ConnectFailed(e.to_string()))?
        };

        Ok(IceConnection { conn })
    }

    /// Closes the underlying ICE agent, releasing all sockets.
    pub async fn close(&self) -> Result<(), IceError> {
        self.agent
            .close()
            .await
            .map_err(|e| IceError::Agent(e.to_string()))
    }
}
