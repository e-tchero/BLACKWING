//! Protocol-aware ICE signaling.
//!
//! [`IcePeer`] wraps an [`IceManager`] and bridges the two signaling
//! directions: locally gathered candidates are emitted as
//! [`ProtocolMessage::ice_candidate`] messages (to be sent to the remote peer
//! over an existing signaling channel such as the relay), and inbound
//! candidate messages from the remote peer are fed back into the agent.
//!
//! Both sides derive their ICE credentials from the shared relay token, so no
//! separate credential-exchange step is required: the token was already
//! authenticated during relay setup, and it seeds a username fragment and
//! password that both peers compute identically.

use std::sync::Arc;

use bw_protocol::message::{IceCandidatePayload, MessageType, ProtocolMessage};
use tokio::sync::mpsc;

use crate::error::IceError;
use crate::manager::{IceConfig, IceConnection, IceManager};

/// Size of the shared relay routing token (`bw_transport`'s `RELAY_HEADER_LEN`).
const TOKEN_LEN: usize = 32;

/// Derives the ICE username fragment + password pair from the shared relay
/// token.
///
/// The username fragment is the hex of the first 4 token bytes (8 chars, 64
/// bits — above the 24-bit minimum); the password is the hex of the full
/// token (64 chars, 512 bits — above the 128-bit minimum).
pub fn ice_credentials_from_token(token: &[u8; TOKEN_LEN]) -> (String, String) {
    let ufrag = hex(&token[..4]);
    let pwd = hex(token);
    (ufrag, pwd)
}

/// Formats bytes as lowercase hex.
fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// A protocol-aware ICE signaling peer.
///
/// Owns an [`IceManager`] and a background worker that:
///
/// * forwards each locally gathered candidate out as a
///   [`MessageType::IceCandidate`] message (drain via
///   [`IcePeer::next_outbound`]),
/// * feeds inbound remote candidates (pushed via [`IcePeer::push_candidate`])
///   into the agent.
///
/// Once the candidates have been exchanged in both directions,
/// [`IcePeer::establish`] runs the connectivity checks and returns the direct
/// P2P connection.
pub struct IcePeer {
    manager: Arc<IceManager>,
    inbound_tx: mpsc::UnboundedSender<String>,
    outbound: tokio::sync::Mutex<mpsc::UnboundedReceiver<ProtocolMessage>>,
}

impl IcePeer {
    /// Creates an ICE peer using credentials derived from the shared relay
    /// token, gathering candidates with the given STUN/TURN server URLs.
    ///
    /// One side of a connection must be `is_controlling: true` (typically the
    /// client) and the other `false` (typically the server).
    pub async fn new(
        token: &[u8; TOKEN_LEN],
        is_controlling: bool,
        urls: Vec<String>,
    ) -> Result<Self, IceError> {
        let (ufrag, pwd) = ice_credentials_from_token(token);
        let manager = IceManager::new(IceConfig {
            urls,
            is_controlling,
            include_loopback: true,
            local_ufrag: Some(ufrag.clone()),
            local_pwd: Some(pwd.clone()),
        })
        .await?;
        // Both peers share the token-derived credentials, so each side's
        // remote credentials are the same pair.
        manager.set_remote_credentials(&ufrag, &pwd).await;
        let candidates = manager.gather_candidates().await?;

        let manager = Arc::new(manager);
        let (inbound_tx, mut inbound_rx) = mpsc::unbounded_channel::<String>();
        let (outbound_tx, outbound_rx) = mpsc::unbounded_channel::<ProtocolMessage>();

        let worker_manager = Arc::clone(&manager);
        tokio::spawn(async move {
            let mut local_rx = candidates;
            // Exchange phase: forward local candidates and inject remote ones
            // until local gathering completes.
            loop {
                tokio::select! {
                    local = local_rx.recv() => {
                        match local {
                            Some(candidate_str) => {
                                let Ok(message) = ProtocolMessage::ice_candidate(
                                    IceCandidatePayload {
                                        candidate_str,
                                        sdp_mid: None,
                                        sdp_mline_index: None,
                                    },
                                ) else {
                                    continue;
                                };
                                if outbound_tx.send(message).is_err() {
                                    return;
                                }
                            }
                            // Gathering finished — drain remaining remote
                            // candidates below.
                            None => break,
                        }
                    }
                    inbound = inbound_rx.recv() => {
                        match inbound {
                            Some(candidate_str) => {
                                if worker_manager
                                    .add_remote_candidate(&candidate_str)
                                    .await
                                    .is_err()
                                {
                                    return;
                                }
                            }
                            None => return,
                        }
                    }
                }
            }
            // Local gathering complete: closing the outbound sender lets
            // `next_outbound` report `None` once all candidates drained.
            drop(outbound_tx);
            // Post-gathering: keep accepting remote candidates until the
            // signaling channel closes.
            while let Some(candidate_str) = inbound_rx.recv().await {
                if worker_manager
                    .add_remote_candidate(&candidate_str)
                    .await
                    .is_err()
                {
                    return;
                }
            }
        });

        Ok(Self {
            manager,
            inbound_tx,
            outbound: tokio::sync::Mutex::new(outbound_rx),
        })
    }

    /// Injects an inbound [`MessageType::IceCandidate`] message received from
    /// the remote peer (e.g. via the relay). Non-ICE messages are rejected.
    pub fn push_candidate(&self, message: &ProtocolMessage) -> Result<(), IceError> {
        if message.message_type != MessageType::IceCandidate {
            return Err(IceError::InvalidCandidate(
                "message is not an ICE candidate".into(),
                String::new(),
            ));
        }
        let payload = message.as_ice_candidate().ok_or_else(|| {
            IceError::InvalidCandidate("undecodable ICE candidate payload".into(), String::new())
        })?;
        self.inbound_tx
            .send(payload.candidate_str)
            .map_err(|_| IceError::ChannelClosed)
    }

    /// Returns the next locally gathered candidate as an outbound
    /// [`MessageType::IceCandidate`] message to send to the remote peer, or
    /// `None` once gathering has completed and all candidates drained.
    pub async fn next_outbound(&self) -> Option<ProtocolMessage> {
        self.outbound.lock().await.recv().await
    }

    /// Runs connectivity checks and blocks until a candidate pair is
    /// selected, returning the direct P2P connection.
    pub async fn establish(&self) -> Result<IceConnection, IceError> {
        self.manager.establish_connection().await
    }
}
