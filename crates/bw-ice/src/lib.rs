//! ICE (STUN/TURN) NAT traversal for BLACKWING.
//!
//! This crate wraps [`webrtc_ice`] to provide direct peer-to-peer (P2P)
//! connectivity. An [`IceManager`] gathers local candidates via STUN servers,
//! the candidates are exchanged out-of-band (for example over the existing
//! relay channel), and connectivity checks establish a direct UDP path between
//! the peers. If P2P fails, the caller falls back to the relay socket.
//!
//! # Example
//!
//! ```no_run
//! use bw_ice::{IceConfig, IceManager};
//!
//! # async fn example() -> Result<(), bw_ice::IceError> {
//! let manager = IceManager::new(IceConfig {
//!     urls: vec!["stun:stun.l.google.com:19302".to_string()],
//!     is_controlling: true,
//!     ..IceConfig::default()
//! })
//! .await?;
//!
//! // Stream local candidates, exchange them with the remote peer, then:
//! let (remote_ufrag, remote_pwd) = /* from the remote peer */ (String::new(), String::new());
//! manager.set_remote_credentials(&remote_ufrag, &remote_pwd).await;
//! let conn = manager.establish_connection().await?;
//! # Ok(())
//! # }
//! ```

pub mod error;
pub mod manager;

pub use error::IceError;
pub use manager::{IceConfig, IceConnection, IceManager};
