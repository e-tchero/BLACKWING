//! Relay rendezvous lifecycle for relay-mode servers.
//!
//! Implements the RT-001/RT-002 remediation:
//!
//! * **RT-001** — the rendezvous loop runs for the lifetime of the
//!   relay-mode server. Accepting one intent never terminates polling;
//!   sessions are serviced sequentially and each one returns to polling.
//! * **RT-002** — per-intent acceptance failures (expired, already
//!   accepted, rejected intents) are logged and skipped instead of being
//!   propagated as fatal errors. Only systemic control-plane failures
//!   (I/O, encoding) terminate the loop.
//!
//! The driver is generic over [`RelayControl`], a deliberately small
//! control-plane surface, so it can be exercised deterministically with a
//! fake in the regression tests while the real [`RelayControlClient`]
//! implements it in production.

use std::future::Future;
use std::time::Duration;

use bw_crypto::DeviceId;
use bw_relay::relay_client::{RelayClientError, RelayControlClient};

/// How often the server polls the relay for pending connection intents.
pub const RELAY_POLL_INTERVAL: Duration = Duration::from_secs(2);

/// How long the server waits for an initiator to establish the QUIC
/// data-plane connection after its intent has been accepted.
///
/// Bounds the RT-001 abandoned-initiator case: an intent whose initiator
/// never connects cannot block rendezvous polling indefinitely.
pub const INITIATOR_CONNECT_TIMEOUT: Duration = Duration::from_secs(60);

/// The minimal relay control-plane surface required by the rendezvous
/// driver.
///
/// Kept deliberately small so the driver can be tested deterministically
/// with a fake while the real [`RelayControlClient`] provides the
/// production implementation.
pub trait RelayControl {
    /// Polls the relay for pending intents targeting this device.
    ///
    /// Returns `(intent_id, initiator_device_id)` pairs for intents that
    /// have not been accepted yet.
    fn poll_pending_intents(
        &self,
    ) -> impl std::future::Future<Output = Result<Vec<([u8; 16], DeviceId)>, RelayClientError>> + Send;

    /// Accepts one pending intent and returns the relay-issued,
    /// session-scoped data-plane token.
    fn accept_connect(
        &self,
        intent_id: [u8; 16],
        initiator: DeviceId,
    ) -> impl std::future::Future<Output = Result<[u8; 32], RelayClientError>> + Send;
}

impl RelayControl for RelayControlClient {
    async fn poll_pending_intents(&self) -> Result<Vec<([u8; 16], DeviceId)>, RelayClientError> {
        RelayControlClient::poll_pending_intents(self).await
    }

    async fn accept_connect(
        &self,
        intent_id: [u8; 16],
        initiator: DeviceId,
    ) -> Result<[u8; 32], RelayClientError> {
        RelayControlClient::accept_connect(self, intent_id, initiator, Vec::new())
            .await
            .map(|(token, _candidates)| token)
    }
}

/// Drives the relay rendezvous lifecycle for a relay-mode server.
///
/// Owns the poll → accept → serve cycle and the policy around failures:
///
/// * per-intent failures are non-fatal (skip and keep polling),
/// * systemic control-plane failures are returned to the caller, which
///   fails closed,
/// * the loop runs for the server's lifetime and only exits on a systemic
///   failure.
pub struct RendezvousDriver<R> {
    source: R,
    poll_interval: Duration,
    initiator_timeout: Duration,
}

impl<R: RelayControl> RendezvousDriver<R> {
    /// Creates a driver over the given relay control-plane source.
    pub fn new(source: R, poll_interval: Duration, initiator_timeout: Duration) -> Self {
        Self {
            source,
            poll_interval,
            initiator_timeout,
        }
    }

    /// Returns how long a serve phase may wait for its initiator to
    /// establish the data-plane connection.
    pub fn initiator_timeout(&self) -> Duration {
        self.initiator_timeout
    }

    /// Polls once and, if an intent is pending, accepts it.
    ///
    /// Returns:
    ///
    /// * `Ok(Some(token))` — an intent was accepted and the relay issued a
    ///   session token.
    /// * `Ok(None)` — no intent was pending, or a pending intent was
    ///   rejected by the relay (expired / invalid lifecycle state) and was
    ///   skipped so polling continues.
    /// * `Err(_)` — a systemic control-plane failure (I/O, encoding, ...).
    ///   Callers should treat this as fatal and fail closed.
    pub async fn next_session_token(&self) -> Result<Option<[u8; 32]>, RelayClientError> {
        let intents = self.source.poll_pending_intents().await?;
        let Some((intent_id, initiator)) = intents.into_iter().next() else {
            return Ok(None);
        };
        match self.source.accept_connect(intent_id, initiator).await {
            Ok(token) => Ok(Some(token)),
            Err(RelayClientError::Rejected(reason)) => {
                eprintln!(
                    "relay rejected intent from {initiator}: {reason} — skipping and continuing to poll"
                );
                Ok(None)
            }
            Err(RelayClientError::Protocol(reason)) => {
                eprintln!(
                    "unexpected relay response while accepting intent from {initiator}: {reason} — skipping and continuing to poll"
                );
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }

    /// Runs the rendezvous lifecycle for the server's lifetime.
    ///
    /// For every accepted intent, `serve` is invoked with the session token
    /// and this driver's initiator timeout. `serve` runs exactly one
    /// data-plane session and must bound its own wait for the initiator
    /// with the provided timeout; when it returns, the loop resumes polling
    /// so the next intent can be serviced (RT-001).
    ///
    /// The loop returns `Err` only for systemic control-plane failures and
    /// otherwise runs until the process shuts down.
    pub async fn run<S, Fut>(self, serve: S) -> Result<(), RelayClientError>
    where
        S: Fn([u8; 32], Duration) -> Fut,
        Fut: Future<Output = ()>,
    {
        loop {
            match self.next_session_token().await {
                Ok(Some(token)) => serve(token, self.initiator_timeout).await,
                Ok(None) => tokio::time::sleep(self.poll_interval).await,
                Err(e) => return Err(e),
            }
        }
    }
}
