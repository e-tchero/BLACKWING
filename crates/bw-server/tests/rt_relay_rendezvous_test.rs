#![allow(clippy::unwrap_used, clippy::expect_used)]
//! RT-001/RT-002 regression tests — relay rendezvous lifecycle.
//!
//! Exercises the [`RendezvousDriver`] against a deterministic fake relay
//! control plane. Proves:
//!
//! * A — multiple sequential intents are all serviced; accepting one intent
//!   does not consume the polling lifecycle.
//! * B/D — per-intent acceptance failures (expired/rejected intents) are
//!   non-fatal: polling continues and a subsequent valid intent is serviced.
//! * C — a non-connecting initiator is abandoned after the initiator timeout
//!   and rendezvous polling resumes.
//! * E — cancellation/shutdown is graceful and never hangs.
//! * Systemic control-plane failures still propagate (fail closed).

use bw_crypto::{DeviceId, SigningKey};
use bw_relay::relay_client::RelayClientError;
use bw_server::rendezvous::{RelayControl, RendezvousDriver};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Poll interval used in tests; with `start_paused` time this is virtual.
const POLL_INTERVAL: Duration = Duration::from_millis(10);
/// Initiator timeout used in tests; with `start_paused` time this is virtual.
const INITIATOR_TIMEOUT: Duration = Duration::from_millis(50);

fn key() -> (SigningKey, DeviceId) {
    let sk = SigningKey::generate_ed25519().unwrap();
    let id = sk.verify_key().device_id();
    (sk, id)
}

/// A scripted fake relay control plane.
///
/// `polls` is consumed one response per poll; missing entries mean "no
/// intents". `accepts` is consumed one result per accepted intent; missing
/// entries mean "rejected". `poll_count` counts polls for assertions.
/// Type aliases for the complex nested types used in scripted relay
/// control-plane fakes. Extracting these keeps the struct fields and
/// method signatures readable and satisfies Clippy's very_complex_type
/// guidance without obscuring test intent.
type PollQueue = VecDeque<Vec<([u8; 16], DeviceId)>>;
type AcceptQueue = VecDeque<Result<[u8; 32], RelayClientError>>;
type PollResponse = Vec<([u8; 16], DeviceId)>;
type AcceptResult = Result<[u8; 32], RelayClientError>;
struct FakeControl {
    polls: Mutex<PollQueue>,
    accepts: Mutex<AcceptQueue>,
    poll_count: Arc<AtomicUsize>,
}

impl FakeControl {
    fn new(
        poll_queue: Vec<Vec<([u8; 16], DeviceId)>>,
        accept_queue: Vec<Result<[u8; 32], RelayClientError>>,
    ) -> Self {
        Self {
            polls: Mutex::new(poll_queue.into()),
            accepts: Mutex::new(accept_queue.into()),
            poll_count: Arc::new(AtomicUsize::new(0)),
        }
    }
}

impl RelayControl for FakeControl {
    async fn poll_pending_intents(&self) -> Result<PollResponse, RelayClientError> {
        self.poll_count.fetch_add(1, Ordering::SeqCst);
        let mut q = self.polls.lock().unwrap_or_else(|e| e.into_inner());
        Ok(q.pop_front().unwrap_or_default())
    }

    async fn accept_connect(&self, _intent_id: [u8; 16], _initiator: DeviceId) -> AcceptResult {
        let mut q = self.accepts.lock().unwrap_or_else(|e| e.into_inner());
        q.pop_front()
            .unwrap_or_else(|| Err(RelayClientError::Rejected("no result queued".into())))
    }
}

/// Test A — multiple sequential intents are all serviced.
///
/// Regression for RT-001: accepting intent A must NOT permanently consume
/// the polling lifecycle; intent B is subsequently discovered and serviced.
#[tokio::test]
async fn a_sequential_intents_are_all_serviced() {
    let (_, id_a) = key();
    let (_, id_b) = key();
    let token_a = [0x41; 32];
    let token_b = [0x42; 32];

    let fake = FakeControl::new(
        vec![vec![([0x01; 16], id_a)], vec![([0x02; 16], id_b)]],
        vec![Ok(token_a), Ok(token_b)],
    );
    let count = Arc::clone(&fake.poll_count);
    let driver = RendezvousDriver::new(fake, POLL_INTERVAL, INITIATOR_TIMEOUT);

    let (tx, mut rx) = tokio::sync::mpsc::channel(4);
    let serve = move |token: [u8; 32], _timeout: Duration| {
        let tx = tx.clone();
        async move {
            tx.send(token).await.ok();
        }
    };

    let task = tokio::spawn(driver.run(serve));
    assert_eq!(rx.recv().await, Some(token_a));
    assert_eq!(rx.recv().await, Some(token_b));
    // Both intents were polled (and served) — polling never stopped.
    assert!(
        count.load(Ordering::SeqCst) >= 2,
        "polling must continue after the first intent"
    );
    task.abort();
    let _ = task.await;
}

/// Test B/D — a failed per-intent acceptance is non-fatal.
///
/// Regression for RT-002: an expired/rejected intent must not terminate the
/// rendezvous loop; a subsequent valid intent is still serviced.
#[tokio::test]
async fn d_failed_accept_is_non_fatal_and_next_intent_serviced() {
    let (_, id_expired) = key();
    let (_, id_valid) = key();
    let token_valid = [0x42; 32];

    let fake = FakeControl::new(
        vec![vec![([0xAA; 16], id_expired)], vec![([0xBB; 16], id_valid)]],
        vec![
            Err(RelayClientError::Rejected("Intent has expired".into())),
            Ok(token_valid),
        ],
    );
    let count = Arc::clone(&fake.poll_count);
    let driver = RendezvousDriver::new(fake, POLL_INTERVAL, INITIATOR_TIMEOUT);

    let (tx, mut rx) = tokio::sync::mpsc::channel(4);
    let serve = move |token: [u8; 32], _timeout: Duration| {
        let tx = tx.clone();
        async move {
            tx.send(token).await.ok();
        }
    };

    let task = tokio::spawn(driver.run(serve));
    // The expired intent was skipped; only the valid one is served.
    assert_eq!(rx.recv().await, Some(token_valid));
    assert!(
        count.load(Ordering::SeqCst) >= 2,
        "polling must continue after a rejected intent"
    );
    task.abort();
    let _ = task.await;
}

/// Test B/D — an unexpected-protocol accept response is also non-fatal.
#[tokio::test]
async fn d_protocol_error_on_accept_is_non_fatal() {
    let (_, id_a) = key();
    let (_, id_b) = key();
    let token_b = [0x42; 32];

    let fake = FakeControl::new(
        vec![vec![([0x01; 16], id_a)], vec![([0x02; 16], id_b)]],
        vec![
            Err(RelayClientError::Protocol("Unexpected response".into())),
            Ok(token_b),
        ],
    );
    let driver = RendezvousDriver::new(fake, POLL_INTERVAL, INITIATOR_TIMEOUT);

    let (tx, mut rx) = tokio::sync::mpsc::channel(4);
    let serve = move |token: [u8; 32], _timeout: Duration| {
        let tx = tx.clone();
        async move {
            tx.send(token).await.ok();
        }
    };

    let task = tokio::spawn(driver.run(serve));
    assert_eq!(rx.recv().await, Some(token_b));
    task.abort();
    let _ = task.await;
}

/// Test C — a non-connecting initiator is abandoned after the initiator
/// timeout and rendezvous polling resumes.
///
/// The serve phase for intent A simulates the real data-plane wait: the
/// initiator never connects, so the wait elapses (`initiator_timeout`) and
/// serve returns; the driver then discovers and serves intent B.
#[tokio::test]
async fn c_non_connecting_initiator_times_out_and_polling_resumes() {
    let (_, id_a) = key();
    let (_, id_b) = key();
    let token_a = [0x41; 32];
    let token_b = [0x42; 32];

    let fake = FakeControl::new(
        vec![vec![([0x01; 16], id_a)], vec![([0x02; 16], id_b)]],
        vec![Ok(token_a), Ok(token_b)],
    );
    let driver = RendezvousDriver::new(fake, POLL_INTERVAL, INITIATOR_TIMEOUT);

    let (tx, mut rx) = tokio::sync::mpsc::channel(4);
    let serve = move |token: [u8; 32], initiator_timeout: Duration| {
        let tx = tx.clone();
        async move {
            if token == token_a {
                // Simulate the real serve's bounded wait for the initiator:
                // the initiator never connects, so the wait elapses and the
                // serve phase returns — the driver resumes polling.
                let _ = tokio::time::timeout(initiator_timeout, std::future::pending::<()>()).await;
                tx.send((token, "initiator-timeout")).await.ok();
            } else {
                tx.send((token, "served")).await.ok();
            }
        }
    };

    let task = tokio::spawn(driver.run(serve));
    assert_eq!(rx.recv().await, Some((token_a, "initiator-timeout")));
    assert_eq!(rx.recv().await, Some((token_b, "served")));
    task.abort();
    let _ = task.await;
}

/// Test E — cancellation/shutdown is graceful and never hangs.
#[tokio::test]
async fn e_graceful_cancellation_never_hangs() {
    // A control plane whose poll never returns keeps the loop parked; the
    // driver must cancel cleanly when its task is aborted.
    struct NeverControl;
    impl RelayControl for NeverControl {
        async fn poll_pending_intents(
            &self,
        ) -> Result<Vec<([u8; 16], DeviceId)>, RelayClientError> {
            std::future::pending::<()>().await;
            unreachable!()
        }

        async fn accept_connect(
            &self,
            _intent_id: [u8; 16],
            _initiator: DeviceId,
        ) -> Result<[u8; 32], RelayClientError> {
            unreachable!()
        }
    }

    let driver = RendezvousDriver::new(NeverControl, POLL_INTERVAL, INITIATOR_TIMEOUT);
    let serve = |_token: [u8; 32], _timeout: Duration| async {};
    let task = tokio::spawn(driver.run(serve));

    // Let the loop start and park on the never-completing poll.
    tokio::task::yield_now().await;
    task.abort();

    // A hard guard: cancellation must complete, not hang.
    // Wait for the aborted task with a hard timeout; cancellation must
    // complete, not hang. The timeout wrapper both bounds the wait and
    // converts a hung task into a test failure.
    let outcome = tokio::time::timeout(Duration::from_secs(5), task).await;
    assert!(outcome.is_ok(), "graceful cancellation must not hang");
    assert!(
        outcome.unwrap().is_err(),
        "aborted rendezvous task must terminate with a cancellation error"
    );
}

/// Systemic control-plane failures still propagate (fail closed).
///
/// Per-intent failures are skipped, but an I/O failure on poll or accept is
/// returned to the caller so infrastructure problems are not swallowed.
#[tokio::test]
async fn d_systemic_failures_still_propagate() {
    struct FailPoll;
    impl RelayControl for FailPoll {
        async fn poll_pending_intents(
            &self,
        ) -> Result<Vec<([u8; 16], DeviceId)>, RelayClientError> {
            Err(RelayClientError::Io(std::io::Error::new(
                std::io::ErrorKind::ConnectionRefused,
                "relay unreachable",
            )))
        }

        async fn accept_connect(
            &self,
            _intent_id: [u8; 16],
            _initiator: DeviceId,
        ) -> Result<[u8; 32], RelayClientError> {
            unreachable!()
        }
    }
    let driver = RendezvousDriver::new(FailPoll, POLL_INTERVAL, INITIATOR_TIMEOUT);
    let serve = |_token: [u8; 32], _timeout: Duration| async {};
    let result = driver.run(serve).await;
    assert!(
        matches!(result, Err(RelayClientError::Io(_))),
        "systemic poll failure must propagate, got {result:?}"
    );

    // Accept failure with an I/O error is systemic too.
    let (_, id) = key();
    let fake = FakeControl::new(
        vec![vec![([0x01; 16], id)]],
        vec![Err(RelayClientError::Io(std::io::Error::new(
            std::io::ErrorKind::ConnectionReset,
            "relay dropped the request",
        )))],
    );
    let driver = RendezvousDriver::new(fake, POLL_INTERVAL, INITIATOR_TIMEOUT);
    let serve = |_token: [u8; 32], _timeout: Duration| async {};
    let result = driver.run(serve).await;
    assert!(
        matches!(result, Err(RelayClientError::Io(_))),
        "systemic accept failure must propagate, got {result:?}"
    );
}
