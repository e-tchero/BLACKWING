use crate::candidate::Candidate;
use crate::clock::{Clock, SystemClock};
use bw_crypto::DeviceId;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// Maximum time (ms) a connect intent can remain in the Pending state before expiring.
pub const INTENT_TIMEOUT_MS: u64 = 30_000;

/// Lifecycle state of a connect intent.
#[derive(Debug, Clone)]
pub enum IntentState {
    /// Waiting for the target to call `AcceptConnect`.
    Pending {
        /// When the intent was created (ms since UNIX epoch).
        created_at: u64,
    },
    /// Target accepted; both parties' candidates are available for exchange.
    Accepted {
        /// The 32-byte routing token generated upon acceptance.
        relay_token: [u8; 32],
    },
    /// The intent expired before the target accepted.
    Expired,
}

/// A connect-intent record stored on the relay.
#[derive(Debug, Clone)]
pub struct PendingIntent {
    /// The endpoint that originated the connect attempt.
    pub initiator: DeviceId,
    /// The endpoint that was targeted.
    pub target: DeviceId,
    /// The candidates provided by the initiator in `ConnectIntent`.
    pub initiator_candidates: Vec<Candidate>,
    /// The candidates provided by the target in `AcceptConnect` (empty until accepted).
    pub target_candidates: Vec<Candidate>,
    /// Current lifecycle state.
    pub state: IntentState,
}

/// Manages the lifecycle of in-flight connect intents on the relay.
///
/// Each intent represents a mutual-consent rendezvous between two registered
/// endpoints. Candidate data is never released to either side until both have
/// cryptographically signed their participation.
pub struct RendezvousRegistry {
    intents: RwLock<HashMap<[u8; 16], PendingIntent>>,
    clock: Arc<dyn Clock>,
}

impl RendezvousRegistry {
    /// Creates a new, empty rendezvous registry using the system clock.
    pub fn new() -> Arc<Self> {
        Self::with_clock(Arc::new(SystemClock))
    }

    /// Creates a new rendezvous registry with a specific clock for testing.
    pub fn with_clock(clock: Arc<dyn Clock>) -> Arc<Self> {
        Arc::new(Self {
            intents: RwLock::new(HashMap::new()),
            clock,
        })
    }

    /// Records a new connect intent from `initiator` targeting `target`.
    ///
    /// Returns `Err` if the `intent_id` collides with an active pending intent.
    pub fn register_intent(
        &self,
        intent_id: [u8; 16],
        initiator: DeviceId,
        target: DeviceId,
        initiator_candidates: Vec<Candidate>,
    ) -> Result<(), &'static str> {
        let now = self.clock.now_ms();

        let mut intents = self
            .intents
            .write()
            .map_err(|_| "Rendezvous registry write lock poisoned")?;

        if intents
            .get(&intent_id)
            .is_some_and(|existing| matches!(existing.state, IntentState::Pending { .. }))
        {
            return Err("Duplicate intent_id: an active intent with this ID already exists");
        }

        intents.insert(
            intent_id,
            PendingIntent {
                initiator,
                target,
                initiator_candidates,
                target_candidates: vec![],
                state: IntentState::Pending { created_at: now },
            },
        );
        Ok(())
    }

    /// Records acceptance by the target. Returns the initiator's DeviceId and candidates.
    ///
    /// Returns `Err` if the intent is not found, expired, or `acceptor` is not the
    /// expected target.
    pub fn accept_intent(
        &self,
        intent_id: [u8; 16],
        acceptor: DeviceId,
        target_candidates: Vec<Candidate>,
    ) -> Result<(DeviceId, Vec<Candidate>, [u8; 32]), &'static str> {
        let now = self.clock.now_ms();

        let mut intents = self
            .intents
            .write()
            .map_err(|_| "Rendezvous registry write lock poisoned")?;

        let intent = intents.get_mut(&intent_id).ok_or("Intent not found")?;

        match &intent.state {
            IntentState::Pending { created_at } => {
                if now.saturating_sub(*created_at) > INTENT_TIMEOUT_MS {
                    intent.state = IntentState::Expired;
                    return Err("Intent has expired");
                }
            }
            IntentState::Accepted { .. } => return Err("Intent is already accepted"),
            IntentState::Expired => return Err("Intent has expired"),
        }

        if intent.target != acceptor {
            return Err("Acceptor identity does not match the intended target");
        }

        let initiator = intent.initiator;
        let initiator_candidates = intent.initiator_candidates.clone();
        intent.target_candidates = target_candidates;

        let mut relay_token = [0u8; 32];
        getrandom::getrandom(&mut relay_token).map_err(|_| "Failed to generate random token")?;

        intent.state = IntentState::Accepted { relay_token };

        Ok((initiator, initiator_candidates, relay_token))
    }

    /// Returns the target's candidates for the initiator.
    ///
    /// Only succeeds after the intent has been accepted. Returns `Err` if the
    /// intent is not found, not yet accepted, or `requester` is not the initiator.
    pub fn get_target_candidates(
        &self,
        intent_id: [u8; 16],
        requester: DeviceId,
    ) -> Result<(Vec<Candidate>, [u8; 32]), &'static str> {
        let intents = self
            .intents
            .read()
            .map_err(|_| "Rendezvous registry read lock poisoned")?;

        let intent = intents.get(&intent_id).ok_or("Intent not found")?;

        let token = match intent.state {
            IntentState::Accepted { relay_token } => relay_token,
            IntentState::Pending { .. } => return Err("Intent not yet accepted by the target"),
            IntentState::Expired => return Err("Intent has expired"),
        };

        if intent.initiator != requester {
            return Err("Unauthorized: requester is not the initiator of this intent");
        }

        Ok((intent.target_candidates.clone(), token))
    }

    /// Marks all intents that have exceeded `INTENT_TIMEOUT_MS` as expired.
    ///
    /// Returns the number of intents that were swept.
    pub fn sweep_expired(&self) -> Result<usize, &'static str> {
        let now = self.clock.now_ms();

        let mut intents = self
            .intents
            .write()
            .map_err(|_| "Rendezvous registry write lock poisoned")?;

        let mut swept = 0;
        for intent in intents.values_mut() {
            if let IntentState::Pending { created_at } = intent.state
                && now.saturating_sub(created_at) > INTENT_TIMEOUT_MS
            {
                intent.state = IntentState::Expired;
                swept += 1;
            }
        }
        Ok(swept)
    }
    /// Peeks at an intent to retrieve the initiator's DeviceId without modifying state.
    ///
    /// Used by the server to retrieve the initiator's identity before accepting, so
    /// it can construct the correct signed payload for `AcceptConnect` verification.
    pub fn peek_initiator(&self, intent_id: [u8; 16]) -> Result<DeviceId, &'static str> {
        let intents = self
            .intents
            .read()
            .map_err(|_| "Rendezvous registry read lock poisoned")?;
        let intent = intents.get(&intent_id).ok_or("Intent not found")?;
        Ok(intent.initiator)
    }
}
