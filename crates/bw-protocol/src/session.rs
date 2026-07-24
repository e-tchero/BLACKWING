//! Session state management with TTL-based expiry and lifecycle cleanup.

use crate::encryption::EncryptionContext;
use crate::error::ProtocolError;
use crate::routing::SessionId;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Default session time-to-live: 24 hours.
const DEFAULT_SESSION_TTL: Duration = Duration::from_secs(86_400);

/// Metadata and state tracked for a single active session.
#[derive(Debug)]
struct SessionEntry {
    /// Monotonic timestamp when the session was created.
    created_at: Instant,
    /// Maximum lifetime of the session.
    ttl: Duration,
    /// Encryption context bound to this session.
    context: EncryptionContext,
}

impl SessionEntry {
    /// Returns `true` if this session has outlived its time-to-live.
    fn is_expired(&self) -> bool {
        self.created_at.elapsed() >= self.ttl
    }

    /// Creates a new session entry with the given context and TTL.
    fn new(context: EncryptionContext, ttl: Duration) -> Self {
        Self {
            created_at: Instant::now(),
            ttl,
            context,
        }
    }
}

/// Manages active connection sessions within a node.
///
/// Each session is keyed by [`SessionId`] and bound to an
/// [`EncryptionContext`] holding the authoritative mutable cryptographic state
/// for that session (packet counters, replay windows, epoch, key material).
///
/// Sessions have a configurable time-to-live (TTL). Expired sessions are
/// detected lazily on every accessor method and eagerly via
/// [`expire_stale`](SessionManager::expire_stale). An optional background
/// sweeper task can be started with
/// [`start_sweeper`](SessionManager::start_sweeper) to reclaim expired
/// sessions at a regular interval.
#[derive(Debug)]
pub struct SessionManager {
    active_sessions: Mutex<HashMap<SessionId, SessionEntry>>,
    default_ttl: Duration,
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionManager {
    /// Creates a new `SessionManager` with the default session TTL (24 hours).
    pub fn new() -> Self {
        Self {
            active_sessions: Mutex::new(HashMap::new()),
            default_ttl: DEFAULT_SESSION_TTL,
        }
    }

    /// Creates a new `SessionManager` with a custom default session TTL.
    pub fn with_ttl(ttl: Duration) -> Self {
        Self {
            active_sessions: Mutex::new(HashMap::new()),
            default_ttl: ttl,
        }
    }

    /// Removes all expired sessions from the map and returns the count
    /// of removed entries.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::InvalidHandshake`] if the internal lock is
    /// poisoned (unrecoverable).
    pub fn expire_stale(&self) -> Result<usize, ProtocolError> {
        let mut sessions = self
            .active_sessions
            .lock()
            .map_err(|_| ProtocolError::InvalidHandshake)?;

        let before = sessions.len();
        sessions.retain(|_, entry| !entry.is_expired());
        Ok(before - sessions.len())
    }

    /// Starts a background Tokio task that calls [`expire_stale`](SessionManager::expire_stale)
    /// at the given `interval`.
    ///
    /// The returned [`tokio::task::JoinHandle`] can be aborted to stop the
    /// sweeper. The sweeper runs until aborted or until the Tokio runtime is
    /// shut down.
    ///
    /// # Panics
    ///
    /// Panics if called outside a Tokio runtime context.
    pub fn start_sweeper(self: &Arc<Self>, interval: Duration) -> tokio::task::JoinHandle<()> {
        let manager = Arc::clone(self);
        tokio::spawn(async move {
            let mut timer = tokio::time::interval(interval);
            timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                timer.tick().await;
                let _ = manager.expire_stale();
            }
        })
    }

    /// Registers a new session bound to the given [`EncryptionContext`].
    ///
    /// # Returns
    ///
    /// `Ok(())` if registered successfully, or `ProtocolError::SessionDuplicate` if the session ID is already active.
    pub fn create_session(
        &self,
        id: SessionId,
        context: EncryptionContext,
    ) -> Result<(), ProtocolError> {
        let mut sessions = self
            .active_sessions
            .lock()
            .map_err(|_| ProtocolError::InvalidHandshake)?;

        if sessions.contains_key(&id) {
            return Err(ProtocolError::SessionDuplicate);
        }

        sessions.insert(id, SessionEntry::new(context, self.default_ttl));
        Ok(())
    }

    /// Orchestrates session creation from a completed handshake negotiation.
    ///
    /// Derives the cryptographic keys from the nonces and master secret, constructs the
    /// [`EncryptionContext`], and registers the active session. If registration fails (e.g.
    /// the session ID is already active), all derived cryptographic keys are dropped and
    /// zeroized immediately.
    ///
    /// # Returns
    ///
    /// `Ok(())` on success, or a `ProtocolError` if derivation or registration fails.
    pub fn create_session_from_handshake(
        &self,
        id: SessionId,
        master_secret: &bw_crypto::SymmetricKey,
        client_nonce: &[u8; 16],
        server_nonce: &[u8; 16],
        rotation_policy: crate::encryption::KeyRotationPolicy,
    ) -> Result<(), ProtocolError> {
        let keys =
            crate::handshake::derive_session_keys(master_secret, client_nonce, server_nonce)?;
        let context = EncryptionContext::new(keys, rotation_policy);

        self.create_session(id, context)
    }

    /// Removes expired entries, then executes a closure against the authoritative
    /// [`EncryptionContext`] of an active session.
    ///
    /// The closure receives an exclusive mutable reference to the stored context. All mutations
    /// (counter advances, replay window updates, epoch changes) occur on the authoritative
    /// instance inside the session lock. The closure's return value is the only data that
    /// escapes; the context itself is never cloned or moved out.
    ///
    /// # Deadlocks
    ///
    /// The manager's internal lock is held for the duration of the closure. Callers must **not**
    /// invoke other `SessionManager` methods (e.g. `validate_session`, `close_session`, etc.) from
    /// within the closure as it will cause a deadlock.
    ///
    /// # Returns
    ///
    /// `Ok(R)` with the closure's return value on success,
    /// `ProtocolError::SessionNotFound` if the session does not exist or has expired, or
    /// `ProtocolError::InvalidHandshake` if the session exists but has no associated context.
    pub fn with_session_context<F, R>(&self, id: &SessionId, f: F) -> Result<R, ProtocolError>
    where
        F: FnOnce(&mut EncryptionContext) -> R,
    {
        let mut sessions = self
            .active_sessions
            .lock()
            .map_err(|_| ProtocolError::InvalidHandshake)?;

        self.remove_expired_locked(&mut sessions);

        match sessions.get_mut(id) {
            None => Err(ProtocolError::SessionNotFound),
            Some(entry) => Ok(f(&mut entry.context)),
        }
    }

    /// Closes an active session, dropping its associated encryption context if present.
    ///
    /// # Returns
    ///
    /// `true` if the session was successfully closed, `false` if it was not active.
    pub fn close_session(&self, id: &SessionId) -> Result<bool, ProtocolError> {
        let mut sessions = self
            .active_sessions
            .lock()
            .map_err(|_| ProtocolError::InvalidHandshake)?;

        self.remove_expired_locked(&mut sessions);

        Ok(sessions.remove(id).is_some())
    }

    /// Validates if a session is currently active and not expired.
    pub fn validate_session(&self, id: &SessionId) -> Result<bool, ProtocolError> {
        let mut sessions = self
            .active_sessions
            .lock()
            .map_err(|_| ProtocolError::InvalidHandshake)?;

        self.remove_expired_locked(&mut sessions);

        Ok(sessions.contains_key(id))
    }

    /// Looks up an active session ID.
    ///
    /// # Returns
    ///
    /// The session ID if active and not expired, or `ProtocolError::SessionNotFound` if the session is missing.
    pub fn lookup_session(&self, id: &SessionId) -> Result<SessionId, ProtocolError> {
        if self.validate_session(id)? {
            Ok(*id)
        } else {
            Err(ProtocolError::SessionNotFound)
        }
    }

    /// Removes all expired entries from an already-locked sessions map.
    ///
    /// Called at the start of every accessor method so that expired sessions
    /// are rejected lazily without requiring the sweeper to run.
    fn remove_expired_locked(&self, sessions: &mut HashMap<SessionId, SessionEntry>) {
        sessions.retain(|_, entry| !entry.is_expired());
    }
}
