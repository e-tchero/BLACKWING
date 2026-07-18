//! Session state management.

use crate::encryption::EncryptionContext;
use crate::error::ProtocolError;
use crate::routing::SessionId;
use std::collections::HashMap;
use std::sync::Mutex;

/// Manages active connection sessions within a node.
///
/// Each session is keyed by [`SessionId`] and optionally bound to an
/// [`EncryptionContext`] holding the authoritative mutable cryptographic state
/// for that session (packet counters, replay windows, epoch, key material).
///
/// # Technical Debt
///
/// The `Option<EncryptionContext>` value type exists solely for compatibility
/// with the legacy [`create_session`](SessionManager::create_session) API, which
/// registers a session without key material. In the BLACKWING protocol there is
/// no legitimate operational state where a session lacks an encryption context.
/// Once all sessions are created through the handshake path (i.e.
/// [`create_session_with_context`](SessionManager::create_session_with_context)
/// is the sole registration point), `Option` should be removed and the map
/// simplified to `HashMap<SessionId, EncryptionContext>`. This is a future
/// lifecycle cleanup task and is intentionally out of scope for WP-4.10.
#[derive(Debug)]
pub struct SessionManager {
    active_sessions: Mutex<HashMap<SessionId, Option<EncryptionContext>>>,
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionManager {
    /// Creates a new `SessionManager`.
    pub fn new() -> Self {
        Self {
            active_sessions: Mutex::new(HashMap::new()),
        }
    }

    /// Registers a new session without an associated encryption context.
    ///
    /// # Returns
    ///
    /// `Ok(())` if registered successfully, or `ProtocolError::SessionDuplicate` if the session ID is already active.
    pub fn create_session(&self, id: SessionId) -> Result<(), ProtocolError> {
        let mut sessions = self
            .active_sessions
            .lock()
            .map_err(|_| ProtocolError::InvalidHandshake)?;

        if sessions.contains_key(&id) {
            return Err(ProtocolError::SessionDuplicate);
        }

        sessions.insert(id, None);
        Ok(())
    }

    /// Registers a new session with an associated [`EncryptionContext`].
    ///
    /// # Returns
    ///
    /// `Ok(())` if registered successfully, or `ProtocolError::SessionDuplicate` if the session ID is already active.
    pub fn create_session_with_context(
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

        sessions.insert(id, Some(context));
        Ok(())
    }

    /// Executes a closure against the authoritative [`EncryptionContext`] of an active session.
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
    /// `ProtocolError::SessionNotFound` if the session does not exist, or
    /// `ProtocolError::InvalidHandshake` if the session exists but has no associated context.
    pub fn with_session_context<F, R>(&self, id: &SessionId, f: F) -> Result<R, ProtocolError>
    where
        F: FnOnce(&mut EncryptionContext) -> R,
    {
        let mut sessions = self
            .active_sessions
            .lock()
            .map_err(|_| ProtocolError::InvalidHandshake)?;

        match sessions.get_mut(id) {
            None => Err(ProtocolError::SessionNotFound),
            Some(None) => Err(ProtocolError::InvalidHandshake),
            Some(Some(ctx)) => Ok(f(ctx)),
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

        Ok(sessions.remove(id).is_some())
    }

    /// Validates if a session is currently active.
    pub fn validate_session(&self, id: &SessionId) -> Result<bool, ProtocolError> {
        let sessions = self
            .active_sessions
            .lock()
            .map_err(|_| ProtocolError::InvalidHandshake)?;

        Ok(sessions.contains_key(id))
    }

    /// Looks up an active session ID.
    ///
    /// # Returns
    ///
    /// The session ID if active, or `ProtocolError::SessionNotFound` if the session is missing.
    pub fn lookup_session(&self, id: &SessionId) -> Result<SessionId, ProtocolError> {
        if self.validate_session(id)? {
            Ok(*id)
        } else {
            Err(ProtocolError::SessionNotFound)
        }
    }
}
