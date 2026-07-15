//! Session state management.

use crate::error::ProtocolError;
use crate::routing::SessionId;
use std::collections::HashSet;
use std::sync::Mutex;

/// Manages active connection sessions within a node.
#[derive(Debug)]
pub struct SessionManager {
    active_sessions: Mutex<HashSet<SessionId>>,
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
            active_sessions: Mutex::new(HashSet::new()),
        }
    }

    /// Registers a new session.
    ///
    /// # Returns
    ///
    /// `Ok(())` if registered successfully, or `ProtocolError::SessionDuplicate` if the session ID is already active.
    pub fn create_session(&self, id: SessionId) -> Result<(), ProtocolError> {
        let mut sessions = self
            .active_sessions
            .lock()
            .map_err(|_| ProtocolError::InvalidHandshake)?;

        if !sessions.insert(id) {
            return Err(ProtocolError::SessionDuplicate);
        }

        Ok(())
    }

    /// Closes an active session.
    ///
    /// # Returns
    ///
    /// `true` if the session was successfully closed, `false` if it was not active.
    pub fn close_session(&self, id: &SessionId) -> Result<bool, ProtocolError> {
        let mut sessions = self
            .active_sessions
            .lock()
            .map_err(|_| ProtocolError::InvalidHandshake)?;

        Ok(sessions.remove(id))
    }

    /// Validates if a session is currently active.
    pub fn validate_session(&self, id: &SessionId) -> Result<bool, ProtocolError> {
        let sessions = self
            .active_sessions
            .lock()
            .map_err(|_| ProtocolError::InvalidHandshake)?;

        Ok(sessions.contains(id))
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
