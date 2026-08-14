//! Error types for OS-level input injection.

use thiserror::Error;

/// Errors that can occur while injecting OS input.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum InputError {
    /// The platform this build targets has no input-injection backend.
    #[error("input injection is not supported on this platform")]
    UnsupportedPlatform,
    /// The OS input stack accepted fewer events than were requested.
    ///
    /// `SendInput` returns the number of events actually inserted; a value
    /// below the request indicates the injection failed (e.g. no interactive
    /// desktop, or blocked by UIPI).
    #[error("SendInput inserted {inserted} of {requested} input events")]
    InjectionFailed {
        /// Number of events successfully inserted.
        inserted: u32,
        /// Number of events that were requested.
        requested: u32,
    },
}
