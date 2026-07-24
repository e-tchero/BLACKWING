//! Type-safe structured logging primitives for Project Blackwing.
//!
//! This module provides the core schema types for structured telemetry:
//! [`Severity`], [`LogEvent`], and [`HealthReport`].
//!
//! # Design constraints
//! - No logging backend. Consumers are responsible for dispatch.
//! - No async I/O, file output, or macro infrastructure.
//! - [`HealthReport`] is fully stack-allocated (`Copy`).
//! - [`LogEvent`] uses owned `String` fields to support dynamic content.
//!   Pre-format messages before construction in hot paths.
//! - JSON serialization via [`LogEvent::emit_json`] requires the `serde` feature.

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Severity classification for a log event, ordered from least to most critical.
///
/// Implements `PartialOrd` and `Ord` so severity levels can be compared and filtered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum Severity {
    /// Fine-grained diagnostic information for low-level tracing.
    Trace,
    /// Diagnostic information useful during active development.
    Debug,
    /// Informational messages confirming normal system operation.
    Info,
    /// Potentially harmful situations that warrant operator attention.
    Warn,
    /// Error events that may allow the application to continue running.
    Error,
    /// Critical failures that require immediate intervention.
    Critical,
}

/// A structured telemetry event conforming to the BLACKWING logging schema.
///
/// `LogEvent` is the primary carrier type for structured logs. Fields use
/// owned `String` values to accommodate dynamic runtime content. In
/// performance-sensitive paths, pre-format all message content before
/// constructing a `LogEvent`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct LogEvent {
    /// Microsecond-precision monotonic timestamp at event creation time.
    pub timestamp_us: u64,
    /// Name of the subsystem or component that emitted this event.
    pub component: String,
    /// Identifier of the thread that emitted this event.
    pub thread: String,
    /// Severity classification of this event.
    pub severity: Severity,
    /// Cryptographically secure session epoch at time of emission.
    pub session_epoch: u64,
    /// Tenant identifier for multi-tenant deployment contexts.
    pub tenant: String,
    /// Unique event code used for downstream filtering and aggregation.
    pub event_id: String,
    /// Human-readable description of the event.
    pub message: String,
    /// Optional stack trace, present on [`Severity::Error`] and [`Severity::Critical`] events.
    pub stacktrace: Option<String>,
}

#[cfg(feature = "serde")]
impl LogEvent {
    /// Serializes this event to a compact single-line JSON string.
    ///
    /// Returns a [`serde_json::Error`] if serialization fails. In practice,
    /// serialization of `LogEvent` is infallible unless custom serializers
    /// are involved.
    pub fn emit_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }
}

/// A point-in-time snapshot of critical application subsystem health.
///
/// `HealthReport` is fully stack-allocated (`Copy`) and safe to use in
/// lock-free or interrupt-adjacent monitoring paths without heap pressure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct HealthReport {
    /// Whether the rendering subsystem is running and responsive.
    pub renderer_alive: bool,
    /// Whether the IPC channel is established and accepting messages.
    pub ipc_alive: bool,
    /// Whether the network stack is initialized and reachable.
    pub network_alive: bool,
    /// Whether the policy configuration has been loaded successfully.
    pub policy_loaded: bool,
    /// Whether the video encoder has completed initialization.
    pub encoder_initialized: bool,
}

impl HealthReport {
    /// Returns `true` if all critical application subsystems are healthy.
    ///
    /// All five subsystems must be alive and initialized. A single `false`
    /// field causes this method to return `false`.
    #[must_use]
    pub fn is_healthy(&self) -> bool {
        self.renderer_alive
            && self.ipc_alive
            && self.network_alive
            && self.policy_loaded
            && self.encoder_initialized
    }
}
