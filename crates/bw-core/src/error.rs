//! Error types and handling utilities for bw-core.

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Core error registry for PROJECT BLACKWING, classifying failures across subsystems.
#[derive(Error, Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[repr(u32)]
pub enum BwError {
    /// Authentication Handshake Failed: Invalid signature or PAKE mismatch.
    #[error("[BW-1000] Authentication Handshake Failed: Invalid signature or PAKE mismatch")]
    AuthHandshakeFailed = 1000,
    /// Authorization Token Expired or Cryptographically Invalid.
    #[error("[BW-1001] Authorization Token Expired or Cryptographically Invalid")]
    AuthTokenExpired = 1001,
    /// Device Identity Revoked by Central Identity Plane.
    #[error("[BW-1002] Device Identity Revoked by Central Identity Plane")]
    DeviceIdentityRevoked = 1002,
    /// Administrative Policy Verification Failed: Bad signature.
    #[error("[BW-1003] Administrative Policy Verification Failed: Bad signature")]
    PolicyVerificationFailed = 1003,

    /// QUIC Connection Timed Out during initial 1-RTT handshake.
    #[error("[BW-2000] QUIC Connection Timed Out during initial 1-RTT handshake")]
    TransportTimeout = 2000,
    /// STUN Hole Punch Failed; fallback to Relay triggered.
    #[error("[BW-2001] STUN Hole Punch Failed; fallback to Relay triggered")]
    StunHolePunchFailed = 2001,
    /// UDP Traffic Blocked; falling back to TCP Relay.
    #[error("[BW-2002] UDP Traffic Blocked; falling back to TCP Relay")]
    UdpTrafficBlocked = 2002,

    /// OS Capture API Initialization Failed.
    #[error("[BW-3000] OS Capture API Initialization Failed")]
    CaptureInitializationFailed = 3000,
    /// Frame Capture Overwrite Triggered: Processing pipeline stalled.
    #[error("[BW-3001] Frame Capture Overwrite Triggered: Processing pipeline stalled")]
    FrameCaptureOverwrite = 3001,

    /// Hardware Encoder Initialization Failed.
    #[error("[BW-4000] Hardware Encoder Initialization Failed")]
    EncoderInitializationFailed = 4000,

    /// Anti-Debugging Violation: Debugger attached, process terminated.
    #[error("[BW-5002] Anti-Debugging Violation: Debugger attached, process terminated")]
    AntiDebugViolation = 5002,
    /// Update Verification Failed: Payload signature mismatch.
    #[error("[BW-5003] Update Verification Failed: Payload signature mismatch")]
    UpdateSignatureMismatch = 5003,

    /// Local Policy Database corrupt or offline SQLite file lock timeout.
    #[error("[BW-6000] Local Policy Database corrupt or offline SQLite file lock timeout")]
    StorageCorruptOrLocked = 6000,

    /// Policy Signature Mismatch: Local JSON validation failed.
    #[error("[BW-7000] Policy Signature Mismatch: Local JSON validation failed")]
    PolicySignatureMismatch = 7000,

    /// Relay Plane Handshake Verification Failed: Signed JWT JWS rejected.
    #[error("[BW-8001] Relay Plane Handshake Verification Failed: Signed JWT JWS rejected")]
    RelayHandshakeFailed = 8001,

    /// Memory Allocation Boundary Violated: Exceeded static pool bounds.
    #[error("[BW-9001] Memory Allocation Boundary Violated: Exceeded static pool bounds")]
    PoolAllocationBoundaryViolated = 9001,
}
