#![deny(clippy::unwrap_used, clippy::expect_used)]
#![deny(unsafe_code)]

//! # bw-core
//! 
//! This crate implements core platform abstractions, type-safe structured logging schemas,
//! system health checkers, and a **strictly zero-allocation, lock-free memory pool**.
//! 
//! The memory pool pre-allocates unified heap memory during initialization and uses
//! atomic state flags (`AtomicBool`) to track occupancy. Checking out a buffer returns an 
//! RAII guard that zeroizes and releases the slot on drop with **zero heap allocations** //! in the hot path.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroize;

// =========================================================================
// 1. Core Error Registry (Strict Failure Classifications)
// =========================================================================

#[derive(Error, Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u32)]
pub enum BwError {
    // BW-1000 Series: Authentication
    #[error("[BW-1000] Authentication Handshake Failed: Invalid signature or PAKE mismatch")]
    AuthHandshakeFailed = 1000,
    #[error("[BW-1001] Authorization Token Expired or Cryptographically Invalid")]
    AuthTokenExpired = 1001,
    #[error("[BW-1002] Device Identity Revoked by Central Identity Plane")]
    DeviceIdentityRevoked = 1002,
    #[error("[BW-1003] Administrative Policy Verification Failed: Bad signature")]
    PolicyVerificationFailed = 1003,

    // BW-2000 Series: Transport
    #[error("[BW-2000] QUIC Connection Timed Out during initial 1-RTT handshake")]
    TransportTimeout = 2000,
    #[error("[BW-2001] STUN Hole Punch Failed; fallback to Relay triggered")]
    StunHolePunchFailed = 2001,
    #[error("[BW-2002] UDP Traffic Blocked; falling back to TCP Relay")]
    UdpTrafficBlocked = 2002,

    // BW-3000 Series: Display
    #[error("[BW-3000] OS Capture API Initialization Failed")]
    CaptureInitializationFailed = 3000,
    #[error("[BW-3001] Frame Capture Overwrite Triggered: Processing pipeline stalled")]
    FrameCaptureOverwrite = 3001,

    // BW-4000 Series: Codec
    #[error("[BW-4000] Hardware Encoder Initialization Failed")]
    EncoderInitializationFailed = 4000,

    // BW-5000 Series: Runtime
    #[error("[BW-5002] Anti-Debugging Violation: Debugger attached, process terminated")]
    AntiDebugViolation = 5002,
    #[error("[BW-5003] Update Verification Failed: Payload signature mismatch")]
    UpdateSignatureMismatch = 5003,

    // BW-6000 Series: Storage
    #[error("[BW-6000] Local Policy Database corrupt or offline SQLite file lock timeout")]
    StorageCorruptOrLocked = 6000,

    // BW-7000 Series: Policy
    #[error("[BW-7000] Policy Signature Mismatch: Local JSON validation failed")]
    PolicySignatureMismatch = 7000,

    // BW-8000 Series: Cloud & Relays
    #[error("[BW-8001] Relay Plane Handshake Verification Failed: Signed JWT JWS rejected")]
    RelayHandshakeFailed = 8001,

    // BW-9000 Series: Developer & Pool Allocations
    #[error("[BW-9001] Memory Allocation Boundary Violated: Exceeded static pool bounds")]
    PoolAllocationBoundaryViolated = 9001,
}

// =========================================================================
// 2. Type-Safe Logging & Telemetry (Section 4.2 Specification)
// =========================================================================

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
    Critical,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct LogEvent {
    pub timestamp_us: u64,
    pub component: String,
    pub thread: String,
    pub severity: Severity,
    pub session_epoch: u64,
    pub tenant: String,
    pub event_id: String,
    pub message: String,
    pub stacktrace: Option<String>,
}

impl LogEvent {
    /// Emit the log as a standardized single-line structured JSON payload.
    pub fn emit_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }
}

// =========================================================================
// 3. Automated Update Health Check Schema (Section 3.5 Specification)
// =========================================================================

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub struct HealthReport {
    pub renderer_alive: bool,
    pub ipc_alive: bool,
    pub network_alive: bool,
    pub policy_loaded: bool,
    pub encoder_initialized: bool,
}

impl HealthReport {
    /// Returns true if all critical application layers are fully initialized and healthy.
    pub fn is_healthy(&self) -> bool {
        self.renderer_alive
            && self.ipc_alive
            && self.network_alive
            && self.policy_loaded
            && self.encoder_initialized
    }
}

// =========================================================================
// 4. Statically-Bounded, Strictly Lock-Free Memory Pool (No allocations!)
// =========================================================================

/// RAII Guard that manages buffer occupancy with a strictly zero-allocation design.
/// When dropped, the guard automatically zeroizes the slice and releases its slot.
pub struct PoolGuard<'a> {
    pool: &'a LockFreeMemoryPool,
    index: usize,
}

impl<'a> PoolGuard<'a> {
    /// Returns a shared reference to the claimed buffer slice.
    pub fn get(&self) -> &[u8] {
        let start = self.index * self.pool.slot_capacity;
        let end = start + self.pool.slot_capacity;
        &self.pool.memory[start..end]
    }

    /// Returns a mutable reference to the claimed buffer slice.
    pub fn get_mut(&mut self) -> &mut [u8] {
        let start = self.index * self.pool.slot_capacity;
        let end = start + self.pool.slot_capacity;
        &mut self.pool.memory[start..end]
    }
}

impl<'a> Drop for PoolGuard<'a> {
    fn drop(&mut self) {
        // Enforce cryptographic zeroization on resource release
        let slice = self.get_mut();
        slice.zeroize();

        // Release the occupancy flag atomically using Release memory ordering
        self.pool.occupancy_flags[self.index].store(false, Ordering::Release);
    }
}

/// A highly optimized memory pool that pre-allocates an entire contiguous buffer array
/// on initialization, strictly guaranteeing zero heap allocations during runtime checkouts.
pub struct LockFreeMemoryPool {
    memory: Vec<u8>,
    occupancy_flags: Arc<[AtomicBool]>,
    pool_size: usize,
    slot_capacity: usize,
}

impl LockFreeMemoryPool {
    /// Creates and pre-allocates a new LockFreeMemoryPool.
    pub fn new(pool_size: usize, slot_capacity: usize) -> Self {
        let total_capacity = pool_size * slot_capacity;
        let memory = vec![0u8; total_capacity];

        let mut flags = Vec::with_capacity(pool_size);
        for _ in 0..pool_size {
            flags.push(AtomicBool::new(false));
        }

        Self {
            memory,
            occupancy_flags: Arc::from(flags),
            pool_size,
            slot_capacity,
        }
    }

    /// Checks out a pre-allocated buffer from the pool using atomic compare-and-swap (CAS).
    /// Strictly zero heap allocations occur during this pathway.
    pub fn checkout(&self) -> Result<PoolGuard<'_>, BwError> {
        for index in 0..self.pool_size {
            let flag = &self.occupancy_flags[index];
            // Atomically swap occupancy status from false to true
            if flag
                .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
            {
                return Ok(PoolGuard { pool: self, index });
            }
        }
        Err(BwError::PoolAllocationBoundaryViolated)
    }
}

// =========================================================================
// 5. Automated Core Testing Suite
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_formatting() {
        let err = BwError::AntiDebugViolation;
        assert_eq!(
            format!("{}", err),
            "[BW-5002] Anti-Debugging Violation: Debugger attached, process terminated"
        );
    }

    #[test]
    fn test_structured_logging_output() {
        let log = LogEvent {
            timestamp_us: 1719918239012,
            component: "bw-transport".to_string(),
            thread: "QUICNetwork".to_string(),
            severity: Severity::Warn,
            session_epoch: 1289381019842,
            tenant: "tenant_enterprise_us_east".to_string(),
            event_id: "EVENT_RELAY_SWITCH".to_string(),
            message: "Direct peer path failed connectivity check.".to_string(),
            stacktrace: None,
        };

        let json_string = log.emit_json().unwrap();
        assert!(json_string.contains("\"event_id\":\"EVENT_RELAY_SWITCH\""));
        assert!(json_string.contains("\"severity\":\"Warn\""));
        assert!(json_string.contains("\"timestamp_us\":1719918239012"));
    }

    #[test]
    fn test_system_health_evaluation() {
        let healthy_system = HealthReport {
            renderer_alive: true,
            ipc_alive: true,
            network_alive: true,
            policy_loaded: true,
            encoder_initialized: true,
        };
        assert!(healthy_system.is_healthy());

        let broken_system = HealthReport {
            renderer_alive: true,
            ipc_alive: false,
            network_alive: true,
            policy_loaded: true,
            encoder_initialized: true,
        };
        assert!(!broken_system.is_healthy());
    }

    #[test]
    fn test_zero_allocation_pool_behavior() {
        // Initialize memory pool with 2 slots of 32 bytes each
        let pool = LockFreeMemoryPool::new(2, 32);

        {
            // First checkout
            let mut guard1 = pool.checkout().unwrap();
            let slice1 = guard1.get_mut();
            assert_eq!(slice1.len(), 32);
            slice1[0] = 42;
            slice1[31] = 99;

            // Second checkout
            let mut guard2 = pool.checkout().unwrap();
            let slice2 = guard2.get_mut();
            assert_eq!(slice2[0], 0); // Verify initialized to zero
            slice2[0] = 11;

            // Third checkout must fail because the pool size limit is strictly 2
            let failed_checkout = pool.checkout();
            assert_eq!(
                failed_checkout.err(),
                Some(BwError::PoolAllocationBoundaryViolated)
            );
        } // Both guards are dropped here: slots are automatically zeroized and released

        // Checkouts are now fully accessible again
        let mut guard3 = pool.checkout().unwrap();
        let slice3 = guard3.get_mut();
        // Assert dropped slice was zeroized on drop
        assert_eq!(slice3[0], 0);
    }
}