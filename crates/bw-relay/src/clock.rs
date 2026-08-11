use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

/// Abstracts system time to allow deterministic testing of timeouts.
pub trait Clock: Send + Sync {
    /// Returns the current time in milliseconds since the UNIX epoch.
    fn now_ms(&self) -> u64;
}

/// The standard production clock using `SystemTime`.
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }
}

use std::sync::atomic::{AtomicU64, Ordering};

/// A deterministic clock for unit testing time-dependent behavior.
pub struct MockClock {
    current_time_ms: Arc<AtomicU64>,
}

impl MockClock {
    /// Creates a mock clock initialized to the given time.
    pub fn new(start_time_ms: u64) -> Self {
        Self {
            current_time_ms: Arc::new(AtomicU64::new(start_time_ms)),
        }
    }

    /// Advances the clock by the specified number of milliseconds.
    pub fn advance(&self, ms: u64) {
        self.current_time_ms.fetch_add(ms, Ordering::SeqCst);
    }
}

impl Clock for MockClock {
    fn now_ms(&self) -> u64 {
        self.current_time_ms.load(Ordering::SeqCst)
    }
}
