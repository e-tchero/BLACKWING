//! Integration test: Deterministic cancellation.
//!
//! Verifies the Phase 3 goal:
//!
//! ```text
//! Create ConnectionManager
//!     ↓
//! Open UDP connection (creates handle)
//!     ↓
//! Drop ConnectionHandle
//!     ↓
//! Assert:
//!     receiver exited
//!     manager entry cleanly reaped
//!     no panic
//! ```

use bw_net::connection::ConnectionManager;
use bw_protocol::dispatcher::MessageDispatcher;
use std::sync::Arc;
use tokio::time::{timeout, Duration};

#[tokio::test]
async fn phase3_deterministic_cancellation() {
    let dispatcher = Arc::new(MessageDispatcher::new());
    let manager = ConnectionManager::new(dispatcher);

    // 1. Create connection (binds local ephemeral port, connects to dummy peer)
    let handle = manager
        .connect_udp(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:8080".parse().unwrap(),
        )
        .await
        .expect("connect must succeed");

    let id = handle.id();
    assert!(!handle.is_closed(), "Handle should be active");

    // 2. Drop handle to trigger deterministic cleanup cascade
    drop(handle);

    // 3. Wait for the manager to reap the task (timeout protects against hangs)
    let result = timeout(Duration::from_secs(2), manager.wait_for_shutdown(id))
        .await
        .expect("Task failed to exit within 2 seconds (orphaned task!)");

    // 4. Assert clean exit
    match result {
        Ok(()) => {} // Task exited cleanly via cancellation token
        Err(bw_net::error::NetError::Shutdown) => {} // Clean shutdown via channel
        Err(e) => panic!("Expected clean shutdown, got error: {:?}", e),
    }
}
