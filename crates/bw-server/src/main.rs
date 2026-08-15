//! BLACKWING server — receives remote input messages and injects them into the
//! operating system.
//!
//! Registers the protocol [`MessageDispatcher`] handlers from the `bw_server`
//! library and idles. The QUIC listener (via `bw-session`) is future work; the
//! full client-to-OS injection flow is proven end-to-end by the integration
//! test (TASK-107).

#![allow(clippy::unwrap_used, clippy::expect_used)]
// ^ Justification: binary crate entry points report fatal startup errors by
//   panicking with a message, per native-application convention.

use std::sync::{Arc, Mutex};

use bw_clipboard::ClipboardManager;
use bw_input::InputInjector;
use bw_protocol::dispatcher::MessageDispatcher;
use bw_server::{register_clipboard_handler, register_input_handlers};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let dispatcher = MessageDispatcher::new();
    register_input_handlers(&dispatcher, InputInjector::new());
    let clipboard = Arc::new(Mutex::new(ClipboardManager::new()?));
    register_clipboard_handler(&dispatcher, clipboard);

    eprintln!("BLACKWING server ready — input and clipboard handlers registered");
    eprintln!("QUIC listener (bw-session) not yet wired; process idles until then.");

    // Keep the process alive; the dispatcher path is exercised by the E2E test.
    std::thread::park();
    Ok(())
}
