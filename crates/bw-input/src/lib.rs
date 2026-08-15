//! OS-level input injection for BLACKWING.
//!
//! The server half of the remote-desktop input path: receives mouse and
//! keyboard events (Mouse Move, Key Press, Key Release) and injects them into
//! the Windows OS via the Win32 `SendInput` API.
//!
//! # Architecture
//!
//! Input events are modelled in a portable representation
//! ([`InjectedInput`]) and delivered through an [`InputBackend`] trait. The
//! default backend calls Win32 `SendInput`; tests inject a recording backend
//! so the injection logic is verifiable without an interactive desktop.
//!
//! # Safety note (unsafe_code override)
//!
//! The Win32 backend interoperates with the raw `user32.dll` `SendInput`
//! API, which inherently requires `unsafe` (building the `INPUT` union and
//! invoking the FFI call). The workspace forbids `unsafe_code`; this crate
//! overrides that to `allow` (see `Cargo.toml`) because the Win32 API surface
//! has no safe wrapper. Every `unsafe` block is confined to the Windows
//! backend module and reviewed per call.
//!
//! # Security
//!
//! Injecting input into elevated windows requires the server process to run
//! with appropriate Windows privileges (`UIAccess` for secure-desktop
//! injection). See the WP-10.0 design document.

/// Error types for OS-level input injection.
pub mod error;
/// Input backends and the public injection API.
pub mod inject;
/// Portable input-event types shared by backends.
pub mod input;

pub use error::InputError;
pub use inject::{
    inject_keyboard, inject_mouse_click, inject_mouse_move, InputBackend, InputInjector,
    RecordingBackend,
};
pub use input::{InjectedInput, MouseButton};
