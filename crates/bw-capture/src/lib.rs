//! Screen capture backends for BLACKWING.
//!
//! Provides platform-specific display capture (DXGI/WGC on Windows) behind a
//! common [`CaptureBackend`] interface, frame/dirty-rectangle types, and a
//! dedicated capture-thread helper.
//!
//! # Safety note (unsafe_code override)
//!
//! The Windows backends (`windows::dxgi`, `windows::wgc`) interoperate with raw
//! COM/DirectX interfaces, which inherently require `unsafe`. The workspace
//! forbids `unsafe_code`; this crate overrides that to `allow` (see
//! `Cargo.toml`) because the DXGI API surface has no safe wrapper. Every
//! `unsafe` block is confined to the Windows modules and reviewed per call.

/// Core capture-backend abstraction and error types.
pub mod backend;
/// Cursor state and shape enumeration.
pub mod cursor;
/// Captured frame types, dirty rectangles, and merge helpers.
pub mod frame;
/// Display/desktop enumeration types.
pub mod monitor;
/// Dedicated capture-thread control.
pub mod thread;

/// Windows-specific capture backends (DXGI and WGC).
#[cfg(target_os = "windows")]
pub mod windows;

pub use backend::{CaptureBackend, CaptureError};
pub use cursor::{CursorInfo, CursorShape};
pub use frame::{merge_dirty_rects, DirtyRect, Frame, MoveRect, PixelFormat};
pub use monitor::DisplayInfo;
pub use thread::CaptureThread;

#[cfg(target_os = "windows")]
pub use windows::dxgi::DxgiCaptureBackend;

#[cfg(target_os = "windows")]
pub use windows::wgc::WgcCaptureBackend;
