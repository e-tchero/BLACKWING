pub mod backend;
pub mod cursor;
pub mod frame;
pub mod monitor;
pub mod thread;

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
