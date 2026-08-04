use crate::cursor::CursorInfo;
use crate::frame::Frame;
use crate::monitor::DisplayInfo;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CaptureError {
    #[error("Capture backend initialization failed: {0}")]
    InitFailed(String),
    #[error("Failed to enumerate displays: {0}")]
    DisplayEnumerationFailed(String),
    #[error("Invalid display specified")]
    InvalidDisplay,
    #[error("Failed to acquire next frame: {0}")]
    FrameAcquisitionFailed(String),
    #[error("Capture was stopped")]
    Stopped,
    #[error("Access denied. Screen capture requires elevated privileges or user consent")]
    AccessDenied,
    #[error("Unsupported pixel format")]
    UnsupportedFormat,
    #[error("Platform not supported")]
    PlatformNotSupported,
}

/// Abstract interface for a platform-specific capture backend.
///
/// Backends should be implemented as synchronous, thread-safe structs
/// that can be run on dedicated capture threads.
pub trait CaptureBackend: Send + Sync {
    /// Enumerates all available displays on the system.
    fn displays(&self) -> Result<Vec<DisplayInfo>, CaptureError>;

    /// Starts capturing the specified display.
    fn start(&mut self, display: &DisplayInfo) -> Result<(), CaptureError>;

    /// Acquires the next frame.
    ///
    /// This method is expected to block until a new frame is available,
    /// returning the frame data and dirty rectangles.
    fn next_frame(&mut self) -> Result<Frame, CaptureError>;

    /// Gets the current cursor information.
    fn cursor_info(&mut self) -> Result<CursorInfo, CaptureError>;

    /// Stops the capture session.
    fn stop(&mut self);
}
