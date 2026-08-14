use crate::cursor::CursorInfo;
use crate::frame::Frame;
use crate::monitor::DisplayInfo;
use thiserror::Error;

/// Errors produced by capture backend operations.
#[derive(Debug, Error)]
pub enum CaptureError {
    /// Backend initialization failed with the given detail.
    #[error("Capture backend initialization failed: {0}")]
    InitFailed(String),
    /// Display enumeration failed with the given detail.
    #[error("Failed to enumerate displays: {0}")]
    DisplayEnumerationFailed(String),
    /// The requested display identifier is invalid or unavailable.
    #[error("Invalid display specified")]
    InvalidDisplay,
    /// Acquiring the next frame failed with the given detail.
    #[error("Failed to acquire next frame: {0}")]
    FrameAcquisitionFailed(String),
    /// The capture session was stopped.
    #[error("Capture was stopped")]
    Stopped,
    /// Screen capture requires elevated privileges or user consent.
    #[error("Access denied. Screen capture requires elevated privileges or user consent")]
    AccessDenied,
    /// The frame pixel format is not supported by this backend.
    #[error("Unsupported pixel format")]
    UnsupportedFormat,
    /// The current platform is not supported by this backend.
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
