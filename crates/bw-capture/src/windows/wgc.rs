use crate::backend::{CaptureBackend, CaptureError};
use crate::cursor::CursorInfo;
use crate::frame::Frame;
use crate::monitor::DisplayInfo;

/// Windows Graphics Capture (WGC) backend.
pub struct WgcCaptureBackend {
    active: bool,
}

impl WgcCaptureBackend {
    pub fn new() -> Result<Self, CaptureError> {
        Ok(Self { active: false })
    }
}

impl CaptureBackend for WgcCaptureBackend {
    fn displays(&self) -> Result<Vec<DisplayInfo>, CaptureError> {
        // TODO: Enumerate displays via Windows.Devices.Display
        Ok(vec![])
    }

    fn start(&mut self, _display: &DisplayInfo) -> Result<(), CaptureError> {
        // TODO: Initialize WGC
        self.active = true;
        Ok(())
    }

    fn next_frame(&mut self) -> Result<Frame, CaptureError> {
        if !self.active {
            return Err(CaptureError::Stopped);
        }

        // TODO: Frame arrival event
        Err(CaptureError::FrameAcquisitionFailed(
            "Not implemented".into(),
        ))
    }

    fn cursor_info(&mut self) -> Result<CursorInfo, CaptureError> {
        if !self.active {
            return Err(CaptureError::Stopped);
        }

        // TODO: Cursor info not directly supported in WGC in the same way, requires User32
        Ok(CursorInfo::default())
    }

    fn stop(&mut self) {
        self.active = false;
        // TODO: Release WGC resources
    }
}
