#![allow(missing_docs)] // Integration-test mock; docs not required (repo convention)
#![allow(clippy::unwrap_used, clippy::expect_used)] // Test code may panic on failure (repo convention)
use bw_capture::{CaptureBackend, CaptureError, CursorInfo, DisplayInfo, Frame, PixelFormat};

/// A mock capture backend for testing the interface contracts.
pub struct MockCaptureBackend {
    pub active: bool,
    pub frame_counter: u64,
    pub mock_display: DisplayInfo,
    pub return_error: bool,
}

impl MockCaptureBackend {
    pub fn new() -> Self {
        Self {
            active: false,
            frame_counter: 0,
            mock_display: DisplayInfo {
                id: "mock1".into(),
                name: "Mock Display".into(),
                width: 1920,
                height: 1080,
                virtual_x: 0,
                virtual_y: 0,
                refresh_hz: 60,
                scale_factor: 1.0,
                is_primary: true,
            },
            return_error: false,
        }
    }
}

impl Default for MockCaptureBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl CaptureBackend for MockCaptureBackend {
    fn displays(&self) -> Result<Vec<DisplayInfo>, CaptureError> {
        Ok(vec![self.mock_display.clone()])
    }

    fn start(&mut self, display: &DisplayInfo) -> Result<(), CaptureError> {
        if self.return_error {
            return Err(CaptureError::InitFailed("Mock error".into()));
        }
        if display.id != self.mock_display.id {
            return Err(CaptureError::InvalidDisplay);
        }
        self.active = true;
        self.frame_counter = 0;
        Ok(())
    }

    fn next_frame(&mut self) -> Result<Frame, CaptureError> {
        if !self.active {
            return Err(CaptureError::Stopped);
        }

        self.frame_counter += 1;

        Ok(Frame {
            width: 1920,
            height: 1080,
            stride: 1920 * 4,
            timestamp_us: self.frame_counter * 16666,
            pixel_format: PixelFormat::Bgra8,
            buffer: vec![0u8; 1920 * 1080 * 4],
            dirty_rects: vec![],
            move_rects: vec![],
            cursor: None,
            is_refresh: false,
        })
    }

    fn cursor_info(&mut self) -> Result<CursorInfo, CaptureError> {
        if !self.active {
            return Err(CaptureError::Stopped);
        }
        Ok(CursorInfo::default())
    }

    fn stop(&mut self) {
        self.active = false;
    }
}

#[test]
fn test_capture_starts_and_stops() {
    let mut backend = MockCaptureBackend::new();
    let displays = backend.displays().unwrap();
    assert_eq!(displays.len(), 1);

    assert!(backend.start(&displays[0]).is_ok());
    assert!(backend.active);

    backend.stop();
    assert!(!backend.active);
    assert!(matches!(backend.next_frame(), Err(CaptureError::Stopped)));
}

#[test]
fn test_frames_have_monotonic_timestamps() {
    let mut backend = MockCaptureBackend::new();
    let displays = backend.displays().unwrap();
    backend.start(&displays[0]).unwrap();

    let frame1 = backend.next_frame().unwrap();
    let frame2 = backend.next_frame().unwrap();

    assert!(frame2.timestamp_us > frame1.timestamp_us);
}

#[test]
fn test_frame_buffer_size_matches_stride() {
    let mut backend = MockCaptureBackend::new();
    let displays = backend.displays().unwrap();
    backend.start(&displays[0]).unwrap();

    let frame = backend.next_frame().unwrap();
    assert_eq!(frame.buffer.len(), frame.expected_buffer_size());
}
