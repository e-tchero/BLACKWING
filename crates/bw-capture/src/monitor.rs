/// Information about a physical or virtual display.
#[derive(Debug, Clone, PartialEq)]
pub struct DisplayInfo {
    /// Platform-specific display identifier (e.g. DXGI output name or X11 screen index).
    pub id: String,
    /// Human-readable display name (e.g. "DISPLAY1", "\\.\DISPLAY2").
    pub name: String,
    /// Width of the display in physical pixels.
    pub width: u32,
    /// Height of the display in physical pixels.
    pub height: u32,
    /// Position of the top-left corner in the virtual desktop coordinate space.
    pub virtual_x: i32,
    pub virtual_y: i32,
    /// Nominal refresh rate in Hz.
    pub refresh_hz: u32,
    /// DPI scale factor (1.0 = 96 DPI, 2.0 = 192 DPI etc).
    pub scale_factor: f32,
    /// Whether this is the primary display.
    pub is_primary: bool,
}

impl DisplayInfo {
    /// Returns the total number of physical pixels on this display.
    pub fn pixel_count(&self) -> u64 {
        self.width as u64 * self.height as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pixel_count() {
        let d = DisplayInfo {
            id: "0".into(),
            name: "TEST".into(),
            width: 1920,
            height: 1080,
            virtual_x: 0,
            virtual_y: 0,
            refresh_hz: 60,
            scale_factor: 1.0,
            is_primary: true,
        };
        assert_eq!(d.pixel_count(), 1920 * 1080);
    }
}
