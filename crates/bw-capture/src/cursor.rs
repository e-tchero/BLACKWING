/// Hardware cursor shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CursorShape {
    /// Standard pointer arrow.
    Arrow,
    /// Text I-beam.
    IBeam,
    /// Crosshair.
    Crosshair,
    /// Resize handle.
    SizeAll,
    /// Hand/pointer.
    Hand,
    /// Hidden / invisible cursor.
    Hidden,
    /// Unknown shape.
    Unknown,
}

/// Current cursor state snapshot.
#[derive(Debug, Clone)]
pub struct CursorInfo {
    /// X position in display coordinates.
    pub x: i32,
    /// Y position in display coordinates.
    pub y: i32,
    /// Whether the cursor is currently visible.
    pub visible: bool,
    /// Logical cursor shape.
    pub shape: CursorShape,
    /// Optional raw RGBA cursor bitmap (32-bit BGRA, row-major).
    /// `None` if the backend does not provide cursor pixel data.
    pub bitmap: Option<Vec<u8>>,
    /// Width of the cursor bitmap in pixels.
    pub bitmap_width: u32,
    /// Height of the cursor bitmap in pixels.
    pub bitmap_height: u32,
}

impl Default for CursorInfo {
    fn default() -> Self {
        CursorInfo {
            x: 0,
            y: 0,
            visible: true,
            shape: CursorShape::Arrow,
            bitmap: None,
            bitmap_width: 0,
            bitmap_height: 0,
        }
    }
}
