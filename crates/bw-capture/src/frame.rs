/// Pixel format of a captured frame buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PixelFormat {
    /// 32-bit BGRA, 8 bits per channel — native DXGI format.
    Bgra8,
    /// 32-bit RGBA, 8 bits per channel.
    Rgba8,
}

/// A rectangular region of a display that changed since the previous frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirtyRect {
    /// Left edge of the region in pixels.
    pub x: u32,
    /// Top edge of the region in pixels.
    pub y: u32,
    /// Region width in pixels.
    pub width: u32,
    /// Region height in pixels.
    pub height: u32,
}

impl DirtyRect {
    /// Returns true if this rect has non-zero area.
    pub fn is_non_empty(&self) -> bool {
        self.width > 0 && self.height > 0
    }

    /// Returns true if this rect fully contains `other`.
    pub fn contains(&self, other: &DirtyRect) -> bool {
        other.x >= self.x
            && other.y >= self.y
            && (other.x + other.width) <= (self.x + self.width)
            && (other.y + other.height) <= (self.y + self.height)
    }

    /// Merges two dirty rects into the smallest bounding rectangle.
    pub fn union(&self, other: &DirtyRect) -> DirtyRect {
        let x = self.x.min(other.x);
        let y = self.y.min(other.y);
        let right = (self.x + self.width).max(other.x + other.width);
        let bottom = (self.y + self.height).max(other.y + other.height);
        DirtyRect {
            x,
            y,
            width: right - x,
            height: bottom - y,
        }
    }
}

/// A rectangular region of a display that was copied from another location (moved).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MoveRect {
    /// X coordinate of the source point the region moved from.
    pub source_point_x: u32,
    /// Y coordinate of the source point the region moved from.
    pub source_point_y: u32,
    /// Destination region the moved content now occupies.
    pub dest_rect: DirtyRect,
}

/// A single captured display frame.
///
/// The pixel buffer contains raw pixels in `pixel_format` layout.
/// `stride` is the number of bytes per row (may be padded beyond `width * 4`).
/// `dirty_rects` contains regions that changed since the previous frame.
/// `move_rects` contains regions that moved.
/// An empty `dirty_rects` and `move_rects` vec means the entire frame should be considered changed if it's a full refresh.
#[derive(Debug, Clone)]
pub struct Frame {
    /// Width of the frame in pixels.
    pub width: u32,
    /// Height of the frame in pixels.
    pub height: u32,
    /// Bytes per row (may include padding).
    pub stride: u32,
    /// Monotonic capture timestamp in microseconds.
    pub timestamp_us: u64,
    /// Pixel format of `buffer`.
    pub pixel_format: PixelFormat,
    /// Raw pixel data.
    pub buffer: Vec<u8>,
    /// Rectangles that changed since the last frame.
    pub dirty_rects: Vec<DirtyRect>,
    /// Rectangles that moved since the last frame.
    pub move_rects: Vec<MoveRect>,
    /// Optional cursor info if updated or drawn separately.
    pub cursor: Option<crate::cursor::CursorInfo>,
}

impl Frame {
    /// Returns true if the frame has at least one dirty region or move region.
    pub fn has_updates(&self) -> bool {
        !self.dirty_rects.is_empty() || !self.move_rects.is_empty()
    }

    /// Returns the total number of bytes expected in the buffer.
    pub fn expected_buffer_size(&self) -> usize {
        self.stride as usize * self.height as usize
    }
}

/// Merges a slice of possibly overlapping dirty rects into a minimal set.
/// Uses a greedy union strategy: any two rects that overlap are merged.
pub fn merge_dirty_rects(rects: &[DirtyRect]) -> Vec<DirtyRect> {
    if rects.is_empty() {
        return Vec::new();
    }

    let mut merged: Vec<DirtyRect> = Vec::new();

    'outer: for rect in rects {
        for existing in &mut merged {
            // If they overlap, absorb `rect` into `existing`
            if rects_overlap(existing, rect) {
                *existing = existing.union(rect);
                continue 'outer;
            }
        }
        merged.push(*rect);
    }

    merged
}

fn rects_overlap(a: &DirtyRect, b: &DirtyRect) -> bool {
    a.x < b.x + b.width && a.x + a.width > b.x && a.y < b.y + b.height && a.y + a.height > b.y
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dirty_rect_union_basic() {
        let a = DirtyRect {
            x: 0,
            y: 0,
            width: 100,
            height: 100,
        };
        let b = DirtyRect {
            x: 50,
            y: 50,
            width: 100,
            height: 100,
        };
        let u = a.union(&b);
        assert_eq!(
            u,
            DirtyRect {
                x: 0,
                y: 0,
                width: 150,
                height: 150
            }
        );
    }

    #[test]
    fn dirty_rect_contains() {
        let outer = DirtyRect {
            x: 0,
            y: 0,
            width: 200,
            height: 200,
        };
        let inner = DirtyRect {
            x: 10,
            y: 10,
            width: 50,
            height: 50,
        };
        assert!(outer.contains(&inner));
        assert!(!inner.contains(&outer));
    }

    #[test]
    fn merge_overlapping_rects() {
        let rects = vec![
            DirtyRect {
                x: 0,
                y: 0,
                width: 100,
                height: 100,
            },
            DirtyRect {
                x: 80,
                y: 80,
                width: 100,
                height: 100,
            },
        ];
        let merged = merge_dirty_rects(&rects);
        assert_eq!(merged.len(), 1);
        assert_eq!(
            merged[0],
            DirtyRect {
                x: 0,
                y: 0,
                width: 180,
                height: 180
            }
        );
    }

    #[test]
    fn merge_non_overlapping_rects() {
        let rects = vec![
            DirtyRect {
                x: 0,
                y: 0,
                width: 10,
                height: 10,
            },
            DirtyRect {
                x: 100,
                y: 100,
                width: 10,
                height: 10,
            },
        ];
        let merged = merge_dirty_rects(&rects);
        assert_eq!(merged.len(), 2);
    }

    #[test]
    fn frame_buffer_size() {
        let frame = Frame {
            width: 1920,
            height: 1080,
            stride: 1920 * 4,
            timestamp_us: 12345,
            pixel_format: PixelFormat::Bgra8,
            buffer: vec![0u8; 1920 * 4 * 1080],
            dirty_rects: vec![],
            move_rects: vec![],
            cursor: None,
        };
        assert_eq!(frame.expected_buffer_size(), frame.buffer.len());
    }
}
