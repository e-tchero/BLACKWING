//! Portable input-event types shared by all injection backends.

/// The mouse button to click.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum MouseButton {
    /// Primary (left) mouse button.
    Left,
    /// Secondary (right) mouse button.
    Right,
    /// Middle (wheel) mouse button.
    Middle,
}

/// A single OS-level input action in a portable representation.
///
/// Backends translate these into platform-specific calls (e.g. Win32
/// `SendInput`). Keeping the representation portable lets the injection logic
/// be unit-tested without an interactive desktop.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum InjectedInput {
    /// Relative mouse movement by `(dx, dy)` pixels from the cursor's
    /// current position. Positive `dx`/`dy` move right/down.
    MouseMove {
        /// Horizontal delta in screen pixels.
        dx: i32,
        /// Vertical delta in screen pixels.
        dy: i32,
    },
    /// Mouse button press (`down = true`) or release (`down = false`).
    MouseClick {
        /// The button being pressed or released.
        button: MouseButton,
        /// `true` presses the button, `false` releases it.
        down: bool,
    },
    /// Virtual-key press (`down = true`) or release (`down = false`).
    ///
    /// `keycode` is a Win32 virtual-key code (e.g. `0x41` = `VK_A`).
    Keyboard {
        /// Win32 virtual-key code.
        keycode: u16,
        /// `true` presses the key, `false` releases it.
        down: bool,
    },
}
