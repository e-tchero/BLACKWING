//! Input backends and the public injection API.
//!
//! The public entry points are [`inject_mouse_move`], [`inject_mouse_click`],
//! and [`inject_keyboard`] (plus their [`InputInjector`] method forms), which
//! deliver events through the platform backend. The [`InputBackend`] trait
//! decouples the OS call from the injection logic so tests can substitute a
//! recording backend.

use std::sync::{Arc, Mutex};

use crate::error::InputError;
use crate::input::{InjectedInput, MouseButton};

/// Backend that delivers an [`InjectedInput`] to the operating system.
///
/// The default implementation uses the Win32 `SendInput` API. Tests inject a
/// recording backend so the injection logic can be verified without touching
/// the real input stack.
pub trait InputBackend: Send + Sync {
    /// Delivers a single input event to the operating system.
    fn send(&self, input: &InjectedInput) -> Result<(), InputError>;
}

/// A handle for injecting OS-level input events.
///
/// Wraps an [`InputBackend`]; the default backend targets Win32 `SendInput`.
#[derive(Clone)]
pub struct InputInjector {
    backend: Arc<dyn InputBackend>,
}

impl InputInjector {
    /// Creates an injector backed by the default platform backend.
    pub fn new() -> Self {
        Self {
            backend: Arc::new(platform_backend()),
        }
    }

    /// Creates an injector with a custom backend (for testing).
    pub fn with_backend(backend: Arc<dyn InputBackend>) -> Self {
        Self { backend }
    }

    /// Moves the cursor by `(dx, dy)` pixels relative to its current position.
    pub fn inject_mouse_move(&self, dx: i32, dy: i32) -> Result<(), InputError> {
        self.backend.send(&InjectedInput::MouseMove { dx, dy })
    }

    /// Presses (`down = true`) or releases (`down = false`) a mouse button.
    pub fn inject_mouse_click(&self, button: MouseButton, down: bool) -> Result<(), InputError> {
        self.backend
            .send(&InjectedInput::MouseClick { button, down })
    }

    /// Presses (`down = true`) or releases (`down = false`) a virtual key.
    pub fn inject_keyboard(&self, keycode: u16, down: bool) -> Result<(), InputError> {
        self.backend
            .send(&InjectedInput::Keyboard { keycode, down })
    }
}

impl Default for InputInjector {
    fn default() -> Self {
        Self::new()
    }
}

/// Moves the cursor by `(dx, dy)` pixels using the default platform backend.
pub fn inject_mouse_move(dx: i32, dy: i32) -> Result<(), InputError> {
    InputInjector::new().inject_mouse_move(dx, dy)
}

/// Presses (`down = true`) or releases (`down = false`) a mouse button.
pub fn inject_mouse_click(button: MouseButton, down: bool) -> Result<(), InputError> {
    InputInjector::new().inject_mouse_click(button, down)
}

/// Presses (`down = true`) or releases (`down = false`) a virtual key.
pub fn inject_keyboard(keycode: u16, down: bool) -> Result<(), InputError> {
    InputInjector::new().inject_keyboard(keycode, down)
}

/// Backend that reports failure on platforms without input-injection support.
#[cfg(not(target_os = "windows"))]
struct UnsupportedBackend;

#[cfg(not(target_os = "windows"))]
impl InputBackend for UnsupportedBackend {
    fn send(&self, _input: &InjectedInput) -> Result<(), InputError> {
        Err(InputError::UnsupportedPlatform)
    }
}

/// A backend that records delivered events instead of injecting them into the
/// OS.
///
/// Intended for tests and simulations: captures every [`InjectedInput`] so the
/// injection logic can be verified without touching the OS input stack.
#[derive(Default)]
pub struct RecordingBackend {
    events: Mutex<Vec<InjectedInput>>,
}

impl RecordingBackend {
    /// Returns a copy of all events delivered so far.
    pub fn events(&self) -> Vec<InjectedInput> {
        self.events
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
}

impl InputBackend for RecordingBackend {
    fn send(&self, input: &InjectedInput) -> Result<(), InputError> {
        self.events
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(*input);
        Ok(())
    }
}

/// Returns the default platform backend for this build target.
#[cfg(target_os = "windows")]
fn platform_backend() -> impl InputBackend {
    win32::Win32Backend
}

/// Returns the default platform backend for this build target.
#[cfg(not(target_os = "windows"))]
fn platform_backend() -> impl InputBackend {
    UnsupportedBackend
}

/// Win32 `SendInput` backend (Windows only).
#[cfg(target_os = "windows")]
pub mod win32 {
    use windows::Win32::UI::Input::KeyboardAndMouse::{
        SendInput, INPUT, INPUT_0, INPUT_KEYBOARD, INPUT_MOUSE, KEYBDINPUT, KEYBD_EVENT_FLAGS,
        KEYEVENTF_KEYUP, MOUSEEVENTF_LEFTDOWN, MOUSEEVENTF_LEFTUP, MOUSEEVENTF_MIDDLEDOWN,
        MOUSEEVENTF_MIDDLEUP, MOUSEEVENTF_MOVE, MOUSEEVENTF_RIGHTDOWN, MOUSEEVENTF_RIGHTUP,
        MOUSEINPUT, MOUSE_EVENT_FLAGS, VIRTUAL_KEY,
    };

    use crate::error::InputError;
    use crate::inject::InputBackend;
    use crate::input::{InjectedInput, MouseButton};

    /// Backend that injects events via the Win32 `SendInput` API.
    pub struct Win32Backend;

    impl InputBackend for Win32Backend {
        fn send(&self, input: &InjectedInput) -> Result<(), InputError> {
            let inputs = build_inputs(input);
            send_inputs(&inputs)
        }
    }

    /// Builds the Win32 [`INPUT`] array for a portable input event.
    fn build_inputs(input: &InjectedInput) -> Vec<INPUT> {
        match input {
            InjectedInput::MouseMove { dx, dy } => vec![mouse_move_input(*dx, *dy)],
            InjectedInput::MouseClick { button, down } => vec![mouse_click_input(*button, *down)],
            InjectedInput::Keyboard { keycode, down } => vec![keyboard_input(*keycode, *down)],
        }
    }

    /// Builds a relative mouse-move [`INPUT`] event.
    fn mouse_move_input(dx: i32, dy: i32) -> INPUT {
        INPUT {
            r#type: INPUT_MOUSE,
            Anonymous: INPUT_0 {
                mi: MOUSEINPUT {
                    dx,
                    dy,
                    mouseData: 0,
                    dwFlags: MOUSEEVENTF_MOVE,
                    time: 0,
                    dwExtraInfo: 0,
                },
            },
        }
    }

    /// Builds a mouse button press/release [`INPUT`] event.
    fn mouse_click_input(button: MouseButton, down: bool) -> INPUT {
        let flags: MOUSE_EVENT_FLAGS = match (button, down) {
            (MouseButton::Left, true) => MOUSEEVENTF_LEFTDOWN,
            (MouseButton::Left, false) => MOUSEEVENTF_LEFTUP,
            (MouseButton::Right, true) => MOUSEEVENTF_RIGHTDOWN,
            (MouseButton::Right, false) => MOUSEEVENTF_RIGHTUP,
            (MouseButton::Middle, true) => MOUSEEVENTF_MIDDLEDOWN,
            (MouseButton::Middle, false) => MOUSEEVENTF_MIDDLEUP,
        };
        INPUT {
            r#type: INPUT_MOUSE,
            Anonymous: INPUT_0 {
                mi: MOUSEINPUT {
                    dx: 0,
                    dy: 0,
                    mouseData: 0,
                    dwFlags: flags,
                    time: 0,
                    dwExtraInfo: 0,
                },
            },
        }
    }

    /// Builds a virtual-key press/release [`INPUT`] event.
    fn keyboard_input(keycode: u16, down: bool) -> INPUT {
        let flags: KEYBD_EVENT_FLAGS = if down {
            KEYBD_EVENT_FLAGS(0)
        } else {
            KEYEVENTF_KEYUP
        };
        INPUT {
            r#type: INPUT_KEYBOARD,
            Anonymous: INPUT_0 {
                ki: KEYBDINPUT {
                    wVk: VIRTUAL_KEY(keycode),
                    wScan: 0,
                    dwFlags: flags,
                    time: 0,
                    dwExtraInfo: 0,
                },
            },
        }
    }

    /// Delivers the given [`INPUT`] events to the OS via `SendInput`.
    ///
    /// Returns an error if the OS inserted fewer events than requested.
    fn send_inputs(inputs: &[INPUT]) -> Result<(), InputError> {
        // SAFETY: `inputs` is a valid, fully-initialized slice of `INPUT`
        // structs that remains alive for the duration of the call, and
        // `cbsize` is the exact size of a single `INPUT` as the API requires.
        let inserted = unsafe { SendInput(inputs, std::mem::size_of::<INPUT>() as i32) };
        let requested = inputs.len() as u32;
        if inserted == requested {
            Ok(())
        } else {
            Err(InputError::InjectionFailed {
                inserted,
                requested,
            })
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use windows::Win32::UI::Input::KeyboardAndMouse::{
            KEYEVENTF_KEYUP, MOUSEEVENTF_LEFTDOWN, MOUSEEVENTF_LEFTUP, MOUSEEVENTF_MIDDLEDOWN,
            MOUSEEVENTF_MIDDLEUP, MOUSEEVENTF_MOVE, MOUSEEVENTF_RIGHTDOWN, MOUSEEVENTF_RIGHTUP,
        };

        #[test]
        fn mouse_move_builds_relative_move() {
            let input = mouse_move_input(120, -30);
            assert_eq!(input.r#type, INPUT_MOUSE);
            // SAFETY: the union field is set by the builder under test.
            let mi = unsafe { input.Anonymous.mi };
            assert_eq!(mi.dx, 120);
            assert_eq!(mi.dy, -30);
            assert_eq!(mi.mouseData, 0);
            assert_eq!(mi.dwFlags, MOUSEEVENTF_MOVE);
        }

        #[test]
        fn mouse_click_builds_correct_button_flags() {
            let cases = [
                (MouseButton::Left, true, MOUSEEVENTF_LEFTDOWN),
                (MouseButton::Left, false, MOUSEEVENTF_LEFTUP),
                (MouseButton::Right, true, MOUSEEVENTF_RIGHTDOWN),
                (MouseButton::Right, false, MOUSEEVENTF_RIGHTUP),
                (MouseButton::Middle, true, MOUSEEVENTF_MIDDLEDOWN),
                (MouseButton::Middle, false, MOUSEEVENTF_MIDDLEUP),
            ];
            for (button, down, expected) in cases {
                let input = mouse_click_input(button, down);
                assert_eq!(input.r#type, INPUT_MOUSE);
                // SAFETY: the union field is set by the builder under test.
                let mi = unsafe { input.Anonymous.mi };
                assert_eq!(mi.dwFlags, expected, "button={button:?} down={down}");
                assert_eq!(mi.dx, 0);
                assert_eq!(mi.dy, 0);
            }
        }

        #[test]
        fn keyboard_builds_press_and_release() {
            let keycode = 0x41u16; // VK_A
            let press = keyboard_input(keycode, true);
            assert_eq!(press.r#type, INPUT_KEYBOARD);
            // SAFETY: the union field is set by the builder under test.
            let press_ki = unsafe { press.Anonymous.ki };
            assert_eq!(press_ki.wVk, VIRTUAL_KEY(keycode));
            assert_eq!(press_ki.dwFlags, KEYBD_EVENT_FLAGS(0));

            let release = keyboard_input(keycode, false);
            // SAFETY: the union field is set by the builder under test.
            let release_ki = unsafe { release.Anonymous.ki };
            assert_eq!(release_ki.wVk, VIRTUAL_KEY(keycode));
            assert_eq!(release_ki.dwFlags, KEYEVENTF_KEYUP);
        }

        #[test]
        fn build_inputs_maps_every_event_kind() {
            assert_eq!(
                build_inputs(&InjectedInput::MouseMove { dx: 5, dy: 6 }).len(),
                1
            );
            assert_eq!(
                build_inputs(&InjectedInput::MouseClick {
                    button: MouseButton::Left,
                    down: true
                })
                .len(),
                1
            );
            assert_eq!(
                build_inputs(&InjectedInput::Keyboard {
                    keycode: 1,
                    down: true
                })
                .len(),
                1
            );
        }
    }
}
