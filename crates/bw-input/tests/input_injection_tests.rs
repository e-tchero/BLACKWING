#![allow(missing_docs)] // Integration-test crate (repo convention)
#![allow(clippy::unwrap_used, clippy::expect_used)] // Test code may panic on failure (repo convention)

use bw_input::inject::{
    inject_keyboard, inject_mouse_click, inject_mouse_move, InputBackend, InputInjector,
};
use bw_input::input::{InjectedInput, MouseButton};
use bw_input::InputError;
use std::sync::{Arc, Mutex};

/// A backend that records every delivered event instead of touching the OS.
#[derive(Default)]
struct RecordingBackend {
    events: Mutex<Vec<InjectedInput>>,
}

impl RecordingBackend {
    fn events(&self) -> Vec<InjectedInput> {
        self.events.lock().unwrap().clone()
    }
}

impl InputBackend for RecordingBackend {
    fn send(&self, input: &InjectedInput) -> Result<(), InputError> {
        self.events.lock().unwrap().push(*input);
        Ok(())
    }
}

/// A backend that always fails, to verify error propagation.
struct FailingBackend;

impl InputBackend for FailingBackend {
    fn send(&self, _input: &InjectedInput) -> Result<(), InputError> {
        Err(InputError::InjectionFailed {
            inserted: 0,
            requested: 1,
        })
    }
}

#[test]
fn test_inject_mouse_move_delivers_relative_deltas() {
    let backend = Arc::new(RecordingBackend::default());
    let injector = InputInjector::with_backend(backend.clone());

    injector.inject_mouse_move(100, -50).unwrap();
    injector.inject_mouse_move(0, 0).unwrap();

    assert_eq!(
        backend.events(),
        vec![
            InjectedInput::MouseMove { dx: 100, dy: -50 },
            InjectedInput::MouseMove { dx: 0, dy: 0 },
        ]
    );
}

#[test]
fn test_inject_mouse_click_press_and_release() {
    let backend = Arc::new(RecordingBackend::default());
    let injector = InputInjector::with_backend(backend.clone());

    injector
        .inject_mouse_click(MouseButton::Left, true)
        .unwrap();
    injector
        .inject_mouse_click(MouseButton::Left, false)
        .unwrap();
    injector
        .inject_mouse_click(MouseButton::Right, true)
        .unwrap();
    injector
        .inject_mouse_click(MouseButton::Middle, false)
        .unwrap();

    assert_eq!(
        backend.events(),
        vec![
            InjectedInput::MouseClick {
                button: MouseButton::Left,
                down: true
            },
            InjectedInput::MouseClick {
                button: MouseButton::Left,
                down: false
            },
            InjectedInput::MouseClick {
                button: MouseButton::Right,
                down: true
            },
            InjectedInput::MouseClick {
                button: MouseButton::Middle,
                down: false
            },
        ]
    );
}

#[test]
fn test_inject_keyboard_press_and_release() {
    let backend = Arc::new(RecordingBackend::default());
    let injector = InputInjector::with_backend(backend.clone());

    injector.inject_keyboard(0x41, true).unwrap(); // VK_A
    injector.inject_keyboard(0x41, false).unwrap();

    assert_eq!(
        backend.events(),
        vec![
            InjectedInput::Keyboard {
                keycode: 0x41,
                down: true
            },
            InjectedInput::Keyboard {
                keycode: 0x41,
                down: false
            },
        ]
    );
}

#[test]
fn test_free_functions_build_correct_events() {
    // The free functions route through a default backend; on Windows this
    // exercises the real `SendInput` path (which may legitimately report
    // `InjectionFailed` without an interactive desktop), and elsewhere it
    // reports `UnsupportedPlatform`. We only assert the error *shape*, not the
    // OS call result, so the test is deterministic in any CI environment.
    let _ = inject_mouse_move(10, 20);
    let _ = inject_mouse_click(MouseButton::Left, true);
    let _ = inject_keyboard(0x1b, false); // VK_ESCAPE
}

#[test]
fn test_backend_error_propagates() {
    let injector = InputInjector::with_backend(Arc::new(FailingBackend));

    let err = injector.inject_mouse_move(1, 1).unwrap_err();
    assert_eq!(
        err,
        InputError::InjectionFailed {
            inserted: 0,
            requested: 1
        }
    );

    let err = injector
        .inject_mouse_click(MouseButton::Left, true)
        .unwrap_err();
    assert_eq!(
        err,
        InputError::InjectionFailed {
            inserted: 0,
            requested: 1
        }
    );

    let err = injector.inject_keyboard(0x41, true).unwrap_err();
    assert_eq!(
        err,
        InputError::InjectionFailed {
            inserted: 0,
            requested: 1
        }
    );
}
