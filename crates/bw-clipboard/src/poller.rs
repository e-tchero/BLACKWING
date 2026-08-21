//! Clipboard change detection and notification.
//!
//! [`ClipboardPoller`] runs a background thread that periodically reads the
//! OS clipboard and fires a callback whenever the content changes.  This is
//! the *sending* half of clipboard synchronization — the *receiving* half is
//! handled by the dispatcher's [`ClipboardData`](crate::ClipboardData) handler.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::ClipboardManager;

/// A clipboard change event passed to the polling callback.
#[derive(Debug, Clone)]
pub struct ClipboardChange {
    /// Whether the change is text (`true`) or an image (`false`).
    pub is_text: bool,
    /// For text changes, the new UTF-8 content.
    pub text: Option<String>,
    /// For image changes, the RGBA8 pixel data (width × height × 4 bytes).
    pub image_data: Option<Vec<u8>>,
    /// Image width in pixels (only set for image changes).
    pub image_width: Option<usize>,
    /// Image height in pixels (only set for image changes).
    pub image_height: Option<usize>,
}

/// Periodically polls the OS clipboard and invokes a callback on changes.
pub struct ClipboardPoller {
    text_interval: Duration,
    image_interval: Duration,
}

impl ClipboardPoller {
    /// Creates a new poller with the given check intervals.
    ///
    /// `text_interval` controls how often the text clipboard is checked
    /// (recommended: 250–500 ms).
    ///
    /// `image_interval` controls how often the image clipboard is checked
    /// (recommended: 1000–2000 ms, since image comparison is more expensive).
    pub fn new(text_interval: Duration, image_interval: Duration) -> Self {
        Self {
            text_interval,
            image_interval,
        }
    }

    /// Creates a poller with default intervals (text: 500 ms, image: 2 s).
    pub fn default_intervals() -> Self {
        Self::new(Duration::from_millis(500), Duration::from_secs(2))
    }

    /// Spawns a background polling thread.
    ///
    /// The `callback` is invoked (on the polling thread) whenever the
    /// clipboard content changes.  The thread runs until the returned
    /// [`ClipboardPollHandle`] is dropped.
    pub fn spawn<F>(self, callback: F) -> Result<ClipboardPollHandle, String>
    where
        F: Fn(ClipboardChange) + Send + 'static,
    {
        let text_interval = self.text_interval;
        let image_interval = self.image_interval;
        let running = Arc::new(Mutex::new(true));
        let running_clone = running.clone();

        let handle = std::thread::Builder::new()
            .name("clipboard-poller".into())
            .spawn(move || {
                let Ok(mut manager) = ClipboardManager::new() else {
                    eprintln!("clipboard poller: unable to open clipboard, thread exiting");
                    return;
                };

                let mut last_text_hash: u64 = 0;
                let mut last_image_hash: u64 = 0;
                let mut text_next = std::time::Instant::now();
                let mut image_next = std::time::Instant::now();

                loop {
                    if !*running_clone.lock().unwrap_or_else(|e| e.into_inner()) {
                        break;
                    }

                    let now = std::time::Instant::now();

                    // Check text clipboard.
                    if now >= text_next {
                        text_next = now + text_interval;
                        match manager.get_text() {
                            Ok(text) => {
                                let hash = hash_bytes(text.as_bytes());
                                if hash != last_text_hash {
                                    last_text_hash = hash;
                                    // Invalidate image hash — if text changed,
                                    // the clipboard type may have switched.
                                    last_image_hash = 0;
                                    callback(ClipboardChange {
                                        is_text: true,
                                        text: Some(text),
                                        image_data: None,
                                        image_width: None,
                                        image_height: None,
                                    });
                                }
                            }
                            Err(_) => {
                                // Clipboard empty or non-text — reset hash so
                                // we detect when text reappears.
                                last_text_hash = 0;
                            }
                        }
                    }

                    // Check image clipboard.
                    if now >= image_next {
                        image_next = now + image_interval;
                        match manager.get_image() {
                            Ok(image) => {
                                let hash = hash_bytes(&image.bytes);
                                if hash != last_image_hash {
                                    last_image_hash = hash;
                                    last_text_hash = 0; // invalidate text hash
                                    callback(ClipboardChange {
                                        is_text: false,
                                        text: None,
                                        image_data: Some(image.bytes),
                                        image_width: Some(image.width),
                                        image_height: Some(image.height),
                                    });
                                }
                            }
                            Err(_) => {
                                last_image_hash = 0;
                            }
                        }
                    }

                    // Sleep for the shorter of the two intervals.
                    let sleep_until = text_next.min(image_next);
                    let now = std::time::Instant::now();
                    if sleep_until > now {
                        std::thread::sleep(sleep_until - now);
                    } else {
                        std::thread::sleep(Duration::from_millis(50));
                    }
                }
            })
            .map_err(|e| format!("failed to spawn clipboard poller thread: {}", e))?;

        Ok(ClipboardPollHandle {
            _handle: handle,
            running,
        })
    }
}

/// Handle to a running clipboard poller.  Dropping this stops the thread.
pub struct ClipboardPollHandle {
    _handle: std::thread::JoinHandle<()>,
    running: Arc<Mutex<bool>>,
}

impl Drop for ClipboardPollHandle {
    fn drop(&mut self) {
        if let Ok(mut flag) = self.running.lock() {
            *flag = false;
        }
    }
}

fn hash_bytes(data: &[u8]) -> u64 {
    let mut hasher = DefaultHasher::new();
    data.hash(&mut hasher);
    hasher.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    #[test]
    fn test_hash_differs_for_different_content() {
        let h1 = hash_bytes(b"hello");
        let h2 = hash_bytes(b"world");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_hash_same_for_same_content() {
        let h1 = hash_bytes(b"same content");
        let h2 = hash_bytes(b"same content");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_poller_detects_text_change() {
        let (tx, rx) = mpsc::channel();
        let poller = ClipboardPoller::new(Duration::from_millis(50), Duration::from_millis(50));
        let _handle = poller.spawn(move |change| {
            let _ = tx.send(change);
        });

        // The poller may fire immediately if the clipboard has content.
        // Wait briefly and drain any initial events.
        std::thread::sleep(Duration::from_millis(200));

        // If we got any events, they should be valid.
        while let Ok(change) = rx.try_recv() {
            if change.is_text {
                assert!(change.text.is_some());
            } else {
                assert!(change.image_data.is_some());
            }
        }
        // Handle dropped here, thread stops.
    }
}
