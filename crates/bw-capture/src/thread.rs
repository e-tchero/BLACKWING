use crate::backend::CaptureBackend;
use crate::frame::Frame;
use crate::monitor::DisplayInfo;
use crate::CaptureError;
use std::thread;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

/// Configuration for the capture thread's frame timer behavior.
///
/// When the display is idle (no dirty regions), DXGI returns empty frames.
/// Without throttling, the capture thread busy-loops on these empty frames,
/// wasting CPU. The frame timer sleeps between empty-frame retries and
/// periodically re-sends the last captured frame to keep the video pipeline
/// warm and ensure the client receives periodic updates.
#[derive(Debug, Clone)]
pub struct FrameTimerConfig {
    /// How long to sleep between empty-frame retries when the screen is idle.
    /// Lower values reduce latency for detecting screen changes; higher values
    /// reduce CPU usage. Default: 16ms (~60 Hz polling).
    pub idle_sleep_ms: u64,
    /// How often to force a periodic refresh frame when the screen has been
    /// idle. The last captured frame is re-sent with `is_refresh: true`, which
    /// causes the encoder to produce an IDR keyframe. Set to 0 to disable
    /// periodic refreshes. Default: 1000ms (1 second).
    pub refresh_interval_ms: u64,
    /// Minimum interval between real (non-idle) frames sent to the encoder.
    /// Caps the capture rate to prevent the encoder from being overwhelmed
    /// with frames it can't keep up with. Default: 33ms (~30 fps).
    pub min_frame_interval_ms: u64,
}

impl Default for FrameTimerConfig {
    fn default() -> Self {
        Self {
            idle_sleep_ms: 16,
            refresh_interval_ms: 1000,
            min_frame_interval_ms: 33,
        }
    }
}

/// Controls a dedicated capture thread.
pub struct CaptureThread {
    stop_tx: std::sync::mpsc::Sender<()>,
    handle: Option<thread::JoinHandle<()>>,
}

impl CaptureThread {
    /// Spawns a dedicated OS thread for the given capture backend with default
    /// frame timer settings (16ms idle sleep, 1s refresh interval).
    ///
    /// See [`Self::spawn_with_config`] for full control over timer behavior.
    pub fn spawn(
        backend: Box<dyn CaptureBackend>,
        display: DisplayInfo,
        channel_capacity: usize,
    ) -> Result<(Self, mpsc::Receiver<Frame>), CaptureError> {
        Self::spawn_with_config(
            backend,
            display,
            channel_capacity,
            FrameTimerConfig::default(),
        )
    }

    /// Spawns a dedicated OS thread for the given capture backend.
    ///
    /// The thread will continuously acquire frames and send them via the returned
    /// `tokio::mpsc::Receiver`. This isolates the synchronous, blocking graphics
    /// API calls from the async runtime.
    ///
    /// # Frame Timer Behavior
    ///
    /// When the display is idle and the backend returns empty frames:
    /// 1. The thread sleeps for `config.idle_sleep_ms` before retrying (prevents
    ///    busy-spinning and reduces CPU usage).
    /// 2. If idle for longer than `config.refresh_interval_ms`, the last captured
    ///    frame is re-sent with `is_refresh: true`. The encoder should force an
    ///    IDR keyframe for these refresh frames so the client can resync.
    /// 3. When a real (non-empty) frame arrives, the idle timer resets.
    pub fn spawn_with_config(
        mut backend: Box<dyn CaptureBackend>,
        display: DisplayInfo,
        channel_capacity: usize,
        config: FrameTimerConfig,
    ) -> Result<(Self, mpsc::Receiver<Frame>), CaptureError> {
        let (stop_tx, stop_rx) = std::sync::mpsc::channel();
        let (frame_tx, frame_rx) = mpsc::channel(channel_capacity);

        backend.start(&display)?;

        let idle_sleep = Duration::from_millis(config.idle_sleep_ms);
        let refresh_interval = if config.refresh_interval_ms > 0 {
            Some(Duration::from_millis(config.refresh_interval_ms))
        } else {
            None
        };
        let min_frame_interval = Duration::from_millis(config.min_frame_interval_ms);

        let handle = thread::Builder::new()
            .name("bw-capture-thread".into())
            .spawn(move || {
                let mut last_frame: Option<Frame> = None;
                let mut last_real_frame_time = Instant::now();

                loop {
                    // Check if we should stop
                    if stop_rx.try_recv().is_ok() {
                        break;
                    }

                    match backend.next_frame() {
                        Ok(frame) => {
                            if frame.buffer.is_empty() {
                                // Screen is idle — sleep to prevent busy-spin,
                                // then check if we need to send a refresh frame.
                                thread::sleep(idle_sleep);

                                if let (Some(refresh_int), Some(cached)) =
                                    (refresh_interval, last_frame.as_ref())
                                {
                                    if last_real_frame_time.elapsed() >= refresh_int {
                                        // Periodic refresh: re-send the last captured frame
                                        // with is_refresh=true so the encoder forces a keyframe.
                                        // Also query the current cursor position so the remote
                                        // crosshair tracks movement even when the desktop is idle.
                                        let mut refresh_frame = (*cached).clone();
                                        refresh_frame.is_refresh = true;
                                        refresh_frame.timestamp_us = 0;
                                        if let Ok(cursor) = backend.cursor_info() {
                                            refresh_frame.cursor = Some(cursor);
                                        }

                                        let _ = frame_tx.try_send(refresh_frame);
                                        // Reset timer so we don't spam refreshes
                                        last_real_frame_time = Instant::now();
                                    }
                                }
                                continue;
                            }

                            // Real frame from the backend — cache it and reset idle timer.
                            // Enforce minimum frame interval to cap the capture rate
                            // and prevent encoder backpressure.
                            let now = Instant::now();
                            let elapsed = now.duration_since(last_real_frame_time);
                            if elapsed < min_frame_interval {
                                thread::sleep(min_frame_interval - elapsed);
                            }

                            last_frame = Some(frame.clone());
                            last_real_frame_time = Instant::now();

                            // LATENCY FIX: use try_send so if the
                            // downstream pipeline is full, we drop this
                            // frame and capture the next one instead of
                            // blocking and queuing stale frames.
                            let _ = frame_tx.try_send(frame);
                        }
                        Err(crate::CaptureError::Stopped) => {
                            // Intentional stop — exit the capture loop.
                            break;
                        }
                        Err(e) => {
                            eprintln!("Capture thread error: {:?}", e);
                            // Attempt recovery for transient errors (e.g.
                            // DXGI_ERROR_ACCESS_LOST during display mode
                            // changes, lock screens, or UAC).
                            backend.stop();
                            thread::sleep(Duration::from_millis(200));
                            if backend.start(&display).is_ok() {
                                eprintln!("Capture thread: recovered after ACCESS_LOST");
                                last_frame = None;
                                last_real_frame_time = Instant::now();
                                continue;
                            }
                            eprintln!("Capture thread: recovery failed, stopping");
                            break;
                        }
                    }
                }
                backend.stop();
            })
            .map_err(|e| CaptureError::InitFailed(format!("Failed to spawn thread: {}", e)))?;

        Ok((
            Self {
                stop_tx,
                handle: Some(handle),
            },
            frame_rx,
        ))
    }

    /// Stops the capture thread and waits for it to exit.
    pub fn stop(&mut self) {
        let _ = self.stop_tx.send(());
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for CaptureThread {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_timer_config_defaults() {
        let config = FrameTimerConfig::default();
        assert_eq!(config.idle_sleep_ms, 16);
        assert_eq!(config.refresh_interval_ms, 1000);
        assert_eq!(config.min_frame_interval_ms, 33);
    }

    #[test]
    fn frame_timer_config_zero_refresh_disables() {
        let config = FrameTimerConfig {
            refresh_interval_ms: 0,
            ..Default::default()
        };
        assert_eq!(config.refresh_interval_ms, 0);
    }
}
