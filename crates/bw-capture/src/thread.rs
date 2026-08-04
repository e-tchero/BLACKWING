use crate::backend::CaptureBackend;
use crate::frame::Frame;
use crate::monitor::DisplayInfo;
use crate::CaptureError;
use std::thread;
use tokio::sync::mpsc;

/// Controls a dedicated capture thread.
pub struct CaptureThread {
    stop_tx: std::sync::mpsc::Sender<()>,
    handle: Option<thread::JoinHandle<()>>,
}

impl CaptureThread {
    /// Spawns a dedicated OS thread for the given capture backend.
    ///
    /// The thread will continuously acquire frames and send them via the returned
    /// `tokio::mpsc::Receiver`. This isolates the synchronous, blocking graphics
    /// API calls from the async runtime.
    pub fn spawn(
        mut backend: Box<dyn CaptureBackend>,
        display: DisplayInfo,
        channel_capacity: usize,
    ) -> Result<(Self, mpsc::Receiver<Frame>), CaptureError> {
        let (stop_tx, stop_rx) = std::sync::mpsc::channel();
        let (frame_tx, frame_rx) = mpsc::channel(channel_capacity);

        backend.start(&display)?;

        let handle = thread::Builder::new()
            .name("bw-capture-thread".into())
            .spawn(move || {
                loop {
                    // Check if we should stop
                    if stop_rx.try_recv().is_ok() {
                        break;
                    }

                    match backend.next_frame() {
                        Ok(frame) => {
                            // If the channel is full or closed, we might drop the frame.
                            // blocking_send is used because we are in a synchronous OS thread.
                            if frame_tx.blocking_send(frame).is_err() {
                                // Receiver dropped, stop capturing.
                                break;
                            }
                        }
                        Err(e) => {
                            // In a real implementation we might log the error and decide
                            // whether to retry (e.g. if access was lost) or break.
                            // For now, if we fail to acquire a frame, we just break.
                            eprintln!("Capture thread error: {:?}", e);
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
