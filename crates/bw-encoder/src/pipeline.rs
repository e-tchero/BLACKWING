use crate::{EncodedFrame, EncoderBackend};
use bw_capture::Frame;
use std::thread;
use tokio::sync::mpsc;

/// A pipeline that manages the encoding process on a dedicated thread.
pub struct EncoderPipeline {
    _handle: thread::JoinHandle<()>,
}

impl EncoderPipeline {
    /// Spawns a dedicated OS thread for encoding.
    /// This prevents heavy CPU encoding operations from blocking the Tokio async runtime.
    pub fn spawn(
        mut backend: Box<dyn EncoderBackend>,
        mut frame_rx: mpsc::Receiver<Frame>,
        encoded_tx: mpsc::Sender<EncodedFrame>,
    ) -> Self {
        let handle = thread::Builder::new()
            .name("bw-encoder-thread".into())
            .spawn(move || {
                let mut sequence = 0;

                // Keep reading frames as long as the channel is open.
                //
                // LATENCY FIX: Instead of encoding every frame (which causes
                // massive queuing lag), we drain the channel to the newest
                // frame before encoding. If 5 frames are queued, we encode
                // only the last one — keeping latency at ~1 frame instead of
                // accumulating a backlog of stale frames.
                while let Some(mut frame) = frame_rx.blocking_recv() {
                    // Drain any newer frames that arrived while we were
                    // blocked — keep only the most recent.
                    while let Ok(newer) = frame_rx.try_recv() {
                        frame = newer;
                    }

                    // Periodic refresh frames must produce an IDR keyframe so
                    // the client can resync its decode reference chain after
                    // idle periods.
                    if frame.is_refresh {
                        backend.force_keyframe();
                    }

                    match backend.encode_frame(&frame, sequence) {
                        Ok(encoded_frame) => {
                            match encoded_tx.try_send(encoded_frame) {
                                Ok(_) => sequence += 1,
                                Err(mpsc::error::TrySendError::Full(_)) => {
                                    // Backpressure: channel is full, drop the frame.
                                    // Force keyframe so client can resync.
                                    backend.force_keyframe();
                                }
                                Err(mpsc::error::TrySendError::Closed(_)) => {
                                    break;
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!("Encoder error: {:?}", e);
                        }
                    }
                }

                backend.stop();
            })
            .unwrap_or_else(|e| panic!("Failed to spawn encoder thread: {}", e));

        Self { _handle: handle }
    }
}
