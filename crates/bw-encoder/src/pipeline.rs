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

                // Keep reading frames as long as the channel is open
                while let Some(frame) = frame_rx.blocking_recv() {
                    match backend.encode_frame(&frame, sequence) {
                        Ok(encoded_frame) => {
                            match encoded_tx.try_send(encoded_frame) {
                                Ok(_) => sequence += 1,
                                Err(mpsc::error::TrySendError::Full(_)) => {
                                    // Backpressure: channel is full, drop the frame.
                                    // Force the next encoded frame to be a keyframe so a
                                    // client that missed this reference frame can resync —
                                    // otherwise the whole P-frame reference chain is lost.
                                    eprintln!(
                                        "EncoderPipeline: Dropping frame {} due to backpressure; forcing keyframe",
                                        sequence
                                    );
                                    backend.force_keyframe();
                                }
                                Err(mpsc::error::TrySendError::Closed(_)) => {
                                    // Receiver dropped, stop encoding
                                    break;
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!("Encoder error: {:?}", e);
                            // We could choose to break or continue; typically we might continue
                            // to see if the next frame encodes successfully.
                        }
                    }
                }

                backend.stop();
            })
            .unwrap_or_else(|e| panic!("Failed to spawn encoder thread: {}", e));

        Self { _handle: handle }
    }
}
