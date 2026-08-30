#![allow(missing_docs)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use bw_capture::{CaptureBackend, CaptureError, CaptureThread, DisplayInfo, Frame, PixelFormat};
use bw_encoder::h264::OpenH264Backend;
use bw_encoder::{EncodedFrame, EncoderBackend, EncoderPipeline};
use bw_transport::{QuicClient, QuicServer};
use tokio::sync::mpsc;
use tokio::time::Duration;

pub struct DummyCaptureBackend {
    width: u32,
    height: u32,
    frame_count: u32,
    max_frames: u32,
}

impl CaptureBackend for DummyCaptureBackend {
    fn displays(&self) -> Result<Vec<DisplayInfo>, CaptureError> {
        Ok(vec![DisplayInfo {
            id: "dummy".into(),
            name: "Dummy Display".into(),
            width: self.width,
            height: self.height,
            virtual_x: 0,
            virtual_y: 0,
            refresh_hz: 60,
            scale_factor: 1.0,
            is_primary: true,
        }])
    }

    fn start(&mut self, _display: &DisplayInfo) -> Result<(), CaptureError> {
        Ok(())
    }

    fn next_frame(&mut self) -> Result<Frame, CaptureError> {
        if self.frame_count >= self.max_frames {
            // Delay to simulate steady state after max frames
            std::thread::sleep(Duration::from_millis(100));
            return Err(CaptureError::Stopped); // Stop capture for test
        }

        std::thread::sleep(Duration::from_millis(16)); // ~60fps

        let mut buffer = vec![0u8; (self.width * self.height * 4) as usize];
        // Fill with a color that changes over time
        for chunk in buffer.chunks_mut(4) {
            chunk[0] = (self.frame_count % 255) as u8; // B
            chunk[1] = 128; // G
            chunk[2] = 255; // R
            chunk[3] = 255; // A
        }

        self.frame_count += 1;

        Ok(Frame {
            width: self.width,
            height: self.height,
            stride: self.width * 4,
            timestamp_us: (self.frame_count as u64) * 16666,
            pixel_format: PixelFormat::Bgra8,
            buffer,
            dirty_rects: vec![],
            move_rects: vec![],
            cursor: None,
            is_refresh: false,
        })
    }

    fn cursor_info(&mut self) -> Result<bw_capture::CursorInfo, CaptureError> {
        Ok(bw_capture::CursorInfo::default())
    }

    fn stop(&mut self) {}
}

#[tokio::test]
async fn test_end_to_end_streaming() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();

    // 1. Setup QUIC Server
    let server = QuicServer::bind("127.0.0.1:0".parse().unwrap(), None).unwrap();
    let server_addr = server.endpoint.local_addr().unwrap();

    let server_handle = tokio::spawn(async move {
        let conn = server.accept().await.unwrap();

        // Receive the stream of frames
        let mut frames_received = 0;
        let mut stream = conn.accept_uni().await.unwrap();

        let mut len_buf = [0u8; 4];
        while let Ok(()) = stream.read_exact(&mut len_buf).await {
            let frame_size = u32::from_be_bytes(len_buf) as usize;
            let mut data = vec![0u8; frame_size];
            stream.read_exact(&mut data).await.unwrap();

            let frame = EncodedFrame::from_bytes(&data).expect("Failed to deserialize frame");
            assert_eq!(frame.width, 1280);
            assert_eq!(frame.height, 720);
            assert_eq!(frame.codec, bw_encoder::Codec::H264);
            assert!(!frame.payload.is_empty());

            frames_received += 1;
            println!(
                "Server received frame {}, sequence: {}, size: {} bytes",
                frames_received,
                frame.sequence,
                frame.payload.len()
            );
            if frames_received >= 2 {
                break;
            }
        }

        assert!(
            frames_received >= 2,
            "Expected at least 2 frames, got {}",
            frames_received
        );
    });

    // 2. Setup QUIC Client
    let client = QuicClient::bind(None).unwrap();
    let conn = client.connect(server_addr).await.unwrap();

    // 3. Setup Capture & Encoding Pipeline
    let capture_backend = Box::new(DummyCaptureBackend {
        width: 1280,
        height: 720,
        frame_count: 0,
        max_frames: 5,
    });

    let displays = capture_backend.displays().unwrap();
    let display = displays[0].clone();

    let (mut capture_thread, frame_rx) =
        CaptureThread::spawn(capture_backend, display, 10).unwrap();

    let mut encoder_backend = OpenH264Backend::new();
    encoder_backend
        .start(1280, 720, bw_encoder::backend::EncoderConfig::default())
        .unwrap();

    let (encoded_tx, mut encoded_rx) = mpsc::channel(10);
    let _encoder_pipeline = EncoderPipeline::spawn(Box::new(encoder_backend), frame_rx, encoded_tx);

    // 4. Transmit loop
    let mut stream = conn.open_uni().await.unwrap();
    let mut _frames_sent = 0;

    while let Some(encoded_frame) = encoded_rx.recv().await {
        println!(
            "Client encoded frame size: {} bytes",
            encoded_frame.payload.len()
        );

        let bytes = encoded_frame.to_bytes();
        let len = bytes.len() as u32;
        stream.write_all(&len.to_be_bytes()).await.unwrap();
        stream.write_all(&bytes).await.unwrap();

        _frames_sent += 1;
    }

    capture_thread.stop();
    server_handle.await.unwrap();
}
