//! BLACKWING server (agent) — accepts authenticated remote sessions.
//!
//! Wire flow:
//!
//! ```text
//! QUIC listener ── accept ── bidi stream ── OPAQUE login (bw-session::wire)
//!   └── MessageSession ── split ── receiver: dispatch input/clipboard/ICE
//!                              └── sender: stream video (DXGI→OpenH264) + audio
//! ```
//!
//! The operator enrolls a device password first:
//!
//! ```text
//! bw-server --register <device-id> --password <password> --data-dir <dir>
//! ```
//!
//! then runs:
//!
//! ```text
//! bw-server --listen 0.0.0.0:9000 --data-dir <dir>
//! ```

#![allow(clippy::unwrap_used, clippy::expect_used)]
// ^ Justification: binary crate entry points report fatal startup errors by
//   panicking with a message, per native-application convention.

use std::path::PathBuf;
use std::sync::Arc;

use bw_auth::store::EnrollmentStore;
use bw_capture::{CaptureBackend, CaptureThread, DxgiCaptureBackend};
use bw_encoder::EncoderPipeline;
use bw_encoder::h264::OpenH264Backend;
use bw_protocol::dispatcher::MessageDispatcher;
use bw_protocol::message::{ProtocolMessage, VideoPayload};
use bw_protocol::routing::{MessageEnvelope, NodeId, Route, SessionId};
use bw_protocol::session::SessionManager;
use bw_server::{audio_packet_message, register_clipboard_handler, register_input_handlers};
use bw_session::wire;
use bw_transport::QuicServer;
use bw_transport::adapter::QuicProtocolAdapter;
use tokio::sync::mpsc;

const DEFAULT_LISTEN: &str = "0.0.0.0:9000";
const FRAME_CAPACITY: usize = 16;

/// Simple positional/flag argument parser.
struct Args {
    listen: String,
    data_dir: Option<PathBuf>,
    register: Option<(String, String)>,
    relay: Option<String>,
}

fn parse_args() -> Args {
    let mut listen = DEFAULT_LISTEN.to_string();
    let mut data_dir: Option<PathBuf> = None;
    let mut register: Option<(String, String)> = None;
    let mut relay: Option<String> = None;

    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--listen" => listen = it.next().expect("--listen requires an address"),
            "--data-dir" => {
                data_dir = Some(it.next().expect("--data-dir requires a path").into());
            }
            "--register" => {
                let id = it.next().expect("--register requires a device id");
                let password = it.next().expect("--register requires a password");
                register = Some((id, password));
            }
            "--relay" => relay = Some(it.next().expect("--relay requires a relay address")),
            "--help" | "-h" => {
                eprintln!(
                    "usage: bw-server [--listen ADDR] [--data-dir DIR] [--register ID PASS] [--relay ADDR]"
                );
                std::process::exit(0);
            }
            other => {
                eprintln!("unknown argument: {other}");
                std::process::exit(2);
            }
        }
    }
    Args {
        listen,
        data_dir,
        register,
        relay,
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = parse_args();

    let data_dir = args
        .data_dir
        .unwrap_or_else(|| std::env::temp_dir().join("blackwing-server"));

    // Enrollment mode: register a device password and exit.
    if let Some((id, password)) = args.register {
        let mut store = match EnrollmentStore::load_from_dir(&data_dir) {
            Ok(store) => store,
            Err(_) => EnrollmentStore::new(),
        };
        store.register(id.as_bytes(), password.as_bytes())?;
        store.save_to_dir(&data_dir)?;
        eprintln!("enrolled device '{id}' in {}", data_dir.display());
        return Ok(());
    }

    let store = match EnrollmentStore::load_from_dir(&data_dir) {
        Ok(store) => store,
        Err(e) => {
            eprintln!(
                "no enrollment data at {} — run `bw-server --register <id> <password> --data-dir {}` first ({e})",
                data_dir.display(),
                data_dir.display()
            );
            std::process::exit(1);
        }
    };
    eprintln!(
        "loaded {} enrollment(s) from {}",
        store.len(),
        data_dir.display()
    );

    let listen_addr: std::net::SocketAddr = args.listen.parse()?;
    eprintln!("starting BLACKWING server on {listen_addr}");

    let tokio_runtime = tokio::runtime::Runtime::new()?;
    tokio_runtime.block_on(run_server(listen_addr, Arc::new(store), args.relay))?;
    Ok(())
}

async fn run_server(
    listen_addr: std::net::SocketAddr,
    store: Arc<EnrollmentStore>,
    relay: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let dispatcher = Arc::new(MessageDispatcher::new());
    register_input_handlers(&dispatcher, bw_input::InputInjector::new());
    let clipboard = Arc::new(std::sync::Mutex::new(bw_clipboard::ClipboardManager::new()?));
    register_clipboard_handler(&dispatcher, clipboard);

    let session_manager = Arc::new(SessionManager::new());

    // Optional relay data-plane routing (token derived from a fixed dev token).
    let quic_server = if let Some(relay_addr) = relay {
        let relay_sock: std::net::SocketAddr = relay_addr.parse()?;
        let token = [0xABu8; 32];
        QuicServer::bind(listen_addr, Some((relay_sock, token)))?
    } else {
        QuicServer::bind(listen_addr, None)?
    };

    eprintln!("server ready — waiting for client sessions");
    loop {
        let Some(conn) = quic_server.accept().await else {
            continue;
        };
        eprintln!("connection accepted");
        let dispatcher = Arc::clone(&dispatcher);
        let session_manager = Arc::clone(&session_manager);
        let store = Arc::clone(&store);
        tokio::spawn(async move {
            if let Err(e) = handle_session(conn, &store, &dispatcher, &session_manager).await {
                eprintln!("session error: {e}");
            }
        });
    }
}

/// Handles one authenticated client session: OPAQUE login, then streams
/// inbound control messages to the dispatcher and outbound video/audio.
async fn handle_session(
    conn: quinn::Connection,
    store: &EnrollmentStore,
    dispatcher: &Arc<MessageDispatcher>,
    session_manager: &Arc<SessionManager>,
) -> Result<(), wire::WireError> {
    // The client opens the first bidi stream and initiates the OPAQUE login.
    let (send, recv) = conn
        .accept_bi()
        .await
        .map_err(|_| wire::WireError::Closed)?;
    let adapter = QuicProtocolAdapter::new(send, recv);
    let (session, identifier) =
        wire::server_establish(adapter, Arc::clone(session_manager), store).await?;
    let identifier = String::from_utf8_lossy(&identifier).to_string();
    eprintln!("authenticated client '{identifier}'");

    let (mut sender, mut receiver) = session.into_split();

    // Outbound channel: video frames and audio packets queue here and are
    // drained by the sender task below.
    let (out_tx, mut out_rx) = mpsc::channel::<ProtocolMessage>(FRAME_CAPACITY);

    // Sender task: drain the outbound queue onto the encrypted session.
    let _sender_task = tokio::spawn(async move {
        while let Some(message) = out_rx.recv().await {
            if sender.send_message(&message).await.is_err() {
                break;
            }
        }
    });

    // Video pipeline: capture the primary display and encode to H.264.
    spawn_video_pipeline(out_tx.clone());

    // Audio pipeline: capture host output and queue AudioData messages.
    spawn_audio_pipeline(out_tx.clone());

    // Clipboard pipeline: poll local clipboard and send changes to the client.
    bw_server::spawn_clipboard_poller(out_tx);

    // Receiver loop: dispatch inbound control messages (input, clipboard).
    loop {
        let message = receiver.recv_message().await?;
        eprintln!("received message type {:?}", message.message_type);
        let envelope = MessageEnvelope {
            source: NodeId(bw_crypto::DeviceId::from_digest([0x01; 32])),
            destination: NodeId(bw_crypto::DeviceId::from_digest([0x02; 32])),
            session_id: SessionId([0u8; 16]),
            route: Route::Direct,
            message,
            routing_flags: 0,
        };
        if let Err(e) = dispatcher.dispatch(envelope) {
            eprintln!("dispatch error: {e}");
        }
    }

    // Note: the sender task and pipelines are intentionally left running for
    // the process lifetime; the session closes when the client disconnects.
}

/// Spawns the DXGI capture → OpenH264 encode → VideoData pipeline.
fn spawn_video_pipeline(out_tx: mpsc::Sender<ProtocolMessage>) {
    let (capture, display) = match start_capture() {
        Some(v) => v,
        None => {
            eprintln!("warning: screen capture unavailable — video streaming disabled");
            return;
        }
    };

    // Capture thread → encoder pipeline → encoded frames.
    let (capture_thread, frame_rx) =
        match CaptureThread::spawn(Box::new(capture), display, FRAME_CAPACITY) {
            Ok(v) => v,
            Err(e) => {
                eprintln!(
                    "warning: failed to start capture thread — video streaming disabled: {e}"
                );
                return;
            }
        };
    let (encoded_tx, mut encoded_rx) = mpsc::channel::<bw_encoder::EncodedFrame>(FRAME_CAPACITY);
    let encoder = EncoderPipeline::spawn(Box::new(OpenH264Backend::new()), frame_rx, encoded_tx);

    tokio::spawn(async move {
        let mut frames_sent: u64 = 0;
        while let Some(frame) = encoded_rx.recv().await {
            let payload = VideoPayload {
                encoded_frame: frame.to_bytes(),
            };
            match ProtocolMessage::video_data(payload) {
                Ok(message) => {
                    if frames_sent == 0 {
                        eprintln!(
                            "video: first frame {} bytes (u16 payload max is 65535)",
                            frame.to_bytes().len()
                        );
                    }
                    if out_tx.send(message).await.is_err() {
                        break;
                    }
                    frames_sent += 1;
                    if frames_sent == 1 || frames_sent.is_multiple_of(600) {
                        eprintln!("video: {frames_sent} frames sent to client");
                    }
                }
                Err(e) => eprintln!("video message serialization failed: {e}"),
            }
        }
        drop(capture_thread);
        drop(encoder);
    });
}

/// Starts the primary-display DXGI capture backend.
fn start_capture() -> Option<(DxgiCaptureBackend, bw_capture::DisplayInfo)> {
    let backend = DxgiCaptureBackend::new().ok()?;
    let displays = backend.displays().ok()?;
    let primary = displays
        .iter()
        .find(|d| d.is_primary)
        .or_else(|| displays.first())?
        .clone();
    Some((backend, primary))
}

/// Spawns host audio capture, queuing each Opus frame as an AudioData message.
fn spawn_audio_pipeline(out_tx: mpsc::Sender<ProtocolMessage>) {
    let (capture, packets) = match bw_audio::AudioCapture::new() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("warning: audio capture unavailable — host audio disabled: {e}");
            return;
        }
    };
    let channels = capture.config().channels;
    let sample_rate = capture.config().sample_rate;

    std::thread::spawn(move || {
        let _capture = capture; // keep the audio device alive
        for packet in packets {
            match audio_packet_message(channels, sample_rate, packet) {
                Ok(message) => {
                    if out_tx.blocking_send(message).is_err() {
                        break; // session closed
                    }
                }
                Err(e) => eprintln!("audio message serialization failed: {e}"),
            }
        }
    });
}
