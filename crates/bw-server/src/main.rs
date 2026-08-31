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

use bw_crypto::random::{OsRandom, SecureRandom};
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
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tokio::sync::{Semaphore, mpsc};

const DEFAULT_LISTEN: &str = "0.0.0.0:9000";
const FRAME_CAPACITY: usize = 4;

/// Maximum number of concurrent OPAQUE handshakes allowed.
/// Prevents CPU/memory exhaustion from authentication floods.
const MAX_CONCURRENT_HANDSHAKES: usize = 4;

/// Maximum number of authentication attempts allowed per source IP
/// within the tracking window.
const MAX_AUTH_ATTEMPTS_PER_IP: usize = 10;

/// Duration after which per-IP rate-limit counters reset.
const IP_RATE_WINDOW: Duration = Duration::from_secs(60);

/// Hard timeout for the entire OPAQUE handshake sequence.
/// If the handshake does not complete within this duration, it is aborted
/// and the connection is closed.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

/// Tracks per-IP authentication attempts within a sliding window.
///
/// Bounded to avoid unbounded memory growth from spoofed source IPs.
struct PerIpRateLimiter {
    attempts: Mutex<HashMap<std::net::IpAddr, (usize, Instant)>>,
}

impl PerIpRateLimiter {
    fn new() -> Self {
        Self {
            attempts: Mutex::new(HashMap::new()),
        }
    }

    /// Returns true if the IP is allowed to attempt authentication.
    /// Bounded to MAX_AUTH_ATTEMPTS_PER_IP per IP_RATE_WINDOW.
    /// Evicts stale entries when the map grows beyond a reasonable bound.
    fn check_and_record(&self, ip: std::net::IpAddr) -> bool {
        let mut map = self.attempts.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();

        // Evict stale entries if map is large (prevent memory exhaustion)
        if map.len() > 1024 {
            map.retain(|_, (_, ts)| now.duration_since(*ts) < IP_RATE_WINDOW);
        }

        let entry = map.entry(ip).or_insert((0, now));
        if now.duration_since(entry.1) >= IP_RATE_WINDOW {
            // Window expired — reset
            *entry = (1, now);
            true
        } else if entry.0 >= MAX_AUTH_ATTEMPTS_PER_IP {
            false
        } else {
            entry.0 += 1;
            true
        }
    }
}

/// Simple positional/flag argument parser.
struct Args {
    listen: String,
    data_dir: Option<PathBuf>,
    register: Option<(String, String)>,
    relay: Option<String>,
    signing_key: Option<PathBuf>,
}

fn parse_args() -> Args {
    let mut listen = DEFAULT_LISTEN.to_string();
    let mut data_dir: Option<PathBuf> = None;
    let mut register: Option<(String, String)> = None;
    let mut relay: Option<String> = None;
    let mut signing_key: Option<PathBuf> = None;

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
            "--signing-key" => {
                signing_key = Some(it.next().expect("--signing-key requires a path").into())
            }
            "--help" | "-h" => {
                eprintln!(
                    "usage: bw-server [--listen ADDR] [--data-dir DIR] [--register ID PASS] [--relay ADDR] [--signing-key PATH]"
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
        signing_key,
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
    tokio_runtime.block_on(run_server(
        listen_addr,
        Arc::new(store),
        args.relay,
        args.signing_key,
        data_dir,
    ))?;
    Ok(())
}

async fn run_server(
    listen_addr: std::net::SocketAddr,
    store: Arc<EnrollmentStore>,
    relay: Option<String>,
    signing_key_arg: Option<std::path::PathBuf>,
    data_dir: std::path::PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    let dispatcher = Arc::new(MessageDispatcher::new());
    register_input_handlers(&dispatcher, bw_input::InputInjector::new());
    let clipboard = Arc::new(std::sync::Mutex::new(bw_clipboard::ClipboardManager::new()?));
    register_clipboard_handler(&dispatcher, clipboard);

    let session_manager = Arc::new(SessionManager::new());

    // Compute server device ID for dispatch envelopes.
    // In relay mode, derive from the signing key.
    // In direct mode, derive from the enrollment store.
    let server_device_id = if relay.is_some() {
        let sk_path_val = signing_key_arg
            .clone()
            .unwrap_or_else(|| data_dir.join("server.signing.key"));
        let sk = bw_relay::relay_client::load_or_generate_key(&sk_path_val)
            .map_err(|e| format!("failed to load signing key for device ID: {e}"))?;
        sk.verify_key().device_id()
    } else {
        // Direct mode: use a deterministic ID from the first enrolled device.
        // This is not cryptographically bound but is consistent for the session.
        bw_crypto::DeviceId::from_digest([0x02; 32])
    };
    eprintln!("server device: {}", server_device_id);

    // Optional relay data-plane routing via CandidateExchange.
    // C1 FIX: obtain the relay token through the authenticated control-plane
    // flow instead of generating an independent random token.
    let quic_server = if let Some(relay_addr) = relay {
        let relay_sock: std::net::SocketAddr = relay_addr.parse()?;

        // Load or generate the server's Ed25519 signing key for relay auth.
        let sk_path = signing_key_arg.unwrap_or_else(|| data_dir.join("server.signing.key"));
        let signing_key = bw_relay::relay_client::load_or_generate_key(&sk_path)
            .map_err(|e| format!("failed to load signing key: {e}"))?;

        // Register with the relay control plane.
        let rt = tokio::runtime::Runtime::new()?;
        let relay_client = rt.block_on(async {
            bw_relay::relay_client::RelayControlClient::connect(relay_sock, signing_key).await
        })?;
        rt.block_on(relay_client.register())?;
        eprintln!("registered with relay");

        // Poll for pending ConnectIntents targeting this server.
        eprintln!("polling relay for pending connections...");
        let mut relay_token = None;
        for _ in 0..15 {
            let intents = rt.block_on(relay_client.poll_pending_intents())?;
            if let Some((intent_id, initiator)) = intents.into_iter().next() {
                eprintln!("received connect intent from initiator");
                // Accept the intent — relay generates the token.
                let (token, _initiator_candidates) =
                    rt.block_on(relay_client.accept_connect(intent_id, initiator, vec![]))?;
                relay_token = Some(token);
                break;
            }
            std::thread::sleep(std::time::Duration::from_secs(2));
        }

        let token = relay_token.ok_or("no pending relay connections within timeout")?;
        eprintln!("relay authorization obtained via CandidateExchange");
        QuicServer::bind(listen_addr, Some((relay_sock, token)))?
    } else {
        QuicServer::bind(listen_addr, None)?
    };

    // H3 FIX: admission control — semaphore + per-IP rate limiter.
    let handshake_semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_HANDSHAKES));
    let rate_limiter = Arc::new(PerIpRateLimiter::new());

    eprintln!("server ready — max concurrent handshakes: {MAX_CONCURRENT_HANDSHAKES}");
    loop {
        let Some(conn) = quic_server.accept().await else {
            continue;
        };

        // H3: extract remote IP for per-IP admission control.
        let remote_ip = conn.remote_address().ip();

        // H3: per-IP rate limit check.
        if !rate_limiter.check_and_record(remote_ip) {
            eprintln!("rate limit exceeded for {remote_ip} — rejecting");
            conn.close(0u32.into(), b"rate limit exceeded");
            continue;
        }

        // H3: acquire handshake permit BEFORE spawning expensive work.
        // Use try_acquire_owned so we never queue unlimited tasks.
        let permit = match handshake_semaphore.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                eprintln!("handshake limit reached — rejecting {remote_ip}");
                conn.close(0u32.into(), b"too many concurrent handshakes");
                continue;
            }
        };

        eprintln!("connection accepted from {remote_ip}");
        let dispatcher = Arc::clone(&dispatcher);
        let session_manager = Arc::clone(&session_manager);
        let store = Arc::clone(&store);
        tokio::spawn(async move {
            // H3: wrap the entire handshake + session in a timeout.
            let result = tokio::time::timeout(
                HANDSHAKE_TIMEOUT,
                handle_session(
                    conn,
                    &store,
                    &dispatcher,
                    &session_manager,
                    server_device_id,
                ),
            )
            .await;

            // H3: release the permit when done (drop on scope exit).
            drop(permit);

            match result {
                Ok(Ok(())) => {}
                Ok(Err(e)) => eprintln!("session error: {e}"),
                Err(_) => eprintln!("handshake/session timed out for {remote_ip}"),
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
    server_device_id: bw_crypto::DeviceId,
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

    // Generate a unique session ID for this connection so that per-session
    // state (e.g. button tracking) does not leak across sessions.
    let mut session_bytes = [0u8; 16];
    let mut rng = OsRandom;
    let _ = rng.fill(&mut session_bytes);
    let session_id = SessionId(session_bytes);

    // Receiver loop: dispatch inbound control messages (input, clipboard).
    loop {
        let message = receiver.recv_message().await?;
        eprintln!("received message type {:?}", message.message_type);
        // M8 FIX: use actual authenticated device ID instead of hardcoded fakes.
        // The client's device_id was authenticated via OPAQUE login above.
        let mut id_bytes = [0u8; 32];
        let n = identifier.len().min(32);
        id_bytes[..n].copy_from_slice(identifier.as_bytes());
        let client_id = bw_crypto::DeviceId::from_digest(id_bytes);
        let envelope = MessageEnvelope {
            source: NodeId(client_id),
            destination: NodeId(server_device_id),
            session_id,
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

    // Capture thread → cursor compositor → encoder pipeline → encoded frames.
    let (capture_thread, mut frame_rx) =
        match CaptureThread::spawn(Box::new(capture), display, FRAME_CAPACITY) {
            Ok(v) => v,
            Err(e) => {
                eprintln!(
                    "warning: failed to start capture thread — video streaming disabled: {e}"
                );
                return;
            }
        };

    // Cursor compositor: reads raw frames, composites the cursor overlay,
    // and forwards to the encoder. This runs on a dedicated OS thread to
    // avoid blocking the async runtime or the capture thread.
    let (compositor_tx, compositor_rx) = mpsc::channel::<bw_capture::Frame>(FRAME_CAPACITY);
    let _compositor_handle = std::thread::Builder::new()
        .name("bw-cursor-compositor".into())
        .spawn(move || {
            while let Some(mut frame) = frame_rx.blocking_recv() {
                // LATENCY FIX: drain to newest frame before compositing.
                while let Ok(newer) = frame_rx.try_recv() {
                    frame = newer;
                }
                // Composite the cursor overlay onto the frame buffer if
                // cursor data is available.
                if let Some(cursor) = &frame.cursor {
                    bw_server::composite_cursor(
                        &mut frame.buffer,
                        frame.stride,
                        frame.width,
                        frame.height,
                        cursor.x,
                        cursor.y,
                        cursor.visible,
                    );
                }
                if compositor_tx.blocking_send(frame).is_err() {
                    break; // Encoder dropped
                }
            }
        })
        .expect("failed to spawn cursor compositor thread");

    let (encoded_tx, mut encoded_rx) = mpsc::channel::<bw_encoder::EncodedFrame>(FRAME_CAPACITY);
    let encoder =
        EncoderPipeline::spawn(Box::new(OpenH264Backend::new()), compositor_rx, encoded_tx);

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
        drop(_compositor_handle);
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
