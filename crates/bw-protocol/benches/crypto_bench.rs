#![allow(missing_docs)] // Benchmark crate (repo convention)
#![allow(clippy::unwrap_used, clippy::expect_used)] // Bench code may panic on setup (repo convention)
use bw_crypto::SymmetricKey;
use bw_protocol::encryption::{EncryptionContext, KeyRotationPolicy, SessionKeys};
use bw_protocol::frame::OwnedProtocolFrame;
use bw_protocol::header::{PacketHeader, PROTOCOL_MAGIC};
use bw_protocol::routing::SessionId;
use bw_protocol::session::SessionManager;
use bw_protocol::version::CURRENT_VERSION;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use std::sync::Arc;
use std::thread;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn symmetric_context() -> EncryptionContext {
    let keys = SessionKeys {
        send_key: SymmetricKey([0xAB; 32]),
        recv_key: SymmetricKey([0xAB; 32]),
        epoch: 0,
    };
    EncryptionContext::new(keys, KeyRotationPolicy::Manual)
}

fn make_frame(size: usize) -> OwnedProtocolFrame {
    OwnedProtocolFrame {
        header: PacketHeader {
            magic: PROTOCOL_MAGIC,
            schema_version: u16::from(CURRENT_VERSION),
            flags: 0,
            packet_type: 1,
            payload_length: size as u16,
            sequence_number: 0,
            session_epoch: 0,
            monotonic_timestamp: 1000,
        },
        payload: vec![0xBE; size],
    }
}

// ---------------------------------------------------------------------------
// Benchmark: HKDF key derivation latency
// ---------------------------------------------------------------------------

fn bench_hkdf_derivation(c: &mut Criterion) {
    let master_secret = SymmetricKey([0xCC; 32]);
    let client_nonce = [0x01u8; 16];
    let server_nonce = [0x02u8; 16];

    c.bench_function("hkdf_derive_session_keys", |b| {
        b.iter(|| {
            let _ = bw_protocol::handshake::derive_session_keys(
                black_box(&master_secret),
                black_box(&client_nonce),
                black_box(&server_nonce),
            );
        });
    });
}

// ---------------------------------------------------------------------------
// Benchmark: AEAD encrypt latency across payload sizes
// ---------------------------------------------------------------------------

fn bench_aead_encrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("aead_encrypt");
    for size in [64usize, 1024, 4096] {
        let frame = make_frame(size);
        group.bench_with_input(BenchmarkId::from_parameter(size), &frame, |b, frame| {
            let mut ctx = symmetric_context();
            b.iter(|| {
                let _ = ctx.encrypt_frame(black_box(frame)).unwrap();
            });
        });
    }
    group.finish();
}

// ---------------------------------------------------------------------------
// Benchmark: AEAD decrypt latency across payload sizes
// ---------------------------------------------------------------------------

fn bench_aead_decrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("aead_decrypt");
    for size in [64usize, 1024, 4096] {
        let frame = make_frame(size);
        let mut enc_ctx = symmetric_context();
        let encrypted = enc_ctx.encrypt_frame(&frame).unwrap();
        group.bench_with_input(
            BenchmarkId::from_parameter(size),
            &encrypted,
            |b, encrypted| {
                // Each iteration needs a fresh decryptor at counter=0.
                // We create a fresh context and a matching encrypted frame per sample.
                b.iter_batched(
                    || {
                        let mut fresh_enc = symmetric_context();
                        let enc = fresh_enc.encrypt_frame(&frame).unwrap();
                        (symmetric_context(), enc)
                    },
                    |(mut dec_ctx, enc)| {
                        let _ = dec_ctx.decrypt_frame(black_box(&enc)).unwrap();
                    },
                    criterion::BatchSize::SmallInput,
                );
                let _ = encrypted; // suppress unused warning
            },
        );
    }
    group.finish();
}

// ---------------------------------------------------------------------------
// Benchmark: Replay-window update cost
// ---------------------------------------------------------------------------

fn bench_replay_window_update(c: &mut Criterion) {
    let frame = make_frame(64);
    c.bench_function("replay_window_update", |b| {
        b.iter_batched(
            || {
                let mut enc = symmetric_context();
                let encrypted = enc.encrypt_frame(&frame).unwrap();
                (symmetric_context(), encrypted)
            },
            |(mut dec_ctx, encrypted)| {
                let _ = dec_ctx.decrypt_frame(black_box(&encrypted)).unwrap();
            },
            criterion::BatchSize::SmallInput,
        );
    });
}

// ---------------------------------------------------------------------------
// Benchmark: SessionManager registration latency
// ---------------------------------------------------------------------------

fn bench_session_registration(c: &mut Criterion) {
    let master_secret = SymmetricKey([0xDD; 32]);
    let client_nonce = [0x03u8; 16];
    let server_nonce = [0x04u8; 16];

    c.bench_function("session_registration", |b| {
        let mut counter = 0u8;
        b.iter(|| {
            let manager = SessionManager::new();
            let id = SessionId([counter; 16]);
            counter = counter.wrapping_add(1);
            let _ = manager.create_session_from_handshake(
                black_box(id),
                black_box(&master_secret),
                black_box(&client_nonce),
                black_box(&server_nonce),
                KeyRotationPolicy::Manual,
            );
        });
    });
}

// ---------------------------------------------------------------------------
// Benchmark: with_session_context() overhead (epoch read — minimal work)
// ---------------------------------------------------------------------------

fn bench_with_session_context_overhead(c: &mut Criterion) {
    let manager = SessionManager::new();
    let id = SessionId([0xEE; 16]);
    manager
        .create_session_from_handshake(
            id,
            &SymmetricKey([0xFF; 32]),
            &[0x05u8; 16],
            &[0x06u8; 16],
            KeyRotationPolicy::Manual,
        )
        .unwrap();

    c.bench_function("with_session_context_overhead", |b| {
        b.iter(|| {
            let _ = manager.with_session_context(black_box(&id), |ctx| ctx.current_key_epoch());
        });
    });
}

// ---------------------------------------------------------------------------
// Benchmark: Lock contention — concurrent access to a single session
// ---------------------------------------------------------------------------

fn bench_lock_contention(c: &mut Criterion) {
    let manager = Arc::new(SessionManager::new());
    let id = SessionId([0x01; 16]);
    manager
        .create_session_from_handshake(
            id,
            &SymmetricKey([0xAA; 32]),
            &[0x07u8; 16],
            &[0x08u8; 16],
            KeyRotationPolicy::Manual,
        )
        .unwrap();

    c.bench_function("lock_contention_4_threads", |b| {
        b.iter(|| {
            let handles: Vec<_> = (0..4)
                .map(|_| {
                    let m = Arc::clone(&manager);
                    thread::spawn(move || {
                        let _ = m.with_session_context(&id, |ctx| ctx.current_key_epoch());
                    })
                })
                .collect();
            for h in handles {
                h.join().unwrap();
            }
        });
    });
}

// ---------------------------------------------------------------------------
// Benchmark: Handshake completion time (validation + key derivation)
// ---------------------------------------------------------------------------

fn bench_handshake_completion(c: &mut Criterion) {
    use bw_protocol::handshake::{Capabilities, HandshakeRequest};
    use bw_protocol::version::ProtocolVersion;

    let device_id = bw_crypto::DeviceId::from_digest([0x55; 32]);
    let request = HandshakeRequest {
        client_version: ProtocolVersion { major: 1, minor: 0 },
        supported_capabilities: Capabilities(Capabilities::ENCRYPTION),
        device_id,
        nonce: [0x09u8; 16],
        timestamp: 1234567890,
    };
    let server_nonce = [0x0Au8; 16];
    let master_secret = SymmetricKey([0xBB; 32]);

    c.bench_function("handshake_completion_time", |b| {
        b.iter(|| {
            let _ = request.validate();
            let _ = bw_protocol::handshake::derive_session_keys(
                black_box(&master_secret),
                black_box(&request.nonce),
                black_box(&server_nonce),
            );
        });
    });
}

// ---------------------------------------------------------------------------
// Criterion groups
// ---------------------------------------------------------------------------

criterion_group!(
    benches,
    bench_hkdf_derivation,
    bench_aead_encrypt,
    bench_aead_decrypt,
    bench_replay_window_update,
    bench_session_registration,
    bench_with_session_context_overhead,
    bench_lock_contention,
    bench_handshake_completion,
);
criterion_main!(benches);
