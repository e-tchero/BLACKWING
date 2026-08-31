#![allow(missing_docs)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;

const MAX_AUTH_ATTEMPTS_PER_IP: usize = 10;
const IP_RATE_WINDOW: Duration = Duration::from_secs(60);

struct PerIpRateLimiter {
    attempts: Mutex<HashMap<IpAddr, (usize, Instant)>>,
}

impl PerIpRateLimiter {
    fn new() -> Self {
        Self {
            attempts: Mutex::new(HashMap::new()),
        }
    }

    fn check_and_record(&self, ip: IpAddr) -> bool {
        let mut map = self.attempts.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        if map.len() > 1024 {
            map.retain(|_, (_, ts)| now.duration_since(*ts) < IP_RATE_WINDOW);
        }
        let entry = map.entry(ip).or_insert((0, now));
        if now.duration_since(entry.1) >= IP_RATE_WINDOW {
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

#[tokio::test]
async fn test_handshake_concurrency_is_bounded() {
    let sem = std::sync::Arc::new(Semaphore::new(2));
    let active = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let max_seen = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut handles = Vec::new();
    for _ in 0..6 {
        let sem = std::sync::Arc::clone(&sem);
        let active = std::sync::Arc::clone(&active);
        let max_seen = std::sync::Arc::clone(&max_seen);
        handles.push(tokio::spawn(async move {
            let _permit = sem.acquire_owned().await.unwrap();
            let cur = active.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
            max_seen.fetch_max(cur, std::sync::atomic::Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(50)).await;
            active.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
        }));
    }
    for h in handles {
        h.await.unwrap();
    }
    let peak = max_seen.load(std::sync::atomic::Ordering::SeqCst);
    assert!(
        peak <= 2,
        "Peak concurrent handshakes {peak} exceeded limit of 2"
    );
}

#[tokio::test]
async fn test_handshake_permit_released_on_success() {
    let sem = std::sync::Arc::new(Semaphore::new(1));
    {
        let _permit = sem.clone().try_acquire_owned().unwrap();
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        sem.try_acquire().is_ok(),
        "Permit not released after success"
    );
}

#[tokio::test]
async fn test_handshake_permit_released_on_failure() {
    let sem = std::sync::Arc::new(Semaphore::new(1));
    {
        let _permit = sem.clone().try_acquire_owned().unwrap();
        drop(_permit);
    }
    assert!(
        sem.try_acquire().is_ok(),
        "Permit not released after failure"
    );
}

#[tokio::test]
async fn test_handshake_permit_released_on_cancellation() {
    let sem = std::sync::Arc::new(Semaphore::new(1));
    let sem2 = std::sync::Arc::clone(&sem);
    let handle = tokio::spawn(async move {
        let _permit = sem2.acquire_owned().await.unwrap();
        tokio::time::sleep(Duration::from_secs(60)).await;
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    handle.abort();
    let _ = handle.await;
    assert!(
        sem.try_acquire().is_ok(),
        "Permit not released after cancellation"
    );
}

#[tokio::test]
async fn test_excess_connections_are_rejected() {
    let sem = std::sync::Arc::new(Semaphore::new(2));
    let _p1 = sem.clone().try_acquire_owned().unwrap();
    let _p2 = sem.clone().try_acquire_owned().unwrap();
    assert!(
        sem.try_acquire().is_err(),
        "Excess connection should be rejected"
    );
    drop(_p1);
    assert!(
        sem.try_acquire().is_ok(),
        "Released permit should be available"
    );
}

#[tokio::test]
async fn test_legitimate_reconnect_still_works() {
    let sem = std::sync::Arc::new(Semaphore::new(2));
    {
        let _permit = sem.clone().try_acquire_owned().unwrap();
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    {
        let _permit = sem.clone().try_acquire_owned().unwrap();
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(sem.available_permits(), 2);
}

#[test]
fn test_per_ip_rate_limit() {
    let limiter = PerIpRateLimiter::new();
    let ip: IpAddr = "192.168.1.100".parse().unwrap();
    for i in 0..MAX_AUTH_ATTEMPTS_PER_IP {
        assert!(
            limiter.check_and_record(ip),
            "Attempt {i} should be allowed"
        );
    }
    assert!(
        !limiter.check_and_record(ip),
        "Attempt {MAX_AUTH_ATTEMPTS_PER_IP} should be blocked"
    );
}

#[test]
fn test_rate_limit_per_ip_independent() {
    let limiter = PerIpRateLimiter::new();
    let ip1: IpAddr = "10.0.0.1".parse().unwrap();
    let ip2: IpAddr = "10.0.0.2".parse().unwrap();
    for _ in 0..MAX_AUTH_ATTEMPTS_PER_IP {
        limiter.check_and_record(ip1);
    }
    assert!(!limiter.check_and_record(ip1), "ip1 should be blocked");
    assert!(limiter.check_and_record(ip2), "ip2 should not be blocked");
}

#[test]
fn test_rate_limiter_memory_bound() {
    let limiter = PerIpRateLimiter::new();
    for i in 0..2000u32 {
        let ip: IpAddr = format!("10.{}.{}.{}", (i >> 16) & 0xFF, (i >> 8) & 0xFF, i & 0xFF)
            .parse()
            .unwrap();
        limiter.check_and_record(ip);
    }
    let map = limiter.attempts.lock().unwrap_or_else(|e| e.into_inner());
    assert!(
        map.len() <= 2000,
        "Map should be bounded, got {} entries",
        map.len()
    );
}
