#![allow(missing_docs)]

use bw_core::logging::{HealthReport, LogEvent, Severity};

// ── Severity ─────────────────────────────────────────────────────────────────

#[test]
fn test_severity_ordering_is_monotonically_increasing() {
    assert!(Severity::Trace < Severity::Debug);
    assert!(Severity::Debug < Severity::Info);
    assert!(Severity::Info < Severity::Warn);
    assert!(Severity::Warn < Severity::Error);
    assert!(Severity::Error < Severity::Critical);
}

#[test]
fn test_severity_equality() {
    assert_eq!(Severity::Warn, Severity::Warn);
    assert_ne!(Severity::Info, Severity::Error);
}

#[test]
fn test_severity_clone_copy() {
    let s = Severity::Critical;
    let s2 = s;
    assert_eq!(s, s2);
}

// ── HealthReport ──────────────────────────────────────────────────────────────

#[test]
fn test_health_report_all_healthy() {
    let report = HealthReport {
        renderer_alive: true,
        ipc_alive: true,
        network_alive: true,
        policy_loaded: true,
        encoder_initialized: true,
    };
    assert!(report.is_healthy());
}

#[test]
fn test_health_report_unhealthy_when_ipc_down() {
    let report = HealthReport {
        renderer_alive: true,
        ipc_alive: false,
        network_alive: true,
        policy_loaded: true,
        encoder_initialized: true,
    };
    assert!(!report.is_healthy());
}

#[test]
fn test_health_report_unhealthy_when_encoder_not_initialized() {
    let report = HealthReport {
        renderer_alive: true,
        ipc_alive: true,
        network_alive: true,
        policy_loaded: true,
        encoder_initialized: false,
    };
    assert!(!report.is_healthy());
}

#[test]
fn test_health_report_all_down() {
    let report = HealthReport {
        renderer_alive: false,
        ipc_alive: false,
        network_alive: false,
        policy_loaded: false,
        encoder_initialized: false,
    };
    assert!(!report.is_healthy());
}

#[test]
fn test_health_report_is_copy() {
    let a = HealthReport {
        renderer_alive: true,
        ipc_alive: true,
        network_alive: true,
        policy_loaded: true,
        encoder_initialized: true,
    };
    let b = a; // Copy, not move
    assert_eq!(a, b);
}

// ── LogEvent ──────────────────────────────────────────────────────────────────

fn make_test_event() -> LogEvent {
    LogEvent {
        timestamp_us: 1_719_918_239_012,
        component: "bw-transport".to_string(),
        thread: "QUICNetwork".to_string(),
        severity: Severity::Warn,
        session_epoch: 1_289_381_019_842,
        tenant: "tenant_enterprise_us_east".to_string(),
        event_id: "EVENT_RELAY_SWITCH".to_string(),
        message: "Direct peer path failed connectivity check.".to_string(),
        stacktrace: None,
    }
}

#[test]
fn test_log_event_fields_are_accessible() {
    let event = make_test_event();
    assert_eq!(event.severity, Severity::Warn);
    assert_eq!(event.event_id, "EVENT_RELAY_SWITCH");
    assert_eq!(event.timestamp_us, 1_719_918_239_012);
    assert!(event.stacktrace.is_none());
}

#[test]
fn test_log_event_with_stacktrace() {
    let mut event = make_test_event();
    event.stacktrace = Some("at bw_net::connect line 42".to_string());
    assert!(event.stacktrace.is_some());
}

#[test]
fn test_log_event_clone() {
    let a = make_test_event();
    let b = a.clone();
    assert_eq!(a, b);
}
