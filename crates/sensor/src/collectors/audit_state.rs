//! Audit subsystem state monitor (spec 074).
//!
//! Polls the kernel audit `enabled` flag (`auditctl -s`) on an interval and
//! emits an `audit.disabled` event when audit is found OFF — either already
//! disabled when the sensor starts, or transitioning enabled -> disabled at
//! runtime. This is STATE-based and therefore method-independent: it catches
//! `auditctl -e 0`, a netlink `AUDIT_SET`, or any other way the flag is
//! cleared, unlike the command-pattern routes in the `auditd_disable` detector
//! (which only fire if they observe the disabling *command* execute). The
//! `auditd_disable` detector turns the emitted event into a Critical incident.
//!
//! Motivation: on 2026-06-09 a prod host had its kernel audit disabled
//! (`enabled 0`) for ~22h with no alert — execve auditing silently stopped and
//! the `auditd` telemetry stream went to zero, because the command-watching
//! detector never saw the disabling command. A state poll closes that gap.
//!
//! Fail-open: if `auditctl` is absent or the read fails, no event is emitted
//! (the host simply has no audit subsystem to monitor).
//!
//! MITRE: T1562.001 (Impair Defenses: Disable or Modify Tools).

use std::process::Command;

use chrono::{DateTime, Utc};
use innerwarden_core::event::{Event, Severity};
use tokio::sync::mpsc;
use tracing::{info, warn};

/// Event kind emitted on disable; consumed by the `auditd_disable` detector.
pub const EVENT_KIND_AUDIT_DISABLED: &str = "audit.disabled";

pub async fn run(tx: mpsc::Sender<Event>, host_id: String, interval_secs: u64) {
    info!("audit_state: starting (interval: {interval_secs}s, polling kernel audit enabled flag)");
    run_with(tx, host_id, interval_secs, read_audit_enabled).await;
}

/// Testable core of [`run`]: the same poll loop with the audit-state reader
/// injected, so tests can drive it without a real `auditctl`.
async fn run_with<F: Fn() -> Option<i64>>(
    tx: mpsc::Sender<Event>,
    host_id: String,
    interval_secs: u64,
    read: F,
) {
    let mut prev: Option<i64> = None;
    loop {
        let (event, next_prev) = poll_once(prev, &read, &host_id, Utc::now());
        prev = next_prev;
        if let Some(event) = event {
            warn!("audit_state: kernel audit is DISABLED");
            if tx.send(event).await.is_err() {
                break;
            }
        }
        if tx.is_closed() {
            break;
        }
        tokio::time::sleep(tokio::time::Duration::from_secs(interval_secs)).await;
    }
}

/// One poll cycle: read the flag, decide whether to emit, and carry `prev`
/// forward. A failed read (`None`) keeps the previous state unchanged so a
/// transient `auditctl` hiccup does not re-fire the alert on recovery.
fn poll_once<F: Fn() -> Option<i64>>(
    prev: Option<i64>,
    read: &F,
    host: &str,
    now: DateTime<Utc>,
) -> (Option<Event>, Option<i64>) {
    match read() {
        Some(cur) => (evaluate(prev, cur, host, now), Some(cur)),
        None => (None, prev),
    }
}

/// Read the kernel audit `enabled` flag via `auditctl -s`. Returns `None` when
/// auditctl is unavailable or the value cannot be parsed (fail-open).
fn read_audit_enabled() -> Option<i64> {
    let output = Command::new("auditctl").arg("-s").output().ok()?;
    if !output.status.success() {
        return None;
    }
    parse_enabled(&String::from_utf8_lossy(&output.stdout))
}

/// Parse the `enabled N` value out of `auditctl -s` output. The status dump is
/// whitespace-separated (single line on some kernels, one key per line on
/// others), e.g. `enabled 1 failure 1 pid 1868145 ...` or `enabled 1\nfailure
/// 1\n...`. Tokenising on whitespace handles both layouts.
fn parse_enabled(status: &str) -> Option<i64> {
    let mut tokens = status.split_whitespace();
    while let Some(tok) = tokens.next() {
        if tok == "enabled" {
            return tokens.next().and_then(|v| v.parse::<i64>().ok());
        }
    }
    None
}

/// Decide whether a poll result warrants an `audit.disabled` event.
///
/// Edge-triggered so a steady disabled state emits at most once per transition
/// (the sensor's incident cooldown dedups further):
/// - first poll (`prev == None`) AND disabled -> emit (already off at start)
/// - enabled (non-zero) -> disabled (`0`)      -> emit (runtime transition)
/// - disabled -> disabled                      -> no event (already reported)
/// - anything -> enabled                       -> no event (re-enable is fine)
fn evaluate(prev: Option<i64>, cur: i64, host: &str, now: DateTime<Utc>) -> Option<Event> {
    let disabled = cur == 0;
    let should_emit = match prev {
        None => disabled,
        Some(p) => disabled && p != 0,
    };
    if !should_emit {
        return None;
    }

    let reason = if prev.is_none() {
        "kernel audit was already disabled when the sensor started"
    } else {
        "kernel audit transitioned enabled -> disabled"
    };

    Some(Event {
        ts: now,
        host: host.to_string(),
        source: "audit_state".into(),
        kind: EVENT_KIND_AUDIT_DISABLED.into(),
        severity: Severity::High,
        summary: format!(
            "Kernel audit subsystem is disabled (enabled={cur}) — {reason}. Syscall auditing \
             (execve/connect/...) is not being recorded."
        ),
        details: serde_json::json!({
            "enabled": cur,
            "previous": prev,
            "reason": reason,
            "detection": "state_poll",
            "mitre": ["T1562.001"],
        }),
        tags: vec![
            "defense_evasion".into(),
            "auditd".into(),
            "state_poll".into(),
        ],
        entities: vec![],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_enabled_single_line() {
        // Some kernels print the whole status on one line.
        let s = "enabled 1 failure 1 pid 1868145 rate_limit 0 backlog 0";
        assert_eq!(parse_enabled(s), Some(1));
    }

    #[test]
    fn parse_enabled_multiline() {
        // Others print one key per line (observed on Ubuntu 24.04 aarch64).
        let s = "enabled 0\nfailure 1\npid 1868145\nbacklog 0\n";
        assert_eq!(parse_enabled(s), Some(0));
    }

    #[test]
    fn parse_enabled_immutable_state_two() {
        // `-e 2` = enabled + locked/immutable; still a non-zero enabled value.
        assert_eq!(parse_enabled("enabled 2\nfailure 1\n"), Some(2));
    }

    #[test]
    fn parse_enabled_missing_or_garbage_is_none() {
        assert_eq!(parse_enabled(""), None);
        assert_eq!(parse_enabled("failure 1\npid 5\n"), None);
        assert_eq!(parse_enabled("enabled notanumber"), None);
        assert_eq!(parse_enabled("enabled"), None);
    }

    #[test]
    fn evaluate_emits_when_disabled_at_startup() {
        // The 2026-06-09 gap: sensor starts and finds audit already off.
        let ev = evaluate(None, 0, "h", Utc::now()).expect("must emit on startup-disabled");
        assert_eq!(ev.kind, EVENT_KIND_AUDIT_DISABLED);
        assert_eq!(ev.severity, Severity::High);
        assert_eq!(ev.details["enabled"], 0);
        assert!(ev.details["previous"].is_null());
        assert!(ev.summary.contains("already disabled"));
    }

    #[test]
    fn evaluate_no_event_when_enabled_at_startup() {
        assert!(evaluate(None, 1, "h", Utc::now()).is_none());
        assert!(evaluate(None, 2, "h", Utc::now()).is_none());
    }

    #[test]
    fn evaluate_emits_on_runtime_transition_enabled_to_disabled() {
        let ev = evaluate(Some(1), 0, "h", Utc::now()).expect("must emit on 1->0");
        assert_eq!(ev.details["previous"], 1);
        assert!(ev.summary.contains("transitioned"));
        // tag is present so downstream routing/labelling is stable.
        assert!(ev.tags.iter().any(|t| t == "defense_evasion"));
    }

    #[test]
    fn evaluate_no_duplicate_while_steady_disabled() {
        // disabled -> disabled must not re-emit (edge-triggered).
        assert!(evaluate(Some(0), 0, "h", Utc::now()).is_none());
    }

    #[test]
    fn evaluate_no_event_on_reenable() {
        // disabled -> enabled is not an alert.
        assert!(evaluate(Some(0), 1, "h", Utc::now()).is_none());
    }

    #[test]
    fn poll_once_emits_and_advances_prev_when_read_succeeds() {
        let read = || Some(0i64);
        let (event, next) = poll_once(None, &read, "h", Utc::now());
        assert!(event.is_some());
        assert_eq!(next, Some(0));
    }

    #[test]
    fn poll_once_keeps_prev_and_emits_nothing_when_read_fails() {
        // auditctl absent / transient failure: hold the last known state.
        let read = || None;
        let (event, next) = poll_once(Some(1), &read, "h", Utc::now());
        assert!(event.is_none());
        assert_eq!(next, Some(1));
    }

    #[test]
    fn poll_once_no_emit_when_enabled() {
        let read = || Some(1i64);
        let (event, next) = poll_once(Some(1), &read, "h", Utc::now());
        assert!(event.is_none());
        assert_eq!(next, Some(1));
    }

    #[tokio::test]
    async fn run_with_emits_disabled_then_stops_on_closed_receiver() {
        let (tx, mut rx) = mpsc::channel(4);
        // Reader reports disabled; first poll (prev=None) emits, steady disabled
        // dedups, and the loop exits once the receiver is dropped.
        let handle = tokio::spawn(run_with(tx, "h".to_string(), 0, || Some(0i64)));
        let ev = rx.recv().await.expect("must emit audit.disabled");
        assert_eq!(ev.kind, EVENT_KIND_AUDIT_DISABLED);
        assert_eq!(ev.severity, Severity::High);
        drop(rx);
        handle.await.expect("run_with task should exit cleanly");
    }
}
