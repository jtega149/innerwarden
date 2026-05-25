//! Pure-function incident builders called by `process_event` when an
//! event is promoted to an Incident.
//!
//! Extracted from `main.rs` on 2026-05-25 as PR4 of the sensor
//! decomposition (see SESSION_LOG.md). Pure code motion — zero
//! behaviour change. The 6 existing anchor tests for these builders
//! moved verbatim; 3 additional shape-pinning anchors were added on
//! top (passthrough_incident had zero tests pre-extraction).
//!
//! ## Why shape-pinning matters here
//!
//! Each builder's output goes to:
//!
//!   1. `incidents-*.jsonl` on disk (operator forensics)
//!   2. The unified SQLite database (dashboard queries, agent triage)
//!   3. Notification channels (Telegram, Slack, webhooks)
//!   4. The agent's correlation engine (which groups by `incident_id`)
//!
//! A silent change to `incident_id` format (e.g. switching the
//! minute-bucket to second-bucket) breaks dedup; a silent change to
//! the `evidence` shape breaks dashboard rendering. The anchor tests
//! pin every operator-visible field — title, summary, evidence keys,
//! recommended_checks, incident_id format — so a refactor that
//! drifts from the contract trips loudly at `cargo test` time.

use innerwarden_core::event::{Event, Severity};
use innerwarden_core::incident::Incident;
use tracing::warn;

use crate::config;
use crate::detectors;

/// Wrap an event from an "external IDS" passthrough source (where the
/// upstream tool has already done the detection) into an Incident
/// without re-evaluating severity. Returns None for events that should
/// not auto-promote — currently always emits Some, but the Option
/// signature is preserved so a future filtering policy can return None.
pub(crate) fn passthrough_incident(ev: &Event) -> Option<Incident> {
    let incident_id = format!(
        "{}:{}:{}",
        ev.source,
        ev.kind,
        ev.ts.format("%Y-%m-%dT%H:%MZ")
    );

    let recommended_checks = vec!["Review source alert details".to_string()];

    Some(Incident {
        ts: ev.ts,
        host: ev.host.clone(),
        incident_id,
        severity: ev.severity.clone(),
        title: ev.summary.clone(),
        summary: format!("[{}] {}", ev.source.to_uppercase(), ev.summary),
        evidence: serde_json::json!([ev.details]),
        recommended_checks,
        tags: ev.tags.clone(),
        entities: ev.entities.clone(),
    })
}

/// Merge the built-in devnode watchlist with operator overrides from
/// TOML. Overrides matched by `pattern` REPLACE the default entry of the
/// same pattern; otherwise they are appended. A malformed
/// `max_allowed_mode_octal` (typo, e.g. "999z") logs a `warn!` and
/// silently keeps the default for that pattern — we never widen the
/// allowed mode through misconfiguration. Returns the resulting
/// watchlist in deterministic insertion order.
pub(crate) fn build_devnode_watchlist(
    overrides: &[config::KernelDevnodeWatchEntryConfig],
) -> Vec<detectors::kernel_devnode_exposed::WatchEntry> {
    use detectors::kernel_devnode_exposed::{default_watchlist, WatchEntry};

    let mut result = default_watchlist();
    for ov in overrides {
        // Accept "0o660", "660", or just plain octal digits.
        let raw = ov.max_allowed_mode_octal.trim().trim_start_matches("0o");
        let parsed = u32::from_str_radix(raw, 8);
        let max_mode = match parsed {
            Ok(v) if v <= 0o7777 => v,
            _ => {
                warn!(
                    pattern = %ov.pattern,
                    raw = %ov.max_allowed_mode_octal,
                    "kernel_devnode_exposed: invalid max_allowed_mode_octal override, keeping default"
                );
                continue;
            }
        };
        let surface = if ov.surface.is_empty() {
            "operator-defined".to_string()
        } else {
            ov.surface.clone()
        };
        if let Some(existing) = result.iter_mut().find(|w| w.pattern == ov.pattern) {
            existing.max_allowed_mode = max_mode;
            existing.surface = surface;
        } else {
            result.push(WatchEntry {
                pattern: ov.pattern.clone(),
                max_allowed_mode: max_mode,
                surface,
            });
        }
    }
    result
}

/// Build the Medium-severity Incident emitted by the kernel_devnode_exposed
/// detector when a watched kernel device is found with wider-than-baseline
/// permissions. Uses an hour-bucket in the incident_id so the same exposure
/// does not re-fire every poll, but a mid-investigation chmod re-emits
/// within the same day cleanly.
pub(crate) fn devnode_exposed_incident(ev: &Event) -> Incident {
    let path = ev
        .details
        .get("path")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let actual = ev
        .details
        .get("actual_mode_octal")
        .and_then(|v| v.as_str())
        .unwrap_or("?");
    let max = ev
        .details
        .get("max_allowed_mode_octal")
        .and_then(|v| v.as_str())
        .unwrap_or("?");
    let surface = ev
        .details
        .get("surface")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown kernel surface");
    let path_slug = path
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect::<String>();
    Incident {
        ts: ev.ts,
        host: ev.host.clone(),
        incident_id: format!(
            "kernel_devnode_exposed:{}:{}",
            path_slug,
            // hour-bucket so the same exposure does not re-fire every
            // poll, but a permission flip (e.g. operator running chmod
            // mid-investigation) re-emits within the same day cleanly.
            ev.ts.format("%Y-%m-%dT%HZ")
        ),
        severity: Severity::Medium,
        title: format!("Kernel device exposed: {path} ({surface})"),
        summary: format!(
            "Sensitive kernel device {path} is mode {actual} (safe-default {max}). \
             This exposes {surface} to unprivileged users. If a process subsequently \
             opens this device and gains capabilities, the agent's CL-071 correlation \
             rule will escalate the combined chain to Critical."
        ),
        evidence: serde_json::json!([ev.details.clone()]),
        recommended_checks: vec![
            format!("chmod 0660 {path} (or 0600 for /dev/mem, /dev/kmem, /dev/port)"),
            "Add legitimate users to a dedicated group instead of widening mode".to_string(),
            "If the exposure is intentional, add this path to \
             [detectors.kernel_devnode_exposed.allowlist] in sensor config"
                .to_string(),
        ],
        tags: ev.tags.clone(),
        entities: ev.entities.clone(),
    }
}

/// Build the Critical-severity Incident emitted by the
/// suid_page_cache_integrity detector when a SUID-root binary's
/// content via the page cache diverges from its on-disk SHA-256.
/// This is consistent with page-cache poisoning used by local
/// privilege-escalation exploits.
pub(crate) fn page_cache_mismatch_incident(ev: &Event) -> Incident {
    let path = ev
        .details
        .get("path")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let path_slug = path
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect::<String>();

    Incident {
        ts: ev.ts,
        host: ev.host.clone(),
        incident_id: format!(
            "suid_page_cache_integrity:{}:{}",
            path_slug,
            ev.ts.format("%Y-%m-%dT%H:%MZ")
        ),
        severity: Severity::Critical,
        title: format!("SUID binary corrupted in page cache: {path}"),
        summary: format!(
            "SUID-root binary {path} has different SHA-256 content via page cache versus direct disk read. \
             This is consistent with page-cache poisoning used by local privilege-escalation exploits."
        ),
        evidence: serde_json::json!([ev.details.clone()]),
        recommended_checks: vec![
            "Treat the host as potentially compromised; preserve volatile state before rebooting".to_string(),
            "Compare the affected SUID binary with a trusted package copy".to_string(),
            "Check for recent local privilege-escalation activity and suspicious root shells".to_string(),
        ],
        tags: ev.tags.clone(),
        entities: ev.entities.clone(),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use innerwarden_core::entities::EntityRef;

    // ── Existing anchors moved from main.rs::tests ───────────────────────

    #[test]
    fn page_cache_mismatch_event_promotes_to_critical_incident() {
        let ts = chrono::DateTime::parse_from_rfc3339("2026-05-23T09:12:30Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let event = Event {
            ts,
            host: "sensor-host".to_string(),
            source: "suid_page_cache_integrity".to_string(),
            kind: "integrity.page_cache_mismatch".to_string(),
            severity: Severity::Critical,
            summary: "SUID binary corrupted in page cache: /usr/bin/su".to_string(),
            details: serde_json::json!({
                "path": "/usr/bin/su",
                "sha256_on_disk": "clean",
                "sha256_via_page_cache": "poisoned",
                "polled_at": ts.to_rfc3339(),
                "mitre_techniques": ["T1014", "T1068"],
            }),
            tags: vec!["integrity".to_string(), "T1068".to_string()],
            entities: vec![EntityRef::path("/usr/bin/su")],
        };

        let incident = page_cache_mismatch_incident(&event);

        assert!(incident
            .incident_id
            .starts_with("suid_page_cache_integrity:_usr_bin_su:"));
        assert_eq!(incident.severity, Severity::Critical);
        assert_eq!(
            incident.title,
            "SUID binary corrupted in page cache: /usr/bin/su"
        );
        assert_eq!(incident.evidence[0]["path"], "/usr/bin/su");
        assert!(incident.summary.contains("direct disk read"));
    }

    #[test]
    fn devnode_exposed_event_promotes_to_medium_incident() {
        // Mirror of the page_cache promotion test, with the kernel
        // devnode exposure event shape from detectors/kernel_devnode_exposed.rs.
        let ts = chrono::DateTime::parse_from_rfc3339("2026-05-24T10:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let event = Event {
            ts,
            host: "sensor-host".to_string(),
            source: "kernel_devnode_exposed".to_string(),
            kind: "integrity.devnode_exposed".to_string(),
            severity: Severity::Medium,
            summary: "Kernel device /dev/infiniband/uverbs0 mode 0o666 > safe 0o660".to_string(),
            details: serde_json::json!({
                "path": "/dev/infiniband/uverbs0",
                "actual_mode_octal": "0o666",
                "max_allowed_mode_octal": "0o660",
                "extra_permission_bits_octal": "0o6",
                "surface": "RDMA verbs ioctl ABI (mana_ib / mlx5 / etc.)",
                "polled_at": ts.to_rfc3339(),
                "mitre_techniques": ["T1068"],
            }),
            tags: vec![
                "integrity".to_string(),
                "hardening".to_string(),
                "T1068".to_string(),
            ],
            entities: vec![EntityRef::path("/dev/infiniband/uverbs0")],
        };

        let incident = devnode_exposed_incident(&event);
        assert!(incident
            .incident_id
            .starts_with("kernel_devnode_exposed:_dev_infiniband_uverbs0:"));
        assert_eq!(incident.severity, Severity::Medium);
        assert!(incident
            .title
            .starts_with("Kernel device exposed: /dev/infiniband/uverbs0"));
        // Summary must point operators at the CL-071 chain so they
        // understand the Medium signal can escalate to Critical.
        assert!(incident.summary.contains("CL-071"));
        // Recommended_checks must include both the chmod fix AND the
        // allowlist escape hatch — exactly one of each.
        assert!(incident
            .recommended_checks
            .iter()
            .any(|c| c.contains("chmod 0660")));
        assert!(incident
            .recommended_checks
            .iter()
            .any(|c| c.contains("allowlist")));
    }

    #[test]
    fn build_devnode_watchlist_keeps_defaults_when_no_overrides() {
        let wl = build_devnode_watchlist(&[]);
        // Same length as the detector's default
        assert_eq!(
            wl.len(),
            detectors::kernel_devnode_exposed::default_watchlist().len()
        );
        // Some sentinel entries that must remain present
        assert!(wl.iter().any(|w| w.pattern == "/dev/kvm"));
        assert!(wl.iter().any(|w| w.pattern == "/dev/infiniband/uverbs*"));
    }

    #[test]
    fn build_devnode_watchlist_override_replaces_default_for_same_pattern() {
        // Operator says: I actually allow /dev/kvm to be 0o666 because
        // I run untrusted VMs and access KVM as a non-root user.
        let ovs = vec![config::KernelDevnodeWatchEntryConfig {
            pattern: "/dev/kvm".to_string(),
            max_allowed_mode_octal: "0o666".to_string(),
            surface: "operator-permitted KVM".to_string(),
        }];
        let wl = build_devnode_watchlist(&ovs);
        let kvm = wl.iter().find(|w| w.pattern == "/dev/kvm").expect("kvm");
        assert_eq!(kvm.max_allowed_mode, 0o666);
        assert_eq!(kvm.surface, "operator-permitted KVM");
    }

    #[test]
    fn build_devnode_watchlist_appends_unknown_pattern() {
        // Operator adds a brand-new pattern not in defaults
        let ovs = vec![config::KernelDevnodeWatchEntryConfig {
            pattern: "/dev/custom-driver".to_string(),
            max_allowed_mode_octal: "660".to_string(),
            surface: "".to_string(),
        }];
        let wl = build_devnode_watchlist(&ovs);
        let custom = wl
            .iter()
            .find(|w| w.pattern == "/dev/custom-driver")
            .expect("custom appended");
        assert_eq!(custom.max_allowed_mode, 0o660);
        assert_eq!(custom.surface, "operator-defined");
    }

    #[test]
    fn build_devnode_watchlist_keeps_default_on_malformed_mode() {
        // Typo in operator config must NOT widen the allowed mode.
        let ovs = vec![config::KernelDevnodeWatchEntryConfig {
            pattern: "/dev/kvm".to_string(),
            max_allowed_mode_octal: "999z".to_string(),
            surface: "typo".to_string(),
        }];
        let wl = build_devnode_watchlist(&ovs);
        let kvm = wl.iter().find(|w| w.pattern == "/dev/kvm").expect("kvm");
        // Default for /dev/kvm is 0o660 — must stay that way even
        // though the operator supplied garbage.
        assert_eq!(kvm.max_allowed_mode, 0o660);
    }

    // ── 2026-05-25 anchors — passthrough_incident had ZERO tests before ──
    //
    // `passthrough_incident` is the path every "external IDS" source
    // takes (Wazuh / Suricata / Falco, when those were live). Output
    // shape feeds the dashboard, SQLite, and notification channels.
    // A silent field drop would silently lose data downstream.

    fn passthrough_event() -> Event {
        let ts = chrono::DateTime::parse_from_rfc3339("2026-05-25T11:30:45Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        Event {
            ts,
            host: "test-host".into(),
            source: "wazuh".into(),
            kind: "wazuh.ssh_bruteforce".into(),
            severity: Severity::High,
            summary: "SSH brute-force from 1.2.3.4".into(),
            details: serde_json::json!({
                "src_ip": "1.2.3.4",
                "rule_id": "5712",
                "agent": "host-7",
            }),
            tags: vec!["passthrough".into(), "wazuh".into()],
            entities: vec![EntityRef::ip("1.2.3.4")],
        }
    }

    #[test]
    fn passthrough_incident_preserves_all_event_fields() {
        // Pin that severity / tags / entities / host / ts all
        // round-trip into the Incident unchanged. A refactor that
        // accidentally drops `tags` or rebuilds `entities` from
        // scratch would silently lose downstream context — the
        // dashboard's entity drill-down depends on these fields
        // arriving in the incident JSON exactly as the collector
        // emitted them.
        let ev = passthrough_event();
        let inc = passthrough_incident(&ev).expect("passthrough must emit Some");

        assert_eq!(inc.ts, ev.ts);
        assert_eq!(inc.host, ev.host);
        assert_eq!(inc.severity, ev.severity);
        assert_eq!(inc.tags, ev.tags);
        assert_eq!(inc.entities, ev.entities);
        assert_eq!(inc.title, ev.summary);
    }

    #[test]
    fn passthrough_incident_id_uses_source_kind_minute_bucket() {
        // The incident_id format is `<source>:<kind>:<YYYY-MM-DDTHH:MMZ>`.
        // The agent's grouping engine dedupes by this ID, so changing
        // it (e.g. to second precision) would silently flood the
        // operator with one alert per second instead of one per
        // minute window. Pin the exact format.
        let ev = passthrough_event();
        let inc = passthrough_incident(&ev).unwrap();
        assert_eq!(
            inc.incident_id, "wazuh:wazuh.ssh_bruteforce:2026-05-25T11:30Z",
            "incident_id format must stay <source>:<kind>:<minute-bucket>"
        );
    }

    #[test]
    fn passthrough_incident_summary_uppercases_source_and_wraps_event_summary() {
        // The summary format is `[<UPPER-SOURCE>] <event.summary>`.
        // Dashboard renders this verbatim — a change would visibly
        // shift every passthrough row.
        let ev = passthrough_event();
        let inc = passthrough_incident(&ev).unwrap();
        assert_eq!(
            inc.summary, "[WAZUH] SSH brute-force from 1.2.3.4",
            "summary format must stay [UPPER-SOURCE] <event-summary>"
        );
    }

    #[test]
    fn devnode_exposed_incident_id_uses_hour_bucket_not_minute() {
        // The devnode-exposed builder INTENTIONALLY uses an hour-bucket
        // (vs passthrough_incident's minute-bucket) so the same kernel
        // exposure does not re-fire every 5-minute poll. Anchor the
        // contract so a future "let's tighten the dedup" refactor that
        // switches to minute-precision is caught — it would flood
        // operators with up to 12 alerts/hour for the same exposure.
        let ts = chrono::DateTime::parse_from_rfc3339("2026-05-25T11:30:45Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let ev = Event {
            ts,
            host: "h".into(),
            source: "kernel_devnode_exposed".into(),
            kind: "integrity.devnode_exposed".into(),
            severity: Severity::Medium,
            summary: "x".into(),
            details: serde_json::json!({"path": "/dev/kvm"}),
            tags: vec![],
            entities: vec![],
        };
        let inc = devnode_exposed_incident(&ev);
        assert!(
            inc.incident_id.ends_with(":2026-05-25T11Z"),
            "devnode incident_id MUST use hour-bucket (no minute component); got: {}",
            inc.incident_id
        );
    }
}
