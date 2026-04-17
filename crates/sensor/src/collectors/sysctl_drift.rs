//! Sysctl drift monitoring collector.
//!
//! Baselines security-critical sysctl values at startup and polls
//! every 60s for changes. Detects attackers modifying kernel parameters
//! after hardening (e.g., enabling IP forwarding, disabling ASLR).

use std::collections::HashMap;

use chrono::Utc;
use innerwarden_core::entities::EntityRef;
use innerwarden_core::event::{Event, Severity};
use tokio::sync::mpsc;
use tracing::info;

/// Security-critical sysctls to monitor.
const CRITICAL_SYSCTLS: &[(&str, &str)] = &[
    // Network
    (
        "net.ipv4.ip_forward",
        "IP forwarding (enables routing/pivoting)",
    ),
    (
        "net.ipv4.conf.all.accept_redirects",
        "ICMP redirect acceptance",
    ),
    ("net.ipv4.conf.all.send_redirects", "ICMP redirect sending"),
    ("net.ipv4.conf.all.accept_source_route", "Source routing"),
    ("net.ipv4.tcp_syncookies", "SYN cookie protection"),
    ("net.ipv6.conf.all.accept_redirects", "IPv6 ICMP redirects"),
    // Kernel hardening
    (
        "kernel.randomize_va_space",
        "ASLR (address space randomization)",
    ),
    ("kernel.kptr_restrict", "Kernel pointer restriction"),
    ("kernel.dmesg_restrict", "dmesg restriction"),
    ("kernel.yama.ptrace_scope", "ptrace restriction (Yama LSM)"),
    ("kernel.modules_disabled", "Kernel module loading disabled"),
    (
        "kernel.unprivileged_bpf_disabled",
        "Unprivileged BPF disabled",
    ),
    (
        "kernel.kexec_load_disabled",
        "kexec disabled (prevents kernel replacement)",
    ),
    ("kernel.sysrq", "Magic SysRq key"),
    // Filesystem
    ("fs.protected_symlinks", "Symlink protection"),
    ("fs.protected_hardlinks", "Hardlink protection"),
    ("fs.suid_dumpable", "SUID core dump policy"),
    ("fs.protected_fifos", "FIFO protection"),
    ("fs.protected_regular", "Regular file protection"),
    // Core
    ("kernel.core_pattern", "Core dump handler (can be hijacked)"),
];

pub async fn run(tx: mpsc::Sender<Event>, host_id: String, interval_secs: u64) {
    info!(
        "sysctl_drift: starting (interval: {interval_secs}s, monitoring {} sysctls)",
        CRITICAL_SYSCTLS.len()
    );

    // Build baseline
    let mut baseline: HashMap<String, String> = HashMap::new();
    for (key, _desc) in CRITICAL_SYSCTLS {
        if let Some(val) = read_sysctl(key) {
            baseline.insert(key.to_string(), val);
        }
    }
    info!("sysctl_drift: baseline {} sysctls", baseline.len());

    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(interval_secs)).await;

        let now = Utc::now();

        for (key, desc) in CRITICAL_SYSCTLS {
            let Some(current) = read_sysctl(key) else {
                continue;
            };

            let changed = baseline
                .get(*key)
                .map(|prev| prev != &current)
                .unwrap_or(true);

            if !changed {
                continue;
            }

            let old = baseline.get(*key).cloned().unwrap_or("(not set)".into());
            baseline.insert(key.to_string(), current.clone());

            // Determine severity based on which sysctl changed
            let severity = classify_sysctl_severity(key, &current);

            let event = Event {
                ts: now,
                host: host_id.clone(),
                source: "sysctl_drift".into(),
                kind: "system.sysctl_changed".into(),
                severity,
                summary: format!(
                    "Sysctl changed: {} = {} (was: {}) — {}",
                    key, current, old, desc
                ),
                details: serde_json::json!({
                    "sysctl": key,
                    "old_value": old,
                    "new_value": current,
                    "description": desc,
                }),
                tags: vec!["sysctl".into(), "drift".into(), "hardening".into()],
                entities: vec![EntityRef::path(key.to_string())],
            };

            let _ = tx.send(event).await;
        }
    }
}

fn read_sysctl(key: &str) -> Option<String> {
    let path = format!("/proc/sys/{}", key.replace('.', "/"));
    std::fs::read_to_string(&path)
        .ok()
        .map(|s| s.trim().to_string())
}

fn classify_sysctl_severity(key: &str, current: &str) -> Severity {
    match key {
        "kernel.randomize_va_space" if current == "0" => Severity::Critical,
        "kernel.modules_disabled" if current == "0" => Severity::Critical,
        "net.ipv4.ip_forward" if current == "1" => Severity::Critical,
        "kernel.core_pattern" => Severity::High,
        "kernel.kexec_load_disabled" if current == "0" => Severity::High,
        "kernel.yama.ptrace_scope" if current == "0" => Severity::High,
        _ => Severity::Medium,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sysctl_path_conversion() {
        // Verifies dotted sysctl names map to /proc/sys paths used by the collector.
        let key = "net.ipv4.ip_forward";
        let path = format!("/proc/sys/{}", key.replace('.', "/"));
        assert_eq!(path, "/proc/sys/net/ipv4/ip_forward");
    }

    #[test]
    fn test_critical_sysctls_not_empty() {
        // Guards the watchlist from accidental shrinkage that would lower detection coverage.
        assert!(CRITICAL_SYSCTLS.len() >= 15);
    }

    #[test]
    fn classify_sysctl_severity_marks_high_impact_drifts_as_critical() {
        // Ensures dangerous hardening regressions keep critical severity classification.
        assert!(matches!(
            classify_sysctl_severity("kernel.randomize_va_space", "0"),
            Severity::Critical
        ));
        assert!(matches!(
            classify_sysctl_severity("net.ipv4.ip_forward", "1"),
            Severity::Critical
        ));
    }

    #[test]
    fn classify_sysctl_severity_marks_specific_regressions_as_high() {
        // Covers high-severity branch for sensitive but non-critical parameter changes.
        assert!(matches!(
            classify_sysctl_severity("kernel.core_pattern", "|/tmp/pwn"),
            Severity::High
        ));
        assert!(matches!(
            classify_sysctl_severity("kernel.yama.ptrace_scope", "0"),
            Severity::High
        ));
    }

    #[test]
    fn classify_sysctl_severity_defaults_to_medium_for_other_changes() {
        // Confirms generic sysctl drifts stay in medium severity to avoid alert inflation.
        assert!(matches!(
            classify_sysctl_severity("fs.protected_symlinks", "0"),
            Severity::Medium
        ));
    }
}
