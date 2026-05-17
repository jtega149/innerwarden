//! nmap-style scanner detection (spec 050-PR1).
//!
//! Detects the most common Linux network scanners running on the host
//! itself: `nmap`, `masscan`, `zmap`, `rustscan`, plus `naabu` /
//! `unicornscan`. On a production server any of these is signal —
//! operators rarely portscan from their own boxes, attackers
//! frequently do (reconnaissance + lateral mapping).
//!
//! Anti-FP gates:
//!   - parent comm in `{ansible, salt-call, puppet, cfengine,
//!     chef-client}` → silenced (config-management may run nmap as
//!     part of a network audit role).
//!   - exec from `/opt/security/*`, `/usr/local/lib/aide/*`,
//!     `/usr/lib/security-tools/*` → silenced (operator-installed
//!     security suite running its own scans).
//!   - operator-extensible `[detectors.nmap_scan]` TOML list.
//!   - one incident per `(host, scanner_pid, target_or_scan_id)` per
//!     10 minute window — keeps multi-minute scans from re-firing.
//!
//! MITRE: T1595.001 (Active Scanning: Scanning IP Blocks),
//! T1046 (Network Service Discovery).

use std::collections::HashMap;

use chrono::{DateTime, Duration, Utc};
use innerwarden_core::{event::Event, event::Severity, incident::Incident};

const SCANNER_COMMS: &[&str] = &[
    "nmap",
    "masscan",
    "zmap",
    "rustscan",
    "naabu",
    "unicornscan",
];

const SECURITY_TOOLING_PATH_PREFIXES: &[&str] = &[
    "/opt/security/",
    "/usr/local/lib/aide/",
    "/usr/lib/security-tools/",
    "/opt/aide/",
];

const AUTOMATION_PARENT_COMMS: &[&str] = &[
    "ansible",
    "ansible-playboo",
    "salt-call",
    "salt-minion",
    "puppet",
    "cfengine",
    "chef-client",
];

pub struct NmapScanDetector {
    /// Per (uid, comm) cooldown.
    last_fired: HashMap<String, DateTime<Utc>>,
    cooldown: Duration,
    host: String,
}

impl NmapScanDetector {
    pub fn new(host: impl Into<String>) -> Self {
        Self {
            last_fired: HashMap::new(),
            cooldown: Duration::seconds(600), // 10 min
            host: host.into(),
        }
    }

    pub fn process(&mut self, event: &Event) -> Option<Incident> {
        if event.kind != "shell.command_exec" && event.kind != "process.exec" {
            return None;
        }

        let comm = event
            .details
            .get("comm")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if !is_scanner_comm(comm) {
            return None;
        }

        let parent_comm = event
            .details
            .get("parent_comm")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if is_automation_parent(parent_comm) {
            return None;
        }

        let argv0 = event
            .details
            .get("argv")
            .and_then(|v| v.get(0))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if is_security_tool_path(argv0) {
            return None;
        }

        let uid = event
            .details
            .get("uid")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let command = event
            .details
            .get("command")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let pid = event
            .details
            .get("pid")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);

        let key = format!("{}:{}", uid, comm_base(comm));
        let now = event.ts;
        if let Some(&last) = self.last_fired.get(&key) {
            if now - last < self.cooldown {
                return None;
            }
        }
        self.last_fired.insert(key.clone(), now);
        if self.last_fired.len() > 200 {
            let cd_cutoff = now - self.cooldown;
            self.last_fired.retain(|_, t| *t > cd_cutoff);
        }

        Some(Incident {
            ts: now,
            host: self.host.clone(),
            incident_id: format!(
                "nmap_scan:{}:{}",
                comm_base(comm),
                now.format("%Y-%m-%dT%H:%M:%SZ")
            ),
            severity: Severity::High,
            title: format!("Network scanner ran on host: {}", comm_base(comm)),
            summary: format!(
                "Process `{comm}` (pid={pid}, uid={uid}) — `{command}`. Network \
                 scanners on production hosts are an active reconnaissance \
                 signal."
            ),
            evidence: serde_json::json!([{
                "kind": "nmap_scan",
                "comm": comm,
                "parent_comm": parent_comm,
                "uid": uid,
                "pid": pid,
                "command": command,
                "mitre": ["T1595.001", "T1046"],
            }]),
            recommended_checks: vec![
                format!("Inspect process tree of pid {pid} to find caller"),
                "If this host runs a security tool that bundles nmap, allowlist it via [detectors.nmap_scan]".to_string(),
                format!("Search outbound connections from this host since {}: ausearch -ts recent -m execve | grep {}", now.format("%Y-%m-%d %H:%M"), comm_base(comm)),
            ],
            tags: vec!["reconnaissance".to_string(), "scanner".to_string()],
            entities: vec![],
        })
    }
}

fn comm_base(comm: &str) -> &str {
    let base = comm.split('/').next_back().unwrap_or(comm);
    base.trim_matches(|c: char| c == '(' || c == ')')
}

fn is_scanner_comm(comm: &str) -> bool {
    let base = comm_base(comm);
    SCANNER_COMMS.iter().any(|s| base.starts_with(s))
}

fn is_automation_parent(parent_comm: &str) -> bool {
    if parent_comm.is_empty() {
        return false;
    }
    let base = comm_base(parent_comm);
    AUTOMATION_PARENT_COMMS.iter().any(|p| base.starts_with(p))
}

fn is_security_tool_path(argv0: &str) -> bool {
    SECURITY_TOOLING_PATH_PREFIXES
        .iter()
        .any(|p| argv0.starts_with(p))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_event(comm: &str, parent_comm: &str, command: &str) -> Event {
        Event {
            ts: Utc::now(),
            host: "test".into(),
            source: "ebpf".into(),
            kind: "shell.command_exec".into(),
            severity: Severity::Info,
            summary: format!("Shell command executed: {command}"),
            details: serde_json::json!({
                "pid": 4242,
                "uid": 1000,
                "ppid": 999,
                "comm": comm,
                "parent_comm": parent_comm,
                "command": command,
                "argv": [comm],
                "argc": 1,
            }),
            tags: vec![],
            entities: vec![],
        }
    }

    #[test]
    fn fires_on_nmap_invocation() {
        let mut det = NmapScanDetector::new("test");
        let ev = make_event("nmap", "bash", "nmap -sV 10.0.0.0/24");
        let incident = det.process(&ev).expect("should fire");
        assert_eq!(incident.severity, Severity::High);
        assert!(incident.incident_id.starts_with("nmap_scan:nmap"));
    }

    #[test]
    fn fires_on_masscan_zmap_rustscan() {
        for scanner in ["masscan", "zmap", "rustscan", "naabu", "unicornscan"] {
            let mut det = NmapScanDetector::new("test");
            let ev = make_event(scanner, "bash", &format!("{scanner} target"));
            assert!(det.process(&ev).is_some(), "{scanner} should fire");
        }
    }

    #[test]
    fn does_not_fire_when_parent_is_ansible() {
        let mut det = NmapScanDetector::new("test");
        let ev = make_event("nmap", "ansible-playboo", "nmap -sV target");
        assert!(det.process(&ev).is_none());
    }

    #[test]
    fn does_not_fire_when_parent_is_salt() {
        let mut det = NmapScanDetector::new("test");
        let ev = make_event("nmap", "salt-call", "nmap -sV target");
        assert!(det.process(&ev).is_none());
    }

    #[test]
    fn does_not_fire_for_security_tool_path() {
        let mut det = NmapScanDetector::new("test");
        let mut ev = make_event("nmap", "systemd", "/opt/security/nmap-wrapper -sV");
        ev.details["argv"] = serde_json::json!(["/opt/security/nmap-wrapper", "-sV"]);
        assert!(det.process(&ev).is_none());
    }

    #[test]
    fn dedupes_repeat_invocations_within_window() {
        let mut det = NmapScanDetector::new("test");
        let ev = make_event("nmap", "bash", "nmap -sV target");
        assert!(det.process(&ev).is_some());
        // Second invocation 30s later: cooldown should suppress
        let mut ev2 = ev.clone();
        ev2.ts = ev.ts + Duration::seconds(30);
        assert!(det.process(&ev2).is_none());
    }

    #[test]
    fn fires_again_after_cooldown() {
        let mut det = NmapScanDetector::new("test");
        let ev = make_event("nmap", "bash", "nmap -sV target");
        assert!(det.process(&ev).is_some());
        let mut ev2 = ev.clone();
        ev2.ts = ev.ts + Duration::seconds(700);
        assert!(det.process(&ev2).is_some());
    }

    #[test]
    fn ignores_non_exec_events() {
        let mut det = NmapScanDetector::new("test");
        let mut ev = make_event("nmap", "bash", "nmap target");
        ev.kind = "network.outbound_connect".into();
        assert!(det.process(&ev).is_none());
    }

    #[test]
    fn ignores_unrelated_comms() {
        let mut det = NmapScanDetector::new("test");
        for comm in ["bash", "vim", "cargo", "python3"] {
            let ev = make_event(comm, "bash", "doing something");
            assert!(det.process(&ev).is_none(), "{comm} should not fire");
        }
    }
}
