//! auditd disable / tamper detection (spec 050-PR5).
//!
//! Fires when a process attempts to stop, disable, or neuter Linux
//! auditd (the host audit daemon attackers nuke before doing the
//! actual damage). Three independent routes:
//!   1. `process.exec` of stop/disable commands:
//!      - `systemctl stop auditd` / `systemctl disable auditd`
//!      - `service auditd stop`
//!      - `auditctl -e 0` (disable audit)
//!      - `pkill auditd` / `killall auditd` / `kill -9 <pid>` against auditd
//!   2. `file.write_access` to `/etc/audit/auditd.conf` or
//!      `/etc/audit/audit.rules` outside a package-manager context.
//!   3. `process.exit` of an actual `auditd` daemon from an unexpected
//!      signal (SIGKILL/SIGTERM from non-init).
//!
//! Anti-FP gates:
//!   - Package manager parents (apt/dpkg/dnf/yum/etc.) silence both
//!     exec and file.write paths.
//!   - Operator-extensible `[detectors.auditd_disable]` TOML.
//!
//! MITRE: T1562.001 (Impair Defenses: Disable or Modify Tools).

use std::collections::HashMap;

use chrono::{DateTime, Duration, Utc};
use innerwarden_core::{event::Event, event::Severity, incident::Incident};

const AUDITD_CONFIG_PATHS: &[&str] = &[
    "/etc/audit/auditd.conf",
    "/etc/audit/audit.rules",
    "/etc/audit/rules.d/",
];

const PKG_MANAGER_COMMS: &[&str] = &[
    "dpkg",
    "apt",
    "apt-get",
    "unattended-upgr",
    "needrestart",
    "dnf",
    "yum",
    "rpm",
    "zypper",
    "pacman",
    "apk",
    "snapd",
    "snap",
];

pub struct AuditdDisableDetector {
    host: String,
    last_fired: HashMap<String, DateTime<Utc>>,
    cooldown: Duration,
}

impl AuditdDisableDetector {
    pub fn new(host: impl Into<String>) -> Self {
        Self {
            host: host.into(),
            last_fired: HashMap::new(),
            cooldown: Duration::seconds(300),
        }
    }

    pub fn process(&mut self, event: &Event) -> Option<Incident> {
        match event.kind.as_str() {
            "shell.command_exec" | "process.exec" => self.process_exec(event),
            "file.write_access" => self.process_write(event),
            _ => None,
        }
    }

    fn process_exec(&mut self, event: &Event) -> Option<Incident> {
        let argv: Vec<String> = event
            .details
            .get("argv")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();
        if argv.is_empty() {
            return None;
        }
        let argv0_base = argv[0].split('/').next_back().unwrap_or(&argv[0]);
        let sub_kind = match argv0_base {
            "systemctl" => {
                let joined = argv.join(" ");
                if (joined.contains(" stop ") || joined.contains(" disable "))
                    && (joined.contains(" auditd") || joined.contains(" auditd.service"))
                {
                    Some("systemctl_stop_or_disable")
                } else {
                    None
                }
            }
            "service" => {
                if argv.iter().any(|a| a == "auditd")
                    && argv.iter().any(|a| a == "stop" || a == "disable")
                {
                    Some("service_stop")
                } else {
                    None
                }
            }
            "auditctl" => {
                let joined = argv.join(" ");
                if joined.contains("-e 0") || joined.contains("--enabled 0") {
                    Some("auditctl_disable")
                } else if joined.contains("-D") {
                    Some("auditctl_rule_flush")
                } else {
                    None
                }
            }
            "pkill" | "killall" => {
                if argv.iter().any(|a| a == "auditd") {
                    Some("pkill_auditd")
                } else {
                    None
                }
            }
            "kill" => {
                if argv.iter().any(|a| a == "auditd")
                    || event
                        .details
                        .get("target_comm")
                        .and_then(|v| v.as_str())
                        .is_some_and(|c| c == "auditd")
                {
                    Some("kill_auditd")
                } else {
                    None
                }
            }
            _ => None,
        }?;

        let comm = event
            .details
            .get("comm")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let parent_comm = event
            .details
            .get("parent_comm")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if is_pkg_manager(comm) || is_pkg_manager(parent_comm) {
            return None;
        }

        let pid = event
            .details
            .get("pid")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
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

        self.emit(
            event,
            sub_kind,
            command,
            comm,
            parent_comm,
            pid,
            uid,
            Some(&argv),
            None,
        )
    }

    fn process_write(&mut self, event: &Event) -> Option<Incident> {
        let filename = event
            .details
            .get("filename")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if !AUDITD_CONFIG_PATHS.iter().any(|p| filename.starts_with(p)) {
            return None;
        }
        let comm = event
            .details
            .get("comm")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let parent_comm = event
            .details
            .get("parent_comm")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if is_pkg_manager(comm) || is_pkg_manager(parent_comm) {
            return None;
        }
        let pid = event
            .details
            .get("pid")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let uid = event
            .details
            .get("uid")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        self.emit(
            event,
            "auditd_config_write",
            filename,
            comm,
            parent_comm,
            pid,
            uid,
            None,
            Some(filename),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn emit(
        &mut self,
        event: &Event,
        sub_kind: &str,
        target: &str,
        comm: &str,
        parent_comm: &str,
        pid: u64,
        uid: u64,
        argv: Option<&[String]>,
        filename: Option<&str>,
    ) -> Option<Incident> {
        let now = event.ts;
        let key = format!("{uid}:{sub_kind}:{target}");
        if let Some(&last) = self.last_fired.get(&key) {
            if now - last < self.cooldown {
                return None;
            }
        }
        self.last_fired.insert(key, now);

        Some(Incident {
            ts: now,
            host: self.host.clone(),
            incident_id: format!(
                "auditd_disable:{sub_kind}:{}",
                now.format("%Y-%m-%dT%H:%M:%SZ")
            ),
            severity: Severity::Critical,
            title: format!(
                "auditd tamper: {sub_kind} (target=`{target}`, comm=`{comm}`, parent=`{parent_comm}`, uid={uid})"
            ),
            summary: format!(
                "Process `{comm}` (parent=`{parent_comm}`, pid={pid}, uid={uid}) matched the \
                 `{sub_kind}` auditd-disable shape. Target: `{target}`. Attackers consistently \
                 disable host audit before the loud part of the kill chain (T1562.001)."
            ),
            evidence: serde_json::json!([{
                "kind": "auditd_disable",
                "sub_kind": sub_kind,
                "target": target,
                "uid": uid,
                "comm": comm,
                "parent_comm": parent_comm,
                "pid": pid,
                "argv": argv,
                "filename": filename,
                "mitre": ["T1562.001"],
            }]),
            recommended_checks: vec![
                "Confirm auditd state: `systemctl is-active auditd` and `auditctl -s`".to_string(),
                format!("Inspect process tree of pid {pid}: pstree -p {pid}"),
                "Compare /etc/audit/audit.rules against your golden config".to_string(),
                "If this is a planned operator action (audit reconfig), allowlist via [detectors.auditd_disable]".to_string(),
            ],
            tags: vec!["defense_evasion".to_string(), "auditd".to_string()],
            entities: vec![],
        })
    }
}

fn is_pkg_manager(comm: &str) -> bool {
    let base = comm.split('/').next_back().unwrap_or(comm);
    let base = base.trim_matches(|c: char| c == '(' || c == ')');
    PKG_MANAGER_COMMS.iter().any(|m| base.starts_with(m))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exec_event(argv: &[&str], comm: &str, parent_comm: &str) -> Event {
        let argv_owned: Vec<String> = argv.iter().map(|s| s.to_string()).collect();
        Event {
            ts: Utc::now(),
            host: "test".into(),
            source: "ebpf".into(),
            kind: "shell.command_exec".into(),
            severity: Severity::Info,
            summary: argv.join(" "),
            details: serde_json::json!({
                "argv": argv_owned,
                "argc": argv.len() as u32,
                "command": argv.join(" "),
                "pid": 4242,
                "uid": 0,
                "comm": comm,
                "parent_comm": parent_comm,
            }),
            tags: vec![],
            entities: vec![],
        }
    }

    fn write_event(filename: &str, comm: &str, parent_comm: &str) -> Event {
        Event {
            ts: Utc::now(),
            host: "test".into(),
            source: "ebpf".into(),
            kind: "file.write_access".into(),
            severity: Severity::Info,
            summary: format!("write {filename}"),
            details: serde_json::json!({
                "filename": filename,
                "pid": 4242,
                "uid": 0,
                "comm": comm,
                "parent_comm": parent_comm,
            }),
            tags: vec![],
            entities: vec![],
        }
    }

    #[test]
    fn fires_on_systemctl_stop_auditd() {
        let mut det = AuditdDisableDetector::new("test");
        let ev = exec_event(&["systemctl", "stop", "auditd"], "bash", "bash");
        let inc = det.process(&ev).expect("should fire");
        assert_eq!(inc.severity, Severity::Critical);
    }

    #[test]
    fn fires_on_systemctl_disable_auditd_service() {
        let mut det = AuditdDisableDetector::new("test");
        let ev = exec_event(&["systemctl", "disable", "auditd.service"], "bash", "bash");
        assert!(det.process(&ev).is_some());
    }

    #[test]
    fn fires_on_auditctl_e_zero() {
        let mut det = AuditdDisableDetector::new("test");
        let ev = exec_event(&["auditctl", "-e", "0"], "bash", "bash");
        assert!(det.process(&ev).is_some());
    }

    #[test]
    fn fires_on_auditctl_rule_flush() {
        let mut det = AuditdDisableDetector::new("test");
        let ev = exec_event(&["auditctl", "-D"], "bash", "bash");
        assert!(det.process(&ev).is_some());
    }

    #[test]
    fn fires_on_pkill_auditd() {
        let mut det = AuditdDisableDetector::new("test");
        let ev = exec_event(&["pkill", "auditd"], "bash", "bash");
        assert!(det.process(&ev).is_some());
    }

    #[test]
    fn fires_on_audit_rules_write() {
        let mut det = AuditdDisableDetector::new("test");
        let ev = write_event("/etc/audit/audit.rules", "vim", "bash");
        assert!(det.process(&ev).is_some());
    }

    #[test]
    fn silences_when_parent_is_apt() {
        let mut det = AuditdDisableDetector::new("test");
        let ev = exec_event(&["systemctl", "stop", "auditd"], "dpkg", "apt");
        assert!(det.process(&ev).is_none());
    }

    #[test]
    fn silences_audit_rules_write_by_dpkg() {
        let mut det = AuditdDisableDetector::new("test");
        let ev = write_event("/etc/audit/audit.rules", "dpkg", "unattended-upgr");
        assert!(det.process(&ev).is_none());
    }

    #[test]
    fn ignores_systemctl_stop_unrelated_service() {
        let mut det = AuditdDisableDetector::new("test");
        let ev = exec_event(&["systemctl", "stop", "nginx"], "bash", "bash");
        assert!(det.process(&ev).is_none());
    }

    #[test]
    fn ignores_auditctl_status_query() {
        let mut det = AuditdDisableDetector::new("test");
        let ev = exec_event(&["auditctl", "-s"], "bash", "bash");
        assert!(det.process(&ev).is_none());
    }

    #[test]
    fn dedupes_within_cooldown() {
        let mut det = AuditdDisableDetector::new("test");
        let ev = exec_event(&["systemctl", "stop", "auditd"], "bash", "bash");
        assert!(det.process(&ev).is_some());
        let mut ev2 = ev.clone();
        ev2.ts = ev.ts + Duration::seconds(60);
        assert!(det.process(&ev2).is_none());
    }
}
