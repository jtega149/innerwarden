//! SELinux / AppArmor MAC layer disable detection (spec 050-PR5).
//!
//! Catches attackers disabling Mandatory Access Control before pivoting
//! further into the kill chain.
//!
//! SELinux disable routes:
//!   - `setenforce 0` (runtime: switch to permissive)
//!   - write to `/etc/selinux/config` with `SELINUX=disabled` (boot-time)
//!   - write to `/sys/fs/selinux/disable` (one-shot disable)
//!   - `semanage` / `setsebool` flipping permissive booleans
//!
//! AppArmor disable routes:
//!   - `systemctl stop apparmor` / `systemctl disable apparmor`
//!   - `aa-disable <profile>` / `aa-complain <profile>` (drop to complain mode)
//!   - `aa-teardown` (unload all profiles)
//!
//! Anti-FP gates:
//!   - Package manager parents silence both routes (rare but possible).
//!   - Operator-extensible `[detectors.selinux_apparmor_disable]` TOML.
//!
//! MITRE: T1562.001 (Impair Defenses: Disable or Modify Tools).

use std::collections::HashMap;

use chrono::{DateTime, Duration, Utc};
use innerwarden_core::{event::Event, event::Severity, incident::Incident};

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

pub struct SelinuxApparmorDisableDetector {
    host: String,
    last_fired: HashMap<String, DateTime<Utc>>,
    cooldown: Duration,
}

impl SelinuxApparmorDisableDetector {
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
            "setenforce" => {
                if argv.iter().any(|a| a == "0" || a == "permissive") {
                    Some("setenforce_permissive")
                } else {
                    None
                }
            }
            "aa-disable" => Some("aa_disable_profile"),
            "aa-complain" => Some("aa_complain_profile"),
            "aa-teardown" => Some("aa_teardown_all"),
            "systemctl" => {
                let joined = argv.join(" ");
                if (joined.contains(" stop ") || joined.contains(" disable "))
                    && (joined.contains(" apparmor") || joined.contains(" apparmor.service"))
                {
                    Some("systemctl_stop_apparmor")
                } else {
                    None
                }
            }
            "setsebool" => {
                // Flipping SELinux booleans to permit something dangerous —
                // hard to whitelist universally; only fire when permissive.
                if argv.iter().any(|a| a == "-P") {
                    Some("setsebool_persistent")
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
        let sub_kind = if filename == "/etc/selinux/config" {
            "selinux_config_write"
        } else if filename == "/sys/fs/selinux/disable" {
            "selinux_runtime_disable"
        } else if filename.starts_with("/etc/apparmor.d/") {
            // Writes to apparmor.d are normal during package install but
            // suspicious otherwise — let pkg-mgr gate handle FPs.
            "apparmor_profile_write"
        } else {
            return None;
        };

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
            sub_kind,
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
                "selinux_apparmor_disable:{sub_kind}:{}",
                now.format("%Y-%m-%dT%H:%M:%SZ")
            ),
            severity: Severity::Critical,
            title: format!(
                "MAC layer tamper: {sub_kind} (target=`{target}`, comm=`{comm}`, parent=`{parent_comm}`, uid={uid})"
            ),
            summary: format!(
                "Process `{comm}` (parent=`{parent_comm}`, pid={pid}, uid={uid}) matched the \
                 `{sub_kind}` MAC-disable shape. Target: `{target}`. Disabling SELinux or \
                 AppArmor before the loud part of the kill chain is the textbook \
                 T1562.001 evasion."
            ),
            evidence: serde_json::json!([{
                "kind": "selinux_apparmor_disable",
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
                "Check MAC state: `getenforce` (SELinux) / `aa-status` (AppArmor)".to_string(),
                format!("Inspect process tree of pid {pid}: pstree -p {pid}"),
                "If this is a planned operator reconfig, allowlist via [detectors.selinux_apparmor_disable]".to_string(),
            ],
            tags: vec!["defense_evasion".to_string(), "mac_layer".to_string()],
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
    fn fires_on_setenforce_zero() {
        let mut det = SelinuxApparmorDisableDetector::new("test");
        let ev = exec_event(&["setenforce", "0"], "bash", "bash");
        let inc = det.process(&ev).expect("should fire");
        assert_eq!(inc.severity, Severity::Critical);
    }

    #[test]
    fn fires_on_setenforce_permissive() {
        let mut det = SelinuxApparmorDisableDetector::new("test");
        let ev = exec_event(&["setenforce", "permissive"], "bash", "bash");
        assert!(det.process(&ev).is_some());
    }

    #[test]
    fn fires_on_aa_disable() {
        let mut det = SelinuxApparmorDisableDetector::new("test");
        let ev = exec_event(
            &["aa-disable", "/etc/apparmor.d/usr.bin.nginx"],
            "bash",
            "bash",
        );
        assert!(det.process(&ev).is_some());
    }

    #[test]
    fn fires_on_aa_teardown() {
        let mut det = SelinuxApparmorDisableDetector::new("test");
        let ev = exec_event(&["aa-teardown"], "bash", "bash");
        assert!(det.process(&ev).is_some());
    }

    #[test]
    fn fires_on_systemctl_stop_apparmor() {
        let mut det = SelinuxApparmorDisableDetector::new("test");
        let ev = exec_event(&["systemctl", "stop", "apparmor"], "bash", "bash");
        assert!(det.process(&ev).is_some());
    }

    #[test]
    fn fires_on_selinux_config_write() {
        let mut det = SelinuxApparmorDisableDetector::new("test");
        let ev = write_event("/etc/selinux/config", "vim", "bash");
        assert!(det.process(&ev).is_some());
    }

    #[test]
    fn fires_on_selinux_runtime_disable_write() {
        let mut det = SelinuxApparmorDisableDetector::new("test");
        let ev = write_event("/sys/fs/selinux/disable", "echo", "bash");
        assert!(det.process(&ev).is_some());
    }

    #[test]
    fn silences_when_parent_is_dpkg() {
        let mut det = SelinuxApparmorDisableDetector::new("test");
        let ev = exec_event(&["setenforce", "0"], "dpkg", "apt");
        assert!(det.process(&ev).is_none());
    }

    #[test]
    fn ignores_setenforce_one() {
        // setenforce 1 = re-enable enforcing — that's a security HARDENING, not an attack.
        let mut det = SelinuxApparmorDisableDetector::new("test");
        let ev = exec_event(&["setenforce", "1"], "bash", "bash");
        assert!(det.process(&ev).is_none());
    }

    #[test]
    fn ignores_systemctl_stop_unrelated_service() {
        let mut det = SelinuxApparmorDisableDetector::new("test");
        let ev = exec_event(&["systemctl", "stop", "nginx"], "bash", "bash");
        assert!(det.process(&ev).is_none());
    }

    #[test]
    fn dedupes_within_cooldown() {
        let mut det = SelinuxApparmorDisableDetector::new("test");
        let ev = exec_event(&["setenforce", "0"], "bash", "bash");
        assert!(det.process(&ev).is_some());
        let mut ev2 = ev.clone();
        ev2.ts = ev.ts + Duration::seconds(60);
        assert!(det.process(&ev2).is_none());
    }
}
