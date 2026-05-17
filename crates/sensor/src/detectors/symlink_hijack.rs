//! Symlink / hardlink hijack of sensitive files.
//!
//! Catches the classic privilege-escalation prelude: the attacker
//! creates a symlink or hardlink that names a sensitive file (e.g.
//! `/etc/shadow`, `/etc/sudoers`, `/etc/pam.d/*`) under a path the
//! attacker controls or that another process is about to read/write.
//! The actual exploit usually happens in the second step — a setuid
//! binary follows the symlink and now reads / writes a file the
//! attacker should not be able to touch.
//!
//! The cheapest unambiguous signal is the exec of `ln` or `ln -s`
//! with a sensitive path in argv. An attacker that wants to dodge
//! this can call the `symlink(2)` / `link(2)` syscall directly from
//! a custom binary — that path is left for a future eBPF wave; for
//! now this detector covers the canonical attack form that uses the
//! standard `coreutils` binary and is observable from any source
//! (eBPF execve, auditd shell.command_exec, etc.).
//!
//! Sensitive targets watched:
//!   - `/etc/shadow`, `/etc/sudoers`, `/etc/passwd`, `/etc/gshadow`
//!   - `/etc/sudoers.d/*`, `/etc/pam.d/*`, `/etc/pam.conf`
//!   - `/etc/ssh/sshd_config`, `/etc/security/`
//!   - `/etc/cron.d/*`, `/etc/crontab`
//!   - `/etc/audit/audit.rules`, `/etc/audit/auditd.conf`
//!   - `/root/.ssh/authorized_keys`, `/home/*/.ssh/authorized_keys`
//!
//! Anti-FP gates:
//!   - Package-manager parent / comm (apt / dpkg / unattended-upgr /
//!     dnf / yum / zypper / pacman / apk / snapd) → silenced. Package
//!     install legitimately relinks PAM modules etc.
//!   - Operator-extensible `[detectors.symlink_hijack]` TOML allowlist
//!     via `dynamic_allowlist::suppress_incident_for_detector`.
//!
//! MITRE: T1555 (Credentials from Password Stores — via symlink to
//! shadow), T1548.003 (Sudo / Sudo Caching — via symlink to sudoers),
//! T1574.005 (Hijack Execution Flow: Executable Installer File
//! Permissions Weakness — for the hardlink variant).

use std::collections::HashMap;

use chrono::{DateTime, Duration, Utc};
use innerwarden_core::{event::Event, event::Severity, incident::Incident};

/// Sensitive paths whose appearance in `ln` argv is the smoking gun.
/// Each entry is matched as a substring against every argv string so
/// `/etc/sudoers.d/anything` and `/home/ubuntu/.ssh/authorized_keys`
/// are both caught by the relevant prefix.
const SENSITIVE_PATH_FRAGMENTS: &[&str] = &[
    "/etc/shadow",
    "/etc/gshadow",
    "/etc/sudoers", // catches /etc/sudoers AND /etc/sudoers.d/...
    "/etc/passwd",
    "/etc/pam.d/", // catches everything under
    "/etc/pam.conf",
    "/etc/ssh/sshd_config",
    "/etc/security/",
    "/etc/crontab",
    "/etc/cron.d/",
    "/etc/audit/audit.rules",
    "/etc/audit/auditd.conf",
    "/.ssh/authorized_keys",
    "/.ssh/id_rsa",
    "/.ssh/id_ed25519",
    "/.ssh/id_ecdsa",
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
    "ldconfig",
];

pub struct SymlinkHijackDetector {
    host: String,
    last_fired: HashMap<String, DateTime<Utc>>,
    cooldown: Duration,
}

impl SymlinkHijackDetector {
    pub fn new(host: impl Into<String>) -> Self {
        Self {
            host: host.into(),
            last_fired: HashMap::new(),
            cooldown: Duration::seconds(600),
        }
    }

    pub fn process(&mut self, event: &Event) -> Option<Incident> {
        if event.kind != "shell.command_exec" && event.kind != "process.exec" {
            return None;
        }
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
        if argv0_base != "ln" {
            return None;
        }

        // Detect whether this is a symlink (-s) or hardlink (default).
        let is_symlink = argv.iter().any(|a| a == "-s" || a == "--symbolic");
        let link_kind = if is_symlink { "symlink" } else { "hardlink" };

        // Find the sensitive-path fragment, if any, anywhere in argv.
        let sensitive_match = argv
            .iter()
            .skip(1)
            .find(|a| {
                !a.starts_with('-') && SENSITIVE_PATH_FRAGMENTS.iter().any(|frag| a.contains(frag))
            })
            .cloned();
        let sensitive_target = sensitive_match?;

        // Anti-FP: pkg-manager comm / parent_comm.
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

        let now = event.ts;
        let key = format!("{uid}:{link_kind}:{sensitive_target}");
        if let Some(&last) = self.last_fired.get(&key) {
            if now - last < self.cooldown {
                return None;
            }
        }
        self.last_fired.insert(key, now);

        let mitre = if is_symlink {
            vec!["T1555"]
        } else {
            vec!["T1574.005"]
        };

        Some(Incident {
            ts: now,
            host: self.host.clone(),
            incident_id: format!(
                "symlink_hijack:{link_kind}:{}",
                now.format("%Y-%m-%dT%H:%M:%SZ")
            ),
            severity: Severity::Critical,
            title: format!(
                "{link_kind} naming sensitive path `{sensitive_target}` (comm=`{comm}`, parent=`{parent_comm}`, uid={uid})"
            ),
            summary: format!(
                "Process `{comm}` (parent=`{parent_comm}`, pid={pid}, uid={uid}) created a \
                 {link_kind} that names `{sensitive_target}`. Command: `{command}`. The classic \
                 privesc prelude — link a sensitive file into a path under the attacker's \
                 control so a later setuid binary follows it and reads/writes \
                 what the attacker cannot."
            ),
            evidence: serde_json::json!([{
                "kind": "symlink_hijack",
                "link_kind": link_kind,
                "sensitive_target": sensitive_target,
                "uid": uid,
                "comm": comm,
                "parent_comm": parent_comm,
                "pid": pid,
                "command": command,
                "argv": argv,
                "mitre": mitre,
            }]),
            recommended_checks: vec![
                format!("Locate the link: `find / -lname '*{sensitive_target}*' -o -inum $(stat -c %i {sensitive_target})`"),
                format!("Inspect process tree: pstree -p {pid}"),
                "Audit recent setuid binary execs for the suspect uid".to_string(),
                "If this is a planned operator install, allowlist via [detectors.symlink_hijack]".to_string(),
            ],
            tags: vec![link_kind.to_string(), "credential_access".to_string(), "privesc_prelude".to_string()],
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

    fn exec_event(argv: &[&str], comm: &str, parent_comm: &str, uid: u64) -> Event {
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
                "uid": uid,
                "comm": comm,
                "parent_comm": parent_comm,
            }),
            tags: vec![],
            entities: vec![],
        }
    }

    #[test]
    fn fires_on_symlink_to_etc_shadow() {
        let mut det = SymlinkHijackDetector::new("test");
        let ev = exec_event(
            &["ln", "-s", "/etc/shadow", "/tmp/innocent"],
            "bash",
            "bash",
            1000,
        );
        let inc = det.process(&ev).expect("should fire");
        assert_eq!(inc.severity, Severity::Critical);
        assert!(inc.incident_id.contains("symlink"));
    }

    #[test]
    fn fires_on_symlink_to_sudoers_d_entry() {
        let mut det = SymlinkHijackDetector::new("test");
        let ev = exec_event(
            &["ln", "-s", "/etc/sudoers.d/00_attacker", "/tmp/cfg"],
            "bash",
            "bash",
            1000,
        );
        assert!(det.process(&ev).is_some());
    }

    #[test]
    fn fires_on_symlink_to_pam_d_file() {
        let mut det = SymlinkHijackDetector::new("test");
        let ev = exec_event(
            &["ln", "-s", "/etc/pam.d/sshd", "/tmp/pam_cfg"],
            "bash",
            "bash",
            1000,
        );
        assert!(det.process(&ev).is_some());
    }

    #[test]
    fn fires_on_symlink_to_authorized_keys() {
        let mut det = SymlinkHijackDetector::new("test");
        let ev = exec_event(
            &["ln", "-s", "/home/ubuntu/.ssh/authorized_keys", "/tmp/keys"],
            "bash",
            "bash",
            1000,
        );
        assert!(det.process(&ev).is_some());
    }

    #[test]
    fn fires_on_hardlink_to_sudoers() {
        let mut det = SymlinkHijackDetector::new("test");
        // hardlink (no -s) — different MITRE id (T1574.005).
        let ev = exec_event(&["ln", "/etc/sudoers", "/tmp/cfg"], "bash", "bash", 1000);
        let inc = det.process(&ev).expect("should fire on hardlink");
        assert!(inc.incident_id.contains("hardlink"));
        // Hardlink variant carries the T1574.005 MITRE id.
        let mitre = inc.evidence[0]["mitre"].as_array().expect("mitre array");
        assert_eq!(mitre[0], "T1574.005");
    }

    #[test]
    fn ignores_ln_against_non_sensitive_targets() {
        let mut det = SymlinkHijackDetector::new("test");
        let ev = exec_event(
            &["ln", "-s", "/usr/local/bin/myapp", "/usr/bin/myapp"],
            "bash",
            "bash",
            1000,
        );
        assert!(det.process(&ev).is_none());
    }

    #[test]
    fn silences_when_parent_is_dpkg() {
        let mut det = SymlinkHijackDetector::new("test");
        // Package install legitimately relinks pam modules.
        let ev = exec_event(
            &["ln", "-sf", "/etc/pam.d/common-auth", "/etc/pam.d/sshd"],
            "ln",
            "dpkg",
            0,
        );
        assert!(det.process(&ev).is_none());
    }

    #[test]
    fn silences_when_comm_is_unattended_upgr() {
        let mut det = SymlinkHijackDetector::new("test");
        let ev = exec_event(
            &["ln", "-s", "/etc/shadow", "/tmp/decoy"],
            "ln",
            "unattended-upgr",
            0,
        );
        assert!(det.process(&ev).is_none());
    }

    #[test]
    fn ignores_non_ln_binaries() {
        let mut det = SymlinkHijackDetector::new("test");
        // `cp /etc/shadow ...` looks similar but is NOT this detector's
        // shape — credential_harvest handles cp/cat reads.
        for bin in ["cp", "cat", "less", "head", "tail"] {
            let ev = exec_event(&[bin, "/etc/shadow", "/tmp/out"], "bash", "bash", 1000);
            assert!(det.process(&ev).is_none(), "{bin} must not fire");
        }
    }

    #[test]
    fn dedupes_within_cooldown() {
        let mut det = SymlinkHijackDetector::new("test");
        let ev = exec_event(&["ln", "-s", "/etc/shadow", "/tmp/x"], "bash", "bash", 1000);
        assert!(det.process(&ev).is_some());
        let mut ev2 = ev.clone();
        ev2.ts = ev.ts + Duration::seconds(60);
        assert!(det.process(&ev2).is_none());
    }

    #[test]
    fn ignores_non_exec_event_kinds() {
        let mut det = SymlinkHijackDetector::new("test");
        let mut ev = exec_event(&["ln", "-s", "/etc/shadow", "/tmp/x"], "bash", "bash", 1000);
        ev.kind = "file.write_access".into();
        assert!(det.process(&ev).is_none());
    }
}
