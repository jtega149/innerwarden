//! RC script / init script persistence detection (spec 050-PR5).
//!
//! Fires when a non-package-manager process writes to legacy SysV-style
//! init / RC script locations that are still honored at boot on many
//! distros and containers:
//!   - `/etc/rc.local`
//!   - `/etc/init.d/*`
//!   - `/etc/rc.d/*` (RHEL/SUSE)
//!   - `/etc/rc<N>.d/*` (SysV runlevel dirs)
//!   - `/etc/network/if-up.d/*` / `/etc/network/if-pre-up.d/*`
//!     (Debian network up hooks — fire on boot when interfaces come up)
//!   - `/etc/cron.d/*` (catch-all dir; the more specific
//!     `crontab_persistence` handles user crontabs)
//!
//! Cron user files are covered by `crontab_persistence`; systemd unit
//! drops are covered by `systemd_persistence`; PAM by
//! `pam_module_change`. This detector is the RC-init slot only.
//!
//! Anti-FP gates:
//!   - Package manager parents/writers silenced.
//!   - Operator-extensible `[detectors.startup_script_persistence]` TOML.
//!
//! MITRE: T1037.004 (Boot or Logon Initialization Scripts: RC Scripts).

use std::collections::HashMap;

use chrono::{DateTime, Duration, Utc};
use innerwarden_core::{event::Event, event::Severity, incident::Incident};

const RC_PATH_PREFIXES: &[&str] = &[
    "/etc/rc.local",
    "/etc/init.d/",
    "/etc/rc.d/",
    "/etc/rc0.d/",
    "/etc/rc1.d/",
    "/etc/rc2.d/",
    "/etc/rc3.d/",
    "/etc/rc4.d/",
    "/etc/rc5.d/",
    "/etc/rc6.d/",
    "/etc/rcS.d/",
    "/etc/network/if-up.d/",
    "/etc/network/if-pre-up.d/",
    "/etc/networkd-dispatcher/",
    "/etc/cron.d/",
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
    "update-rc.d",
    "systemctl",
];

pub struct StartupScriptPersistenceDetector {
    host: String,
    last_fired: HashMap<String, DateTime<Utc>>,
    cooldown: Duration,
}

impl StartupScriptPersistenceDetector {
    pub fn new(host: impl Into<String>) -> Self {
        Self {
            host: host.into(),
            last_fired: HashMap::new(),
            cooldown: Duration::seconds(600),
        }
    }

    pub fn process(&mut self, event: &Event) -> Option<Incident> {
        if event.kind != "file.write_access" {
            return None;
        }
        let filename = event
            .details
            .get("filename")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if !RC_PATH_PREFIXES.iter().any(|p| filename.starts_with(p)) {
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

        let now = event.ts;
        let key = format!("{uid}:{filename}");
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
                "startup_script_persistence:{}",
                now.format("%Y-%m-%dT%H:%M:%SZ")
            ),
            severity: Severity::High,
            title: format!(
                "RC/init script persistence: write to `{filename}` (comm=`{comm}`, parent=`{parent_comm}`, uid={uid})"
            ),
            summary: format!(
                "Process `{comm}` (parent=`{parent_comm}`, pid={pid}, uid={uid}) wrote to \
                 `{filename}` outside a package-manager context. RC / init / network-hook \
                 scripts run at boot or interface-up — the canonical poor-man's persistence \
                 vector (T1037.004) that survives reboots without systemd unit visibility."
            ),
            evidence: serde_json::json!([{
                "kind": "startup_script_persistence",
                "filename": filename,
                "uid": uid,
                "comm": comm,
                "parent_comm": parent_comm,
                "pid": pid,
                "mitre": ["T1037.004"],
            }]),
            recommended_checks: vec![
                format!("Diff `{filename}` against package-shipped version (debsums / rpm -V)"),
                "Audit all RC scripts: `ls -la /etc/init.d/ /etc/rc.d/ /etc/network/if-up.d/`".to_string(),
                format!("Inspect process tree of pid {pid}: pstree -p {pid}"),
                "If this is a planned operator script install, allowlist via [detectors.startup_script_persistence]".to_string(),
            ],
            tags: vec!["persistence".to_string(), "rc_scripts".to_string()],
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
    fn fires_on_rc_local_write() {
        let mut det = StartupScriptPersistenceDetector::new("test");
        let ev = write_event("/etc/rc.local", "vim", "bash");
        let inc = det.process(&ev).expect("should fire");
        assert_eq!(inc.severity, Severity::High);
    }

    #[test]
    fn fires_on_init_d_script_drop() {
        let mut det = StartupScriptPersistenceDetector::new("test");
        let ev = write_event("/etc/init.d/sneaky", "cp", "bash");
        assert!(det.process(&ev).is_some());
    }

    #[test]
    fn fires_on_network_if_up_hook() {
        let mut det = StartupScriptPersistenceDetector::new("test");
        let ev = write_event("/etc/network/if-up.d/backdoor", "dd", "bash");
        assert!(det.process(&ev).is_some());
    }

    #[test]
    fn fires_on_rc3_d_symlink_drop() {
        let mut det = StartupScriptPersistenceDetector::new("test");
        let ev = write_event("/etc/rc3.d/S99sneaky", "ln", "bash");
        assert!(det.process(&ev).is_some());
    }

    #[test]
    fn fires_on_etc_cron_d_drop() {
        let mut det = StartupScriptPersistenceDetector::new("test");
        let ev = write_event("/etc/cron.d/persist", "cp", "bash");
        assert!(det.process(&ev).is_some());
    }

    #[test]
    fn silences_dpkg_write() {
        let mut det = StartupScriptPersistenceDetector::new("test");
        let ev = write_event("/etc/init.d/postgresql", "dpkg", "apt");
        assert!(det.process(&ev).is_none());
    }

    #[test]
    fn silences_update_rc_d() {
        let mut det = StartupScriptPersistenceDetector::new("test");
        let ev = write_event("/etc/rc3.d/S20openvpn", "update-rc.d", "dpkg");
        assert!(det.process(&ev).is_none());
    }

    #[test]
    fn ignores_unrelated_etc_writes() {
        let mut det = StartupScriptPersistenceDetector::new("test");
        let ev = write_event("/etc/hostname", "vim", "bash");
        assert!(det.process(&ev).is_none());
    }

    #[test]
    fn dedupes_within_cooldown() {
        let mut det = StartupScriptPersistenceDetector::new("test");
        let ev = write_event("/etc/rc.local", "vim", "bash");
        assert!(det.process(&ev).is_some());
        let mut ev2 = ev.clone();
        ev2.ts = ev.ts + Duration::seconds(60);
        assert!(det.process(&ev2).is_none());
    }

    #[test]
    fn ignores_non_file_write_events() {
        let mut det = StartupScriptPersistenceDetector::new("test");
        let mut ev = write_event("/etc/rc.local", "vim", "bash");
        ev.kind = "shell.command_exec".into();
        assert!(det.process(&ev).is_none());
    }
}
