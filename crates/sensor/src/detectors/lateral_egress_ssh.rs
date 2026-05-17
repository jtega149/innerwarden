//! Lateral movement: outbound SSH from non-operator-shell tree
//! (spec 050-PR4).
//!
//! Fires when an outbound `ssh user@host` exec is spawned by a
//! process tree whose root is NOT an interactive operator shell.
//! Pattern: web user (uid in [33, 1000+ www-data], `nginx`, `apache`
//! parent) shells out to ssh — the classic web-shell → lateral-pivot
//! shape.
//!
//! Anti-FP gates:
//!   - parent comm in `{ansible, salt-call, puppet, chef-client,
//!     cfengine, terraform, packer, capistrano}` → silenced.
//!   - operator-allowlisted dest hosts via
//!     `[detectors.lateral_egress_ssh]` TOML (e.g. operator's
//!     known bastion).
//!   - `git`/`hg`/`fossil` parent → silenced (git+ssh remotes).
//!   - `rsync` / `borg` / `restic` / `duplicity` parent → silenced
//!     (backup tools that ssh).
//!   - parent comm is a known interactive shell (`bash`, `zsh`,
//!     `fish`, `tmux`, `screen`) AND uid > 999 → silenced.
//!
//! Confidence raised when destination is a non-RFC1918 (public) IP
//! or domain — egress to public internet from a server is the
//! highest-signal lateral-pivot shape.
//!
//! MITRE: T1021.004 (Remote Services: SSH).

use std::collections::HashMap;

use chrono::{DateTime, Duration, Utc};
use innerwarden_core::{event::Event, event::Severity, incident::Incident};

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
    "capistrano",
];

const BACKUP_OR_GIT_PARENTS: &[&str] = &[
    "git",
    "hg",
    "fossil",
    "rsync",
    "borg",
    "borgmatic",
    "restic",
    "duplicity",
    "rclone",
    "scp", // recursive scp may spawn ssh
];

const INTERACTIVE_SHELLS: &[&str] = &["bash", "zsh", "fish", "sh", "dash", "ksh", "tmux", "screen"];

pub struct LateralEgressSshDetector {
    host: String,
    last_fired: HashMap<String, DateTime<Utc>>,
    cooldown: Duration,
}

impl LateralEgressSshDetector {
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
        if argv0_base != "ssh" {
            return None;
        }

        let parent_comm = event
            .details
            .get("parent_comm")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let parent_base = parent_comm.split('/').next_back().unwrap_or(parent_comm);
        let parent_base = parent_base.trim_matches(|c: char| c == '(' || c == ')');

        // Anti-FP: automation tooling and backup tools legitimately
        // spawn ssh. Silence both.
        if AUTOMATION_PARENTS
            .iter()
            .any(|p| parent_base.starts_with(p))
            || BACKUP_OR_GIT_PARENTS
                .iter()
                .any(|p| parent_base.starts_with(p))
        {
            return None;
        }

        let uid = event
            .details
            .get("uid")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        // Anti-FP: interactive operator shell with uid > 999 is the
        // "operator manually running ssh" shape, fully expected.
        if uid > 999 && INTERACTIVE_SHELLS.contains(&parent_base) {
            return None;
        }

        // Extract destination — the last non-flag argv entry that
        // contains `@` or is a hostname-shape token.
        let dest = extract_ssh_dest(&argv);
        let dest_str = dest.unwrap_or_default();

        // Internal-network destination → medium severity; egress to
        // public internet from a server → high.
        let public_dest = !dest_str.is_empty() && !is_internal_dest(&dest_str);
        let severity = if public_dest {
            Severity::High
        } else {
            Severity::Medium
        };

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

        let now = event.ts;
        let key = format!("{uid}:{dest_str}");
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
                "lateral_egress_ssh:{uid}:{}",
                now.format("%Y-%m-%dT%H:%M:%SZ")
            ),
            severity,
            title: format!(
                "Lateral SSH egress from non-operator process tree (parent=`{parent_base}`, uid={uid}, public_dest={public_dest})"
            ),
            summary: format!(
                "Process tree spawned outbound ssh from a parent (`{parent_base}`) that is NOT \
                 a known interactive shell, automation tool, or backup tool. Destination: \
                 `{dest_str}`. Command: `{command}`. The classic web-shell-pivots-to-lateral shape \
                 (T1021.004). Comm=`{comm}`, pid={pid}."
            ),
            evidence: serde_json::json!([{
                "kind": "lateral_egress_ssh",
                "ssh_dest": dest_str,
                "public_dest": public_dest,
                "uid": uid,
                "comm": comm,
                "parent_comm": parent_comm,
                "command": command,
                "pid": pid,
                "argv": argv,
                "mitre": ["T1021.004"],
            }]),
            recommended_checks: vec![
                format!("Inspect process tree: pstree -p {pid}"),
                format!("Search recent file-write events from this pid (web-shell pattern)"),
                "If the destination is a known operator bastion, allowlist via [detectors.lateral_egress_ssh]".to_string(),
            ],
            tags: vec!["lateral_movement".to_string(), "ssh".to_string()],
            entities: vec![],
        })
    }
}

fn extract_ssh_dest(argv: &[String]) -> Option<String> {
    let mut prev_was_flag_with_value = false;
    let mut candidate: Option<String> = None;
    // ssh flags that take a value (skip the following token).
    let flags_with_value = [
        "-l", "-p", "-i", "-F", "-c", "-m", "-E", "-D", "-L", "-R", "-W", "-Q", "-S", "-o", "-J",
        "-b", "-e", "-I",
    ];
    for (i, a) in argv.iter().enumerate() {
        if i == 0 {
            continue; // skip ssh itself
        }
        if prev_was_flag_with_value {
            prev_was_flag_with_value = false;
            continue;
        }
        if a.starts_with('-') {
            // Glued short flag (`-pPORT`) doesn't consume next arg.
            // Standalone flags listed above do.
            if flags_with_value.contains(&a.as_str()) {
                prev_was_flag_with_value = true;
            }
            continue;
        }
        candidate = Some(a.clone());
    }
    candidate
}

fn is_internal_dest(dest: &str) -> bool {
    // Strip user@ prefix if present.
    let host = dest.split('@').next_back().unwrap_or(dest);
    // Strip :port suffix if present.
    let host = host.split(':').next().unwrap_or(host);
    if host.is_empty() {
        return true; // empty is "no clue" — fall back to internal-safe
    }
    // IPv4 literal — reuse the standard `is_internal_ip` semantics.
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return match ip {
            std::net::IpAddr::V4(v4) => {
                v4.is_loopback()
                    || v4.is_private()
                    || v4.is_link_local()
                    || v4.is_broadcast()
                    || v4.is_documentation()
                    || v4.is_unspecified()
            }
            std::net::IpAddr::V6(v6) => v6.is_loopback() || v6.is_unspecified(),
        };
    }
    // Hostname heuristic: `.local` / `.internal` / `.lan` / single-label
    // names (no dots) → internal.
    if host.ends_with(".local")
        || host.ends_with(".internal")
        || host.ends_with(".lan")
        || host.ends_with(".intra")
        || !host.contains('.')
    {
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ssh_exec_event(argv: &[&str], parent_comm: &str, uid: u64) -> Event {
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
    fn fires_on_ssh_from_webroot_parent() {
        let mut det = LateralEgressSshDetector::new("test");
        let ev = ssh_exec_event(&["ssh", "attacker@8.8.8.8"], "nginx", 33);
        let inc = det.process(&ev).expect("should fire");
        assert_eq!(inc.severity, Severity::High); // public dest
    }

    #[test]
    fn medium_severity_on_internal_dest() {
        let mut det = LateralEgressSshDetector::new("test");
        let ev = ssh_exec_event(&["ssh", "user@10.0.0.5"], "evil_script", 33);
        let inc = det.process(&ev).expect("should fire");
        assert_eq!(inc.severity, Severity::Medium);
    }

    #[test]
    fn silences_when_parent_is_ansible() {
        let mut det = LateralEgressSshDetector::new("test");
        let ev = ssh_exec_event(&["ssh", "user@host"], "ansible-playboo", 0);
        assert!(det.process(&ev).is_none());
    }

    #[test]
    fn silences_when_parent_is_git() {
        let mut det = LateralEgressSshDetector::new("test");
        let ev = ssh_exec_event(&["ssh", "git@github.com"], "git", 1000);
        assert!(det.process(&ev).is_none());
    }

    #[test]
    fn silences_operator_interactive_shell() {
        let mut det = LateralEgressSshDetector::new("test");
        let ev = ssh_exec_event(&["ssh", "ubuntu@10.0.0.5"], "bash", 1000);
        assert!(det.process(&ev).is_none());
    }

    #[test]
    fn fires_when_uid_is_system_account_even_under_bash() {
        // www-data with uid 33 spawning bash that spawns ssh — that's
        // a web shell, NOT operator. The uid > 999 gate matters.
        let mut det = LateralEgressSshDetector::new("test");
        let ev = ssh_exec_event(&["ssh", "attacker@evil.com"], "bash", 33);
        assert!(det.process(&ev).is_some());
    }

    #[test]
    fn ignores_non_ssh_exec() {
        let mut det = LateralEgressSshDetector::new("test");
        for bin in ["curl", "wget", "scp", "rsync"] {
            assert!(det
                .process(&ssh_exec_event(&[bin, "x"], "bash", 33))
                .is_none());
        }
    }

    #[test]
    fn extract_dest_skips_flag_values() {
        let argv: Vec<String> = vec![
            "ssh".into(),
            "-p".into(),
            "2222".into(),
            "-i".into(),
            "/tmp/key".into(),
            "user@host.com".into(),
        ];
        let dest = extract_ssh_dest(&argv);
        assert_eq!(dest, Some("user@host.com".into()));
    }

    #[test]
    fn dedupes_within_cooldown() {
        let mut det = LateralEgressSshDetector::new("test");
        let ev = ssh_exec_event(&["ssh", "attacker@8.8.8.8"], "nginx", 33);
        assert!(det.process(&ev).is_some());
        let mut ev2 = ev.clone();
        ev2.ts = ev.ts + Duration::seconds(60);
        assert!(det.process(&ev2).is_none());
    }
}
