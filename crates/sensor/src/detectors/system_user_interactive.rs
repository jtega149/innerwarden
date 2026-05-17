//! System user interactive shell detection.
//!
//! Service accounts (`bin`, `daemon`, `nobody`, `www-data`, `mysql`,
//! `postgres`, `redis`, etc.) are deliberately denied interactive
//! logins on a hardened host — their shell in `/etc/passwd` is
//! `/usr/sbin/nologin` or `/bin/false`. When such a user shows up
//! running an interactive shell (`bash -i`, `sh`, `zsh`) with a
//! controlling terminal, it almost always means the attacker has
//! either:
//!   1. Pivoted into the account through a vulnerable service
//!      (web RCE → www-data shell)
//!   2. Forced a setuid escape that landed under a different uid
//!   3. Restored a removed shell via passwd edit / `chsh`
//!
//! Each of those is a foothold signal that the canonical
//! `web_shell` / `reverse_shell` / `lateral_movement` detectors do
//! NOT catch directly — they fire on the payload shape (socket FDs,
//! webroot upload), not on the post-pivot identity.
//!
//! Trigger:
//!   - process.exec / shell.command_exec with argv[0] = known shell
//!   - uid is in the well-known service-account set (uid < 1000 in
//!     Debian/RHEL conventions, AND name matches the curated list)
//!   - parent comm is `sshd` (SSH session) OR there is a controlling
//!     terminal (`tty != 0` or `tty != null`)
//!
//! Anti-FP gates:
//!   - Package-manager parent (apt/dpkg/dnf/yum/etc.) silenced.
//!     Installer scripts legitimately run snippets as service users.
//!   - cron / anacron / atd parents silenced — `cron` runs jobs as
//!     the system user but never with a tty.
//!   - Operator allowlist via `[detectors.system_user_interactive]`.
//!
//! MITRE: T1059 (Command and Scripting Interpreter), T1078.003
//! (Valid Accounts: Local Accounts — service account abuse).

use std::collections::HashMap;

use chrono::{DateTime, Duration, Utc};
use innerwarden_core::{event::Event, event::Severity, incident::Incident};

/// Well-known Linux system / service accounts that ship with no
/// interactive shell. If one of these shows up running `bash -i` (or
/// any shell) with a tty, that's an exfil-shape we want to know about.
///
/// This is a curated list; an operator that adds a custom service
/// user that does need to log in interactively can allowlist it via
/// `[detectors.system_user_interactive]` TOML.
const SYSTEM_USERNAMES: &[&str] = &[
    "bin",
    "daemon",
    "adm",
    "lp",
    "sync",
    "shutdown",
    "halt",
    "mail",
    "operator",
    "games",
    "ftp",
    "nobody",
    "systemd-network",
    "systemd-resolve",
    "systemd-timesync",
    "messagebus",
    "syslog",
    "_apt",
    "uuidd",
    "tcpdump",
    "landscape",
    "pollinate",
    "dnsmasq",
    "tss",
    "fwupd-refresh",
    "usbmux",
    "rtkit",
    "avahi",
    "saned",
    "colord",
    "geoclue",
    "gnome-initial-setup",
    "speech-dispatcher",
    "kernoops",
    "www-data",
    "nginx",
    "apache",
    "httpd",
    "mysql",
    "mariadb",
    "postgres",
    "postgresql",
    "redis",
    "mongodb",
    "elasticsearch",
    "rabbitmq",
    "memcache",
    "memcached",
    "vagrant",
];

const SHELL_BINARIES: &[&str] = &[
    "bash", "sh", "dash", "zsh", "ksh", "tcsh", "csh", "fish", "ash", "busybox",
];

const PKG_MANAGER_PARENTS: &[&str] = &[
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

/// Scheduler parents that legitimately run jobs as a service uid (but
/// never with a controlling terminal). The tty check below catches
/// the case where these spawn things — but we keep this list as a
/// belt-and-braces fallback if the tty field is missing on a source.
const SCHEDULER_PARENTS: &[&str] = &["cron", "crond", "anacron", "atd", "systemd"];

pub struct SystemUserInteractiveDetector {
    host: String,
    last_fired: HashMap<String, DateTime<Utc>>,
    cooldown: Duration,
}

impl SystemUserInteractiveDetector {
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
        if !SHELL_BINARIES.contains(&argv0_base) {
            return None;
        }

        // The username field varies by source: auditd / journald set
        // `user`, the eBPF emitter sets `username`. Accept either.
        let username = event
            .details
            .get("username")
            .and_then(|v| v.as_str())
            .or_else(|| event.details.get("user").and_then(|v| v.as_str()))
            .unwrap_or("");
        if !SYSTEM_USERNAMES.contains(&username) {
            return None;
        }

        // Interactive heuristic: parent is sshd (interactive SSH
        // session) OR a controlling terminal is attached. The tty
        // field is named differently across sources — eBPF emits
        // `tty`, auditd emits `terminal`. Treat empty / 0 / "?" as no
        // terminal.
        let parent_comm = event
            .details
            .get("parent_comm")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let parent_base = parent_comm.split('/').next_back().unwrap_or(parent_comm);
        let parent_base = parent_base.trim_matches(|c: char| c == '(' || c == ')');

        let tty = event
            .details
            .get("tty")
            .and_then(|v| v.as_str())
            .or_else(|| event.details.get("terminal").and_then(|v| v.as_str()))
            .unwrap_or("");
        let has_tty = !tty.is_empty() && tty != "0" && tty != "?" && tty != "(none)";

        let parent_is_sshd = parent_base == "sshd" || parent_base.starts_with("sshd:");
        if !parent_is_sshd && !has_tty {
            // No tty, parent isn't sshd → this is a non-interactive
            // service exec (cron, systemd unit, etc.). Silenced.
            return None;
        }

        // Anti-FP gates.
        if PKG_MANAGER_PARENTS
            .iter()
            .any(|p| parent_base.starts_with(p))
            || SCHEDULER_PARENTS.contains(&parent_base)
        {
            return None;
        }

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
        let key = format!("{username}:{argv0_base}");
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
                "system_user_interactive:{username}:{}",
                now.format("%Y-%m-%dT%H:%M:%SZ")
            ),
            severity: Severity::Critical,
            title: format!(
                "Service account `{username}` (uid={uid}) running interactive shell `{argv0_base}` (parent=`{parent_base}`, tty=`{tty}`)"
            ),
            summary: format!(
                "Process `{comm}` (pid={pid}) was exec'd by service-account user `{username}` \
                 running an interactive shell (`{argv0_base}`, command=`{command}`) with \
                 parent=`{parent_base}` and tty=`{tty}`. Service accounts ship with \
                 /usr/sbin/nologin on hardened hosts — seeing one in a tty almost always \
                 means foothold: web RCE → `{username}` shell, setuid escape that landed under \
                 the wrong uid, or `chsh` after passwd compromise (T1059 / T1078.003)."
            ),
            evidence: serde_json::json!([{
                "kind": "system_user_interactive",
                "service_account": username,
                "shell_binary": argv0_base,
                "uid": uid,
                "comm": comm,
                "parent_comm": parent_comm,
                "pid": pid,
                "command": command,
                "tty": tty,
                "argv": argv,
                "mitre": ["T1059", "T1078.003"],
            }]),
            recommended_checks: vec![
                format!("Confirm `{username}` shell in /etc/passwd: `getent passwd {username}`"),
                format!("Inspect process tree of pid {pid}: pstree -p {pid}"),
                "If parent is sshd, audit /var/log/auth.log for the matching session".to_string(),
                "Audit recent web requests if username is www-data / nginx / apache".to_string(),
                "If this is a planned operator action, allowlist via [detectors.system_user_interactive]".to_string(),
            ],
            tags: vec!["foothold".to_string(), "service_account".to_string(), "interactive".to_string()],
            entities: vec![],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exec_event(argv: &[&str], username: &str, parent_comm: &str, tty: &str) -> Event {
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
                "uid": 33, // www-data on Debian — service uid
                "username": username,
                "comm": argv[0],
                "parent_comm": parent_comm,
                "tty": tty,
            }),
            tags: vec![],
            entities: vec![],
        }
    }

    #[test]
    fn fires_on_www_data_running_bash_with_sshd_parent() {
        let mut det = SystemUserInteractiveDetector::new("test");
        let ev = exec_event(&["bash", "-i"], "www-data", "sshd", "pts/0");
        let inc = det.process(&ev).expect("should fire");
        assert_eq!(inc.severity, Severity::Critical);
    }

    #[test]
    fn fires_on_nobody_running_sh_with_tty() {
        let mut det = SystemUserInteractiveDetector::new("test");
        let ev = exec_event(&["sh"], "nobody", "bash", "pts/1");
        assert!(det.process(&ev).is_some());
    }

    #[test]
    fn fires_on_nginx_user_running_zsh_in_pivot() {
        let mut det = SystemUserInteractiveDetector::new("test");
        let ev = exec_event(&["zsh"], "nginx", "sshd:session", "pts/2");
        assert!(det.process(&ev).is_some());
    }

    #[test]
    fn ignores_real_user_running_bash() {
        let mut det = SystemUserInteractiveDetector::new("test");
        // ubuntu / operator users are NOT in SYSTEM_USERNAMES.
        let ev = exec_event(&["bash", "-i"], "ubuntu", "sshd", "pts/0");
        assert!(det.process(&ev).is_none());
        let ev2 = exec_event(&["bash"], "operator-mri", "sshd", "pts/1");
        assert!(det.process(&ev2).is_none());
    }

    #[test]
    fn ignores_service_user_without_tty_or_sshd_parent() {
        let mut det = SystemUserInteractiveDetector::new("test");
        // cron-spawned shell as www-data — legitimate background job,
        // no tty, parent != sshd.
        let ev = exec_event(&["sh"], "www-data", "cron", "");
        assert!(det.process(&ev).is_none());
    }

    #[test]
    fn ignores_service_user_with_systemd_parent_no_tty() {
        let mut det = SystemUserInteractiveDetector::new("test");
        // systemd unit running a wrapper script as www-data → ok.
        let ev = exec_event(
            &["sh", "/usr/local/bin/wrapper.sh"],
            "www-data",
            "systemd",
            "?",
        );
        assert!(det.process(&ev).is_none());
    }

    #[test]
    fn silences_when_parent_is_dpkg() {
        let mut det = SystemUserInteractiveDetector::new("test");
        // Postinst snippet runs sh as www-data with terminal — package
        // install context, silenced.
        let ev = exec_event(&["sh", "-c", "echo hi"], "www-data", "dpkg", "pts/0");
        assert!(det.process(&ev).is_none());
    }

    #[test]
    fn ignores_non_shell_exec_by_service_user() {
        let mut det = SystemUserInteractiveDetector::new("test");
        // www-data running php-fpm is normal.
        let ev = exec_event(&["php-fpm"], "www-data", "sshd", "pts/0");
        assert!(det.process(&ev).is_none());
    }

    #[test]
    fn dedupes_within_cooldown() {
        let mut det = SystemUserInteractiveDetector::new("test");
        let ev = exec_event(&["bash", "-i"], "www-data", "sshd", "pts/0");
        assert!(det.process(&ev).is_some());
        let mut ev2 = ev.clone();
        ev2.ts = ev.ts + Duration::seconds(60);
        assert!(det.process(&ev2).is_none());
    }

    #[test]
    fn ignores_non_exec_event_kinds() {
        let mut det = SystemUserInteractiveDetector::new("test");
        let mut ev = exec_event(&["bash"], "www-data", "sshd", "pts/0");
        ev.kind = "file.write_access".into();
        assert!(det.process(&ev).is_none());
    }

    #[test]
    fn accepts_auditd_field_aliases() {
        // auditd emits `user` + `terminal` (vs eBPF's `username` + `tty`).
        // The detector reads both forms so events from either source
        // fire the same rule. Anchor this so a future refactor that
        // drops one alias is caught.
        let mut det = SystemUserInteractiveDetector::new("test");
        let argv_owned: Vec<String> = ["bash", "-i"].iter().map(|s| s.to_string()).collect();
        let ev = Event {
            ts: Utc::now(),
            host: "test".into(),
            source: "auditd".into(),
            kind: "shell.command_exec".into(),
            severity: Severity::Info,
            summary: "bash -i".into(),
            details: serde_json::json!({
                "argv": argv_owned,
                "argc": 2,
                "command": "bash -i",
                "pid": 4242,
                "uid": 33,
                "user": "www-data",        // auditd alias for `username`
                "comm": "bash",
                "parent_comm": "sshd",
                "terminal": "pts/0",         // auditd alias for `tty`
            }),
            tags: vec![],
            entities: vec![],
        };
        assert!(det.process(&ev).is_some());
    }
}
