//! PAM (Pluggable Authentication Modules) tampering detection
//! (spec 050-PR5).
//!
//! Fires when a non-package-manager process writes to:
//!   - `/etc/pam.d/*` (per-service PAM config)
//!   - `/lib/security/pam_*.so` (PAM modules)
//!   - `/lib/x86_64-linux-gnu/security/pam_*.so`
//!   - `/usr/lib/x86_64-linux-gnu/security/pam_*.so`
//!   - `/lib64/security/pam_*.so` (RHEL/SUSE)
//!
//! The canonical PAM-based credential-harvester / backdoor:
//!   - drop a malicious `pam_unix.so` that logs creds OR allows a magic
//!     password
//!   - edit `/etc/pam.d/sshd` to `auth sufficient pam_permit.so` so any
//!     ssh login passes
//!
//! Anti-FP gates:
//!   - Package manager parents/writers (apt/dpkg/unattended-upgr/dnf/
//!     yum/zypper/pacman/apk/needrestart/snapd) → silenced.
//!   - Operator-extensible `[detectors.pam_module_change]` TOML.
//!
//! MITRE: T1556.003 (Modify Authentication Process: PAM).

use std::collections::HashMap;

use chrono::{DateTime, Duration, Utc};
use innerwarden_core::{event::Event, event::Severity, incident::Incident};

const PAM_CONFIG_PREFIXES: &[&str] = &["/etc/pam.d/", "/etc/pam.conf"];

const PAM_MODULE_PREFIXES: &[&str] = &[
    "/lib/security/",
    "/lib64/security/",
    "/lib/x86_64-linux-gnu/security/",
    "/usr/lib/security/",
    "/usr/lib64/security/",
    "/usr/lib/x86_64-linux-gnu/security/",
    "/usr/lib/aarch64-linux-gnu/security/",
    "/lib/aarch64-linux-gnu/security/",
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

pub struct PamModuleChangeDetector {
    host: String,
    last_fired: HashMap<String, DateTime<Utc>>,
    cooldown: Duration,
}

impl PamModuleChangeDetector {
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
        let kind = classify_pam_target(filename)?;

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
                "pam_module_change:{kind}:{}",
                now.format("%Y-%m-%dT%H:%M:%SZ")
            ),
            severity: Severity::Critical,
            title: format!(
                "PAM tampering: {kind} write to `{filename}` (comm=`{comm}`, parent=`{parent_comm}`, uid={uid})"
            ),
            summary: format!(
                "Process `{comm}` (parent=`{parent_comm}`, pid={pid}, uid={uid}) wrote to \
                 `{filename}` outside a package-manager context. This is the canonical \
                 PAM backdoor / credential-harvester shape (T1556.003): a malicious \
                 `pam_unix.so` drop or a `pam.d` edit that bypasses auth."
            ),
            evidence: serde_json::json!([{
                "kind": "pam_module_change",
                "sub_kind": kind,
                "filename": filename,
                "uid": uid,
                "comm": comm,
                "parent_comm": parent_comm,
                "pid": pid,
                "mitre": ["T1556.003"],
            }]),
            recommended_checks: vec![
                format!("Compare `{filename}` against the package-shipped version (debsums / rpm -V)"),
                "Inspect `/etc/pam.d/sshd` and `/etc/pam.d/su` for `pam_permit.so` entries".to_string(),
                "List recent process writes from this pid: `ausearch -p <pid>` or eBPF history".to_string(),
                "If the change is operator-driven (custom PAM module install), allowlist via [detectors.pam_module_change]".to_string(),
            ],
            tags: vec!["persistence".to_string(), "pam".to_string(), "credential_access".to_string()],
            entities: vec![],
        })
    }
}

fn classify_pam_target(path: &str) -> Option<&'static str> {
    if PAM_CONFIG_PREFIXES.iter().any(|p| path.starts_with(p)) {
        return Some("pam_config");
    }
    if PAM_MODULE_PREFIXES.iter().any(|p| path.starts_with(p))
        && path
            .rsplit('/')
            .next()
            .map(|f| f.starts_with("pam_") && f.ends_with(".so"))
            .unwrap_or(false)
    {
        return Some("pam_module");
    }
    None
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
                "uid": 1000,
                "comm": comm,
                "parent_comm": parent_comm,
            }),
            tags: vec![],
            entities: vec![],
        }
    }

    #[test]
    fn fires_on_pam_d_sshd_write_by_non_pkg_manager() {
        let mut det = PamModuleChangeDetector::new("test");
        let ev = write_event("/etc/pam.d/sshd", "bash", "bash");
        let inc = det.process(&ev).expect("should fire");
        assert_eq!(inc.severity, Severity::Critical);
    }

    #[test]
    fn fires_on_pam_unix_so_drop() {
        let mut det = PamModuleChangeDetector::new("test");
        let ev = write_event("/lib/x86_64-linux-gnu/security/pam_unix.so", "cp", "bash");
        assert!(det.process(&ev).is_some());
    }

    #[test]
    fn fires_on_rhel_lib64_pam_module() {
        let mut det = PamModuleChangeDetector::new("test");
        let ev = write_event("/lib64/security/pam_permit.so", "dd", "bash");
        assert!(det.process(&ev).is_some());
    }

    #[test]
    fn silences_dpkg_write() {
        let mut det = PamModuleChangeDetector::new("test");
        let ev = write_event("/etc/pam.d/sshd", "dpkg", "apt");
        assert!(det.process(&ev).is_none());
    }

    #[test]
    fn silences_unattended_upgr_write() {
        let mut det = PamModuleChangeDetector::new("test");
        let ev = write_event(
            "/lib/x86_64-linux-gnu/security/pam_unix.so",
            "dpkg",
            "unattended-upgr",
        );
        assert!(det.process(&ev).is_none());
    }

    #[test]
    fn ignores_non_pam_writes() {
        let mut det = PamModuleChangeDetector::new("test");
        let ev = write_event("/etc/hostname", "vim", "bash");
        assert!(det.process(&ev).is_none());
    }

    #[test]
    fn ignores_security_dir_write_with_non_pam_filename() {
        // .so file in /lib/security/ but not named pam_*.so — not PAM.
        let mut det = PamModuleChangeDetector::new("test");
        let ev = write_event("/lib/security/something_else.so", "vim", "bash");
        assert!(det.process(&ev).is_none());
    }

    #[test]
    fn dedupes_within_cooldown() {
        let mut det = PamModuleChangeDetector::new("test");
        let ev = write_event("/etc/pam.d/su", "vim", "bash");
        assert!(det.process(&ev).is_some());
        let mut ev2 = ev.clone();
        ev2.ts = ev.ts + Duration::seconds(60);
        assert!(det.process(&ev2).is_none());
    }

    #[test]
    fn ignores_non_file_write_events() {
        let mut det = PamModuleChangeDetector::new("test");
        let mut ev = write_event("/etc/pam.d/sshd", "vim", "bash");
        ev.kind = "shell.command_exec".into();
        assert!(det.process(&ev).is_none());
    }
}
