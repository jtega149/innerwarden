//! Untrusted namespace-pivot detector (Spec 070).
//!
//! Consumes `namespace.setns` events (emitted by the `dispatch_setns` kprobe).
//! Fires when a **root (uid 0) process joins a USER namespace** from outside any
//! container / managed-runtime context. A root task `setns`-ing into a
//! user-namespace it did not legitimately create is the technique-independent
//! pivot primitive behind container-escape and user-namespace-based LPE: the
//! kernel hands a helper root, the helper enters the attacker's namespace, then
//! runs attacker-controlled resolution as root.
//!
//! The target namespace OWNER uid is resolved best-effort in userspace via the
//! `NS_GET_OWNER_UID` ioctl on `/proc/<pid>/ns/user` (after a successful
//! `setns(CLONE_NEWUSER)` the caller is IN the target ns). If the owner is a
//! non-root uid the verdict is `Illegitimate`; if the process raced away before
//! we could read it, `Unknown` (never a false downgrade).
//!
//! Container runtimes legitimately setns constantly (runc/containerd/crun/k8s),
//! so a container cgroup OR a container-runtime exe is a tier-0 NOISE filter by
//! non-forgeable signal (mirrors the in-kernel comm allowlist) — those are not
//! security events and are dropped here, not merely downgraded.

use chrono::{DateTime, Duration, Utc};
use innerwarden_core::{entities::EntityRef, event::Event, event::Severity, incident::Incident};
use std::collections::HashMap;

use super::provenance::{self, cgroup_is_container, Provenance};

/// Container-runtime executables (by absolute path) that legitimately setns.
const RUNTIME_EXES: &[&str] = &[
    "/usr/bin/runc",
    "/usr/sbin/runc",
    "/usr/bin/crun",
    "/usr/bin/conmon",
    "/usr/bin/containerd",
    "/usr/bin/containerd-shim",
    "/usr/bin/containerd-shim-runc-v2",
    "/usr/bin/dockerd",
    "/usr/bin/podman",
    "/usr/bin/conmonrs",
    "/usr/bin/crio",
    "/usr/lib/systemd/systemd-nspawn",
    "/usr/bin/systemd-nspawn",
    "/usr/bin/lxc-start",
    "/usr/sbin/lxc-start",
    "/usr/bin/lxd",
];

pub struct SetnsOwnerDetector {
    host: String,
    cooldown: Duration,
    alerted: HashMap<u32, DateTime<Utc>>,
}

impl SetnsOwnerDetector {
    pub fn new(host: impl Into<String>, cooldown_seconds: u64) -> Self {
        Self {
            host: host.into(),
            cooldown: Duration::seconds(cooldown_seconds as i64),
            alerted: HashMap::new(),
        }
    }

    pub fn process(&mut self, event: &Event) -> Option<Incident> {
        if event.kind != "namespace.setns" {
            return None;
        }
        let uid = event
            .details
            .get("uid")
            .and_then(|v| v.as_u64())
            .unwrap_or(1);
        // Only a ROOT setns is the pivot primitive — an unprivileged setns gains
        // nothing it doesn't already have.
        if uid != 0 {
            return None;
        }
        let nstype_name = event
            .details
            .get("nstype_name")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        // Only USER-namespace entry matters (or an fd-based join that may be one).
        if !(nstype_name.contains("user") || nstype_name == "by-fd") {
            return None;
        }
        let pid = event.details.get("pid").and_then(|v| v.as_u64())? as u32;
        let comm = event
            .details
            .get("comm")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();

        let ppid = resolve_ppid(pid);
        let prov = provenance::resolve(pid, ppid);

        // Tier-0 noise filter: container/runtime setns is expected, drop it.
        if cgroup_is_container(prov.cgroup_hint.as_deref())
            || prov.exe.as_deref().map(is_runtime_exe).unwrap_or(false)
        {
            return None;
        }

        // Best-effort owner-uid of the target user namespace.
        let owner = resolve_userns_owner(pid);
        // Root entering a root-owned userns is normal (admin/nsenter into a
        // root ns); only a non-root owner — or an unresolved owner outside any
        // container context — is the pivot.
        if owner == Some(0) {
            return None;
        }

        // Cooldown per pid.
        let now = event.ts;
        if let Some(&last) = self.alerted.get(&pid) {
            if now - last < self.cooldown {
                return None;
            }
        }
        self.alerted.insert(pid, now);
        if self.alerted.len() > 1024 {
            let cutoff = now - self.cooldown;
            self.alerted.retain(|_, t| *t > cutoff);
        }

        Some(build_setns_incident(
            &self.host,
            pid,
            ppid,
            &comm,
            prov.exe.as_deref(),
            owner,
            nstype_name,
            now,
        ))
    }
}

/// Pure incident constructor (kept separate from the /proc-reading `process`
/// so the construction path is unit-testable without a live namespace).
#[allow(clippy::too_many_arguments)]
fn build_setns_incident(
    host: &str,
    pid: u32,
    ppid: u32,
    comm: &str,
    exe: Option<&str>,
    owner: Option<u32>,
    nstype_name: &str,
    now: DateTime<Utc>,
) -> Incident {
    let verdict = match owner {
        Some(_) => Provenance::Illegitimate, // owner is a non-root uid
        None => Provenance::Unknown,         // raced; still suspicious outside a container
    };
    let owner_str = owner
        .map(|u| u.to_string())
        .unwrap_or_else(|| "unresolved".to_string());
    let exe = exe.unwrap_or("unknown").to_string();
    Incident {
        ts: now,
        host: host.to_string(),
        incident_id: format!(
            "namespace.setns_unpriv_owner:{pid}:{}",
            now.format("%Y-%m-%dT%H:%MZ")
        ),
        severity: Severity::High,
        title: format!("Root joined a user namespace it does not own: {comm} (PID {pid})"),
        summary: format!(
            "Root process '{comm}' (pid={pid}, exe={exe}) called setns() into a user \
             namespace owned by uid {owner_str}, outside any container runtime context. A \
             privileged task entering a user-namespace it did not legitimately create is the \
             pivot primitive of container-escape and user-namespace privilege-escalation \
             chains, independent of the underlying bug."
        ),
        evidence: serde_json::json!([{
            "kind": "namespace.setns",
            "pid": pid,
            "ppid": ppid,
            "comm": comm,
            "exe": exe,
            "ns_owner_uid": owner,
            "nstype": nstype_name,
        }]),
        recommended_checks: vec![
            format!("Inspect the process: ps -fp {pid}; cat /proc/{pid}/status"),
            format!("Confirm '{exe}' is an expected privileged binary, not a kernel helper or planted payload"),
            "Check what the process did next: writes to /etc/sudoers, /etc/shadow, cron, or loaded libraries from writable paths".to_string(),
            "Correlate with any privilege.escalation / execution.untrusted_root on the same PID".to_string(),
        ],
        tags: vec![
            "privilege_escalation".to_string(),
            "namespace".to_string(),
            "container_escape".to_string(),
            verdict.tag().to_string(),
        ],
        entities: vec![EntityRef::path(exe)],
    }
}

fn is_runtime_exe(exe: &str) -> bool {
    RUNTIME_EXES.contains(&exe)
}

fn resolve_ppid(pid: u32) -> u32 {
    if let Ok(content) = std::fs::read_to_string(format!("/proc/{pid}/status")) {
        for line in content.lines() {
            if let Some(val) = line.strip_prefix("PPid:\t") {
                return val.trim().parse().unwrap_or(0);
            }
        }
    }
    0
}

/// Best-effort owner uid of the user namespace `pid` is currently in.
///
/// `NS_GET_OWNER_UID = _IO(0xb7, 4)`. After a successful `setns(CLONE_NEWUSER)`
/// the caller IS in the target ns, so `/proc/<pid>/ns/user` refers to it. Returns
/// None on any failure (process gone, permission, foreign mount) — the caller
/// treats None as `Unknown`, never as a safe owner.
#[cfg(target_os = "linux")]
fn resolve_userns_owner(pid: u32) -> Option<u32> {
    use std::os::unix::io::AsRawFd;
    const NS_GET_OWNER_UID: libc::c_ulong = 0xb704; // _IO(0xb7, 4)
    let f = std::fs::File::open(format!("/proc/{pid}/ns/user")).ok()?;
    let mut uid: libc::uid_t = u32::MAX;
    // SAFETY: ioctl on an nsfs fd; uid is a valid out-pointer for the request.
    let rc = unsafe { libc::ioctl(f.as_raw_fd(), NS_GET_OWNER_UID, &mut uid) };
    if rc != 0 || uid == u32::MAX {
        return None;
    }
    Some(uid)
}

#[cfg(not(target_os = "linux"))]
fn resolve_userns_owner(_pid: u32) -> Option<u32> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use innerwarden_core::event::Severity;

    fn setns_event(uid: u64, nstype_name: &str, pid: u64) -> Event {
        Event {
            ts: Utc::now(),
            host: "h".into(),
            source: "ebpf".into(),
            kind: "namespace.setns".into(),
            severity: Severity::Debug,
            summary: String::new(),
            details: serde_json::json!({
                "pid": pid, "uid": uid, "fd": 3, "nstype": 0x10000000u32,
                "nstype_name": nstype_name, "comm": "cifs.upcall"
            }),
            tags: vec![],
            entities: vec![],
        }
    }

    #[test]
    fn ignores_non_root_setns() {
        let mut d = SetnsOwnerDetector::new("h", 60);
        assert!(d.process(&setns_event(1000, "user", 4242)).is_none());
    }

    #[test]
    fn ignores_non_userns_setns() {
        let mut d = SetnsOwnerDetector::new("h", 60);
        assert!(d.process(&setns_event(0, "net", 4242)).is_none());
    }

    #[test]
    fn ignores_wrong_kind() {
        let mut d = SetnsOwnerDetector::new("h", 60);
        let mut ev = setns_event(0, "user", 4242);
        ev.kind = "process.clone".into();
        assert!(d.process(&ev).is_none());
    }

    #[test]
    fn runtime_exe_allowlist_is_exact_path() {
        assert!(is_runtime_exe("/usr/bin/runc"));
        assert!(!is_runtime_exe("/tmp/runc")); // planted payload must not pass
        assert!(!is_runtime_exe("/usr/bin/runc-evil"));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn process_root_setns_self_drives_proc_path() {
        // uid 0 + this test process's real pid drives resolve_ppid + resolve +
        // resolve_userns_owner. The test runs in the init user namespace
        // (owner uid 0), so this returns None — but it exercises the /proc and
        // ioctl reading path that a live exploit hits.
        let mut d = SetnsOwnerDetector::new("h", 60);
        let ev = setns_event(0, "user", std::process::id() as u64);
        let _ = d.process(&ev);
    }

    #[test]
    fn build_incident_non_root_owner_is_high_illegitimate() {
        let inc = build_setns_incident(
            "h",
            4242,
            7,
            "cifs.upcall",
            Some("/usr/sbin/cifs.upcall"),
            Some(1000),
            "user",
            Utc::now(),
        );
        assert_eq!(inc.severity, Severity::High);
        assert!(inc.title.contains("user namespace"));
        assert!(inc
            .incident_id
            .starts_with("namespace.setns_unpriv_owner:4242:"));
        assert!(inc.tags.iter().any(|t| t == "provenance:illegitimate"));
        assert!(inc.summary.contains("owned by uid 1000"));
    }

    #[test]
    fn build_incident_unresolved_owner_is_unknown() {
        let inc = build_setns_incident("h", 5, 1, "x", None, None, "by-fd", Utc::now());
        assert!(inc.tags.iter().any(|t| t == "provenance:unknown"));
        assert!(inc.summary.contains("uid unresolved"));
    }
    // NOTE: a positive end-to-end fire (root setns into a uid!=0 userns) needs a
    // live /proc + a real foreign userns and is exercised by the on-host
    // CIFSwitch-class integration run, not a unit test (it depends on a live
    // NS_GET_OWNER_UID ioctl against a real namespace).
}
