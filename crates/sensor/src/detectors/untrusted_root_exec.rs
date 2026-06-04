//! Untrusted-root-execution detector (Spec 070, invariant 2a).
//!
//! The single most technique-independent LPE signal: a **uid-0 process running
//! a binary from a path an unprivileged user could control** — `/tmp`, `/home`,
//! `/dev/shm`, a world-writable file, or a file owned by a non-root uid. The
//! escalation bug is irrelevant; what matters is that root is now executing
//! attacker-plantable code. This is what nearly every successful local exploit
//! does once it has the primitive (drop a payload, run it as root).
//!
//! Consumes `shell.command_exec` (the eBPF execve event). Only uid-0 execs are
//! considered, and only an `Illegitimate` provenance verdict fires — a container
//! runtime executing from an overlay path, or a package manager running from
//! `/usr/bin`, is `Trusted` and stays silent (the layered-FP model). Fires High;
//! Critical is reserved for the correlation chain that ties this to a goal action.

use chrono::{DateTime, Duration, Utc};
use innerwarden_core::{entities::EntityRef, event::Event, event::Severity, incident::Incident};
use std::collections::HashMap;

use super::provenance::{self, Provenance};

pub struct UntrustedRootExecDetector {
    host: String,
    cooldown: Duration,
    alerted: HashMap<String, DateTime<Utc>>,
}

impl UntrustedRootExecDetector {
    pub fn new(host: impl Into<String>, cooldown_seconds: u64) -> Self {
        Self {
            host: host.into(),
            cooldown: Duration::seconds(cooldown_seconds as i64),
            alerted: HashMap::new(),
        }
    }

    pub fn process(&mut self, event: &Event) -> Option<Incident> {
        if event.kind != "shell.command_exec" {
            return None;
        }
        let uid = event
            .details
            .get("uid")
            .and_then(|v| v.as_u64())
            .unwrap_or(1);
        // Only ROOT execution from attacker-plantable code is the LPE signature.
        if uid != 0 {
            return None;
        }
        let pid = event.details.get("pid").and_then(|v| v.as_u64())? as u32;
        let ppid = event
            .details
            .get("ppid")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32;
        let comm = event
            .details
            .get("comm")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();

        let prov = provenance::resolve(pid, ppid);
        // root_exec_verdict: container cgroup -> Trusted; exe in writable/unpriv
        // path or non-root-owned/world-writable -> Illegitimate; trusted system
        // prefix -> Trusted; gone -> Unknown. Only Illegitimate fires.
        if prov.root_exec_verdict() != Provenance::Illegitimate {
            return None;
        }
        let exe = prov.exe.clone().unwrap_or_else(|| "unknown".to_string());

        // Cooldown keyed on (exe) so a crash-looping payload doesn't spam.
        let key = format!("{exe}:{pid}");
        let now = event.ts;
        if let Some(&last) = self.alerted.get(&key) {
            if now - last < self.cooldown {
                return None;
            }
        }
        self.alerted.insert(key, now);
        if self.alerted.len() > 1024 {
            let cutoff = now - self.cooldown;
            self.alerted.retain(|_, t| *t > cutoff);
        }

        Some(build_untrusted_exec_incident(
            &self.host,
            pid,
            prov.ppid,
            &comm,
            &exe,
            prov.parent_exe.as_deref().unwrap_or("unknown"),
            prov.exe_writable,
            now,
        ))
    }
}

/// Pure incident constructor (kept separate from the /proc-reading `process` so
/// the construction path is unit-testable without a live /proc entry).
#[allow(clippy::too_many_arguments)]
fn build_untrusted_exec_incident(
    host: &str,
    pid: u32,
    ppid: u32,
    comm: &str,
    exe: &str,
    parent_exe: &str,
    exe_writable: bool,
    now: DateTime<Utc>,
) -> Incident {
    Incident {
        ts: now,
        host: host.to_string(),
        incident_id: format!(
            "execution.untrusted_root:{pid}:{}",
            now.format("%Y-%m-%dT%H:%MZ")
        ),
        severity: Severity::High,
        title: format!("Root executed code from an untrusted path: {comm} ({exe})"),
        summary: format!(
            "Root process '{comm}' (pid={pid}) executed '{exe}' — a path an unprivileged user \
             can write (temp/home/world-writable or non-root-owned), outside any container \
             runtime. Running attacker-plantable code as root is the technique-independent \
             hallmark of a successful local privilege escalation, regardless of the bug used."
        ),
        evidence: serde_json::json!([{
            "kind": "execution.untrusted_root",
            "pid": pid,
            "ppid": ppid,
            "comm": comm,
            "exe": exe,
            "parent_exe": parent_exe,
            "exe_writable": exe_writable,
            "provenance": Provenance::Illegitimate.tag(),
        }]),
        recommended_checks: vec![
            format!("Inspect the binary: ls -l {exe}; sha256sum {exe}; file {exe}"),
            format!("How was it launched? parent={parent_exe} (pid {ppid})"),
            "Check what it did as root: writes to /etc/sudoers, /etc/shadow, cron, kernel modules, or outbound connections".to_string(),
            "If unexpected: isolate the host, preserve the binary, and investigate the initial access vector".to_string(),
        ],
        tags: vec![
            "privilege_escalation".to_string(),
            "execution".to_string(),
            Provenance::Illegitimate.tag().to_string(),
        ],
        entities: vec![EntityRef::path(exe)],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use innerwarden_core::event::Severity;

    fn exec_event(uid: u64, pid: u64) -> Event {
        Event {
            ts: Utc::now(),
            host: "h".into(),
            source: "ebpf".into(),
            kind: "shell.command_exec".into(),
            severity: Severity::Info,
            summary: String::new(),
            details: serde_json::json!({
                "pid": pid, "uid": uid, "ppid": 1, "comm": "payload",
            }),
            tags: vec![],
            entities: vec![],
        }
    }

    #[test]
    fn ignores_non_root_exec() {
        let mut d = UntrustedRootExecDetector::new("h", 60);
        // uid 1000 -> never considered, regardless of /proc state.
        assert!(d.process(&exec_event(1000, 999_999)).is_none());
    }

    #[test]
    fn ignores_wrong_kind() {
        let mut d = UntrustedRootExecDetector::new("h", 60);
        let mut ev = exec_event(0, 999_999);
        ev.kind = "process.clone".into();
        assert!(d.process(&ev).is_none());
    }

    #[test]
    fn build_incident_shape() {
        let inc = build_untrusted_exec_incident(
            "h",
            4242,
            10,
            "payload",
            "/tmp/iw_payload",
            "/bin/bash",
            true,
            Utc::now(),
        );
        assert_eq!(inc.severity, Severity::High);
        assert!(inc
            .incident_id
            .starts_with("execution.untrusted_root:4242:"));
        assert!(inc.title.contains("/tmp/iw_payload"));
        assert!(inc.tags.iter().any(|t| t == "provenance:illegitimate"));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn process_root_exec_self_drives_proc_path() {
        // uid 0 + this test process's real pid drives the full /proc-reading
        // path (resolve + root_exec_verdict + possibly the builder). The verdict
        // depends on where the test binary lives + the runner cgroup, so we do
        // not assert the outcome — only that the live path runs without panic.
        let mut d = UntrustedRootExecDetector::new("h", 60);
        let ev = exec_event(0, std::process::id() as u64);
        let _ = d.process(&ev);
    }

    #[test]
    fn nonexistent_pid_is_unknown_not_illegitimate() {
        // A pid that does not exist resolves to exe=None -> Unknown -> no fire
        // (fail-safe: we never fabricate an Illegitimate verdict from a race).
        let mut d = UntrustedRootExecDetector::new("h", 60);
        assert!(d.process(&exec_event(0, 4_000_000_000)).is_none());
    }
    // A positive fire (uid 0 exec of /tmp/payload) needs a live /proc entry with
    // an exe symlink into a writable path; it is exercised by the on-host
    // integration run, not a unit test.
}
