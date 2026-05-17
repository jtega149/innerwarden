//! Linux capabilities abuse detection (spec 050-PR4).
//!
//! Process holds one of the dangerous capabilities (CAP_SYS_ADMIN,
//! CAP_DAC_READ_SEARCH, CAP_SETUID, CAP_NET_RAW) **and** its argv
//! looks like exploitation. Confidence comes from the pairing —
//! capabilities alone are normal (systemd holds them all), argv
//! shape alone is also normal (cat /etc/shadow as root is just root
//! work). Together with NON-zero uid is the privesc signal.
//!
//! Anti-FP gates:
//!   - uid 0 (root) → silenced (root holds caps legitimately).
//!   - parent comm in `{systemd, init, kthreadd}` → silenced.
//!   - Operator-extensible `[detectors.capabilities_abuse]` TOML.
//!
//! MITRE: T1548.005 (Linux Capabilities) / T1068 (Exploitation for
//! Privilege Escalation).

use std::collections::HashMap;

use chrono::{DateTime, Duration, Utc};
use innerwarden_core::{event::Event, event::Severity, incident::Incident};

/// The four caps that, when held by a non-root process running a
/// suspicious argv, produce the highest-signal privesc indication.
/// Each cap matches a distinct exploitation pattern below.
const DANGEROUS_CAPS: &[&str] = &[
    "CAP_SYS_ADMIN",       // can mount, ptrace anyone, namespace tricks
    "CAP_DAC_READ_SEARCH", // can read /etc/shadow, /root/, anything
    "CAP_SETUID",          // can setuid(0) without being root
    "CAP_NET_RAW",         // can craft raw sockets / sniff
    "CAP_SYS_PTRACE",      // can attach to any process
    "CAP_SYS_MODULE",      // can load kernel modules
];

/// argv patterns that, paired with a dangerous cap on a non-root
/// process, signal active exploitation. Each entry maps to which cap
/// makes it suspicious.
fn argv_matches_exploitation(argv0_base: &str, command: &str) -> Option<&'static str> {
    let lower = command.to_lowercase();
    // CAP_DAC_READ_SEARCH abuse: reading sensitive files.
    if (argv0_base == "cat" || argv0_base == "less" || argv0_base == "head" || argv0_base == "tail")
        && (lower.contains("/etc/shadow")
            || lower.contains("/etc/sudoers")
            || lower.contains("/root/")
            || lower.contains("authorized_keys"))
    {
        return Some("CAP_DAC_READ_SEARCH:sensitive_read");
    }
    // CAP_SYS_ADMIN abuse: mounting / ptrace.
    if (argv0_base == "mount" || argv0_base == "umount" || argv0_base == "unshare")
        && (lower.contains(" --bind")
            || lower.contains(" -o ")
            || lower.contains(" /proc")
            || lower.contains(" /etc"))
    {
        return Some("CAP_SYS_ADMIN:mount_escape");
    }
    // CAP_SETUID abuse via capsh / setpriv invocations.
    if (argv0_base == "capsh" || argv0_base == "setpriv")
        && (lower.contains("--caps=")
            || lower.contains("--user=root")
            || lower.contains("--reuid=0"))
    {
        return Some("CAP_SETUID:reuid_root");
    }
    // CAP_NET_RAW abuse: tcpdump / raw socket craft from non-root.
    if argv0_base == "tcpdump" || argv0_base == "tshark" || argv0_base == "wireshark" {
        return Some("CAP_NET_RAW:raw_sniff");
    }
    // CAP_SYS_PTRACE abuse: gdb / strace attaching to arbitrary pid.
    if (argv0_base == "gdb" || argv0_base == "strace")
        && (lower.contains(" -p ") || lower.contains(" --pid "))
    {
        return Some("CAP_SYS_PTRACE:remote_attach");
    }
    // CAP_SYS_MODULE abuse: modprobe / insmod from non-root.
    if argv0_base == "modprobe" || argv0_base == "insmod" || argv0_base == "rmmod" {
        return Some("CAP_SYS_MODULE:kernel_module_load");
    }
    None
}

const TRUSTED_PARENTS: &[&str] = &["systemd", "init", "kthreadd", "containerd-shim"];

pub struct CapabilitiesAbuseDetector {
    host: String,
    last_fired: HashMap<String, DateTime<Utc>>,
    cooldown: Duration,
}

impl CapabilitiesAbuseDetector {
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
        let uid = event
            .details
            .get("uid")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        if uid == 0 {
            // root holds these caps legitimately; nothing to flag.
            return None;
        }

        // Need the event to carry the cap list. eBPF capability hooks
        // include it; auditd events do not. Skip when absent — better
        // to under-fire than to fire on every non-root exec.
        let caps: Vec<String> = event
            .details
            .get("capabilities")
            .or_else(|| event.details.get("caps_effective"))
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();
        if caps.is_empty() {
            return None;
        }
        let dangerous: Vec<&String> = caps
            .iter()
            .filter(|c| DANGEROUS_CAPS.iter().any(|d| c.eq_ignore_ascii_case(d)))
            .collect();
        if dangerous.is_empty() {
            return None;
        }

        let parent_comm = event
            .details
            .get("parent_comm")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if is_trusted_parent(parent_comm) {
            return None;
        }

        let argv0 = event
            .details
            .get("argv")
            .and_then(|v| v.get(0))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let argv0_base = argv0.split('/').next_back().unwrap_or(argv0);
        let command = event
            .details
            .get("command")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let exploitation = argv_matches_exploitation(argv0_base, command)?;

        let comm = event
            .details
            .get("comm")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let pid = event
            .details
            .get("pid")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);

        let now = event.ts;
        let key = format!("{uid}:{exploitation}");
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
                "capabilities_abuse:{exploitation}:{}",
                now.format("%Y-%m-%dT%H:%M:%SZ")
            ),
            severity: Severity::Critical,
            title: format!("Capabilities abuse: {exploitation} (uid={uid})"),
            summary: format!(
                "Non-root process (uid={uid}, comm=`{comm}`, parent=`{parent_comm}`, pid={pid}) \
                 holds dangerous caps ({}) and executed `{argv0_base}` with an argv shape \
                 matching the `{exploitation}` exploitation pattern: `{command}`. T1548.005 / \
                 T1068.",
                dangerous
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            evidence: serde_json::json!([{
                "kind": "capabilities_abuse",
                "exploitation": exploitation,
                "uid": uid,
                "capabilities": caps,
                "dangerous_caps": dangerous,
                "argv0": argv0,
                "comm": comm,
                "parent_comm": parent_comm,
                "command": command,
                "pid": pid,
                "mitre": ["T1548.005", "T1068"],
            }]),
            recommended_checks: vec![
                format!("getpcaps {pid} — confirm caps on the live process"),
                format!("ls -la $(which {argv0_base}); getcap $(which {argv0_base})"),
                "Investigate how the non-root user acquired these caps (file-caps, ambient, inherited)".to_string(),
                "If a known workflow legitimately needs this cap+argv pair, allowlist via [detectors.capabilities_abuse]".to_string(),
            ],
            tags: vec!["privesc".to_string(), "capabilities".to_string()],
            entities: vec![],
        })
    }
}

fn is_trusted_parent(parent_comm: &str) -> bool {
    if parent_comm.is_empty() {
        return false;
    }
    let base = parent_comm.split('/').next_back().unwrap_or(parent_comm);
    let base = base.trim_matches(|c: char| c == '(' || c == ')');
    TRUSTED_PARENTS.iter().any(|p| base.starts_with(p))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cap_exec_event(
        argv0: &str,
        command: &str,
        uid: u64,
        caps: &[&str],
        parent_comm: &str,
    ) -> Event {
        let caps_v: Vec<String> = caps.iter().map(|s| s.to_string()).collect();
        Event {
            ts: Utc::now(),
            host: "test".into(),
            source: "ebpf".into(),
            kind: "shell.command_exec".into(),
            severity: Severity::Info,
            summary: format!("cap exec {command}"),
            details: serde_json::json!({
                "pid": 4242,
                "uid": uid,
                "ppid": 4241,
                "capabilities": caps_v,
                "comm": "bash",
                "parent_comm": parent_comm,
                "command": command,
                "argv": [argv0],
                "argc": 1,
            }),
            tags: vec![],
            entities: vec![],
        }
    }

    #[test]
    fn fires_on_cap_dac_read_search_reading_shadow() {
        let mut det = CapabilitiesAbuseDetector::new("test");
        let ev = cap_exec_event(
            "/usr/bin/cat",
            "cat /etc/shadow",
            1000,
            &["CAP_DAC_READ_SEARCH"],
            "bash",
        );
        let inc = det.process(&ev).expect("should fire");
        assert!(inc.incident_id.contains("CAP_DAC_READ_SEARCH"));
    }

    #[test]
    fn fires_on_cap_sys_admin_mount_bind() {
        let mut det = CapabilitiesAbuseDetector::new("test");
        let ev = cap_exec_event(
            "/usr/bin/mount",
            "mount --bind /proc /tmp/p",
            1000,
            &["CAP_SYS_ADMIN"],
            "bash",
        );
        let inc = det.process(&ev).expect("should fire");
        assert!(inc.incident_id.contains("CAP_SYS_ADMIN"));
    }

    #[test]
    fn fires_on_cap_setuid_capsh_reuid_0() {
        let mut det = CapabilitiesAbuseDetector::new("test");
        let ev = cap_exec_event(
            "/usr/sbin/capsh",
            "capsh --caps='cap_setuid+ep' -- --reuid=0",
            1000,
            &["CAP_SETUID"],
            "bash",
        );
        let inc = det.process(&ev).expect("should fire");
        assert!(inc.incident_id.contains("CAP_SETUID"));
    }

    #[test]
    fn fires_on_cap_sys_ptrace_strace_attach() {
        let mut det = CapabilitiesAbuseDetector::new("test");
        let ev = cap_exec_event(
            "/usr/bin/strace",
            "strace -p 1234",
            1000,
            &["CAP_SYS_PTRACE"],
            "bash",
        );
        let inc = det.process(&ev).expect("should fire");
        assert!(inc.incident_id.contains("CAP_SYS_PTRACE"));
    }

    #[test]
    fn silences_root_uid() {
        let mut det = CapabilitiesAbuseDetector::new("test");
        let ev = cap_exec_event(
            "/usr/bin/cat",
            "cat /etc/shadow",
            0,
            &["CAP_DAC_READ_SEARCH"],
            "bash",
        );
        assert!(det.process(&ev).is_none());
    }

    #[test]
    fn silences_systemd_parent() {
        let mut det = CapabilitiesAbuseDetector::new("test");
        let ev = cap_exec_event(
            "/usr/bin/cat",
            "cat /etc/shadow",
            1000,
            &["CAP_DAC_READ_SEARCH"],
            "systemd",
        );
        assert!(det.process(&ev).is_none());
    }

    #[test]
    fn ignores_when_no_dangerous_cap() {
        let mut det = CapabilitiesAbuseDetector::new("test");
        let ev = cap_exec_event(
            "/usr/bin/cat",
            "cat /etc/shadow",
            1000,
            &["CAP_FOWNER", "CAP_CHOWN"],
            "bash",
        );
        assert!(det.process(&ev).is_none());
    }

    #[test]
    fn ignores_when_argv_not_exploitation_shape() {
        let mut det = CapabilitiesAbuseDetector::new("test");
        // Has cap, but argv is benign — cat'ing /etc/hostname isn't
        // exploitation even with the cap held.
        let ev = cap_exec_event(
            "/usr/bin/cat",
            "cat /etc/hostname",
            1000,
            &["CAP_DAC_READ_SEARCH"],
            "bash",
        );
        assert!(det.process(&ev).is_none());
    }

    #[test]
    fn dedupes_within_cooldown() {
        let mut det = CapabilitiesAbuseDetector::new("test");
        let ev = cap_exec_event(
            "/usr/bin/cat",
            "cat /etc/shadow",
            1000,
            &["CAP_DAC_READ_SEARCH"],
            "bash",
        );
        assert!(det.process(&ev).is_some());
        let mut ev2 = ev.clone();
        ev2.ts = ev.ts + Duration::seconds(60);
        assert!(det.process(&ev2).is_none());
    }
}
