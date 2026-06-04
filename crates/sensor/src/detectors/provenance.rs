//! Privilege provenance primitives (Spec 070).
//!
//! Technique-independent helpers for deciding whether a privileged process
//! acquired or is using its privilege through a LEGITIMATE path. The escalation
//! *mechanism* of an LPE is unknowable (every CVE differs), but the end-state is
//! observable: a process now holds root / capabilities, or is performing a
//! root-only action, and its PROVENANCE (executable, parent, namespace, caps)
//! does not justify it.
//!
//! Everything here keys on NON-FORGEABLE signals:
//!   - `/proc/<pid>/exe` (kernel-maintained symlink — defeats `prctl(PR_SET_NAME)`
//!     and `argv[0]` spoofing that the comm-based allowlists fall for),
//!   - the exe's on-disk owner + mode (attacker payloads live in writable dirs),
//!   - `/proc/<pid>/cgroup` (container context),
//!   - `/proc/<pid>/status` `CapEff`.
//!
//! These are DETECT-LAYER ENRICHERS. They never suppress an incident at detect
//! time; they attach a [`Provenance`] verdict that downstream layers (severity
//! downgrade, baseline, AI triage) consume. Aggressive detect, layered FP.
//!
//! Constants are compile-time (never a per-host `allowlist.toml`, deprecated in
//! spec 054), so every install benefits identically.

/// Non-writable system prefixes — the only trusted homes for privileged
/// binaries. A uid-0 process executing from outside these is suspect.
pub const TRUSTED_EXE_PREFIXES: &[&str] = &[
    "/usr/bin/",
    "/usr/sbin/",
    "/bin/",
    "/sbin/",
    "/usr/lib/",
    "/usr/lib64/",
    "/lib/",
    "/lib64/",
    "/usr/libexec/",
    "/lib/systemd/",
    "/usr/lib/systemd/",
    "/snap/",
    "/opt/",
    "/nix/store/",
];

/// Unprivileged-writable roots. exec / library provenance from here, for a
/// uid-0 process, is the untrusted-root-execution signature.
pub const UNPRIV_WRITABLE_PREFIXES: &[&str] = &[
    "/tmp/",
    "/var/tmp/",
    "/dev/shm/",
    "/home/",
    "/run/user/",
    "/run/lock/",
    "/var/lib/lxcfs/",
];

/// Legitimate privilege-escalation ancestors, identified by EXE PATH (not the
/// forgeable comm). A uid->0 transition whose parent exe is one of these is an
/// authorized escalation (the user typed a password / a login happened).
pub const TRUSTED_ESCALATION_EXES: &[&str] = &[
    "/usr/bin/sudo",
    "/bin/sudo",
    "/usr/bin/sudoedit",
    "/usr/bin/su",
    "/bin/su",
    "/usr/bin/pkexec",
    "/usr/bin/login",
    "/bin/login",
    "/usr/sbin/sshd",
    "/usr/sbin/crond",
    "/usr/sbin/cron",
    "/usr/sbin/atd",
    "/lib/systemd/systemd",
    "/usr/lib/systemd/systemd",
    "/usr/bin/systemd-run",
    "/usr/bin/runuser",
    "/usr/sbin/runuser",
    "/usr/bin/machinectl",
    "/usr/bin/dbus-daemon",
    "/usr/bin/dbus-broker",
];

/// Substrings that, when present in `/proc/<pid>/cgroup`, mark a container /
/// managed-runtime context where exec-from-overlay and root-setns are normal.
pub const CONTAINER_CGROUP_HINTS: &[&str] = &[
    "docker",
    "containerd",
    "cri-containerd",
    "kubepods",
    "kubelet",
    "libpod",
    "crio",
    "lxc",
    "machine.slice",
    "buildkit",
    "/actions_job/",
    "/runner",
];

/// Provenance verdict attached to an incident. Never used to DROP at detect
/// time — only to set severity / tags that downstream layers consume.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provenance {
    /// A non-forgeable signal vouches for legitimacy (trusted exe/parent, or
    /// container-runtime context).
    Trusted,
    /// Could not be attributed (exe gone, kernel task, race). Fail-SAFE: this
    /// is NOT downgraded — an attacker racing the read must not earn Trusted.
    Unknown,
    /// A non-forgeable signal contradicts legitimacy (exe in a writable path,
    /// illegitimate parent). The strongest evidence of an exploit.
    Illegitimate,
}

impl Provenance {
    /// Stable tag for evidence + dashboard.
    pub fn tag(self) -> &'static str {
        match self {
            Provenance::Trusted => "provenance:trusted",
            Provenance::Unknown => "provenance:unknown",
            Provenance::Illegitimate => "provenance:illegitimate",
        }
    }
}

/// Resolved, non-forgeable facts about a process.
#[derive(Debug, Clone, Default)]
pub struct ProcProvenance {
    /// `readlink /proc/<pid>/exe` (None if the process is gone or a kernel task).
    pub exe: Option<String>,
    /// `readlink /proc/<ppid>/exe`.
    pub parent_exe: Option<String>,
    pub ppid: u32,
    /// First container hint found in `/proc/<pid>/cgroup`, if any.
    pub cgroup_hint: Option<String>,
    /// True iff the exe lives in an unprivileged-writable path, OR its file is
    /// owned by a non-root uid, OR it is group/other-writable.
    pub exe_writable: bool,
}

/// True iff `path` starts with any prefix in `prefixes`.
pub fn has_prefix(path: &str, prefixes: &[&str]) -> bool {
    prefixes.iter().any(|p| path.starts_with(p))
}

/// True iff `exe` is a legitimate escalation binary by absolute path.
pub fn is_trusted_escalation_exe(exe: &str) -> bool {
    TRUSTED_ESCALATION_EXES.contains(&exe)
}

/// True iff the cgroup hint marks a container / managed-runtime context.
pub fn cgroup_is_container(hint: Option<&str>) -> bool {
    matches!(hint, Some(h) if CONTAINER_CGROUP_HINTS.iter().any(|c| h.contains(c)))
}

/// True iff an executable path is suspicious for a uid-0 process: it lives in a
/// known unprivileged-writable root. (Ownership/mode is checked separately by
/// the resolver where the fs is available.)
pub fn exe_path_is_unprivileged(exe: &str) -> bool {
    has_prefix(exe, UNPRIV_WRITABLE_PREFIXES)
        // Anything NOT under a trusted system prefix is also suspect for root.
        || !has_prefix(exe, TRUSTED_EXE_PREFIXES)
}

/// `readlink /proc/<pid>/exe`. None for kernel threads / exited processes.
pub fn read_exe(pid: u32) -> Option<String> {
    std::fs::read_link(format!("/proc/{pid}/exe"))
        .ok()
        .map(|p| p.to_string_lossy().into_owned())
        // A deleted exe reads as "/path/to/bin (deleted)"; strip the suffix so
        // prefix checks still work, but the deletion itself is suspicious and is
        // surfaced by callers via `exe_writable`/`Illegitimate`.
        .map(|s| {
            s.strip_suffix(" (deleted)")
                .map(str::to_string)
                .unwrap_or(s)
        })
}

/// First [`CONTAINER_CGROUP_HINTS`] substring present in `/proc/<pid>/cgroup`.
pub fn read_cgroup_hint(pid: u32) -> Option<String> {
    let content = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()?;
    for hint in CONTAINER_CGROUP_HINTS {
        if content.contains(hint) {
            return Some((*hint).to_string());
        }
    }
    None
}

/// True iff the file at `exe` is owned by a non-root uid OR is group/other
/// writable — i.e. an unprivileged user could have planted/altered it.
#[cfg(target_os = "linux")]
pub fn exe_file_is_writable(exe: &str) -> bool {
    use std::os::unix::fs::MetadataExt;
    match std::fs::metadata(exe) {
        Ok(m) => m.uid() != 0 || (m.mode() & 0o022) != 0,
        // Can't stat (gone / in a foreign mount ns): treat as not-provably-safe,
        // but callers combine this with the path check, so a missing stat alone
        // does not force Illegitimate.
        Err(_) => false,
    }
}

#[cfg(not(target_os = "linux"))]
pub fn exe_file_is_writable(_exe: &str) -> bool {
    false
}

/// Resolve the non-forgeable provenance of `pid` (and its parent `ppid`).
pub fn resolve(pid: u32, ppid: u32) -> ProcProvenance {
    let exe = read_exe(pid);
    let parent_exe = if ppid != 0 { read_exe(ppid) } else { None };
    let cgroup_hint = read_cgroup_hint(pid);
    let exe_writable = exe
        .as_deref()
        .map(|e| has_prefix(e, UNPRIV_WRITABLE_PREFIXES) || exe_file_is_writable(e))
        .unwrap_or(false);
    ProcProvenance {
        exe,
        parent_exe,
        ppid,
        cgroup_hint,
        exe_writable,
    }
}

impl ProcProvenance {
    /// Verdict for an EXECVE / process-running context (invariant 2a):
    /// is this uid-0 process running attacker-controlled code?
    pub fn root_exec_verdict(&self) -> Provenance {
        // Container/managed-runtime exec-from-overlay is expected.
        if cgroup_is_container(self.cgroup_hint.as_deref()) {
            return Provenance::Trusted;
        }
        match self.exe.as_deref() {
            None => Provenance::Unknown, // kernel task / raced exit
            Some(exe) => {
                if self.exe_writable || exe_path_is_unprivileged(exe) {
                    Provenance::Illegitimate
                } else if has_prefix(exe, TRUSTED_EXE_PREFIXES) {
                    Provenance::Trusted
                } else {
                    Provenance::Unknown
                }
            }
        }
    }

    /// Verdict for a uid->0 ESCALATION (invariant 1a): did it come through a
    /// legitimate escalation path? Decided by NON-FORGEABLE exe paths (self or
    /// parent), not the comm — so a payload renamed `sudo` in `/tmp` is caught.
    pub fn escalation_verdict(&self) -> Provenance {
        if cgroup_is_container(self.cgroup_hint.as_deref()) {
            return Provenance::Trusted;
        }
        // Self IS a trusted escalation binary (e.g. /usr/bin/sudo calling
        // commit_creds), or its parent is one (login/sshd spawning a shell).
        if let Some(e) = self.exe.as_deref() {
            if is_trusted_escalation_exe(e) {
                return Provenance::Trusted;
            }
        }
        if let Some(p) = self.parent_exe.as_deref() {
            if is_trusted_escalation_exe(p) {
                return Provenance::Trusted;
            }
        }
        // The escalating process's own exe in a writable path is decisive.
        if self.exe_writable {
            return Provenance::Illegitimate;
        }
        // Parent runs from a writable path → attacker-controlled chain.
        if let Some(p) = self.parent_exe.as_deref() {
            if exe_path_is_unprivileged(p) {
                return Provenance::Illegitimate;
            }
        }
        Provenance::Unknown
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefixes_classify() {
        assert!(has_prefix("/usr/bin/ls", TRUSTED_EXE_PREFIXES));
        assert!(has_prefix("/tmp/x", UNPRIV_WRITABLE_PREFIXES));
        assert!(!has_prefix("/usr/bin/ls", UNPRIV_WRITABLE_PREFIXES));
    }

    #[test]
    fn trusted_escalation_exact_match_only() {
        assert!(is_trusted_escalation_exe("/usr/bin/sudo"));
        // A renamed payload at /tmp/sudo must NOT pass (path, not basename).
        assert!(!is_trusted_escalation_exe("/tmp/sudo"));
        assert!(!is_trusted_escalation_exe("/usr/bin/sudo-evil"));
    }

    #[test]
    fn container_cgroup_detected() {
        assert!(cgroup_is_container(Some(
            "0::/system.slice/docker-abc.scope"
        )));
        assert!(cgroup_is_container(Some("0::/kubepods/pod123")));
        assert!(!cgroup_is_container(Some("0::/user.slice/user-1000.slice")));
        assert!(!cgroup_is_container(None));
    }

    #[test]
    fn root_exec_verdict_writable_is_illegitimate() {
        let p = ProcProvenance {
            exe: Some("/home/user/.cache/payload".to_string()),
            parent_exe: None,
            ppid: 0,
            cgroup_hint: None,
            exe_writable: true,
        };
        assert_eq!(p.root_exec_verdict(), Provenance::Illegitimate);
    }

    #[test]
    fn root_exec_verdict_trusted_path() {
        let p = ProcProvenance {
            exe: Some("/usr/bin/apt".to_string()),
            parent_exe: None,
            ppid: 0,
            cgroup_hint: None,
            exe_writable: false,
        };
        assert_eq!(p.root_exec_verdict(), Provenance::Trusted);
    }

    #[test]
    fn root_exec_verdict_container_is_trusted() {
        let p = ProcProvenance {
            exe: Some("/tmp/whatever".to_string()),
            parent_exe: None,
            ppid: 0,
            cgroup_hint: Some("docker".to_string()),
            exe_writable: true,
        };
        assert_eq!(p.root_exec_verdict(), Provenance::Trusted);
    }

    #[test]
    fn root_exec_verdict_unknown_when_exe_gone() {
        let p = ProcProvenance {
            exe: None,
            parent_exe: None,
            ppid: 0,
            cgroup_hint: None,
            exe_writable: false,
        };
        assert_eq!(p.root_exec_verdict(), Provenance::Unknown);
    }

    #[test]
    fn escalation_verdict_sudo_parent_trusted() {
        let p = ProcProvenance {
            exe: Some("/usr/bin/sudo".to_string()),
            parent_exe: Some("/usr/bin/sudo".to_string()),
            ppid: 10,
            cgroup_hint: None,
            exe_writable: false,
        };
        assert_eq!(p.escalation_verdict(), Provenance::Trusted);
    }

    #[test]
    fn escalation_verdict_tmp_exe_illegitimate() {
        let p = ProcProvenance {
            exe: Some("/tmp/exploit".to_string()),
            parent_exe: Some("/bin/bash".to_string()),
            ppid: 10,
            cgroup_hint: None,
            exe_writable: true,
        };
        assert_eq!(p.escalation_verdict(), Provenance::Illegitimate);
    }

    #[test]
    fn escalation_verdict_unknown_kernel_task() {
        let p = ProcProvenance {
            exe: None,
            parent_exe: None,
            ppid: 0,
            cgroup_hint: None,
            exe_writable: false,
        };
        assert_eq!(p.escalation_verdict(), Provenance::Unknown);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn resolve_reads_live_proc_for_self() {
        // Exercises the real /proc readers (read_exe, read_cgroup_hint,
        // exe_file_is_writable, resolve) against this test process.
        let me = std::process::id();
        let p = resolve(me, me);
        assert!(p.exe.is_some(), "own /proc/<pid>/exe must be readable");
        // A non-existent pid yields None (the kernel-task / raced branch).
        assert!(read_exe(u32::MAX).is_none());
        // cgroup hint + writable check are best-effort; just drive them.
        let _ = read_cgroup_hint(me);
        let _ = exe_file_is_writable(p.exe.as_deref().unwrap_or("/bin/true"));
        // Verdicts on the live data must not panic.
        let _ = p.root_exec_verdict();
        let _ = p.escalation_verdict();
    }

    #[test]
    fn exe_path_unprivileged_logic() {
        assert!(exe_path_is_unprivileged("/tmp/x"));
        assert!(exe_path_is_unprivileged("/var/data/custom-bin")); // not under trusted
        assert!(!exe_path_is_unprivileged("/usr/bin/ls"));
        assert!(!exe_path_is_unprivileged("/snap/foo/bar"));
    }
}
