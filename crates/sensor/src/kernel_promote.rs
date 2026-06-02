//! Spec 069 follow-up #2 — promote orphan high-signal kernel syscall events
//! to incidents, with **layered** false-positive containment.
//!
//! ## Why
//!
//! Post-#919 the eBPF ring reader emits `process.ptrace_attach` (Critical),
//! `memory.mprotect_exec` RWX (Critical), `filesystem.mount` in-container
//! (Critical) and `process.memfd_create` (High). Before this module **no
//! sensor detector matched those kinds, no correlation rule referenced them,
//! and `is_passthrough_source` is a hardcoded `false`** — so they landed in
//! the DB + knowledge graph but never became incidents, never reached AI
//! triage, never triggered a response. An attacker using direct
//! ptrace/mprotect/memfd/mount was *seen but not acted on*.
//!
//! ## Philosophy: detect wide, contain FP across layers (never at detect time)
//!
//! Suppressing at detection loses coverage. Instead we promote aggressively
//! and let InnerWarden's existing layers strip false positives **before the
//! operator sees an alert**:
//!
//! 1. **Default allowlist** (this module) — `comm` sets of common-good actors
//!    that are stable *across* servers (debuggers ptrace; JIT runtimes mark
//!    RWX; init/desktop/container managers use memfd). Curated + documented.
//! 2. **Per-server allowlist** — `DynamicAllowlist::is_process_allowed`
//!    (`allowlist.toml`), so operators tune each host without a recompile.
//! 3. **Incident suppression** — `DetectorSet::is_incident_suppressed`
//!    (per-kind `kernel_*` name) at the call site in `process_event`.
//! 4. **Agent layers (downstream, no code here)** — baseline learned-normal,
//!    cloud safelist, and the AI `decide()` triage decide block vs ignore.
//!
//! Only an event that survives **all** layers reaches the operator.

use innerwarden_core::event::{Event, Severity};
use innerwarden_core::incident::Incident;

use crate::detectors::allowlists::DynamicAllowlist;

/// Debuggers legitimately `ptrace` other processes.
const PTRACE_DEBUGGERS: &[&str] = &[
    "gdb",
    "gdbserver",
    "strace",
    "ltrace",
    "lldb",
    "lldb-server",
    "valgrind",
    "rr",
    "perf",
    "dlv",
    "drgn",
    "crash",
    "bpftrace",
    "memcheck",
    "callgrind",
];

/// JIT / managed runtimes legitimately mark memory RWX.
const JIT_RUNTIMES: &[&str] = &[
    "node",
    "java",
    "python",
    "python3",
    "dotnet",
    "mono",
    "ruby",
    "php",
    "beam.smp",
    "erlang",
    "julia",
    "luajit",
    "v8",
    "chrome",
    "chromium",
    "firefox",
    "wine",
    "wineserver",
    "qemu",
    "qemu-system",
    "clr",
    "node.js",
    "deno",
    "bun",
    "Web Content",
    "WebKitWebProc",
];

/// Processes that legitimately use `memfd_create`.
const MEMFD_LEGIT: &[&str] = &[
    "systemd",
    "systemd-udevd",
    "(sd-pam)",
    "dbus-daemon",
    "dbus-broker",
    "snapd",
    "chrome",
    "chromium",
    "firefox",
    "gnome-shell",
    "pulseaudio",
    "pipewire",
    "wireplumber",
    "docker",
    "containerd",
    "dockerd",
    "crun",
    "runc",
    "qemu",
    "qemu-system",
    "Xorg",
    "Xwayland",
];

/// PTRACE request ops that read/write/control another process — the
/// injection / credential-dump surface. PEEK (read) ops are deliberately
/// excluded as too noisy; ATTACH/SEIZE are the entry to any injection.
/// POKETEXT=4 POKEDATA=5 POKEUSR=6 SETREGS=13 SETFPREGS=15 ATTACH=16
/// SETREGSET=0x4205 SEIZE=0x4206.
fn ptrace_op_is_invasive(req: u64) -> bool {
    matches!(req, 4 | 5 | 6 | 13 | 15 | 16 | 0x4205 | 0x4206)
}

/// Normalise a comm to its base name (strip a path, strip kernel-thread
/// parens) for allowlist comparison.
fn comm_base(comm: &str) -> &str {
    let b = comm.rsplit('/').next().unwrap_or(comm);
    b.trim_matches(|c: char| c == '(' || c == ')')
}

/// The per-kind detector name used for incident-level suppression
/// (`is_incident_suppressed`) so operators can tune each independently.
pub(crate) fn suppression_name(kind: &str) -> &'static str {
    match kind {
        "process.ptrace_attach" => "kernel_ptrace",
        "memory.mprotect_exec" => "kernel_mprotect",
        "process.memfd_create" => "kernel_memfd",
        "filesystem.mount" => "kernel_mount",
        _ => "kernel_exploit",
    }
}

fn num(ev: &Event, k: &str) -> u64 {
    ev.details.get(k).and_then(|v| v.as_u64()).unwrap_or(0)
}
fn flag(ev: &Event, k: &str) -> bool {
    ev.details.get(k).and_then(|v| v.as_bool()).unwrap_or(false)
}
fn text<'a>(ev: &'a Event, k: &str) -> &'a str {
    ev.details.get(k).and_then(|v| v.as_str()).unwrap_or("")
}

fn build_incident(
    ev: &Event,
    severity: Severity,
    title: String,
    summary: String,
    checks: Vec<String>,
    tag: &str,
) -> Incident {
    let pid = num(ev, "pid");
    Incident {
        ts: ev.ts,
        host: ev.host.clone(),
        incident_id: format!("kernel:{}:{}:{}", tag, pid, ev.ts.format("%Y-%m-%dT%H:%MZ")),
        severity,
        title,
        summary,
        evidence: serde_json::json!([ev.details]),
        recommended_checks: checks,
        tags: vec![
            "ebpf".to_string(),
            "kernel_exploit".to_string(),
            tag.to_string(),
        ],
        entities: ev.entities.clone(),
    }
}

/// Promote a high-signal kernel syscall event to an incident, or `None` if
/// it is benign / allowlisted. Layers 1 (default allowlist) and 2 (per-server
/// `DynamicAllowlist`) are applied here; layer 3 (incident suppression) is at
/// the call site.
pub(crate) fn kernel_syscall_incident(
    ev: &Event,
    allowlist: &DynamicAllowlist,
) -> Option<Incident> {
    let comm = text(ev, "comm");
    let base = comm_base(comm);
    let pid = num(ev, "pid");

    match ev.kind.as_str() {
        "process.ptrace_attach" => {
            let req = num(ev, "request");
            let target = num(ev, "target_pid");
            // Only invasive ops into a *different* live process.
            if !ptrace_op_is_invasive(req) || target == 0 || target == pid {
                return None;
            }
            if PTRACE_DEBUGGERS.contains(&base)
                || allowlist.is_process_allowed(comm, Some("kernel_ptrace"))
            {
                return None;
            }
            let op = text(ev, "request_name");
            Some(build_incident(
                ev,
                Severity::Critical,
                format!("Process injection via ptrace: {comm} (PID {pid})"),
                format!(
                    "{comm} (PID {pid}) issued {op} against PID {target} — writing to or seizing \
                     another process is the core of code injection and credential dumping (T1055.008 / \
                     T1003). The actor is not a known debugger.",
                ),
                vec![
                    format!("Inspect PID {pid} ({comm}) and its parent — unexpected ptrace source"),
                    format!("Check what PID {target} is and whether its memory was tampered"),
                ],
                "ptrace_injection",
            ))
        }
        "memory.mprotect_exec" => {
            // Only RWX (writable + executable) — the shellcode-staging signal.
            if !flag(ev, "rwx") {
                return None;
            }
            if JIT_RUNTIMES.contains(&base)
                || allowlist.is_process_allowed(comm, Some("kernel_mprotect"))
            {
                return None;
            }
            Some(build_incident(
                ev,
                Severity::Critical,
                format!("RWX memory by non-JIT process: {comm} (PID {pid})"),
                format!(
                    "{comm} (PID {pid}) marked memory read+write+execute at {} ({} bytes). RWX is the \
                     classic shellcode / runtime-unpacking pattern (T1055) and {comm} is not a known \
                     JIT/managed runtime.",
                    text(ev, "addr"),
                    num(ev, "len"),
                ),
                vec![
                    format!("Dump and inspect the RWX region of PID {pid}"),
                    "Confirm the binary is signed/expected; scan for injected shellcode".to_string(),
                ],
                "rwx_mprotect",
            ))
        }
        "process.memfd_create" => {
            if MEMFD_LEGIT.contains(&base)
                || allowlist.is_process_allowed(comm, Some("kernel_memfd"))
            {
                return None;
            }
            Some(build_incident(
                ev,
                Severity::High,
                format!("Fileless payload staging via memfd: {comm} (PID {pid})"),
                format!(
                    "{comm} (PID {pid}) created an anonymous in-memory file ({}). memfd-backed execution \
                     leaves nothing on disk (T1620 fileless) and {comm} is not a known legitimate memfd \
                     user.",
                    text(ev, "name"),
                ),
                vec![
                    format!("Check whether PID {pid} exec'd from the memfd (fexecve)"),
                    format!("Inspect PID {pid} lineage — how was it spawned"),
                ],
                "memfd_fileless",
            ))
        }
        "filesystem.mount" => {
            // Mounting from inside a container is the namespace-escape signal.
            if !flag(ev, "in_container") || allowlist.is_process_allowed(comm, Some("kernel_mount"))
            {
                return None;
            }
            Some(build_incident(
                ev,
                Severity::Critical,
                format!("Mount inside container: {comm} (PID {pid})"),
                format!(
                    "{comm} (PID {pid}) called mount inside a container — mounting the host filesystem or \
                     a sensitive path is a container/namespace escape primitive (T1611). source={} \
                     target={} fs={}.",
                    text(ev, "source"),
                    text(ev, "target"),
                    text(ev, "fs_type"),
                ),
                vec![
                    format!("Identify the container of PID {pid} and what it mounted"),
                    "Verify the container is not privileged / lacks CAP_SYS_ADMIN".to_string(),
                ],
                "container_mount_escape",
            ))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(kind: &str, details: serde_json::Value) -> Event {
        Event {
            ts: chrono::Utc::now(),
            host: "h".into(),
            source: "ebpf".into(),
            kind: kind.into(),
            severity: Severity::High,
            summary: "s".into(),
            details,
            tags: vec![],
            entities: vec![],
        }
    }

    fn empty_allowlist() -> DynamicAllowlist {
        // load() of a missing path yields an empty dynamic allowlist (the
        // static const lists inside allowlists.rs still apply — which is why
        // the positive tests below use clearly attacker-shaped comms).
        DynamicAllowlist::load(std::path::Path::new("/nonexistent/iw-test-allowlist.toml"))
    }

    #[test]
    fn ptrace_invasive_into_other_process_promotes() {
        let inc = kernel_syscall_incident(
            &ev(
                "process.ptrace_attach",
                serde_json::json!({"pid":1000,"target_pid":2000,"request":16,"request_name":"PTRACE_ATTACH","comm":"evil"}),
            ),
            &empty_allowlist(),
        )
        .expect("non-debugger ATTACH into another process must promote");
        assert_eq!(inc.severity, Severity::Critical);
        assert!(inc.tags.contains(&"ptrace_injection".to_string()));
    }

    #[test]
    fn ptrace_debugger_and_self_and_readop_are_benign() {
        // debugger comm
        assert!(kernel_syscall_incident(
            &ev(
                "process.ptrace_attach",
                serde_json::json!({"pid":1,"target_pid":2,"request":16,"comm":"gdb"})
            ),
            &empty_allowlist()
        )
        .is_none());
        // self / thread (target == pid)
        assert!(kernel_syscall_incident(
            &ev(
                "process.ptrace_attach",
                serde_json::json!({"pid":5,"target_pid":5,"request":16,"comm":"evil"})
            ),
            &empty_allowlist()
        )
        .is_none());
        // non-invasive read op (PEEKTEXT=1)
        assert!(kernel_syscall_incident(
            &ev(
                "process.ptrace_attach",
                serde_json::json!({"pid":1,"target_pid":2,"request":1,"comm":"evil"})
            ),
            &empty_allowlist()
        )
        .is_none());
    }

    #[test]
    fn mprotect_rwx_non_jit_promotes_but_jit_and_non_rwx_are_benign() {
        assert!(kernel_syscall_incident(
            &ev(
                "memory.mprotect_exec",
                serde_json::json!({"pid":1,"rwx":true,"addr":"0xdead","len":4096,"comm":"evil"})
            ),
            &empty_allowlist()
        )
        .is_some());
        // JIT runtime
        assert!(kernel_syscall_incident(
            &ev(
                "memory.mprotect_exec",
                serde_json::json!({"pid":1,"rwx":true,"comm":"node"})
            ),
            &empty_allowlist()
        )
        .is_none());
        // not RWX (RX only)
        assert!(kernel_syscall_incident(
            &ev(
                "memory.mprotect_exec",
                serde_json::json!({"pid":1,"rwx":false,"comm":"evil"})
            ),
            &empty_allowlist()
        )
        .is_none());
    }

    #[test]
    fn memfd_non_legit_promotes_legit_is_benign() {
        assert!(kernel_syscall_incident(
            &ev(
                "process.memfd_create",
                serde_json::json!({"pid":1,"name":"x","comm":"evil"})
            ),
            &empty_allowlist()
        )
        .is_some());
        assert!(kernel_syscall_incident(
            &ev(
                "process.memfd_create",
                serde_json::json!({"pid":1,"name":"x","comm":"systemd"})
            ),
            &empty_allowlist()
        )
        .is_none());
    }

    #[test]
    fn mount_in_container_promotes_host_mount_is_benign() {
        let inc = kernel_syscall_incident(
            &ev(
                "filesystem.mount",
                serde_json::json!({"pid":1,"in_container":true,"source":"/dev/sda","target":"/mnt","fs_type":"ext4","comm":"evilmount"}),
            ),
            &empty_allowlist(),
        );
        assert!(inc.is_some());
        assert_eq!(inc.unwrap().severity, Severity::Critical);
        // host-side mount (not in container) is normal admin activity
        assert!(kernel_syscall_incident(
            &ev(
                "filesystem.mount",
                serde_json::json!({"pid":1,"in_container":false,"comm":"mount"})
            ),
            &empty_allowlist()
        )
        .is_none());
    }

    #[test]
    fn unrelated_kind_is_ignored() {
        assert!(kernel_syscall_incident(
            &ev("process.exit", serde_json::json!({"pid":1,"comm":"x"})),
            &empty_allowlist()
        )
        .is_none());
    }

    #[test]
    fn suppression_name_is_per_kind() {
        assert_eq!(suppression_name("process.ptrace_attach"), "kernel_ptrace");
        assert_eq!(suppression_name("memory.mprotect_exec"), "kernel_mprotect");
        assert_eq!(suppression_name("process.memfd_create"), "kernel_memfd");
        assert_eq!(suppression_name("filesystem.mount"), "kernel_mount");
    }
}
