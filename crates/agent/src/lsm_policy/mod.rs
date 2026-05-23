//! Agent-side control plane for the kernel LSM block (Spec 052 Phase 1b).
//!
//! Opens the `BLOCKED_PIDS` LRU map that the sensor pinned at
//! `/sys/fs/bpf/innerwarden/blocked_pids` (see
//! `crates/sensor/src/collectors/ebpf_syscall.rs`) and exposes
//! `register_blocked_pid` / `unregister_blocked_pid` for the kill chain
//! detector and process-exit GC to call.
//!
//! INV-LSM-03: every map write goes through this module's
//! `register_blocked_pid` — no other code in the agent or sensor pokes
//! the map directly.
//!
//! INV-LSM-07: `register_blocked_pid` writes BOTH the PID (thread id)
//! and the TGID (process id, looked up via `/proc/<pid>/status:Tgid:`)
//! so a chain that matched on a non-main thread still gets blocked at
//! exec time on the main thread of the same process.
//!
//! ## File layout
//!
//! This module is split for one specific reason: the aya FFI wrapper
//! (`aya_impl.rs`) can't be unit-tested in CI because it needs a real
//! kernel BPF map at `BLOCKED_PIDS_PIN` and CAP_BPF. The testable
//! logic — the trait abstraction, the GC inner function, the `/proc`
//! TGID parser — lives in this file and is exercised by the tests at
//! the bottom. `aya_impl.rs` is excluded from the patch-coverage gate
//! in `codecov.yml` for the same reason `main.rs` / `boot.rs` are:
//! an FFI / orchestration boundary that the prod e2e validates.

#[cfg(target_os = "linux")]
use tracing::{info, warn};

mod aya_impl;

#[cfg(target_os = "linux")]
pub use aya_impl::{register_blocked_pid, unregister_blocked_pid};
#[cfg(not(target_os = "linux"))]
pub use aya_impl::{register_blocked_pid, unregister_blocked_pid};

/// Read `/proc/<pid>/status` and return the `Tgid:` value. Returns
/// `None` if the process has already exited (ENOENT) or status parsing
/// fails — the caller treats that as "couldn't dual-register" and
/// proceeds with the PID-only registration.
//
// dead_code allow on non-Linux: this helper is only called by the Linux
// register_blocked_pid path and the macOS-gated unit test, neither of
// which the workspace clippy run sees on the macOS build cfg.
#[allow(dead_code)]
pub(super) fn read_tgid_from_proc(pid: u32) -> Option<u32> {
    let path = format!("/proc/{pid}/status");
    let content = std::fs::read_to_string(&path).ok()?;
    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("Tgid:") {
            return rest.trim().parse::<u32>().ok();
        }
    }
    None
}

/// Minimal abstraction over the BLOCKED_PIDS map so the probe + remove +
/// log logic in `unregister_inner` is testable without a real BPF map.
/// The aya `HashMap<MapData, u32, u8>` wrapper directly implements this
/// for the production path in `aya_impl.rs`; tests provide an in-memory
/// mock.
#[cfg(target_os = "linux")]
pub(super) trait BlockedPidsMap {
    fn contains(&self, pid: u32) -> bool;
    fn remove(&mut self, pid: u32) -> Result<(), String>;
}

/// Probe-then-remove-then-log. Hot path is every host process.exit
/// (~25-50/s), 99 %+ of which are PIDs we never registered, so we
/// probe first and only log when we actually had an entry.
#[cfg(target_os = "linux")]
pub(super) fn unregister_inner<M: BlockedPidsMap>(map: &mut M, pid: u32) {
    if !map.contains(pid) {
        return;
    }
    match map.remove(pid) {
        Ok(_) => info!(
            pid,
            "lsm_policy: unregistered exited PID from BLOCKED_PIDS (sched_process_exit GC)"
        ),
        Err(e) => warn!(
            pid,
            error = %e,
            "lsm_policy: GC remove failed — entry will sit until LRU eviction"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `read_tgid_from_proc` against the test process itself — pid and
    /// tgid will match (test runs as a single-threaded worker as far
    /// as cargo test is concerned, so `pid == tgid` is expected).
    #[test]
    #[cfg(target_os = "linux")]
    fn read_tgid_from_proc_works_on_self() {
        let pid = std::process::id();
        let tgid = read_tgid_from_proc(pid).expect("self /proc/<pid>/status should be readable");
        // The test process's pid equals its tgid because the main thread
        // is what cargo executes the test in.
        assert_eq!(tgid, pid);
    }

    /// On macOS (no /proc) the helper must return None, not panic.
    #[test]
    #[cfg(target_os = "macos")]
    fn read_tgid_from_proc_returns_none_on_macos() {
        assert!(read_tgid_from_proc(std::process::id()).is_none());
    }

    /// `register_blocked_pid` on a host without the BPF map pinned must
    /// not panic and must not write anywhere; it should log a warn and
    /// return cleanly. We can't verify the map state here (no map), but
    /// we can verify the call completes without panic.
    #[test]
    fn register_blocked_pid_no_pin_is_noop() {
        // The first call to map_handle() on a host without the pin will
        // initialize the OnceLock with None. Subsequent calls are no-ops.
        register_blocked_pid(99999, "test:no_pin");
        unregister_blocked_pid(99999);
    }

    // ── unregister_inner coverage ────────────────────────────────────
    // The production `unregister_blocked_pid` (in aya_impl.rs) opens
    // the BPF map via aya and calls into `unregister_inner`. CI has no
    // BPF map and no CAP_BPF, so we can't exercise the aya path here.
    // Instead, the probe + remove + log logic was extracted into
    // `unregister_inner` generic over `BlockedPidsMap`, and these tests
    // drive it with an in-memory mock to lock down the three behaviours
    // the prod GC path depends on:
    //   1. PID present + remove succeeds  → entry gone, info logged
    //   2. PID present + remove fails     → entry kept, warn logged
    //   3. PID absent                     → silent no-op

    #[cfg(target_os = "linux")]
    struct MockMap {
        entries: std::collections::HashMap<u32, u8>,
        remove_should_fail: bool,
        remove_attempts: usize,
    }

    #[cfg(target_os = "linux")]
    impl BlockedPidsMap for MockMap {
        fn contains(&self, pid: u32) -> bool {
            self.entries.contains_key(&pid)
        }
        fn remove(&mut self, pid: u32) -> Result<(), String> {
            self.remove_attempts += 1;
            if self.remove_should_fail {
                return Err("mock: kernel says no".into());
            }
            self.entries.remove(&pid);
            Ok(())
        }
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn unregister_inner_removes_existing_pid() {
        let mut map = MockMap {
            entries: [(42u32, 1u8)].into_iter().collect(),
            remove_should_fail: false,
            remove_attempts: 0,
        };
        unregister_inner(&mut map, 42);
        assert!(
            !map.entries.contains_key(&42),
            "entry must be gone after successful remove"
        );
        assert_eq!(map.remove_attempts, 1);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn unregister_inner_skips_unknown_pid_without_calling_remove() {
        let mut map = MockMap {
            entries: [(42u32, 1u8)].into_iter().collect(),
            remove_should_fail: false,
            remove_attempts: 0,
        };
        unregister_inner(&mut map, 99);
        assert!(
            map.entries.contains_key(&42),
            "unrelated entry must be untouched"
        );
        assert_eq!(
            map.remove_attempts, 0,
            "remove must NOT be called when contains() says no — that's the whole point of probing first (avoids flooding journald)"
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn unregister_inner_logs_warn_when_remove_fails_but_does_not_panic() {
        let mut map = MockMap {
            entries: [(42u32, 1u8)].into_iter().collect(),
            remove_should_fail: true,
            remove_attempts: 0,
        };
        // Must not panic. The warn path is exercised; the entry stays
        // because the mock's failure path skips the actual remove.
        unregister_inner(&mut map, 42);
        assert_eq!(map.remove_attempts, 1);
        assert!(
            map.entries.contains_key(&42),
            "mock failure path keeps the entry; LRU eviction will eventually drop it in prod"
        );
    }
}
