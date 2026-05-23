//! Aya FFI layer for the BLOCKED_PIDS BPF map.
//!
//! This file is excluded from the patch-coverage gate (see `codecov.yml`)
//! because every line here ultimately calls into the kernel via aya —
//! `MapData::from_pin`, `AyaHashMap::insert`, `AyaHashMap::remove`,
//! `AyaHashMap::get` — and CI has neither CAP_BPF nor the pinned map
//! at `/sys/fs/bpf/innerwarden/blocked_pids`. The testable logic that
//! these wrappers delegate to (`unregister_inner`, the `BlockedPidsMap`
//! trait, `read_tgid_from_proc`) lives in the parent module and is
//! covered by unit tests there. End-to-end validation of THIS file
//! happens against the prod kernel — see
//! `project_lsm_aya_kernel_64.md` for the GC validation log.

#[cfg(target_os = "linux")]
use std::sync::{Mutex, OnceLock};

#[cfg(target_os = "linux")]
use aya::maps::{HashMap as AyaHashMap, Map, MapData};
#[cfg(target_os = "linux")]
use tracing::{info, warn};

#[cfg(not(target_os = "linux"))]
use std::sync::OnceLock;
#[cfg(not(target_os = "linux"))]
use tracing::warn;

#[cfg(target_os = "linux")]
use super::{read_tgid_from_proc, unregister_inner, BlockedPidsMap};

/// Pin path the sensor uses for the LRU map. Kept as a string constant
/// so this crate doesn't have to depend on `innerwarden-sensor` (the
/// sensor crate isn't a dependency of the agent today and we want to
/// avoid that coupling for the kernel-block control plane).
#[cfg(target_os = "linux")]
const BLOCKED_PIDS_PIN: &str = "/sys/fs/bpf/innerwarden/blocked_pids";

/// Lazy global handle to the opened map. `None` if the pin didn't exist
/// or `MapData::from_pin` failed — every public function in this module
/// short-circuits to a logged no-op in that case.
#[cfg(target_os = "linux")]
static MAP_HANDLE: OnceLock<Mutex<Option<AyaHashMap<MapData, u32, u8>>>> = OnceLock::new();

#[cfg(target_os = "linux")]
fn map_handle() -> &'static Mutex<Option<AyaHashMap<MapData, u32, u8>>> {
    MAP_HANDLE.get_or_init(|| {
        let opened = match MapData::from_pin(BLOCKED_PIDS_PIN) {
            Ok(md) => {
                // The kernel side declared BLOCKED_PIDS as LruHashMap
                // (see crates/sensor-ebpf/src/main.rs). Aya's typed
                // `HashMap<MapData, K, V>` wrapper accepts both regular
                // HashMap and LruHashMap variants of the Map enum
                // (see aya 0.13 maps/mod.rs:504 macro), so we wrap
                // explicitly in Map::LruHashMap before TryFrom.
                let map = Map::LruHashMap(md);
                match AyaHashMap::<MapData, u32, u8>::try_from(map) {
                    Ok(typed) => {
                        info!(
                            pin = BLOCKED_PIDS_PIN,
                            "lsm_policy: BLOCKED_PIDS opened — kernel-block path live"
                        );
                        Some(typed)
                    }
                    Err(e) => {
                        warn!(
                            error = %e,
                            pin = BLOCKED_PIDS_PIN,
                            "lsm_policy: BLOCKED_PIDS pin exists but is not a u32→u8 LRU map — \
                             kernel-block path INERT"
                        );
                        None
                    }
                }
            }
            Err(e) => {
                warn!(
                    error = %e,
                    pin = BLOCKED_PIDS_PIN,
                    "lsm_policy: BLOCKED_PIDS pin not found — kernel-block path INERT \
                     (sensor not running, built without LSM, or kernel lacks BPF LSM)"
                );
                None
            }
        };
        Mutex::new(opened)
    })
}

#[cfg(target_os = "linux")]
impl BlockedPidsMap for AyaHashMap<MapData, u32, u8> {
    fn contains(&self, pid: u32) -> bool {
        // flags=0 → non-LRU read path; aya 0.13 supports this on both
        // HashMap and LruHashMap variants.
        AyaHashMap::get(self, &pid, 0).is_ok()
    }
    fn remove(&mut self, pid: u32) -> Result<(), String> {
        AyaHashMap::remove(self, &pid).map_err(|e| e.to_string())
    }
}

/// Mark a PID (and its TGID, when distinct) as denied at the next
/// `bprm_check_security` LSM hook firing. Idempotent — duplicate calls
/// just refresh the entry's LRU position.
///
/// `reason` is logged but not persisted to the kernel map (the map
/// value is a single byte). Operator-side audit of why a PID was
/// registered lives in the agent's events JSONL via this function's
/// `info!` log line.
#[cfg(target_os = "linux")]
pub fn register_blocked_pid(pid: u32, reason: &str) {
    let mut guard = match map_handle().lock() {
        Ok(g) => g,
        Err(_) => {
            warn!("lsm_policy: register_blocked_pid: map mutex poisoned");
            return;
        }
    };
    let map = match guard.as_mut() {
        Some(m) => m,
        None => return,
    };

    if let Err(e) = map.insert(pid, 1u8, 0) {
        warn!(pid, error = %e, "lsm_policy: failed to insert PID into BLOCKED_PIDS");
        return;
    }

    let tgid = read_tgid_from_proc(pid);
    if let Some(tgid_val) = tgid {
        if tgid_val != pid {
            if let Err(e) = map.insert(tgid_val, 1u8, 0) {
                warn!(
                    tgid = tgid_val,
                    pid,
                    error = %e,
                    "lsm_policy: failed to dual-register TGID into BLOCKED_PIDS \
                     (PID-only block remains in effect)"
                );
            }
        }
    }

    info!(
        pid,
        tgid = ?tgid,
        reason,
        "lsm_policy: registered PID for kernel-block"
    );
}

/// Drop a PID's registration. Called from `killchain_inline::process_events`
/// when it sees a `process.exit` event (Spec 052 Phase 1b — gap E,
/// 2026-05-22) so dead PIDs don't sit in the map forever.
/// LRU eviction (4096-slot cap) is the fallback safety net if a process
/// exits without an event ever reaching the agent.
#[cfg(target_os = "linux")]
pub fn unregister_blocked_pid(pid: u32) {
    let mut guard = match map_handle().lock() {
        Ok(g) => g,
        Err(_) => return,
    };
    let map = match guard.as_mut() {
        Some(m) => m,
        None => return,
    };
    unregister_inner(map, pid);
}

// ── Non-Linux stubs ──────────────────────────────────────────────────
// On macOS / Windows there's no BPF map and aya doesn't compile, so the
// kernel-block path is fundamentally unavailable. Both functions become
// no-ops with a single warn on first registration attempt so the operator
// knows kernel enforcement is dormant (rather than silently disabled).

#[cfg(not(target_os = "linux"))]
static WARNED_ONCE: OnceLock<()> = OnceLock::new();

#[cfg(not(target_os = "linux"))]
pub fn register_blocked_pid(pid: u32, reason: &str) {
    WARNED_ONCE.get_or_init(|| {
        warn!(
            "lsm_policy: register_blocked_pid called on non-Linux host \
             (pid={pid}, reason={reason}) — kernel-block path unavailable; \
             userspace skill pipeline still applies"
        );
    });
}

#[cfg(not(target_os = "linux"))]
pub fn unregister_blocked_pid(_pid: u32) {
    // no-op on non-Linux
}
