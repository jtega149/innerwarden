//! Aya FFI layer for the Execution Gate live maps (spec 080 G4).
//!
//! Excluded from the patch-coverage gate (see codecov.yml) for the same reason
//! as `lsm_policy/aya_impl.rs`: every line here calls into aya, which calls into
//! the kernel — reading the pinned maps at
//! `/sys/fs/bpf/innerwarden/{exec_allowlist,lsm_policy}` needs CAP_BPF + the real
//! pins, which CI has neither of. The testable verdict logic this delegates to
//! (`innerwarden_core::execution_gate` + the monitor's pure helpers) is
//! unit-tested; end-to-end validation happens against the prod kernel.

#[cfg(target_os = "linux")]
use innerwarden_core::execution_gate;
use innerwarden_core::execution_gate::GateMode;

/// `(live EXEC_ALLOWLIST count, live gate mode)`. `live_count = None` means the
/// map could not be read (no pin, no privilege, non-Linux) — the verdict treats
/// that as "unknown, do not cry wolf".
#[cfg(target_os = "linux")]
pub(crate) fn read_live_gate() -> (Option<usize>, GateMode) {
    (read_live_allowlist_count(), read_live_gate_mode())
}

#[cfg(target_os = "linux")]
fn read_live_allowlist_count() -> Option<usize> {
    use aya::maps::{HashMap as AyaHashMap, Map, MapData};
    let md = MapData::from_pin(execution_gate::EXEC_ALLOWLIST_PIN).ok()?;
    let map = Map::HashMap(md);
    let typed = AyaHashMap::<MapData, u64, u8>::try_from(map).ok()?;
    Some(typed.keys().filter(|k| k.is_ok()).count())
}

#[cfg(target_os = "linux")]
fn read_live_gate_mode() -> GateMode {
    use aya::maps::{HashMap as AyaHashMap, Map, MapData};
    let Ok(md) = MapData::from_pin(execution_gate::LSM_POLICY_PIN) else {
        return GateMode::Inert; // no policy map = nothing consults the gate
    };
    let map = Map::HashMap(md);
    let Ok(typed) = AyaHashMap::<MapData, u32, u32>::try_from(map) else {
        return GateMode::Inert;
    };
    let v = typed.get(&execution_gate::GATE_MODE_KEY, 0).ok();
    GateMode::from_policy_key(v)
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn read_live_gate() -> (Option<usize>, GateMode) {
    // No BPF maps off Linux — unknown live state, inert.
    (None, GateMode::Inert)
}
