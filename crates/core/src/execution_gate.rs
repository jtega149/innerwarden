//! Execution Gate state + divergence verdict (spec 080 G4 — the FREE honesty net).
//!
//! Pure, dependency-light types shared by the agent (live aya map readers + the
//! slow-loop self-incident) and ctl (`doctor`'s read-only report). The honesty
//! rule — same principle as spec 076 block live-verify — is: NEVER trust the
//! signed config file as proof that the kernel is configured. Compare the signed
//! intent to the LIVE pinned map, and raise drift when they disagree, so the
//! paid Execution Gate can never silently go inert (the 2026-06-17 Oracle case:
//! a signed `observe` allowlist with 1685 entries while the kernel gate was
//! inert with 0 entries — staged but never applied).

use serde::{Deserialize, Serialize};

/// Pin path the sensor pins + the paid active-defence watcher writes. Lowercase
/// on purpose (an aya ByName pin would use the UPPERCASE map name; see the
/// spec-080-P0 note in `crates/sensor/src/collectors/ebpf_syscall.rs`).
pub const EXEC_ALLOWLIST_PIN: &str = "/sys/fs/bpf/innerwarden/exec_allowlist";
/// Pin path for the policy map (`u32 -> u32`).
pub const LSM_POLICY_PIN: &str = "/sys/fs/bpf/innerwarden/lsm_policy";
/// LSM_POLICY key 3 = gate_mode (0 inert, 1 enforce, 2 observe). See
/// `crates/sensor-ebpf/src/main.rs`.
pub const GATE_MODE_KEY: u32 = 3;
/// Default signed allowlist file (paid active-defence managed). Shape:
/// `{ "mode": "observe", "entries": { "<fnv>": "<path>", ... } }`.
pub const SIGNED_ALLOWLIST_FILE: &str = "/etc/innerwarden/exec_allowlist.json";

/// The gate's operating mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GateMode {
    /// Loaded but consulted for nothing — denies nothing (the free default).
    Inert,
    /// Denies an unknown exec with `-EPERM` (paid, armed).
    Enforce,
    /// Logs what it *would* deny but allows it (paid, telemetry).
    Observe,
    /// A policy value we don't recognise.
    Unknown,
}

impl GateMode {
    /// From the live LSM_POLICY key-3 value. A missing key (`None`) is inert —
    /// the kernel gate consults nothing until the bit is set.
    pub fn from_policy_key(v: Option<u32>) -> Self {
        match v {
            None | Some(0) => GateMode::Inert,
            Some(1) => GateMode::Enforce,
            Some(2) => GateMode::Observe,
            Some(_) => GateMode::Unknown,
        }
    }

    /// From the signed file's `mode` string.
    pub fn from_str_label(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "observe" => GateMode::Observe,
            "enforce" | "arm" | "armed" | "block" => GateMode::Enforce,
            "inert" | "off" | "disarm" | "disarmed" | "disabled" | "none" => GateMode::Inert,
            _ => GateMode::Unknown,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            GateMode::Inert => "inert",
            GateMode::Enforce => "enforce",
            GateMode::Observe => "observe",
            GateMode::Unknown => "unknown",
        }
    }

    /// Enforce or observe — the gate is actually doing something (and so the
    /// live allowlist had better be populated).
    pub fn is_active(&self) -> bool {
        matches!(self, GateMode::Enforce | GateMode::Observe)
    }
}

/// Live + intended Execution Gate state, gathered from the kernel maps + the
/// signed file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GateState {
    /// Entries in the signed allowlist file (`None` = no file / unreadable).
    pub signed_count: Option<usize>,
    /// Intended mode from the signed file's `mode` field (`None` = no file).
    pub intended_mode: Option<GateMode>,
    /// Entries in the LIVE pinned `EXEC_ALLOWLIST` map (`None` = map unavailable:
    /// gate not loaded, no pin, or no privilege to read it).
    pub live_count: Option<usize>,
    /// Live gate mode from `LSM_POLICY` key 3.
    pub live_mode: GateMode,
}

/// Ignore a live-vs-signed gap smaller than this percent — the paid watcher
/// applies incrementally, so a small transient lag is not drift.
const APPLY_GAP_TOLERANCE_PCT: usize = 5;

/// The verdict of comparing live kernel state to signed intent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Divergence {
    /// Live state matches intent (or nothing is configured) — healthy.
    None,
    /// The gate is ACTIVE (enforce/observe) but the live allowlist is empty.
    /// Enforce + empty = every exec denied (brick); observe + empty = blind.
    /// The single most dangerous state — highest priority.
    ActiveButEmpty { mode: GateMode, live: usize },
    /// A signed config exists (entries and/or an active intended mode) but the
    /// kernel never converged to it: live map short/empty, or live mode inert
    /// while the file intends active. The "staged-not-applied" drift.
    ApplyDrift {
        signed: usize,
        live: usize,
        intended_mode: Option<GateMode>,
        live_mode: GateMode,
    },
}

impl Divergence {
    pub fn is_drift(&self) -> bool {
        !matches!(self, Divergence::None)
    }
}

/// PURE verdict over a [`GateState`]. Order matters: active-but-empty (active
/// danger) outranks staged-not-applied.
///
/// A live map we could not read (`live_count = None`) NEVER produces drift on
/// its own — an unreadable map must not masquerade as "empty" and cry wolf
/// (privilege-blind reader safety).
pub fn evaluate_divergence(s: &GateState) -> Divergence {
    // 1) Live gate armed/observing but the allowlist is empty.
    if s.live_mode.is_active() && s.live_count == Some(0) {
        return Divergence::ActiveButEmpty {
            mode: s.live_mode,
            live: 0,
        };
    }

    // 2) Signed config present but not converged in the kernel. Needs a real
    //    live read to claim drift.
    let signed = s.signed_count.unwrap_or(0);
    let intends_active = s.intended_mode.map(|m| m.is_active()).unwrap_or(false);
    if (signed > 0 || intends_active) && s.live_count.is_some() {
        let live_n = s.live_count.unwrap_or(0);
        let count_drift = signed > 0
            && live_n < signed
            && (live_n == 0 || (signed - live_n) * (100 / APPLY_GAP_TOLERANCE_PCT) > signed);
        let mode_drift = intends_active && !s.live_mode.is_active();
        if count_drift || mode_drift {
            return Divergence::ApplyDrift {
                signed,
                live: live_n,
                intended_mode: s.intended_mode,
                live_mode: s.live_mode,
            };
        }
    }

    Divergence::None
}

/// Parse the signed allowlist file JSON into `(entry_count, intended_mode)`.
/// Canonical shape `{ "mode": "observe", "entries": { ... } }`; tolerates a bare
/// entries array/object. Either component may be absent.
pub fn parse_signed_allowlist(value: &serde_json::Value) -> (Option<usize>, Option<GateMode>) {
    let count = match value.get("entries") {
        Some(e) => count_json_collection(e),
        None => match value {
            serde_json::Value::Array(a) => Some(a.len()),
            // A bare object with no wrapper fields = the entries map itself.
            serde_json::Value::Object(o) if !o.contains_key("mode") => Some(o.len()),
            _ => None,
        },
    };
    let mode = value
        .get("mode")
        .and_then(|m| m.as_str())
        .map(GateMode::from_str_label);
    (count, mode)
}

fn count_json_collection(v: &serde_json::Value) -> Option<usize> {
    match v {
        serde_json::Value::Array(a) => Some(a.len()),
        serde_json::Value::Object(o) => Some(o.len()),
        _ => None,
    }
}

/// Count entries in `bpftool map dump` text. bpftool prints one `key: …` block
/// per entry (or `"key": …` with `-j`), and newer versions append a
/// `Found N elements` summary; an empty map prints only the summary. Returns 0
/// when nothing parses.
pub fn count_bpftool_dump(text: &str) -> usize {
    let key_lines = text
        .lines()
        .filter(|l| {
            let t = l.trim_start();
            t.starts_with("key:") || t.starts_with("\"key\"")
        })
        .count();
    if key_lines > 0 {
        return key_lines;
    }
    for l in text.lines() {
        if let Some(rest) = l.trim().strip_prefix("Found ") {
            if let Some(n) = rest
                .split_whitespace()
                .next()
                .and_then(|x| x.parse::<usize>().ok())
            {
                return n;
            }
        }
    }
    0
}

/// Parse the `value:` u32 (little-endian, first 4 bytes) from a
/// `bpftool map lookup … key … value: BB BB BB BB` line. Used to read the live
/// gate mode (LSM_POLICY key 3) without aya from ctl. Returns `None` if the map
/// has no such key (`bpftool` prints "Not found" / non-zero) or it can't parse.
pub fn parse_bpftool_value_u32(text: &str) -> Option<u32> {
    let after = text.split("value:").nth(1)?;
    let bytes: Vec<u8> = after
        .split_whitespace()
        .take(4)
        .map(|b| u8::from_str_radix(b.trim_start_matches("0x"), 16).ok())
        .collect::<Option<Vec<u8>>>()?;
    if bytes.len() < 4 {
        return None;
    }
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(
        signed: Option<usize>,
        intended: Option<GateMode>,
        live: Option<usize>,
        live_mode: GateMode,
    ) -> GateState {
        GateState {
            signed_count: signed,
            intended_mode: intended,
            live_count: live,
            live_mode,
        }
    }

    #[test]
    fn gate_mode_from_policy_key() {
        assert_eq!(GateMode::from_policy_key(None), GateMode::Inert);
        assert_eq!(GateMode::from_policy_key(Some(0)), GateMode::Inert);
        assert_eq!(GateMode::from_policy_key(Some(1)), GateMode::Enforce);
        assert_eq!(GateMode::from_policy_key(Some(2)), GateMode::Observe);
        assert_eq!(GateMode::from_policy_key(Some(9)), GateMode::Unknown);
    }

    #[test]
    fn gate_mode_from_str_and_active() {
        assert_eq!(GateMode::from_str_label("observe"), GateMode::Observe);
        assert_eq!(GateMode::from_str_label("ENFORCE"), GateMode::Enforce);
        assert_eq!(GateMode::from_str_label(" arm "), GateMode::Enforce);
        assert_eq!(GateMode::from_str_label("inert"), GateMode::Inert);
        assert_eq!(GateMode::from_str_label("wat"), GateMode::Unknown);
        assert!(GateMode::Enforce.is_active());
        assert!(GateMode::Observe.is_active());
        assert!(!GateMode::Inert.is_active());
        assert!(!GateMode::Unknown.is_active());
    }

    #[test]
    fn healthy_when_converged() {
        // armed observe, live populated to signed count — no drift.
        let d = evaluate_divergence(&state(
            Some(1685),
            Some(GateMode::Observe),
            Some(1685),
            GateMode::Observe,
        ));
        assert_eq!(d, Divergence::None);
    }

    #[test]
    fn healthy_when_nothing_configured() {
        // no signed file, gate inert, live readable + empty — an OSS box with
        // the gate loaded but never armed. Silent.
        let d = evaluate_divergence(&state(None, None, Some(0), GateMode::Inert));
        assert_eq!(d, Divergence::None);
    }

    #[test]
    fn the_oracle_case_is_apply_drift() {
        // signed observe / 1685, but kernel inert / 0 — staged-not-applied.
        let d = evaluate_divergence(&state(
            Some(1685),
            Some(GateMode::Observe),
            Some(0),
            GateMode::Inert,
        ));
        assert_eq!(
            d,
            Divergence::ApplyDrift {
                signed: 1685,
                live: 0,
                intended_mode: Some(GateMode::Observe),
                live_mode: GateMode::Inert,
            }
        );
        assert!(d.is_drift());
    }

    #[test]
    fn enforce_with_empty_map_is_active_but_empty_brick_risk() {
        let d = evaluate_divergence(&state(
            Some(1685),
            Some(GateMode::Enforce),
            Some(0),
            GateMode::Enforce,
        ));
        // ActiveButEmpty outranks ApplyDrift: live enforce + empty = brick.
        assert_eq!(
            d,
            Divergence::ActiveButEmpty {
                mode: GateMode::Enforce,
                live: 0
            }
        );
    }

    #[test]
    fn observe_with_empty_map_is_active_but_empty_blind() {
        let d = evaluate_divergence(&state(None, None, Some(0), GateMode::Observe));
        assert_eq!(
            d,
            Divergence::ActiveButEmpty {
                mode: GateMode::Observe,
                live: 0
            }
        );
    }

    #[test]
    fn unreadable_live_map_never_cries_wolf() {
        // signed says observe/1685 but we couldn't read the live map. No drift —
        // a privilege-blind reader must not claim the kernel is empty.
        let d = evaluate_divergence(&state(
            Some(1685),
            Some(GateMode::Observe),
            None,
            GateMode::Inert,
        ));
        assert_eq!(d, Divergence::None);
    }

    #[test]
    fn small_incremental_lag_within_tolerance_is_not_drift() {
        // 1685 signed, 1660 live (~1.5% behind) while still applying — tolerated.
        let d = evaluate_divergence(&state(
            Some(1685),
            Some(GateMode::Observe),
            Some(1660),
            GateMode::Observe,
        ));
        assert_eq!(d, Divergence::None);
    }

    #[test]
    fn large_count_gap_is_drift_even_when_modes_agree() {
        // 1685 signed vs 100 live (94% behind), both observe — apply stalled.
        let d = evaluate_divergence(&state(
            Some(1685),
            Some(GateMode::Observe),
            Some(100),
            GateMode::Observe,
        ));
        assert!(matches!(
            d,
            Divergence::ApplyDrift {
                signed: 1685,
                live: 100,
                ..
            }
        ));
    }

    #[test]
    fn mode_drift_alone_is_flagged() {
        // signed intends enforce, counts match, but live mode is inert.
        let d = evaluate_divergence(&state(
            Some(10),
            Some(GateMode::Enforce),
            Some(10),
            GateMode::Inert,
        ));
        assert!(matches!(
            d,
            Divergence::ApplyDrift {
                live_mode: GateMode::Inert,
                ..
            }
        ));
    }

    #[test]
    fn parse_signed_canonical_shape() {
        let v = serde_json::json!({
            "mode": "observe",
            "entries": { "111": "/usr/bin/a", "222": "/usr/bin/b", "333": "/usr/bin/c" }
        });
        let (count, mode) = parse_signed_allowlist(&v);
        assert_eq!(count, Some(3));
        assert_eq!(mode, Some(GateMode::Observe));
    }

    #[test]
    fn parse_signed_bare_array_and_missing_mode() {
        let v = serde_json::json!(["/a", "/b"]);
        let (count, mode) = parse_signed_allowlist(&v);
        assert_eq!(count, Some(2));
        assert_eq!(mode, None);
    }

    #[test]
    fn parse_signed_bare_entries_object() {
        let v = serde_json::json!({ "111": "/a", "222": "/b" });
        let (count, mode) = parse_signed_allowlist(&v);
        assert_eq!(count, Some(2));
        assert_eq!(mode, None);
    }

    #[test]
    fn count_bpftool_dump_variants() {
        // plain text entries
        let plain = "key: 01 02 03 04  value: 01\nkey: 05 06 07 08  value: 01\n";
        assert_eq!(count_bpftool_dump(plain), 2);
        // empty map summary
        assert_eq!(count_bpftool_dump("Found 0 elements"), 0);
        // json form
        let json = "[{\n\"key\": 1,\n\"value\": 1\n},{\n\"key\": 2,\n\"value\": 1\n}]";
        assert_eq!(count_bpftool_dump(json), 2);
        // nothing parseable
        assert_eq!(count_bpftool_dump("garbage"), 0);
    }

    #[test]
    fn parse_bpftool_value_u32_reads_little_endian() {
        // observe (2) at key 3
        let txt = "key: 03 00 00 00  value: 02 00 00 00";
        assert_eq!(parse_bpftool_value_u32(txt), Some(2));
        // enforce (1)
        assert_eq!(
            parse_bpftool_value_u32("key: 03 00 00 00  value: 01 00 00 00"),
            Some(1)
        );
        // no value section
        assert_eq!(parse_bpftool_value_u32("Not found"), None);
    }
}
