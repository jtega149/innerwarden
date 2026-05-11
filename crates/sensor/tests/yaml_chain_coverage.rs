//! Anchor: every event-kind referenced in correlation chain YAML must be
//! emitted by at least one detector/collector/agent module.
//!
//! ## Why this exists
//!
//! Graphify 2026-05-10 surfaced as a "surprising connection" that
//! `specs/correlation/cross_layer_rules.yml` references kinds (in chain
//! arrays) that correspond to Rust structs and detector emitters in
//! `crates/sensor/src/`. Without a CI gate, a detector rename or removal
//! silently breaks every correlation chain that referenced the old
//! kind — the rule no longer fires in production, but tests still pass.
//! Class of bug: silent semantic drift between spec YAML and source.
//!
//! ## What this test does
//!
//! 1. Loads `specs/correlation/cross_layer_rules.yml`.
//! 2. Extracts each chain stage's atoms. A "stage" looks like
//!    `"ssh_bruteforce|credential_stuffing"` — splits on `|` into atoms.
//!    Each atom may be exact (`port_scan`), glob suffix (`firmware.*`,
//!    `honeypot*`), or a placeholder (`__multi_low_placeholder__`,
//!    `__silence_placeholder__`) handled by custom code in
//!    `correlation_engine.rs`.
//! 3. Walks the Rust source tree and collects every emitted `"kind":
//!    "<atom>"` literal from `crates/{sensor,agent,killchain,dna}/src/`.
//! 4. Asserts every YAML atom is covered by the catalog (exact, glob-prefix,
//!    or known placeholder).
//!
//! Failure points the operator at the YAML reference that no longer
//! corresponds to an emitter — the fix is either to remove the chain
//! reference or restore the emitter.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use serde_yaml::Value;

const PLACEHOLDER_ATOMS: &[&str] = &[
    // Special-cased in correlation_engine.rs custom logic.
    "__multi_low_placeholder__",
    "__silence_placeholder__",
];

/// Allow-listed chain atoms documented as KNOWN SPEC DRIFT — referenced
/// by `specs/correlation/cross_layer_rules.yml` but with no matching
/// emitter anywhere in the codebase. Each entry must come with a `//
/// why:` comment explaining the situation. Removing an entry here
/// without restoring the emitter (or removing the YAML reference)
/// will fail the integration test.
///
/// The architectural anchor is the test itself: NEW drift introduced
/// by future PRs will fail CI. Existing documented drift surfaces in
/// this list so the next person to clean up the spec knows where to
/// start.
const ALLOWLISTED_KINDS: &[&str] = &[
    // why: CL-006 (Fileless Malware Chain) references the raw syscall
    // names `memfd_create` and `mprotect`, but the sensor's eBPF
    // collector emits these as derived kinds — most notably
    // `memory.mprotect_exec` from `ebpf_syscall.rs:2138` for mprotect,
    // and `fileless_execution` from `fileless.rs:127` for memfd-based
    // execution. The YAML names predate the kind-mapping conventions
    // adopted in spec 014 (knowledge graph). Follow-up: rewrite the
    // CL-006 chain to use `memory.mprotect_exec` and
    // `fileless_execution`, OR re-introduce explicit kinds named after
    // the raw syscalls. Tracked as spec-drift item, not a regression
    // from this PR.
    "memfd_create",
    "mprotect",
    // why: CL-007 (Reverse Shell via eBPF Sequence) references
    // `dup.redirect`, but the eBPF collector emits `shell.command_exec`
    // (ebpf_syscall.rs:192) with no `dup.*` family kind. Same class as
    // memfd_create/mprotect above. Either CL-007 needs to chain
    // against `shell.command_exec` + `network.outbound_connect`, or the
    // collector needs a dedicated `dup.redirect` event kind for the
    // dup2/dup3 stdio rewiring pattern reverse shells use.
    "dup.redirect",
    // why: CL-024 / CL-025 / CL-027 reference `user_agent_scanner` as
    // a chain atom, but the detector at
    // `crates/sensor/src/detectors/user_agent_scanner.rs:103` emits
    // `incident_id: format!("scanner_ua:{}:{}:{}", ...)`. The detector
    // FILE is named user_agent_scanner but the incident PREFIX is
    // `scanner_ua`. `detector_from_incident_id` returns `scanner_ua`,
    // not `user_agent_scanner`, so the chain rule references in YAML
    // never match in production. Spec drift since the rename. Fix:
    // either rename the YAML atoms to `scanner_ua` OR change the
    // detector's incident_id format to use `user_agent_scanner:`.
    "user_agent_scanner",
    // why: CL-028 (Discovery to Credential Access) references three
    // synthetic discovery kinds that have NO emitter anywhere. The
    // strings appear in `correlation_engine.rs` only as `kind_patterns`
    // declarations on the CL-028 RuleStage itself — a Rust mirror of
    // the YAML rule, not an event source. Pure spec dead code at the
    // moment. Follow-up: either implement a discovery-burst detector
    // family that emits these kinds, or merge into the existing
    // `discovery_burst:{}:` incident_id prefix.
    "file_discovery",
    "network_discovery",
    "process_discovery",
    // why: CL-018 (eBPF Weaponization Detection) references the glob
    // `lsm.bpf*`, expecting at least one event kind starting with
    // `lsm.bpf`. The LSM-on-BPF program-load hook exists
    // (`crates/sensor/src/collectors/ebpf_syscall.rs:525` attaches
    // `innerwarden_lsm_bpf`) and a real "new eBPF program loaded"
    // event IS emitted by `crates/sensor/src/collectors/kernel_integrity.rs`
    // as `kind: "kernel.bpf_program_loaded"` — but under the
    // `kernel.*` family, not `lsm.*`. The chain needs to point at
    // `kernel.bpf_program_loaded`, or the kernel_integrity collector
    // should mint a parallel `lsm.bpf_program_loaded` event when the
    // LSM hook is what triggered the discovery. Either way, the YAML
    // atom is stale relative to the actual emitter.
    "lsm.bpf*",
];

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates/sensor parent")
        .parent()
        .expect("workspace root")
        .to_path_buf()
}

fn collect_emitted_kinds() -> HashSet<String> {
    let mut kinds = HashSet::new();
    let root = workspace_root();
    let scan_dirs = [
        "crates/sensor/src",
        "crates/agent/src",
        "crates/killchain/src",
        "crates/dna/src",
        "crates/core/src",
    ];
    for dir in scan_dirs {
        let abs = root.join(dir);
        if !abs.exists() {
            continue;
        }
        let pattern = abs.join("**/*.rs");
        for entry in glob::glob(pattern.to_str().expect("utf8")).expect("glob pattern") {
            let path = match entry {
                Ok(p) => p,
                Err(_) => continue,
            };
            if let Ok(content) = std::fs::read_to_string(&path) {
                extract_kinds_into(&content, &mut kinds);
                extract_incident_id_detectors_into(&content, &mut kinds);
                extract_layer_event_kinds_into(&content, &mut kinds);
                extract_rust_field_kind_into(&content, &mut kinds);
                extract_dotted_quoted_strings_into(&content, &mut kinds);
            }
        }
    }
    kinds
}

/// Pull every `"kind": "<atom>"` literal out of one Rust source file.
/// Matches the canonical `serde_json::json!({"kind": "..."})` pattern
/// that sensor detectors use for the event-emit construct. The match
/// is conservative: kebab/snake_case lowercase letters, digits, `.`,
/// and `_` only. Skips anything that contains formatting `{...}`.
fn extract_kinds_into(content: &str, out: &mut HashSet<String>) {
    // Token: "kind"  (whitespace) :  (whitespace) "<lowercase + dots>"
    // No regex dep — implemented as a forward scan that's robust to
    // multi-line indentation in serde_json::json! macros.
    let bytes = content.as_bytes();
    let needle = b"\"kind\"";
    let mut i = 0;
    while i + needle.len() <= bytes.len() {
        if &bytes[i..i + needle.len()] == needle {
            let mut j = i + needle.len();
            while j < bytes.len() && (bytes[j] == b' ' || bytes[j] == b'\t') {
                j += 1;
            }
            if j < bytes.len() && bytes[j] == b':' {
                j += 1;
                while j < bytes.len()
                    && (bytes[j] == b' ' || bytes[j] == b'\t' || bytes[j] == b'\n')
                {
                    j += 1;
                }
                if j < bytes.len() && bytes[j] == b'"' {
                    j += 1;
                    let start = j;
                    while j < bytes.len() && bytes[j] != b'"' && bytes[j] != b'\n' {
                        j += 1;
                    }
                    if j < bytes.len() && bytes[j] == b'"' {
                        if let Ok(atom) = std::str::from_utf8(&bytes[start..j]) {
                            if is_valid_kind_literal(atom) {
                                out.insert(atom.to_string());
                            }
                        }
                    }
                }
            }
            i = j.max(i + 1);
        } else {
            i += 1;
        }
    }
}

fn is_valid_kind_literal(s: &str) -> bool {
    !s.is_empty()
        && !s.contains('{')
        && !s.contains('}')
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '.')
}

/// Pull every `incident_id: format!("DETECTOR:..."` detector prefix out
/// of one Rust source file. The correlation engine derives the chain
/// kind from `detector_from_incident_id` (the part before the first
/// `:`), so any incident this codebase emits with that prefix becomes
/// a valid chain atom in YAML.
fn extract_incident_id_detectors_into(content: &str, out: &mut HashSet<String>) {
    let bytes = content.as_bytes();
    let needle = b"incident_id:";
    let mut i = 0;
    while i + needle.len() <= bytes.len() {
        if &bytes[i..i + needle.len()] == needle {
            let mut j = i + needle.len();
            // Skip whitespace + an optional `format!(` token wrapper.
            while j < bytes.len()
                && (bytes[j] == b' ' || bytes[j] == b'\t' || bytes[j] == b'\n' || bytes[j] == b'\r')
            {
                j += 1;
            }
            let fmt_prefix = b"format!(";
            if j + fmt_prefix.len() <= bytes.len() && &bytes[j..j + fmt_prefix.len()] == fmt_prefix
            {
                j += fmt_prefix.len();
                while j < bytes.len()
                    && (bytes[j] == b' '
                        || bytes[j] == b'\t'
                        || bytes[j] == b'\n'
                        || bytes[j] == b'\r')
                {
                    j += 1;
                }
            }
            if j < bytes.len() && bytes[j] == b'"' {
                j += 1;
                let start = j;
                while j < bytes.len() && bytes[j] != b'"' && bytes[j] != b':' && bytes[j] != b'\n' {
                    j += 1;
                }
                if j < bytes.len() && bytes[j] == b':' {
                    if let Ok(atom) = std::str::from_utf8(&bytes[start..j]) {
                        if is_valid_kind_literal(atom) {
                            out.insert(atom.to_string());
                        }
                    }
                }
            }
            i = j.max(i + 1);
        } else {
            i += 1;
        }
    }
}

/// Pull every `kind: "X"` Rust struct field literal (with optional
/// `.to_string()`) out of one Rust source file. Collectors emit
/// `Event { kind: "file.encrypted_write".to_string(), ... }`-style
/// literals rather than JSON `"kind"` keys.
///
/// Heuristic to avoid false positives: only match when the `kind`
/// identifier is at a word boundary (not e.g. `inkind`, `mankind`).
/// The byte preceding must be whitespace, `(`, `,`, `{`, or `:` (the
/// last covers `Self::kind:` and similar struct paths). Accept `kind`
/// followed by `:` then optional whitespace then a quoted string with
/// optional `.to_string()` suffix.
fn extract_rust_field_kind_into(content: &str, out: &mut HashSet<String>) {
    let bytes = content.as_bytes();
    let needle = b"kind:";
    let mut i = 0;
    while i + needle.len() <= bytes.len() {
        if &bytes[i..i + needle.len()] == needle {
            // Word-boundary check on the preceding byte. `"kind":` (JSON
            // form, prefixed with `"`) is handled by extract_kinds_into,
            // so skip it here to avoid double-counting.
            let prev_ok = if i == 0 {
                true
            } else {
                matches!(
                    bytes[i - 1],
                    b' ' | b'\t' | b'\n' | b'\r' | b'(' | b',' | b'{'
                )
            };
            if !prev_ok {
                i += 1;
                continue;
            }
            let mut j = i + needle.len();
            while j < bytes.len()
                && (bytes[j] == b' ' || bytes[j] == b'\t' || bytes[j] == b'\n' || bytes[j] == b'\r')
            {
                j += 1;
            }
            if j < bytes.len() && bytes[j] == b'"' {
                j += 1;
                let start = j;
                while j < bytes.len() && bytes[j] != b'"' && bytes[j] != b'\n' {
                    j += 1;
                }
                if j < bytes.len() && bytes[j] == b'"' {
                    if let Ok(atom) = std::str::from_utf8(&bytes[start..j]) {
                        if is_valid_kind_literal(atom) {
                            out.insert(atom.to_string());
                        }
                    }
                }
            } else if j + b"format!(".len() <= bytes.len()
                && &bytes[j..j + b"format!(".len()] == b"format!("
            {
                // `kind: format!("memory.{}", ...)` — extract the literal
                // prefix before the first `{` placeholder and register
                // it as a dynamic-family marker (`prefix*`). Any chain
                // atom glob `memory.anon*` then matches via the
                // `covered_by` dynamic-family rule.
                j += b"format!(".len();
                while j < bytes.len()
                    && (bytes[j] == b' '
                        || bytes[j] == b'\t'
                        || bytes[j] == b'\n'
                        || bytes[j] == b'\r')
                {
                    j += 1;
                }
                if j < bytes.len() && bytes[j] == b'"' {
                    j += 1;
                    let start = j;
                    while j < bytes.len()
                        && bytes[j] != b'"'
                        && bytes[j] != b'{'
                        && bytes[j] != b'\n'
                    {
                        j += 1;
                    }
                    let prefix = if start < j {
                        std::str::from_utf8(&bytes[start..j]).unwrap_or("")
                    } else {
                        ""
                    };
                    // Only treat as a kind family when the prefix is a
                    // valid kind shape (lowercase + dots + underscores)
                    // and ends in a separator that signals further
                    // dynamic content. `memory.` is a family; `port_`
                    // would not be (it's an unsafe partial).
                    if (prefix.ends_with('.') || prefix.ends_with('_'))
                        && prefix.len() > 1
                        && is_valid_kind_literal(prefix)
                    {
                        out.insert(format!("{prefix}*"));
                    }
                }
            }
            i = j.max(i + 1);
        } else {
            i += 1;
        }
    }
}

/// Pull every quoted-string literal that has the shape of a dotted
/// event kind (`"layer.specific_event"`) out of one Rust source file.
/// Catches struct-field literals embedded in conditional expressions
/// where `extract_rust_field_kind_into` cannot follow:
/// ```ignore
/// Event { kind: if cond { "file.encrypted_write".to_string() } else { ... } }
/// ```
/// Also catches array-of-strings patterns like firmware_integrity.rs's
/// `vec!["firmware.efivar_changed", ...]`.
///
/// Preprocessing: strips `//`-line, `/* */`-block, and doc (`///`,
/// `//!`) comments before scanning so a chain atom that was REMOVED
/// from emitter code but still mentioned in a doc comment does NOT
/// falsely register as covered. CodeRabbit flagged this on PR #525:
/// without the strip, a stale doc-comment reference like
/// `/// example: emits "file.zombie_kind"` would silently mark
/// `file.zombie_kind` as covered even after the real emitter was
/// deleted.
///
/// Filter: must contain at least one `.` so we don't grab unrelated
/// short identifiers like `"alice"` or `"openai"` that pass
/// `is_valid_kind_literal`. Single-word kinds (`sigma`, `port_scan`,
/// `web_scan`) are already covered by the incident_id / kind /
/// layer_event scanners.
fn extract_dotted_quoted_strings_into(content: &str, out: &mut HashSet<String>) {
    let stripped = strip_rust_comments(content);
    let bytes = stripped.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'"' {
            let start = i + 1;
            let mut j = start;
            while j < bytes.len() && bytes[j] != b'"' && bytes[j] != b'\n' {
                j += 1;
            }
            if j < bytes.len() && bytes[j] == b'"' {
                if let Ok(s) = std::str::from_utf8(&bytes[start..j]) {
                    if s.contains('.') && is_valid_kind_literal(s) {
                        out.insert(s.to_string());
                    }
                }
            }
            i = j + 1;
        } else {
            i += 1;
        }
    }
}

/// Replace every `//`-line and `/* */`-block comment (including `///`
/// and `//!` doc comments) in `content` with spaces of the same
/// length. Keeps byte offsets aligned with the original — failure
/// diagnostics still point at the right column — but the
/// dotted-quoted scanner sees only real code, never doc comment text.
///
/// String-literal aware: a `//` inside `"..."` is NOT treated as a
/// comment start. Handles `\"` escapes so we don't exit a string
/// early. Newlines are preserved so line counts stay consistent.
fn strip_rust_comments(content: &str) -> String {
    let bytes = content.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'"' {
            out.push(bytes[i]);
            i += 1;
            while i < bytes.len() {
                if bytes[i] == b'\\' && i + 1 < bytes.len() {
                    out.push(bytes[i]);
                    out.push(bytes[i + 1]);
                    i += 2;
                    continue;
                }
                let b = bytes[i];
                out.push(b);
                i += 1;
                if b == b'"' || b == b'\n' {
                    break;
                }
            }
            continue;
        }
        if i + 1 < bytes.len() && bytes[i] == b'/' && bytes[i + 1] == b'/' {
            while i < bytes.len() && bytes[i] != b'\n' {
                out.push(b' ');
                i += 1;
            }
            continue;
        }
        if i + 1 < bytes.len() && bytes[i] == b'/' && bytes[i + 1] == b'*' {
            out.push(b' ');
            out.push(b' ');
            i += 2;
            while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                out.push(if bytes[i] == b'\n' { b'\n' } else { b' ' });
                i += 1;
            }
            if i + 1 < bytes.len() {
                out.push(b' ');
                out.push(b' ');
                i += 2;
            }
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8(out).unwrap_or_default()
}

/// Pull every `{layer}_event("KIND", ...)` call out of one Rust source
/// file. `firmware_event`, `killchain_event`, `hypervisor_event` are the
/// correlation_engine constructors that take the kind as the first
/// positional argument. Any literal there is a valid chain atom.
fn extract_layer_event_kinds_into(content: &str, out: &mut HashSet<String>) {
    let bytes = content.as_bytes();
    for needle in [
        b"firmware_event(".as_slice(),
        b"killchain_event(".as_slice(),
        b"hypervisor_event(".as_slice(),
        b"honeypot_event(".as_slice(),
    ] {
        let mut i = 0;
        while i + needle.len() <= bytes.len() {
            if &bytes[i..i + needle.len()] == needle {
                let mut j = i + needle.len();
                while j < bytes.len()
                    && (bytes[j] == b' '
                        || bytes[j] == b'\t'
                        || bytes[j] == b'\n'
                        || bytes[j] == b'\r')
                {
                    j += 1;
                }
                if j < bytes.len() && bytes[j] == b'"' {
                    j += 1;
                    let start = j;
                    while j < bytes.len() && bytes[j] != b'"' && bytes[j] != b'\n' {
                        j += 1;
                    }
                    if j < bytes.len() && bytes[j] == b'"' {
                        if let Ok(atom) = std::str::from_utf8(&bytes[start..j]) {
                            if is_valid_kind_literal(atom) {
                                out.insert(atom.to_string());
                            }
                        }
                    }
                }
                i = j.max(i + 1);
            } else {
                i += 1;
            }
        }
    }
}

fn load_cross_layer_rules() -> Value {
    let path = workspace_root()
        .join("specs")
        .join("correlation")
        .join("cross_layer_rules.yml");
    let content =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {}", path.display(), e));
    serde_yaml::from_str(&content).unwrap_or_else(|e| panic!("parse {}: {}", path.display(), e))
}

fn chain_atoms(yaml: &Value) -> Vec<(String, String)> {
    let rules = yaml["rules"].as_sequence().expect("rules: sequence");
    let mut out = Vec::new();
    for rule in rules {
        let rid = rule["id"]
            .as_str()
            .map(str::to_string)
            .unwrap_or_else(|| "<no-id>".into());
        let chain = match rule.get("chain").and_then(|v| v.as_sequence()) {
            Some(c) => c,
            None => continue,
        };
        for stage in chain {
            let stage_s = match stage.as_str() {
                Some(s) => s,
                None => continue,
            };
            for atom in stage_s.split('|') {
                let atom = atom.trim();
                if atom.is_empty() {
                    continue;
                }
                out.push((rid.clone(), atom.to_string()));
            }
        }
    }
    out
}

fn covered_by(atom: &str, kinds: &HashSet<String>) -> bool {
    if PLACEHOLDER_ATOMS.contains(&atom) {
        return true;
    }
    if ALLOWLISTED_KINDS.contains(&atom) {
        return true;
    }
    if let Some(prefix) = atom.strip_suffix(".*") {
        let dotted = format!("{prefix}.");
        // (a) any exact kind starts with `prefix.`
        if kinds.iter().any(|k| k.starts_with(&dotted)) {
            return true;
        }
        // (b) a dynamic-family marker `prefix.*` is registered.
        return kinds.contains(&format!("{prefix}.*"));
    }
    if let Some(prefix) = atom.strip_suffix('*') {
        if prefix.is_empty() {
            return !kinds.is_empty();
        }
        // (a) any kind starts with `prefix` directly
        if kinds.iter().any(|k| k.starts_with(prefix)) {
            return true;
        }
        // (b) dynamic-family marker covers a SUPER-set. For atom
        // `memory.anon*`, walk up the prefix tree (`memory.anon` →
        // `memory.` → break) checking for a registered `family*`.
        // This catches `kind: format!("memory.{}", ...)` emitters that
        // can produce `memory.anon_*` at runtime. Guard: each step
        // must strictly shorten `cursor` to prevent the infinite loop
        // observed when `cursor` already ends in a separator (the
        // rfind returns the trailing separator, slicing yields the
        // same string).
        let mut cursor: &str = prefix;
        loop {
            if kinds.contains(&format!("{cursor}*")) {
                return true;
            }
            match cursor.rfind(|c: char| c == '.' || c == '_') {
                Some(idx) if idx + 1 < cursor.len() => {
                    cursor = &cursor[..idx + 1];
                }
                _ => break,
            }
        }
        return false;
    }
    kinds.contains(atom)
}

#[test]
fn cross_layer_rules_chain_kinds_are_all_emitted() {
    let kinds = collect_emitted_kinds();
    assert!(
        !kinds.is_empty(),
        "no emitted kinds found — the scanner regressed; check workspace_root() and the scan dirs"
    );

    let yaml = load_cross_layer_rules();
    let atoms = chain_atoms(&yaml);
    assert!(
        !atoms.is_empty(),
        "no atoms extracted from cross_layer_rules.yml — check the YAML shape (expected `rules: [{{id,chain}}]`)"
    );

    let mut missing: Vec<(String, String)> = atoms
        .into_iter()
        .filter(|(_, atom)| !covered_by(atom, &kinds))
        .collect();
    missing.sort();
    missing.dedup();

    if !missing.is_empty() {
        let detail = missing
            .iter()
            .map(|(rid, atom)| format!("  {rid}: {atom}"))
            .collect::<Vec<_>>()
            .join("\n");
        panic!(
            "cross_layer_rules.yml references chain atoms with no emitter in any \
             scanned crate. The most likely cause is a detector that emitted these \
             kinds was renamed or removed without updating the YAML. The fix is \
             either to restore the emitter or to remove the dangling reference. \
             For atoms that are emitted via a non-standard pattern (not the \
             canonical `\"kind\": \"...\"` literal), add to ALLOWLISTED_KINDS \
             with a `// why:` comment.\n\n\
             Missing atoms (rule_id: atom):\n{detail}\n\n\
             Catalog size (for sanity): {} emitted kinds across the scanned crates.",
            kinds.len()
        );
    }
}

// ---------------------------------------------------------------------------
// Unit tests for the helpers — keep these green so the integration test
// failure mode is clearly "spec drift", not "scanner bug".
// ---------------------------------------------------------------------------

#[cfg(test)]
mod helpers {
    use super::*;

    #[test]
    fn extract_kinds_picks_up_canonical_serde_json_literal() {
        let src = r#"
            let evt = serde_json::json!({
                "kind": "credential_harvest",
                "ts": now,
            });
        "#;
        let mut out = HashSet::new();
        extract_kinds_into(src, &mut out);
        assert!(out.contains("credential_harvest"), "got: {out:?}");
    }

    #[test]
    fn extract_kinds_handles_inline_single_line() {
        let src = r#"event.kind = "data_exfiltration"; let _ = "kind": "kernel_module_load" "#;
        let mut out = HashSet::new();
        extract_kinds_into(src, &mut out);
        assert!(out.contains("kernel_module_load"), "got: {out:?}");
    }

    #[test]
    fn extract_kinds_rejects_format_placeholders() {
        // `format!("kind": "{}", x)` would otherwise be treated as a
        // literal — the `{}` filter in `is_valid_kind_literal` rejects.
        let src = r#""kind": "{}" "#;
        let mut out = HashSet::new();
        extract_kinds_into(src, &mut out);
        assert!(out.is_empty(), "format placeholder leaked: {out:?}");
    }

    #[test]
    fn extract_kinds_ignores_uppercase_and_special_chars() {
        let src = r#""kind": "Bad-Kind!""#;
        let mut out = HashSet::new();
        extract_kinds_into(src, &mut out);
        assert!(out.is_empty(), "non-lowercase kind leaked: {out:?}");
    }

    #[test]
    fn covered_by_handles_exact() {
        let mut k = HashSet::new();
        k.insert("port_scan".to_string());
        assert!(covered_by("port_scan", &k));
        assert!(!covered_by("port_scan2", &k));
    }

    #[test]
    fn covered_by_handles_dotted_glob() {
        let mut k = HashSet::new();
        k.insert("firmware.msr_write".to_string());
        assert!(covered_by("firmware.*", &k));
        assert!(!covered_by("kernel.*", &k));
    }

    #[test]
    fn extract_dotted_quoted_strings_picks_up_struct_field_in_if_else() {
        // Mirrors fanotify_watch.rs:159-162 layout: a struct-field kind
        // whose value is an if-else returning quoted literals. The
        // narrow `extract_rust_field_kind_into` scanner does not enter
        // the brace body; the dotted broad-pass catches them.
        let src = r#"
            let ev = Event {
                source: "fanotify".to_string(),
                kind: if encrypted {
                    "file.encrypted_write".to_string()
                } else {
                    "file.realtime_modified".to_string()
                },
            };
        "#;
        let mut out = HashSet::new();
        extract_dotted_quoted_strings_into(src, &mut out);
        assert!(out.contains("file.encrypted_write"), "got: {out:?}");
        assert!(out.contains("file.realtime_modified"), "got: {out:?}");
    }

    #[test]
    fn extract_dotted_quoted_strings_ignores_doc_comment_examples() {
        // CodeRabbit regression anchor (PR #525 review): a chain atom
        // removed from emitter code but still mentioned in a doc
        // comment MUST NOT register as covered. The `///` example
        // here uses `file.zombie_kind` — if the strip is removed,
        // the test fails because the catalog falsely includes it.
        let src = r#"
            /// Demonstration only — emits "file.zombie_kind" historically;
            /// modern code uses the kind below.
            fn nothing() {
                // also "file.deleted_kind" once, but no longer
                /* commented "file.block_kind" example */
            }
        "#;
        let mut out = HashSet::new();
        extract_dotted_quoted_strings_into(src, &mut out);
        assert!(
            !out.contains("file.zombie_kind"),
            "doc comment leaked into catalog: {out:?}"
        );
        assert!(
            !out.contains("file.deleted_kind"),
            "line comment leaked: {out:?}"
        );
        assert!(
            !out.contains("file.block_kind"),
            "block comment leaked: {out:?}"
        );
    }

    #[test]
    fn extract_dotted_quoted_strings_keeps_real_emitters_after_strip() {
        // Confirm the strip preserves actual quoted-string emitters
        // in code. fanotify_watch.rs's struct-field literal pattern
        // must still register.
        let src = r#"
            /// This collector emits "file.encrypted_write" — legit doc.
            let ev = Event {
                kind: if encrypted {
                    "file.encrypted_write".to_string()
                } else {
                    "file.realtime_modified".to_string()
                },
            };
        "#;
        let mut out = HashSet::new();
        extract_dotted_quoted_strings_into(src, &mut out);
        assert!(out.contains("file.encrypted_write"), "got: {out:?}");
        assert!(out.contains("file.realtime_modified"), "got: {out:?}");
    }

    #[test]
    fn strip_rust_comments_preserves_string_literal_content() {
        // A `//` inside a quoted string must NOT be treated as a
        // comment start. Otherwise the strip would mangle real
        // emitters that contain URL fragments or path strings.
        let src = r#"let url = "http://example.com/path"; // trailing comment"#;
        let stripped = strip_rust_comments(src);
        assert!(
            stripped.contains("http://example.com/path"),
            "got: {stripped}"
        );
        assert!(
            !stripped.contains("trailing comment"),
            "real comment leaked: {stripped}"
        );
    }

    #[test]
    fn extract_dotted_quoted_strings_rejects_undotted_strings() {
        // Single-word identifiers like `"alice"` or `"openai"` are
        // not kinds. The `.` requirement filters them out so the
        // catalog stays precise.
        let src = r#"
            let user = "alice";
            let provider = "openai";
        "#;
        let mut out = HashSet::new();
        extract_dotted_quoted_strings_into(src, &mut out);
        assert!(out.is_empty(), "undotted strings leaked: {out:?}");
    }

    #[test]
    fn covered_by_walks_up_to_dynamic_family_marker() {
        // Catalog has `memory.*` registered as a family marker (from a
        // `kind: format!("memory.{}", ...)` emitter). Chain atom is
        // `memory.anon*` — walk-up rule must climb to the family root.
        let mut k = HashSet::new();
        k.insert("memory.*".to_string());
        assert!(covered_by("memory.anon*", &k));
        assert!(covered_by("memory.rwx*", &k));
    }

    #[test]
    fn covered_by_does_not_loop_on_trailing_separator() {
        // Regression anchor: an earlier walk-up tried `cursor[..idx+1]`
        // unconditionally, which left `cursor` unchanged when the only
        // separator was the trailing character. The test binary hung
        // at 99% CPU for 5 minutes. Asserts the walk terminates and
        // returns false cleanly for an atom that has no covering kind.
        let k = HashSet::new();
        assert!(!covered_by("memory.anon*", &k));
        assert!(!covered_by("foo.bar.baz*", &k));
    }

    #[test]
    fn covered_by_handles_prefix_glob() {
        let mut k = HashSet::new();
        k.insert("honeypot_session".to_string());
        assert!(covered_by("honeypot*", &k));
    }

    #[test]
    fn covered_by_accepts_placeholder() {
        let k = HashSet::new();
        assert!(covered_by("__multi_low_placeholder__", &k));
        assert!(covered_by("__silence_placeholder__", &k));
    }

    #[test]
    fn extract_incident_id_detectors_picks_up_format_macro() {
        let src = r#"
            incident_id: format!("port_scan:{}:{}", ip, ts),
            incident_id: format!("ssh_bruteforce:{ip}:{ts}"),
        "#;
        let mut out = HashSet::new();
        extract_incident_id_detectors_into(src, &mut out);
        assert!(out.contains("port_scan"), "got: {out:?}");
        assert!(out.contains("ssh_bruteforce"), "got: {out:?}");
    }

    #[test]
    fn extract_incident_id_detectors_handles_multiline_format() {
        let src = r#"
            incident_id: format!(
                "credential_harvest:{}:{}",
                ip, ts
            ),
        "#;
        let mut out = HashSet::new();
        extract_incident_id_detectors_into(src, &mut out);
        assert!(out.contains("credential_harvest"), "got: {out:?}");
    }

    #[test]
    fn extract_layer_event_kinds_picks_up_constructor_arg() {
        let src = r#"
            firmware_event("msr_write", json!({}))
            killchain_event("c2_beacon", json!({}))
            hypervisor_event("vm_escape", json!({}))
        "#;
        let mut out = HashSet::new();
        extract_layer_event_kinds_into(src, &mut out);
        assert!(out.contains("msr_write"), "got: {out:?}");
        assert!(out.contains("c2_beacon"), "got: {out:?}");
        assert!(out.contains("vm_escape"), "got: {out:?}");
    }

    #[test]
    fn chain_atoms_splits_or_alternatives() {
        let yaml: Value = serde_yaml::from_str(
            r#"
rules:
  - id: CL-XX
    chain: ["a|b", "c"]
"#,
        )
        .unwrap();
        let atoms: Vec<_> = chain_atoms(&yaml).into_iter().map(|(_, a)| a).collect();
        assert_eq!(atoms, vec!["a", "b", "c"]);
    }
}
