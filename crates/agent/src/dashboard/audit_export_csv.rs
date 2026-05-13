//! Spec 049 PR11 — CSV format for the audit export.
//!
//! Renders an `InvestigationExport` snapshot as RFC 4180 CSV with a
//! metadata header (lines starting with `#`) followed by a single
//! cases table. The operator emails / attaches the file as audit
//! evidence; the MSSP attaches it to the client deliverable.
//!
//! The deliverable is a flattened view of the journey timeline plus
//! a reproducibility hash. Same `period + filters + cases data`
//! always produces the same hash; the `generated_at` timestamp is
//! NOT part of the hash so two exports of the same query at
//! different times still match.
//!
//! NO new dependency. Hand-rolled RFC 4180 quoting:
//!   - If a field contains `,`, `"`, `\r`, or `\n`, wrap in quotes.
//!   - Escape `"` by doubling: `"` → `""`.
//!
//! Pure rendering. No I/O. Testable with `serde_json::Value` as
//! input via the public `render_csv_export` entry point.

use serde_json::Value;
use sha2::{Digest, Sha256};

/// Canonical column set for the cases table. Operator audits these
/// fields per row; field order is part of the wire contract (a
/// future PR that adds a column must append, not reorder).
const COLUMNS: &[&str] = &[
    "ts",
    "kind",
    "severity",
    "detector",
    "incident_id",
    "action_type",
    "target_ip",
    "confidence",
    "execution_result",
    "decision_layer",
    "decision_layer_detail",
    "reason",
];

/// Render an `InvestigationExport` (serialised as a `serde_json::Value`)
/// as CSV with metadata header. Taking JSON keeps the renderer free
/// of dependencies on the Rust struct shape — the test layer can
/// inject hand-crafted snapshots without constructing full
/// `InvestigationExport` instances.
pub(super) fn render_csv_export(snapshot: &Value) -> String {
    let mut out = String::new();

    // ── Metadata header ──
    let generated_at = snapshot
        .get("generated_at")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let date = snapshot.get("date").and_then(|v| v.as_str()).unwrap_or("");
    let subject_type = snapshot
        .get("subject_type")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let subject = snapshot
        .get("subject")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let filters_str = snapshot
        .get("filters")
        .map(flatten_filters_for_header)
        .unwrap_or_default();
    let reproducibility_hash = compute_reproducibility_hash(snapshot);

    out.push_str("# InnerWarden Audit Export (spec 049 PR11)\n");
    out.push_str(&format!("# Generated: {generated_at}\n"));
    out.push_str(&format!("# Period: {date}\n"));
    if !subject.is_empty() {
        out.push_str(&format!("# Subject: {subject_type}:{subject}\n"));
    }
    if !filters_str.is_empty() {
        out.push_str(&format!("# Filters: {filters_str}\n"));
    }
    out.push_str(&format!(
        "# Reproducibility hash (SHA-256, excludes generated_at): {reproducibility_hash}\n"
    ));
    out.push_str(
        "# Same period+filters+cases produce the same hash; verify via re-export to confirm content integrity.\n",
    );
    out.push('\n');

    // ── Column header row ──
    out.push_str(&COLUMNS.join(","));
    out.push('\n');

    // ── Cases table ──
    // The most useful audit content lives in the journey entries
    // (incident + decision pairs). Fall back to overview-only when
    // no journey is in the snapshot.
    if let Some(entries) = snapshot
        .get("journey")
        .and_then(|j| j.get("entries"))
        .and_then(|e| e.as_array())
    {
        for entry in entries {
            out.push_str(&render_entry_row(entry));
            out.push('\n');
        }
    }

    out
}

/// Render one journey entry as a CSV row. Pulls the canonical
/// columns from the entry's nested `data` object; missing fields
/// emit an empty cell (CSV-empty == `""`).
fn render_entry_row(entry: &Value) -> String {
    let ts = entry.get("ts").and_then(|v| v.as_str()).unwrap_or("");
    let kind = entry.get("kind").and_then(|v| v.as_str()).unwrap_or("");
    let data = entry.get("data").cloned().unwrap_or(Value::Null);

    let get_str = |key: &str| -> String {
        data.get(key)
            .map(|v| match v {
                Value::String(s) => s.clone(),
                Value::Null => String::new(),
                other => other.to_string(),
            })
            .unwrap_or_default()
    };

    let cells = [
        ts.to_string(),
        kind.to_string(),
        get_str("severity"),
        get_str("detector"),
        get_str("incident_id"),
        get_str("action_type"),
        get_str("target_ip"),
        get_str("confidence"),
        get_str("execution_result"),
        get_str("decision_layer"),
        get_str("decision_layer_detail"),
        get_str("reason"),
    ];
    cells
        .iter()
        .map(|c| csv_quote(c))
        .collect::<Vec<_>>()
        .join(",")
}

/// RFC 4180 CSV field quoting. A field is wrapped in double quotes
/// when it contains `,`, `"`, `\r`, or `\n`. Internal `"` doubles.
fn csv_quote(field: &str) -> String {
    let needs_quote = field
        .chars()
        .any(|c| c == ',' || c == '"' || c == '\r' || c == '\n');
    if !needs_quote {
        return field.to_string();
    }
    let mut out = String::with_capacity(field.len() + 2);
    out.push('"');
    for c in field.chars() {
        if c == '"' {
            out.push('"');
            out.push('"');
        } else {
            out.push(c);
        }
    }
    out.push('"');
    out
}

/// Flatten the `filters` JSON object into a `k=v, k=v` string for
/// the metadata header. Skips null / empty values.
fn flatten_filters_for_header(filters: &Value) -> String {
    let Some(map) = filters.as_object() else {
        return String::new();
    };
    map.iter()
        .filter_map(|(k, v)| {
            let s = match v {
                Value::Null => return None,
                Value::String(s) => {
                    if s.is_empty() {
                        return None;
                    }
                    s.clone()
                }
                other => other.to_string(),
            };
            Some(format!("{k}={s}"))
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// Compute a stable SHA-256 hash over the snapshot's content,
/// excluding `generated_at` (which changes per export) so the same
/// period + filters + cases yield the same hash across re-runs.
///
/// Implementation: clone the snapshot, drop `generated_at`,
/// serialize with `serde_json::to_vec` using BTreeMap-backed
/// object iteration order (serde_json's default for arbitrary
/// preserves insertion order; we canonicalise to sorted-key here).
pub(super) fn compute_reproducibility_hash(snapshot: &Value) -> String {
    let canonical = canonicalize_for_hash(snapshot);
    let bytes = canonical.as_bytes();
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

/// Serialise `value` with sorted object keys and `generated_at`
/// stripped. Deterministic for the same logical content regardless
/// of which order serde happened to populate the input map.
fn canonicalize_for_hash(value: &Value) -> String {
    // Strip `generated_at` from the top-level object before
    // canonicalising. Defensive clone so the caller's snapshot
    // stays untouched.
    let mut cloned = value.clone();
    if let Some(obj) = cloned.as_object_mut() {
        obj.remove("generated_at");
    }
    let canonical = sort_value_keys(cloned);
    serde_json::to_string(&canonical).unwrap_or_default()
}

/// Recursively re-emit `value` with object keys sorted. Arrays
/// preserve their input order (audit timeline IS order-sensitive).
fn sort_value_keys(value: Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut entries: Vec<(String, Value)> = map.into_iter().collect();
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            let mut sorted = serde_json::Map::new();
            for (k, v) in entries {
                sorted.insert(k, sort_value_keys(v));
            }
            Value::Object(sorted)
        }
        Value::Array(arr) => Value::Array(arr.into_iter().map(sort_value_keys).collect()),
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ── CSV quoting ────────────────────────────────────────────────

    #[test]
    fn csv_quote_passes_through_simple_string() {
        assert_eq!(csv_quote("hello"), "hello");
        assert_eq!(csv_quote("203.0.113.10"), "203.0.113.10");
    }

    #[test]
    fn csv_quote_wraps_field_with_comma() {
        assert_eq!(csv_quote("a,b"), "\"a,b\"");
    }

    #[test]
    fn csv_quote_doubles_internal_quotes() {
        assert_eq!(csv_quote("she said \"hi\""), "\"she said \"\"hi\"\"\"");
    }

    #[test]
    fn csv_quote_wraps_field_with_newline() {
        assert_eq!(csv_quote("line1\nline2"), "\"line1\nline2\"");
    }

    #[test]
    fn csv_quote_wraps_field_with_carriage_return() {
        assert_eq!(csv_quote("line1\rline2"), "\"line1\rline2\"");
    }

    #[test]
    fn csv_quote_passes_empty_string() {
        assert_eq!(csv_quote(""), "");
    }

    // ── Metadata header ────────────────────────────────────────────

    #[test]
    fn export_carries_metadata_header_comments() {
        let snap = json!({
            "generated_at": "2026-05-13T01:00:00Z",
            "date": "2026-05-12",
            "subject_type": "ip",
            "subject": "203.0.113.10",
            "filters": {
                "date": "2026-05-12",
                "severity_min": "high"
            },
            "journey": null,
        });
        let csv = render_csv_export(&snap);
        assert!(csv.contains("# InnerWarden Audit Export (spec 049 PR11)"));
        assert!(csv.contains("# Generated: 2026-05-13T01:00:00Z"));
        assert!(csv.contains("# Period: 2026-05-12"));
        assert!(csv.contains("# Subject: ip:203.0.113.10"));
        assert!(csv.contains("date=2026-05-12") && csv.contains("severity_min=high"));
        assert!(csv.contains("# Reproducibility hash (SHA-256"));
    }

    #[test]
    fn export_omits_subject_header_when_subject_empty() {
        let snap = json!({
            "generated_at": "2026-05-13T01:00:00Z",
            "date": "2026-05-12",
            "subject_type": "",
            "subject": "",
            "filters": {},
            "journey": null,
        });
        let csv = render_csv_export(&snap);
        assert!(!csv.contains("# Subject:"));
    }

    #[test]
    fn export_carries_column_header_row_in_exact_order() {
        let snap = json!({"generated_at":"","date":"","journey":null,"filters":{}});
        let csv = render_csv_export(&snap);
        let expected = COLUMNS.join(",");
        assert!(
            csv.contains(&expected),
            "column header row must match canonical order"
        );
    }

    // ── Row rendering ──────────────────────────────────────────────

    #[test]
    fn export_emits_one_row_per_journey_entry() {
        let snap = json!({
            "generated_at": "2026-05-13T01:00:00Z",
            "date": "2026-05-12",
            "filters": {},
            "journey": {
                "entries": [
                    {
                        "ts": "2026-05-12T14:30:02Z",
                        "kind": "incident",
                        "data": {
                            "severity": "high",
                            "detector": "ssh_bruteforce",
                            "incident_id": "ssh_bruteforce:001"
                        }
                    },
                    {
                        "ts": "2026-05-12T14:30:03Z",
                        "kind": "decision",
                        "data": {
                            "action_type": "block_ip",
                            "target_ip": "203.0.113.10",
                            "confidence": 0.97,
                            "execution_result": "ok",
                            "decision_layer": "ai_local_warden",
                            "decision_layer_detail": "Local Warden Model · confidence 0.97",
                            "reason": "score > threshold"
                        }
                    }
                ]
            }
        });
        let csv = render_csv_export(&snap);
        // Find the table portion (after the metadata header block).
        let table_start = csv.find("ts,kind,severity").expect("header row present");
        let table = &csv[table_start..];
        // Header + 2 data rows = 3 newlines minimum.
        let row_count = table.lines().filter(|l| !l.is_empty()).count();
        assert_eq!(row_count, 3, "header + 2 entries = 3 rows");
        // Spot-check known cells.
        assert!(table.contains("2026-05-12T14:30:02Z,incident,high,ssh_bruteforce"));
        assert!(table.contains("ai_local_warden"));
        assert!(table.contains("block_ip"));
    }

    #[test]
    fn export_handles_empty_journey_with_only_header() {
        let snap = json!({
            "generated_at": "2026-05-13T01:00:00Z",
            "date": "2026-05-12",
            "filters": {},
            "journey": {"entries": []}
        });
        let csv = render_csv_export(&snap);
        let table_start = csv.find("ts,kind,severity").expect("header row present");
        let table = &csv[table_start..];
        let row_count = table.lines().filter(|l| !l.is_empty()).count();
        assert_eq!(
            row_count, 1,
            "empty journey emits only the header row, no data rows"
        );
    }

    #[test]
    fn export_quotes_cells_with_commas() {
        let snap = json!({
            "generated_at": "",
            "date": "",
            "filters": {},
            "journey": {
                "entries": [{
                    "ts": "2026-05-12T14:30:02Z",
                    "kind": "decision",
                    "data": {
                        "reason": "skipped, ip on allowlist"
                    }
                }]
            }
        });
        let csv = render_csv_export(&snap);
        assert!(
            csv.contains("\"skipped, ip on allowlist\""),
            "reason cell with comma must be quoted"
        );
    }

    #[test]
    fn export_quotes_cells_with_internal_quotes() {
        let snap = json!({
            "generated_at": "",
            "date": "",
            "filters": {},
            "journey": {
                "entries": [{
                    "ts": "2026-05-12T14:30:02Z",
                    "kind": "decision",
                    "data": {
                        "reason": "matched signature \"DDoS-burst\""
                    }
                }]
            }
        });
        let csv = render_csv_export(&snap);
        assert!(
            csv.contains("\"matched signature \"\"DDoS-burst\"\"\""),
            "reason cell with internal quotes must double-escape"
        );
    }

    // ── Reproducibility hash ───────────────────────────────────────

    #[test]
    fn reproducibility_hash_is_stable_for_same_content() {
        let snap1 = json!({
            "generated_at": "2026-05-13T01:00:00Z",
            "date": "2026-05-12",
            "filters": {"x": 1},
            "data": {"a": 1, "b": 2}
        });
        let snap2 = json!({
            "generated_at": "2026-05-13T01:00:00Z",
            "date": "2026-05-12",
            "filters": {"x": 1},
            "data": {"a": 1, "b": 2}
        });
        assert_eq!(
            compute_reproducibility_hash(&snap1),
            compute_reproducibility_hash(&snap2),
            "same logical content must hash to the same value"
        );
    }

    #[test]
    fn reproducibility_hash_ignores_generated_at() {
        let snap1 = json!({
            "generated_at": "2026-05-13T01:00:00Z",
            "date": "2026-05-12",
            "data": {"a": 1}
        });
        let snap2 = json!({
            "generated_at": "2026-05-13T15:30:00Z",
            "date": "2026-05-12",
            "data": {"a": 1}
        });
        assert_eq!(
            compute_reproducibility_hash(&snap1),
            compute_reproducibility_hash(&snap2),
            "generated_at MUST NOT affect the hash (re-running the same export at a later time must match)"
        );
    }

    #[test]
    fn reproducibility_hash_changes_when_content_changes() {
        let snap1 = json!({"date": "2026-05-12", "data": {"a": 1}});
        let snap2 = json!({"date": "2026-05-12", "data": {"a": 2}});
        assert_ne!(
            compute_reproducibility_hash(&snap1),
            compute_reproducibility_hash(&snap2),
            "changing content must change the hash"
        );
    }

    #[test]
    fn reproducibility_hash_is_key_order_insensitive() {
        // serde_json::Map preserves insertion order; the hash must
        // canonicalise to sorted-key order so two snapshots with
        // identical content but different insertion order match.
        let snap1: Value =
            serde_json::from_str(r#"{"date":"2026-05-12","data":{"a":1,"b":2}}"#).unwrap();
        let snap2: Value =
            serde_json::from_str(r#"{"data":{"b":2,"a":1},"date":"2026-05-12"}"#).unwrap();
        assert_eq!(
            compute_reproducibility_hash(&snap1),
            compute_reproducibility_hash(&snap2),
            "key insertion order must not affect the hash"
        );
    }
}
