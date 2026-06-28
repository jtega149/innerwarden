use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use innerwarden_store::Store;

use crate::{
    append_admin_action, current_operator, epoch_secs_to_date, looks_like_ip, resolve_data_dir,
    AdminActionEntry, Cli,
};

/// One incident line ready to print, grouped under a `YYYY-MM-DD` header.
/// Produced by both the SQLite-store reader and the legacy JSONL reader so
/// the printer renders an identical layout regardless of source.
struct IncidentRow {
    /// `HH:MM` (already trimmed from the RFC3339 timestamp).
    time: String,
    severity: String,
    title: String,
    /// First `Ip` entity value, or empty.
    ip: String,
}

/// Read incidents from the unified SQLite store for the last `days` days and
/// group them by UTC date (descending, newest day first — matching the legacy
/// JSONL day ordering which iterates `today` back to `today-(days-1)`).
///
/// Returns `Ok(None)` when the store cannot be opened OR has no rows in the
/// window, so the caller can fall back to the legacy per-day JSONL files for
/// boxes that have not migrated yet. Severity filtering is applied here so the
/// `total == 0` empty-state branch in `cmd_incidents` behaves identically to
/// the JSONL path.
fn incidents_rows_from_store(
    dir: &Path,
    days: u64,
    min_rank: u8,
) -> Option<Vec<(String, Vec<IncidentRow>)>> {
    let store = match Store::open(dir) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("  [warn] get incidents: store open failed ({e:#}); falling back to JSONL");
            return None;
        }
    };

    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let start_secs = now_secs.saturating_sub(days.saturating_sub(1) * 86400);
    let start_date = epoch_secs_to_date(start_secs);
    // RFC3339 midnight-UTC for the window start. The store keeps `ts` as
    // `DateTime::to_rfc3339()` (`...+00:00`); lexicographic `>=` against this
    // string selects every incident on `start_date` 00:00 onward.
    let start_ts = format!("{start_date}T00:00:00+00:00");

    // A generous cap: a day can hold hundreds of incidents; reading a week
    // should still be bounded. 100k is far above any realistic operator window
    // while protecting against an unbounded scan.
    let incidents = match store.incidents_since_ts(&start_ts, 100_000) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("  [warn] get incidents: store query failed ({e:#}); falling back to JSONL");
            return None;
        }
    };

    if incidents.is_empty() {
        // Empty store window: let the caller try the legacy JSONL files. A box
        // mid-migration may still have JSONL data the store lacks.
        return None;
    }

    // Group by UTC date, newest day first.
    use std::collections::BTreeMap;
    let mut by_date: BTreeMap<String, Vec<IncidentRow>> = BTreeMap::new();
    for inc in &incidents {
        if severity_rank(&format!("{:?}", inc.severity)) < min_rank {
            continue;
        }
        let ts = inc.ts.to_rfc3339();
        let date = ts.get(..10).unwrap_or("").to_string();
        let time = if ts.len() >= 16 {
            ts[11..16].to_string()
        } else {
            ts.clone()
        };
        let ip = inc
            .entities
            .iter()
            .find(|e| e.r#type == innerwarden_core::entities::EntityType::Ip)
            .map(|e| e.value.clone())
            .unwrap_or_default();
        by_date.entry(date).or_default().push(IncidentRow {
            time,
            severity: format!("{:?}", inc.severity),
            title: inc.title.clone(),
            ip,
        });
    }

    // BTreeMap is ascending by date; reverse to newest-first to mirror the
    // legacy loop (which walks today -> today-(days-1)).
    Some(by_date.into_iter().rev().collect())
}

/// Print grouped incident rows. Shared by the store and JSONL paths so the
/// human-facing output (date header + `HH:MM [SEV] title ip`) is identical.
/// Returns the number of incident lines printed.
fn print_incident_groups(groups: &[(String, Vec<IncidentRow>)]) -> usize {
    let mut total = 0usize;
    for (date, rows) in groups {
        if rows.is_empty() {
            continue;
        }
        println!("── {date} ─────────────────────────────────────────────");
        for row in rows {
            let sev_tag = sev_tag_bracket(&row.severity);
            let ip_part = if row.ip.is_empty() {
                String::new()
            } else {
                format!("  {}", row.ip)
            };
            println!("  {}  {sev_tag}  {}{ip_part}", row.time, row.title);
            total += 1;
        }
        println!();
    }
    total
}

/// Legacy fallback: read incidents from the per-day `incidents-YYYY-MM-DD.jsonl`
/// files for the last `days` days, applying the severity filter, and return
/// them grouped by date (newest day first). Preserves the exact field
/// extraction the original `cmd_incidents` JSONL path used (`entities[].type
/// == "Ip"`, `ts[11..16]`, etc.).
fn incidents_rows_from_jsonl(
    dir: &Path,
    days: u64,
    min_rank: u8,
) -> Vec<(String, Vec<IncidentRow>)> {
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let mut dates = Vec::new();
    for i in 0..days {
        dates.push(epoch_secs_to_date(now_secs.saturating_sub(i * 86400)));
    }

    let mut groups = Vec::new();
    for date in &dates {
        let path = dir.join(format!("incidents-{date}.jsonl"));
        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        let mut rows = Vec::new();
        for line in content.lines().filter(|l| !l.trim().is_empty()) {
            let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
                continue;
            };
            let sev = v["severity"].as_str().unwrap_or("Info");
            if severity_rank(sev) < min_rank {
                continue;
            }
            let title = v["title"].as_str().unwrap_or("Unknown threat");
            let ts = v["ts"].as_str().unwrap_or("");
            let time = if ts.len() >= 16 { &ts[11..16] } else { ts };
            let ip = v["entities"]
                .as_array()
                .and_then(|arr| {
                    arr.iter()
                        .find(|e| e["type"].as_str() == Some("Ip"))
                        .and_then(|e| e["value"].as_str())
                })
                .unwrap_or("");
            rows.push(IncidentRow {
                time: time.to_string(),
                severity: sev.to_string(),
                title: title.to_string(),
                ip: ip.to_string(),
            });
        }
        if !rows.is_empty() {
            groups.push((date.clone(), rows));
        }
    }
    groups
}

fn severity_rank(sev: &str) -> u8 {
    match sev.to_lowercase().as_str() {
        "critical" => 5,
        "high" => 4,
        "medium" => 3,
        "low" => 2,
        _ => 1,
    }
}

fn sev_tag_bracket(sev: &str) -> &'static str {
    match sev.to_lowercase().as_str() {
        "critical" => "[CRITICAL]",
        "high" => "[HIGH]    ",
        "medium" => "[MEDIUM]  ",
        "low" => "[LOW]     ",
        _ => "[INFO]    ",
    }
}

fn sev_tag_plain(sev: &str) -> &'static str {
    match sev.to_lowercase().as_str() {
        "critical" => " CRITICAL",
        "high" => " HIGH    ",
        "medium" => " MEDIUM  ",
        "low" => " LOW     ",
        _ => "         ",
    }
}

pub(crate) fn cmd_incidents(
    cli: &Cli,
    days: u64,
    severity_filter: &str,
    data_dir: &Path,
) -> Result<()> {
    let effective_dir = resolve_data_dir(cli, data_dir);
    let min_rank = severity_rank(severity_filter);

    // Prefer the unified SQLite store (the canonical source the sensor/agent
    // write to). Fall back to the legacy per-day JSONL files only when the
    // store is absent / unreadable / empty in the window — backward compat for
    // boxes that have not migrated.
    let total = if let Some(groups) = incidents_rows_from_store(&effective_dir, days, min_rank) {
        print_incident_groups(&groups)
    } else {
        let groups = incidents_rows_from_jsonl(&effective_dir, days, min_rank);
        print_incident_groups(&groups)
    };

    if total == 0 {
        if severity_filter != "low" {
            println!(
                "No {} or higher incidents found in the last {} day(s).",
                severity_filter, days
            );
        } else {
            println!("No incidents found in the last {} day(s). Quiet!", days);
        }
    } else {
        println!("{total} incident(s) shown.  Run 'innerwarden report' for the full narrative.");
    }
    Ok(())
}

pub(crate) fn cmd_export(
    cli: &Cli,
    kind: &str,
    from_arg: Option<&str>,
    to_arg: Option<&str>,
    format: &str,
    output_path: Option<&Path>,
    data_dir: &Path,
) -> Result<()> {
    let effective_dir = resolve_data_dir(cli, data_dir);

    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let today = epoch_secs_to_date(now_secs);

    let from = from_arg.unwrap_or(&today).to_string();
    let to = to_arg.unwrap_or(&today).to_string();

    let prefix = match kind {
        "events" => "events",
        "decisions" => "decisions",
        _ => "incidents",
    };

    let mut all_lines: Vec<serde_json::Value> = Vec::new();

    if let Ok(entries) = std::fs::read_dir(&effective_dir) {
        let mut files: Vec<_> = entries
            .flatten()
            .filter(|e| {
                let name = e.file_name().to_string_lossy().to_string();
                if let Some(date) = name
                    .strip_prefix(&format!("{prefix}-"))
                    .and_then(|s| s.strip_suffix(".jsonl"))
                {
                    date >= from.as_str() && date <= to.as_str()
                } else {
                    false
                }
            })
            .collect();
        files.sort_by_key(|e| e.file_name());

        for entry in files {
            if let Ok(content) = std::fs::read_to_string(entry.path()) {
                for line in content.lines().filter(|l| !l.trim().is_empty()) {
                    if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
                        all_lines.push(v);
                    }
                }
            }
        }
    }

    if all_lines.is_empty() {
        eprintln!("No {kind} found between {from} and {to}.");
        return Ok(());
    }

    let content = match format {
        "csv" => {
            let mut keys: Vec<String> = all_lines
                .iter()
                .filter_map(|v| v.as_object())
                .flat_map(|o| o.keys().cloned())
                .collect::<std::collections::BTreeSet<_>>()
                .into_iter()
                .collect();
            keys.retain(|k| k != "evidence" && k != "details" && k != "entities");

            let mut out = keys.join(",") + "\n";
            for row in &all_lines {
                let fields: Vec<String> = keys
                    .iter()
                    .map(|k| {
                        let v = &row[k];
                        let s = match v {
                            serde_json::Value::String(s) => s.replace('"', "\"\""),
                            serde_json::Value::Null => String::new(),
                            other => other.to_string().replace('"', "\"\""),
                        };
                        if s.contains(',') || s.contains('"') || s.contains('\n') {
                            format!("\"{s}\"")
                        } else {
                            s
                        }
                    })
                    .collect();
                out += &(fields.join(",") + "\n");
            }
            out
        }
        _ => serde_json::to_string_pretty(&all_lines)?,
    };

    match output_path {
        Some(path) => {
            std::fs::write(path, &content)
                .with_context(|| format!("failed to write to {}", path.display()))?;
            eprintln!(
                "Exported {} {kind}(s) ({from} → {to}) to {}",
                all_lines.len(),
                path.display()
            );
        }
        None => print!("{content}"),
    }

    Ok(())
}

pub(crate) fn cmd_tail(cli: &Cli, kind: &str, interval_secs: u64, data_dir: &Path) -> Result<()> {
    let effective_dir = resolve_data_dir(cli, data_dir);
    let prefix = if kind == "events" {
        "events"
    } else {
        "incidents"
    };

    println!("Streaming {kind}... (Ctrl-C to stop)\n");

    let mut offset: u64 = 0;
    let mut current_date = String::new();

    loop {
        let today = epoch_secs_to_date(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        );

        if today != current_date {
            current_date = today.clone();
            offset = 0;
        }

        let path = effective_dir.join(format!("{prefix}-{today}.jsonl"));

        if let Ok(content) = std::fs::read_to_string(&path) {
            let bytes = content.as_bytes();
            if bytes.len() as u64 > offset {
                let new_bytes = &bytes[offset as usize..];
                let new_text = std::str::from_utf8(new_bytes).unwrap_or("");
                for line in new_text.lines().filter(|l| !l.trim().is_empty()) {
                    if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
                        print_tail_entry(&v, kind);
                    }
                }
                offset = bytes.len() as u64;
            }
        }

        std::thread::sleep(std::time::Duration::from_secs(interval_secs));
    }
}

fn print_tail_entry(v: &serde_json::Value, kind: &str) {
    let ts = v["ts"].as_str().unwrap_or("");
    let time = if ts.len() >= 16 { &ts[11..16] } else { ts };

    if kind == "events" {
        let source = v["source"].as_str().unwrap_or("?");
        let ev_kind = v["kind"].as_str().unwrap_or("?");
        let sev = v["severity"].as_str().unwrap_or("Info");
        let summary = v["summary"].as_str().unwrap_or("");
        println!("{time}  [{sev:<8}]  {source:<16}  {ev_kind}  {summary}");
    } else {
        let sev = v["severity"].as_str().unwrap_or("Info");
        let title = v["title"].as_str().unwrap_or("Unknown");
        let ip = v["entities"]
            .as_array()
            .and_then(|arr| {
                arr.iter()
                    .find(|e| e["type"].as_str() == Some("Ip"))
                    .and_then(|e| e["value"].as_str())
            })
            .unwrap_or("");
        let sev_tag = sev_tag_bracket(sev);
        let ip_part = if ip.is_empty() {
            String::new()
        } else {
            format!("  {ip}")
        };
        println!("{time}  {sev_tag}  {title}{ip_part}");
    }
}

pub(crate) fn cmd_incidents_live(cli: &Cli, severity_filter: &str, data_dir: &Path) -> Result<()> {
    let effective_dir = resolve_data_dir(cli, data_dir);
    let min_sev = parse_severity_filter(severity_filter);

    println!("● LIVE - streaming incidents (Ctrl-C to stop)\n");

    let mut offset: u64 = 0;
    let mut current_date = String::new();

    loop {
        let today = epoch_secs_to_date(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        );

        if today != current_date {
            current_date = today.clone();
            offset = 0;
        }

        let safe_date: String = today
            .chars()
            .filter(|c| c.is_ascii_digit() || *c == '-')
            .collect();
        let path = effective_dir.join(format!("incidents-{safe_date}.jsonl"));

        if let Ok(content) = std::fs::read_to_string(&path) {
            let bytes = content.as_bytes();
            if bytes.len() as u64 > offset {
                let new_bytes = &bytes[offset as usize..];
                let new_text = std::str::from_utf8(new_bytes).unwrap_or("");
                for line in new_text.lines().filter(|l| !l.trim().is_empty()) {
                    if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
                        let sev = v["severity"].as_str().unwrap_or("info");
                        if severity_rank_str(sev) >= min_sev {
                            print_live_incident(&v);
                        }
                    }
                }
                offset = bytes.len() as u64;
            }
        }

        std::thread::sleep(std::time::Duration::from_secs(2));
    }
}

fn print_live_incident(v: &serde_json::Value) {
    let ts = v["ts"].as_str().unwrap_or("");
    let time = if ts.len() >= 19 { &ts[11..19] } else { ts };
    let sev = v["severity"].as_str().unwrap_or("info");
    let title = v["title"].as_str().unwrap_or("Unknown");
    let summary = v["summary"].as_str().unwrap_or("");

    let icon = match sev {
        "critical" => "🔴",
        "high" => "🟠",
        "medium" => "🟡",
        "low" => "🟢",
        _ => "⚪",
    };

    let entities: Vec<String> = v["entities"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|e| e["value"].as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();
    let entity_str = if entities.is_empty() {
        String::new()
    } else {
        format!("  [{}]", entities.join(", "))
    };

    println!("{icon} {time}  {title}{entity_str}");
    if !summary.is_empty() && summary != title {
        let short: String = summary.chars().take(100).collect();
        println!("  └ {short}");
    }
    println!();
}

fn parse_severity_filter(s: &str) -> u8 {
    match s.to_lowercase().as_str() {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

fn severity_rank_str(s: &str) -> u8 {
    match s.to_lowercase().as_str() {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

/// One decision line ready to print, grouped under a `YYYY-MM-DD` header.
/// Produced by both the SQLite-store reader and the legacy JSONL reader.
struct DecisionDisplayRow {
    /// `HH:MM` trimmed from the RFC3339 timestamp.
    time: String,
    action: String,
    target_ip: String,
    target_user: String,
    confidence: f64,
    dry_run: bool,
    provider: String,
}

/// Build a `DecisionDisplayRow` from a decision `data` JSON blob, applying the
/// `action_filter` (case-insensitive match on `action_type`). Returns `None`
/// when the row is filtered out or the timestamp/action cannot be read. The
/// field names mirror the canonical `DecisionEntry` serialization
/// (`action_type`, `target_ip`, `target_user`, `confidence`, `dry_run`,
/// `ai_provider`) — identical to what the JSONL writer emits.
fn decision_row_from_json(
    v: &serde_json::Value,
    action_filter: Option<&str>,
) -> Option<DecisionDisplayRow> {
    let action = v["action_type"].as_str().unwrap_or("unknown");
    if let Some(f) = action_filter {
        if !action.eq_ignore_ascii_case(f) {
            return None;
        }
    }
    let ts = v["ts"].as_str().unwrap_or("");
    let time = if ts.len() >= 16 { &ts[11..16] } else { ts };
    Some(DecisionDisplayRow {
        time: time.to_string(),
        action: action.to_string(),
        target_ip: v["target_ip"].as_str().unwrap_or("").to_string(),
        target_user: v["target_user"].as_str().unwrap_or("").to_string(),
        confidence: v["confidence"].as_f64().unwrap_or(0.0),
        dry_run: v["dry_run"].as_bool().unwrap_or(false),
        provider: v["ai_provider"].as_str().unwrap_or("").to_string(),
    })
}

/// Print grouped decision rows. Shared by the store and JSONL paths so the
/// human-facing output is byte-identical regardless of source. Returns the
/// number of decision lines printed.
fn print_decision_groups(groups: &[(String, Vec<DecisionDisplayRow>)]) -> usize {
    let mut total = 0usize;
    for (date, rows) in groups {
        if rows.is_empty() {
            continue;
        }
        println!("── {date} ─────────────────────────────────────────────");
        for row in rows {
            let target = if !row.target_ip.is_empty() {
                row.target_ip.clone()
            } else if !row.target_user.is_empty() {
                format!("user:{}", row.target_user)
            } else {
                String::new()
            };
            let dry_tag = if row.dry_run { " [dry-run]" } else { "" };
            let conf_tag = if row.confidence > 0.0 {
                format!("  conf:{:.2}", row.confidence)
            } else {
                String::new()
            };
            let provider_tag = if !row.provider.is_empty() {
                format!("  via:{}", row.provider)
            } else {
                String::new()
            };
            let target_part = if target.is_empty() {
                String::new()
            } else {
                format!("  {target}")
            };
            let action_tag = match row.action.as_str() {
                "block_ip" => "[BLOCK]      ",
                "suspend_user_sudo" => "[SUSPEND]    ",
                "ignore" => "[IGNORE]     ",
                "monitor" => "[MONITOR]    ",
                "honeypot" => "[HONEYPOT]   ",
                "request_confirmation" => "[PENDING]    ",
                _ => "[UNKNOWN]    ",
            };
            println!(
                "  {}  {action_tag}{target_part}{conf_tag}{provider_tag}{dry_tag}",
                row.time
            );
            total += 1;
        }
        println!();
    }
    total
}

/// Read decisions from the unified SQLite store for the last `days` days,
/// looping per UTC date (the store keys decisions by `ts LIKE 'date%'`), and
/// group them newest-day-first. Returns `Ok(None)` to trigger the legacy JSONL
/// fallback when the store cannot be opened OR has no matching rows in the
/// window.
fn decisions_rows_from_store(
    dir: &Path,
    days: u64,
    action_filter: Option<&str>,
) -> Option<Vec<(String, Vec<DecisionDisplayRow>)>> {
    let store = match Store::open(dir) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("  [warn] get decisions: store open failed ({e:#}); falling back to JSONL");
            return None;
        }
    };

    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let mut dates = Vec::new();
    for i in 0..days {
        dates.push(epoch_secs_to_date(now_secs.saturating_sub(i * 86400)));
    }

    let mut groups = Vec::new();
    let mut any = false;
    for date in &dates {
        let rows = match store.decisions_for_date(date, 100_000) {
            Ok(r) => r,
            Err(e) => {
                eprintln!(
                    "  [warn] get decisions: store query failed ({e:#}); falling back to JSONL"
                );
                return None;
            }
        };
        any = any || !rows.is_empty();
        let mut display_rows = Vec::new();
        for (_ts, _incident_id, data_json) in &rows {
            let Ok(v) = serde_json::from_str::<serde_json::Value>(data_json) else {
                continue;
            };
            if let Some(row) = decision_row_from_json(&v, action_filter) {
                display_rows.push(row);
            }
        }
        if !display_rows.is_empty() {
            groups.push((date.clone(), display_rows));
        }
    }

    // Nothing in the store window (no rows on any date) -> let the caller try
    // the legacy JSONL files. Note: an empty result AFTER the action filter is
    // also possible when the store DID hold decisions but none matched the
    // filter; in that case we still want the store-path's filtered empty-state
    // message, so we keep the store path when `any` rows existed.
    if !any {
        return None;
    }
    Some(groups)
}

/// Legacy fallback: read decisions from the per-day
/// `decisions-YYYY-MM-DD.jsonl` files for the last `days` days, applying the
/// action filter, grouped newest-day-first.
fn decisions_rows_from_jsonl(
    dir: &Path,
    days: u64,
    action_filter: Option<&str>,
) -> Vec<(String, Vec<DecisionDisplayRow>)> {
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let mut dates = Vec::new();
    for i in 0..days {
        dates.push(epoch_secs_to_date(now_secs.saturating_sub(i * 86400)));
    }

    let mut groups = Vec::new();
    for date in &dates {
        let path = dir.join(format!("decisions-{date}.jsonl"));
        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let mut display_rows = Vec::new();
        for line in content.lines().filter(|l| !l.trim().is_empty()) {
            let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
                continue;
            };
            if let Some(row) = decision_row_from_json(&v, action_filter) {
                display_rows.push(row);
            }
        }
        if !display_rows.is_empty() {
            groups.push((date.clone(), display_rows));
        }
    }
    groups
}

pub(crate) fn cmd_decisions(
    cli: &Cli,
    days: u64,
    action_filter: Option<&str>,
    data_dir: &Path,
) -> Result<()> {
    let effective_dir = resolve_data_dir(cli, data_dir);

    // Prefer the unified SQLite store. Fall back to the legacy per-day JSONL
    // files only when the store is absent / unreadable / empty in the window.
    let total = if let Some(groups) = decisions_rows_from_store(&effective_dir, days, action_filter)
    {
        print_decision_groups(&groups)
    } else {
        let groups = decisions_rows_from_jsonl(&effective_dir, days, action_filter);
        print_decision_groups(&groups)
    };

    if total == 0 {
        if let Some(f) = action_filter {
            println!("No '{f}' decisions found in the last {days} day(s).");
        } else {
            println!("No decisions recorded in the last {days} day(s).");
            println!("The agent may be in observe-only mode or not running.");
            println!("Run 'innerwarden status' to check.");
        }
    } else {
        println!(
            "{total} decision(s) shown.  Full audit trail: {}/decisions-*.jsonl",
            effective_dir.display()
        );
    }
    Ok(())
}

pub(crate) fn cmd_entity(cli: &Cli, target: &str, days: u64, data_dir: &Path) -> Result<()> {
    let effective_dir = resolve_data_dir(cli, data_dir);
    let is_ip = looks_like_ip(target);

    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let mut dates = Vec::new();
    for i in 0..days {
        dates.push(epoch_secs_to_date(now_secs.saturating_sub(i * 86400)));
    }

    #[derive(Debug)]
    struct Entry {
        ts: String,
        kind: &'static str,
        severity: String,
        summary: String,
        extra: String,
    }

    let mut entries: Vec<Entry> = Vec::new();

    for date in &dates {
        let events_path = effective_dir.join(format!("events-{date}.jsonl"));
        if let Ok(content) = std::fs::read_to_string(&events_path) {
            for line in content.lines().filter(|l| !l.trim().is_empty()) {
                let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
                    continue;
                };
                let matched = if is_ip {
                    v["entities"]
                        .as_array()
                        .map(|arr| {
                            arr.iter().any(|e| {
                                e["type"].as_str() == Some("Ip")
                                    && e["value"].as_str() == Some(target)
                            })
                        })
                        .unwrap_or(false)
                } else {
                    v["entities"]
                        .as_array()
                        .map(|arr| {
                            arr.iter().any(|e| {
                                e["type"].as_str() == Some("User")
                                    && e["value"].as_str() == Some(target)
                            })
                        })
                        .unwrap_or(false)
                };
                if matched {
                    entries.push(Entry {
                        ts: v["ts"].as_str().unwrap_or("").to_string(),
                        kind: "event",
                        severity: v["severity"].as_str().unwrap_or("Info").to_string(),
                        summary: v["summary"].as_str().unwrap_or("").to_string(),
                        extra: v["kind"].as_str().unwrap_or("").to_string(),
                    });
                }
            }
        }

        let incidents_path = effective_dir.join(format!("incidents-{date}.jsonl"));
        if let Ok(content) = std::fs::read_to_string(&incidents_path) {
            for line in content.lines().filter(|l| !l.trim().is_empty()) {
                let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
                    continue;
                };
                let matched = if is_ip {
                    v["entities"]
                        .as_array()
                        .map(|arr| {
                            arr.iter().any(|e| {
                                e["type"]
                                    .as_str()
                                    .map(|t| t.eq_ignore_ascii_case("ip"))
                                    .unwrap_or(false)
                                    && e["value"].as_str() == Some(target)
                            })
                        })
                        .unwrap_or(false)
                } else {
                    v["entities"]
                        .as_array()
                        .map(|arr| {
                            arr.iter().any(|e| {
                                e["type"]
                                    .as_str()
                                    .map(|t| t.eq_ignore_ascii_case("user"))
                                    .unwrap_or(false)
                                    && e["value"].as_str() == Some(target)
                            })
                        })
                        .unwrap_or(false)
                };
                if matched {
                    entries.push(Entry {
                        ts: v["ts"].as_str().unwrap_or("").to_string(),
                        kind: "incident",
                        severity: v["severity"].as_str().unwrap_or("Info").to_string(),
                        summary: v["title"].as_str().unwrap_or("").to_string(),
                        extra: v["summary"].as_str().unwrap_or("").to_string(),
                    });
                }
            }
        }

        let decisions_path = effective_dir.join(format!("decisions-{date}.jsonl"));
        if let Ok(content) = std::fs::read_to_string(&decisions_path) {
            for line in content.lines().filter(|l| !l.trim().is_empty()) {
                let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
                    continue;
                };
                let ip_match = is_ip && v["target_ip"].as_str() == Some(target);
                let user_match = !is_ip && v["target_user"].as_str() == Some(target);
                if ip_match || user_match {
                    let action = v["action_type"].as_str().unwrap_or("unknown");
                    let dry_run = v["dry_run"].as_bool().unwrap_or(false);
                    let dry_tag = if dry_run { " [dry-run]" } else { "" };
                    entries.push(Entry {
                        ts: v["ts"].as_str().unwrap_or("").to_string(),
                        kind: "decision",
                        severity: String::new(),
                        summary: format!("Action: {action}{dry_tag}"),
                        extra: format!(
                            "conf:{:.2}  via:{}",
                            v["confidence"].as_f64().unwrap_or(0.0),
                            v["ai_provider"].as_str().unwrap_or("?")
                        ),
                    });
                }
            }
        }
    }

    if entries.is_empty() {
        let entity_type = if is_ip { "IP" } else { "user" };
        println!("No activity found for {entity_type} '{target}' in the last {days} day(s).");
        println!("Try --days 7 to search further back.");
        return Ok(());
    }

    entries.sort_by(|a, b| a.ts.cmp(&b.ts));

    let entity_type = if is_ip { "IP" } else { "User" };
    let event_count = entries.iter().filter(|e| e.kind == "event").count();
    let incident_count = entries.iter().filter(|e| e.kind == "incident").count();
    let decision_count = entries.iter().filter(|e| e.kind == "decision").count();

    println!("Entity: {entity_type} {target}");
    println!("Period: last {days} day(s)");
    println!("Found:  {event_count} event(s)  {incident_count} incident(s)  {decision_count} decision(s)");
    println!("{}", "─".repeat(72));

    for entry in &entries {
        let time = if entry.ts.len() >= 16 {
            &entry.ts[..16]
        } else {
            &entry.ts
        };
        let kind_tag = match entry.kind {
            "incident" => "[INCIDENT]  ",
            "decision" => "[DECISION]  ",
            _ => "[event]     ",
        };
        let sev_tag = if entry.kind == "event" || entry.kind == "incident" {
            sev_tag_plain(&entry.severity)
        } else {
            "         "
        };
        println!("{time}  {kind_tag}{sev_tag}  {}", entry.summary);
        if !entry.extra.is_empty() && entry.kind != "event" {
            println!("                                     {}", entry.extra);
        }
    }

    println!("{}", "─".repeat(72));
    println!("Open dashboard for full details: innerwarden status");
    Ok(())
}

pub(crate) fn matches_entity(line: &str, entity: &str) -> bool {
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(line) {
        if let Some(entities) = value.get("entities").and_then(|v| v.as_array()) {
            for e in entities {
                if let Some(val) = e.get("value").and_then(|v| v.as_str()) {
                    if val == entity {
                        return true;
                    }
                }
            }
        }
        for field in &["target_ip", "target_user", "operator", "target"] {
            if let Some(val) = value.get(*field).and_then(|v| v.as_str()) {
                if val == entity {
                    return true;
                }
            }
        }
    }
    false
}

fn recompute_hash_chain(lines: &mut [String]) {
    use innerwarden_core::audit::sha256_hex;
    let mut last_hash: Option<String> = None;
    for line in lines.iter_mut() {
        if let Ok(mut value) = serde_json::from_str::<serde_json::Value>(line) {
            value["prev_hash"] = match &last_hash {
                Some(h) => serde_json::Value::String(h.clone()),
                None => serde_json::Value::Null,
            };
            let new_line = serde_json::to_string(&value).unwrap();
            last_hash = Some(sha256_hex(&new_line));
            *line = new_line;
        }
    }
}

pub(crate) fn cmd_gdpr_export(data_dir: &Path, entity: &str, output: Option<&Path>) -> Result<()> {
    let patterns = &[
        "events-",
        "incidents-",
        "decisions-",
        "admin-actions-",
        "telemetry-",
    ];
    let mut total = 0usize;
    let mut writer: Box<dyn Write> = match output {
        Some(p) => Box::new(std::fs::File::create(p)?),
        None => Box::new(std::io::stdout()),
    };

    for entry in std::fs::read_dir(data_dir)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.ends_with(".jsonl") {
            continue;
        }
        if !patterns.iter().any(|p| name.starts_with(p)) {
            continue;
        }

        let content = std::fs::read_to_string(entry.path())?;
        for line in content.lines() {
            if line.trim().is_empty() {
                continue;
            }
            if matches_entity(line, entity) {
                writeln!(writer, "{line}")?;
                total += 1;
            }
        }
    }

    eprintln!("  Found {total} records matching '{entity}'");
    Ok(())
}

pub(crate) fn cmd_gdpr_erase(data_dir: &Path, entity: &str, yes: bool) -> Result<()> {
    let patterns = &[
        "events-",
        "incidents-",
        "decisions-",
        "admin-actions-",
        "telemetry-",
    ];
    let hash_chained = &["decisions-", "admin-actions-"];

    let mut file_matches: Vec<(PathBuf, String, usize)> = Vec::new();
    for entry in std::fs::read_dir(data_dir)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.ends_with(".jsonl") {
            continue;
        }
        let prefix = match patterns.iter().find(|p| name.starts_with(**p)) {
            Some(p) => p.to_string(),
            None => continue,
        };

        let content = std::fs::read_to_string(entry.path())?;
        let count = content
            .lines()
            .filter(|l| !l.trim().is_empty())
            .filter(|l| matches_entity(l, entity))
            .count();
        if count > 0 {
            file_matches.push((entry.path(), prefix, count));
        }
    }

    let total: usize = file_matches.iter().map(|(_, _, c)| *c).sum();
    if total == 0 {
        println!("  No records found matching '{entity}'");
        return Ok(());
    }

    println!(
        "  Found {total} records matching '{entity}' across {} files",
        file_matches.len()
    );
    if !yes {
        print!("  Proceed with erasure? [y/N] ");
        std::io::stdout().flush()?;
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        if !input.trim().eq_ignore_ascii_case("y") {
            println!("  Aborted.");
            return Ok(());
        }
    }

    let mut erased = 0usize;
    for (path, prefix, _) in &file_matches {
        let content = std::fs::read_to_string(path)?;
        let mut kept: Vec<String> = Vec::new();
        let mut removed = 0usize;

        for line in content.lines() {
            if line.trim().is_empty() {
                continue;
            }
            if matches_entity(line, entity) {
                removed += 1;
            } else {
                kept.push(line.to_string());
            }
        }

        if hash_chained.iter().any(|h| prefix.starts_with(h)) {
            recompute_hash_chain(&mut kept);
        }

        let tmp = tempfile::Builder::new()
            .prefix("innerwarden-gdpr-")
            .tempfile_in(data_dir)?;
        let tmp_path = tmp.path().to_path_buf();
        {
            let mut writer = std::io::BufWriter::new(&tmp);
            for line in &kept {
                writeln!(writer, "{line}")?;
            }
            writer.flush()?;
        }
        std::fs::rename(&tmp_path, path)?;

        erased += removed;
    }

    println!(
        "  Erased {erased} records across {} files",
        file_matches.len()
    );

    let mut audit = AdminActionEntry {
        ts: chrono::Utc::now(),
        operator: current_operator(),
        source: "cli".to_string(),
        action: "gdpr_erase".to_string(),
        target: entity.to_string(),
        parameters: serde_json::json!({
            "records_erased": erased,
            "files_modified": file_matches.len(),
        }),
        result: "success".to_string(),
        prev_hash: None,
    };
    if let Err(e) = append_admin_action(data_dir, &mut audit) {
        eprintln!("  [warn] failed to write audit: {e:#}");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn make_cli(tmp: &TempDir) -> Cli {
        Cli {
            sensor_config: tmp.path().join("config.toml"),
            agent_config: tmp.path().join("agent.toml"),
            data_dir: tmp.path().to_path_buf(),
            dry_run: true,
            command: None,
        }
    }

    fn today() -> String {
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        epoch_secs_to_date(now_secs)
    }

    fn write_jsonl(path: &Path, rows: &[serde_json::Value]) {
        let mut out = String::new();
        for row in rows {
            out.push_str(&serde_json::to_string(row).expect("serialize row"));
            out.push('\n');
        }
        std::fs::write(path, out).expect("write jsonl");
    }

    fn incident(title: &str, severity: &str, ip: &str) -> serde_json::Value {
        serde_json::json!({
            "ts": "2026-05-01T12:34:56Z",
            "severity": severity,
            "title": title,
            "summary": format!("summary for {title}"),
            "entities": [{ "type": "Ip", "value": ip }]
        })
    }

    fn event(summary: &str, user: &str) -> serde_json::Value {
        serde_json::json!({
            "ts": "2026-05-01T10:11:12Z",
            "source": "sensor",
            "kind": "shell.command_exec",
            "severity": "Medium",
            "summary": summary,
            "entities": [{ "type": "User", "value": user }]
        })
    }

    fn decision(action: &str, ip: &str, user: &str) -> serde_json::Value {
        serde_json::json!({
            "ts": "2026-05-01T13:14:15Z",
            "action_type": action,
            "target_ip": ip,
            "target_user": user,
            "confidence": 0.91,
            "dry_run": true,
            "ai_provider": "stub"
        })
    }

    // ---- SQLite-store seeding helpers (spec: get readers route to store) ----

    use innerwarden_core::entities::EntityRef;
    use innerwarden_core::event::Severity;
    use innerwarden_core::incident::Incident;
    use innerwarden_store::decisions::DecisionRow;
    use innerwarden_store::Store;

    /// A `ts` on today's UTC date so store window queries (`incidents_since_ts`
    /// / `decisions_for_date` for the last N days) include the seeded row.
    fn today_ts(hhmmss: &str) -> String {
        format!("{}T{hhmmss}+00:00", today())
    }

    fn store_incident(title: &str, severity: Severity, ip: &str, detector: &str) -> Incident {
        Incident {
            ts: chrono::DateTime::parse_from_rfc3339(&today_ts("12:34:56"))
                .unwrap()
                .with_timezone(&chrono::Utc),
            host: "test-host".to_string(),
            incident_id: format!("{detector}:{ip}:test"),
            severity,
            title: title.to_string(),
            summary: format!("summary for {title}"),
            evidence: serde_json::json!({}),
            recommended_checks: vec![],
            tags: vec![],
            entities: vec![EntityRef::ip(ip)],
        }
    }

    fn store_decision_row(action: &str, ip: &str, user: &str) -> DecisionRow {
        // The store's `data` blob is the canonical DecisionEntry JSON; the
        // get-decisions reader parses these exact field names.
        let data = serde_json::json!({
            "ts": today_ts("13:14:15"),
            "action_type": action,
            "target_ip": ip,
            "target_user": user,
            "confidence": 0.91,
            "dry_run": false,
            "ai_provider": "local_classifier",
        });
        DecisionRow {
            ts: today_ts("13:14:15"),
            incident_id: format!("{action}:{ip}:test"),
            action_type: action.to_string(),
            target_ip: (!ip.is_empty()).then(|| ip.to_string()),
            target_user: (!user.is_empty()).then(|| user.to_string()),
            confidence: 0.91,
            auto_executed: true,
            reason: None,
            data: serde_json::to_string(&data).unwrap(),
        }
    }

    #[test]
    fn incidents_rows_from_store_reads_seeded_incidents_and_filters_severity() {
        let tmp = TempDir::new().expect("tempdir");
        let store = Store::open(tmp.path()).expect("open store");
        store
            .insert_incident(&store_incident(
                "High hit",
                Severity::High,
                "203.0.113.10",
                "ssh_bruteforce",
            ))
            .expect("seed high");
        store
            .insert_incident(&store_incident(
                "Low noise",
                Severity::Low,
                "203.0.113.11",
                "port_scan",
            ))
            .expect("seed low");

        // min_rank for "low" is 2 -> both rows pass.
        let groups = incidents_rows_from_store(tmp.path(), 1, severity_rank("low"))
            .expect("store path should yield rows");
        let total: usize = groups.iter().map(|(_, r)| r.len()).sum();
        assert_eq!(total, 2, "both incidents read from store");
        let titles: Vec<&str> = groups
            .iter()
            .flat_map(|(_, rows)| rows.iter().map(|r| r.title.as_str()))
            .collect();
        assert!(titles.contains(&"High hit"));
        assert!(titles.contains(&"Low noise"));

        // min_rank for "high" is 4 -> only the High incident survives.
        let groups_high = incidents_rows_from_store(tmp.path(), 1, severity_rank("high"))
            .expect("store path should yield rows");
        let total_high: usize = groups_high.iter().map(|(_, r)| r.len()).sum();
        assert_eq!(total_high, 1, "only High passes the high filter");
        let row = &groups_high[0].1[0];
        assert_eq!(row.ip, "203.0.113.10");
    }

    #[test]
    fn incidents_rows_from_store_returns_none_when_store_empty() {
        // Empty store -> None so the caller falls back to JSONL.
        let tmp = TempDir::new().expect("tempdir");
        let _store = Store::open(tmp.path()).expect("open store");
        assert!(incidents_rows_from_store(tmp.path(), 1, severity_rank("low")).is_none());
    }

    #[test]
    fn cmd_incidents_reads_from_seeded_store() {
        // End-to-end: a seeded store must drive `get incidents` (the JSONL
        // files are absent, so a non-empty render proves the store path).
        let tmp = TempDir::new().expect("tempdir");
        let cli = make_cli(&tmp);
        let store = Store::open(tmp.path()).expect("open store");
        store
            .insert_incident(&store_incident(
                "Reverse shell",
                Severity::Critical,
                "198.51.100.5",
                "reverse_shell",
            ))
            .expect("seed");
        drop(store);

        cmd_incidents(&cli, 1, "low", tmp.path()).expect("store-backed incidents render");
    }

    #[test]
    fn decisions_rows_from_store_reads_and_filters_actions() {
        let tmp = TempDir::new().expect("tempdir");
        let store = Store::open(tmp.path()).expect("open store");
        store
            .insert_decision(&store_decision_row("block_ip", "203.0.113.10", ""))
            .expect("seed block");
        store
            .insert_decision(&store_decision_row("ignore", "", "root"))
            .expect("seed ignore");

        // Unfiltered -> both decisions.
        let groups =
            decisions_rows_from_store(tmp.path(), 1, None).expect("store path should yield rows");
        let total: usize = groups.iter().map(|(_, r)| r.len()).sum();
        assert_eq!(total, 2);

        // Filtered to block_ip -> one decision, with the IP preserved.
        let filtered = decisions_rows_from_store(tmp.path(), 1, Some("block_ip"))
            .expect("store had rows so the filtered store path is kept");
        let block_rows: Vec<&DecisionDisplayRow> =
            filtered.iter().flat_map(|(_, r)| r.iter()).collect();
        assert_eq!(block_rows.len(), 1);
        assert_eq!(block_rows[0].action, "block_ip");
        assert_eq!(block_rows[0].target_ip, "203.0.113.10");
        assert_eq!(block_rows[0].provider, "local_classifier");
        assert!(!block_rows[0].dry_run);
    }

    #[test]
    fn decisions_rows_from_store_returns_none_when_store_empty() {
        let tmp = TempDir::new().expect("tempdir");
        let _store = Store::open(tmp.path()).expect("open store");
        assert!(decisions_rows_from_store(tmp.path(), 1, None).is_none());
    }

    #[test]
    fn cmd_decisions_reads_from_seeded_store() {
        let tmp = TempDir::new().expect("tempdir");
        let cli = make_cli(&tmp);
        let store = Store::open(tmp.path()).expect("open store");
        store
            .insert_decision(&store_decision_row("block_ip", "203.0.113.10", ""))
            .expect("seed");
        drop(store);

        cmd_decisions(&cli, 1, None, tmp.path()).expect("store-backed decisions render");
        cmd_decisions(&cli, 1, Some("block_ip"), tmp.path()).expect("filtered store decisions");
    }

    #[test]
    fn severity_helpers_cover_known_and_default_levels() {
        assert_eq!(severity_rank("critical"), 5);
        assert_eq!(severity_rank("HIGH"), 4);
        assert_eq!(severity_rank("medium"), 3);
        assert_eq!(severity_rank("low"), 2);
        assert_eq!(severity_rank("info"), 1);

        assert_eq!(sev_tag_bracket("critical"), "[CRITICAL]");
        assert_eq!(sev_tag_bracket("unknown"), "[INFO]    ");
        assert_eq!(sev_tag_plain("high"), " HIGH    ");
        assert_eq!(sev_tag_plain("unknown"), "         ");

        assert_eq!(parse_severity_filter("critical"), 4);
        assert_eq!(parse_severity_filter("high"), 3);
        assert_eq!(parse_severity_filter("medium"), 2);
        assert_eq!(parse_severity_filter("low"), 1);
        assert_eq!(parse_severity_filter("anything"), 0);
        assert_eq!(severity_rank_str("critical"), 4);
        assert_eq!(severity_rank_str("anything"), 0);
    }

    #[test]
    fn print_helpers_accept_event_incident_and_live_shapes() {
        let inc = incident("Blocked", "High", "203.0.113.10");
        let ev = event("shell ran", "root");
        print_tail_entry(&ev, "events");
        print_tail_entry(&inc, "incidents");
        print_live_incident(&inc);
        print_live_incident(&serde_json::json!({
            "ts": "bad",
            "severity": "info",
            "title": "Title only",
            "summary": "Title only",
            "entities": []
        }));
    }

    #[test]
    fn cmd_incidents_filters_by_severity_and_handles_empty_results() {
        let tmp = TempDir::new().expect("tempdir");
        let cli = make_cli(&tmp);
        let date = today();
        write_jsonl(
            &tmp.path().join(format!("incidents-{date}.jsonl")),
            &[
                incident("High hit", "High", "203.0.113.10"),
                incident("Low noise", "Low", "203.0.113.11"),
            ],
        );

        cmd_incidents(&cli, 1, "high", tmp.path()).expect("incidents should render");

        let empty = TempDir::new().expect("empty tempdir");
        let empty_cli = make_cli(&empty);
        cmd_incidents(&empty_cli, 1, "high", empty.path()).expect("empty high path");
        cmd_incidents(&empty_cli, 1, "low", empty.path()).expect("empty low path");
    }

    #[test]
    fn cmd_export_writes_json_and_csv_outputs() {
        let tmp = TempDir::new().expect("tempdir");
        let cli = make_cli(&tmp);
        let date = today();
        write_jsonl(
            &tmp.path().join(format!("incidents-{date}.jsonl")),
            &[
                incident("High, quoted", "High", "203.0.113.10"),
                serde_json::json!({ "ts": "2026-05-01T00:00:00Z", "severity": "Low" }),
            ],
        );

        let json_out = tmp.path().join("incidents.json");
        cmd_export(
            &cli,
            "incidents",
            Some(&date),
            Some(&date),
            "json",
            Some(&json_out),
            tmp.path(),
        )
        .expect("json export should pass");
        let json = std::fs::read_to_string(json_out).expect("read json export");
        assert!(json.contains("High, quoted"));

        let csv_out = tmp.path().join("incidents.csv");
        cmd_export(
            &cli,
            "incidents",
            Some(&date),
            Some(&date),
            "csv",
            Some(&csv_out),
            tmp.path(),
        )
        .expect("csv export should pass");
        let csv = std::fs::read_to_string(csv_out).expect("read csv export");
        assert!(csv.contains("severity"));
        assert!(csv.contains("\"High, quoted\""));

        cmd_export(
            &cli,
            "events",
            Some(&date),
            Some(&date),
            "json",
            Some(&tmp.path().join("empty.json")),
            tmp.path(),
        )
        .expect("empty export should be non-fatal");
    }

    #[test]
    fn cmd_decisions_filters_and_reports_empty_paths() {
        let tmp = TempDir::new().expect("tempdir");
        let cli = make_cli(&tmp);
        let date = today();
        write_jsonl(
            &tmp.path().join(format!("decisions-{date}.jsonl")),
            &[
                decision("block_ip", "203.0.113.10", ""),
                decision("ignore", "", "root"),
            ],
        );

        cmd_decisions(&cli, 1, Some("block_ip"), tmp.path()).expect("filtered decisions");
        cmd_decisions(&cli, 1, None, tmp.path()).expect("all decisions");

        let empty = TempDir::new().expect("empty tempdir");
        let empty_cli = make_cli(&empty);
        cmd_decisions(&empty_cli, 1, Some("block_ip"), empty.path()).expect("empty filtered");
        cmd_decisions(&empty_cli, 1, None, empty.path()).expect("empty all");
    }

    #[test]
    fn cmd_entity_collects_ip_user_and_empty_activity() {
        let tmp = TempDir::new().expect("tempdir");
        let cli = make_cli(&tmp);
        let date = today();
        write_jsonl(
            &tmp.path().join(format!("events-{date}.jsonl")),
            &[event("root shell", "root")],
        );
        write_jsonl(
            &tmp.path().join(format!("incidents-{date}.jsonl")),
            &[incident("IP incident", "Critical", "203.0.113.10")],
        );
        write_jsonl(
            &tmp.path().join(format!("decisions-{date}.jsonl")),
            &[
                decision("block_ip", "203.0.113.10", ""),
                decision("suspend_user_sudo", "", "root"),
            ],
        );

        cmd_entity(&cli, "203.0.113.10", 1, tmp.path()).expect("ip entity");
        cmd_entity(&cli, "root", 1, tmp.path()).expect("user entity");
        cmd_entity(&cli, "nobody", 1, tmp.path()).expect("empty entity");
    }

    #[test]
    fn matches_entity_covers_entities_and_direct_fields() {
        assert!(matches_entity(
            &serde_json::to_string(&event("root shell", "root")).unwrap(),
            "root"
        ));
        assert!(matches_entity(
            &serde_json::to_string(&decision("block_ip", "203.0.113.10", "")).unwrap(),
            "203.0.113.10"
        ));
        assert!(matches_entity(
            r#"{"operator":"alice","target":"system"}"#,
            "alice"
        ));
        assert!(!matches_entity("not-json", "root"));
        assert!(!matches_entity(r#"{"entities":[]}"#, "root"));
    }

    #[test]
    fn recompute_hash_chain_rewrites_prev_hashes() {
        let mut lines = vec![
            r#"{"target_ip":"203.0.113.10","prev_hash":"old"}"#.to_string(),
            r#"{"target_ip":"203.0.113.11","prev_hash":"old"}"#.to_string(),
        ];

        recompute_hash_chain(&mut lines);

        let first: serde_json::Value = serde_json::from_str(&lines[0]).unwrap();
        let second: serde_json::Value = serde_json::from_str(&lines[1]).unwrap();
        assert!(first["prev_hash"].is_null());
        assert!(second["prev_hash"].as_str().is_some());
    }

    #[test]
    fn cmd_gdpr_export_writes_matching_records_only() {
        let tmp = TempDir::new().expect("tempdir");
        let date = today();
        write_jsonl(
            &tmp.path().join(format!("events-{date}.jsonl")),
            &[event("root shell", "root"), event("deploy shell", "deploy")],
        );
        std::fs::write(tmp.path().join("ignore.txt"), "root\n").expect("write ignored file");

        let out = tmp.path().join("gdpr.jsonl");
        cmd_gdpr_export(tmp.path(), "root", Some(&out)).expect("gdpr export");

        let exported = std::fs::read_to_string(out).expect("read gdpr export");
        assert!(exported.contains("root shell"));
        assert!(!exported.contains("deploy shell"));
    }

    #[test]
    fn cmd_gdpr_erase_removes_matches_and_recomputes_hash_chain() {
        let tmp = TempDir::new().expect("tempdir");
        let date = today();
        write_jsonl(
            &tmp.path().join(format!("decisions-{date}.jsonl")),
            &[
                decision("block_ip", "203.0.113.10", ""),
                decision("block_ip", "203.0.113.11", ""),
            ],
        );

        cmd_gdpr_erase(tmp.path(), "203.0.113.10", true).expect("gdpr erase");

        let decisions = std::fs::read_to_string(tmp.path().join(format!("decisions-{date}.jsonl")))
            .expect("read decisions");
        assert!(!decisions.contains("203.0.113.10"));
        assert!(decisions.contains("203.0.113.11"));
        let remaining: serde_json::Value = serde_json::from_str(decisions.lines().next().unwrap())
            .expect("remaining decision json");
        assert!(remaining["prev_hash"].is_null());

        let audit = std::fs::read_dir(tmp.path())
            .expect("read tempdir")
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.path())
            .find(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with("admin-actions-"))
            })
            .expect("audit log created");
        let audit = std::fs::read_to_string(audit).expect("read audit");
        assert!(audit.contains("\"action\":\"gdpr_erase\""));
    }

    #[test]
    fn cmd_gdpr_erase_no_matches_is_noop() {
        let tmp = TempDir::new().expect("tempdir");
        let date = today();
        write_jsonl(
            &tmp.path().join(format!("events-{date}.jsonl")),
            &[event("deploy shell", "deploy")],
        );

        cmd_gdpr_erase(tmp.path(), "root", true).expect("gdpr erase no matches");

        let events = std::fs::read_to_string(tmp.path().join(format!("events-{date}.jsonl")))
            .expect("read events");
        assert!(events.contains("deploy"));
    }
}
