//! Allowlist + false-positive bot-command helpers extracted from
//! `telegram/client.rs`.
//!
//! These functions do filesystem I/O (append to `allowlist.toml`, write to
//! `allowlist-history.jsonl`, write to `false-positive-history.jsonl`) and
//! are triggered by `/add`, `/rm`, and `/fp` bot commands on the
//! operator's Telegram chat. They don't touch the TelegramClient's HTTP
//! layer at all — keeping them here makes client.rs exclusively about
//! speaking to the Telegram API.

pub fn append_to_allowlist(
    allowlist_path: &std::path::Path,
    section: &str,
    key: &str,
    reason: &str,
) -> anyhow::Result<()> {
    use fs2::FileExt;
    use std::io::Write;

    fn toml_escape(value: &str) -> String {
        value
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('\n', " ")
    }

    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(allowlist_path)?;
    file.lock_exclusive()?;
    let escaped_key = toml_escape(key);
    let escaped_reason = toml_escape(reason);
    writeln!(file, "\n[{section}]")?;
    writeln!(file, "\"{}\" = \"{}\"", escaped_key, escaped_reason)?;
    file.flush()?;
    file.unlock()?;
    Ok(())
}

/// Log an allowlist change (add or remove) to allowlist-history.jsonl.
pub fn log_allowlist_change(
    data_dir: &std::path::Path,
    key: &str,
    section: &str,
    operator: &str,
    action: &str,
) {
    let path = data_dir.join("allowlist-history.jsonl");
    let entry = serde_json::json!({
        "ts": chrono::Utc::now().to_rfc3339(),
        "key": key,
        "section": section,
        "operator": operator,
        "action": action,
    });
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        use std::io::Write;
        let _ = writeln!(f, "{}", entry);
    }
}

/// Read allowlist history and return last N "add" entries without matching "remove".
pub fn read_undoable_allowlist_entries(
    data_dir: &std::path::Path,
    max_entries: usize,
) -> Vec<(String, String, String, String)> {
    // Returns Vec<(key, section, operator, ts)>
    let path = data_dir.join("allowlist-history.jsonl");
    let content = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    let mut adds: Vec<(String, String, String, String)> = Vec::new();
    let mut removed_keys: std::collections::HashSet<(String, String)> =
        std::collections::HashSet::new();

    // Parse all entries
    for line in content.lines() {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
            let key = v
                .get("key")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let section = v
                .get("section")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let operator = v
                .get("operator")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let ts = v
                .get("ts")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let action = v
                .get("action")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            if action == "add" {
                adds.push((key, section, operator, ts));
            } else if action == "remove" {
                removed_keys.insert((key, section));
            }
        }
    }

    // Filter out entries that have been removed, take last N
    adds.into_iter()
        .rev()
        .filter(|(key, section, _, _)| !removed_keys.contains(&(key.clone(), section.clone())))
        .take(max_entries)
        .collect()
}

/// Remove a key from allowlist.toml atomically.
/// Reads the file, removes lines containing the key in the appropriate section,
/// writes to a temp file, and renames over the original.
pub fn remove_from_allowlist(
    allowlist_path: &std::path::Path,
    section: &str,
    key: &str,
) -> anyhow::Result<()> {
    use fs2::FileExt;

    let content = std::fs::read_to_string(allowlist_path).unwrap_or_default();

    let mut result_lines: Vec<String> = Vec::new();
    let mut in_target_section = false;
    let escaped_key = key.replace('\\', "\\\\").replace('"', "\\\"");

    for line in content.lines() {
        let trimmed = line.trim();
        // Track section headers
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            let sec = &trimmed[1..trimmed.len() - 1];
            in_target_section = sec == section;
            result_lines.push(line.to_string());
            continue;
        }

        // If in the target section, skip lines containing the key
        if in_target_section
            && (trimmed.contains(&format!("\"{}\"", escaped_key))
                || trimmed.contains(&format!("\"{}\"", key)))
        {
            continue;
        }

        result_lines.push(line.to_string());
    }

    // Remove trailing empty lines and consecutive empty section headers
    let output = result_lines.join("\n");

    // Write atomically: temp file + rename
    let temp_path = allowlist_path.with_extension("toml.tmp");
    {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&temp_path)?;
        file.lock_exclusive()?;
        use std::io::Write;
        let mut writer = std::io::BufWriter::new(&file);
        writer.write_all(output.as_bytes())?;
        writer.write_all(b"\n")?;
        writer.flush()?;
        file.unlock()?;
    }
    std::fs::rename(&temp_path, allowlist_path)?;

    Ok(())
}

/// Log an incident as a false positive to a daily JSONL file.
///
/// Used for training data collection and FP-rate tracking.  The file
/// is created if missing and each entry is one JSON line.
pub fn log_false_positive(
    data_dir: &std::path::Path,
    incident_id: &str,
    detector: &str,
    reporter: &str,
) {
    let today = chrono::Utc::now().format("%Y-%m-%d");
    let path = data_dir.join(format!("fp-reports-{today}.jsonl"));
    let entry = serde_json::json!({
        "ts": chrono::Utc::now().to_rfc3339(),
        "incident_id": incident_id,
        "detector": detector,
        "reporter": reporter,
        "action": "reported_fp"
    });
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        use std::io::Write;
        let _ = writeln!(f, "{}", entry);
    }
}
