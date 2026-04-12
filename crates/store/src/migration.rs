//! One-time migration from legacy storage (JSONL + JSON files).
//!
//! Runs on first startup when legacy files are detected alongside SQLite.
//! Old files are archived to `legacy-archive/` (not deleted).

use std::fs;
use std::io::{BufRead, BufReader};
use std::path::Path;

use tracing::{info, warn};

use crate::decisions::DecisionRow;
use crate::error::Result;
use crate::Store;

/// Report of what was migrated.
#[derive(Debug, Default)]
pub struct MigrationReport {
    pub incidents_migrated: u64,
    pub incidents_skipped: u64,
    pub decisions_migrated: u64,
    pub decisions_skipped: u64,
    pub graph_snapshots_migrated: u64,
    pub state_blobs_migrated: u64,
    pub files_archived: u64,
}

impl std::fmt::Display for MigrationReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "incidents={} decisions={} snapshots={} blobs={} archived={} (skipped: incidents={}, decisions={})",
            self.incidents_migrated,
            self.decisions_migrated,
            self.graph_snapshots_migrated,
            self.state_blobs_migrated,
            self.files_archived,
            self.incidents_skipped,
            self.decisions_skipped,
        )
    }
}

impl Store {
    /// Check if legacy files exist that should be migrated.
    pub fn has_legacy_files(data_dir: &Path) -> bool {
        // Check for any of the legacy storage artifacts
        let patterns = [
            "incidents-*.jsonl",
            "decisions-*.jsonl",
            "graph-snapshot-*.json",
            "responses.json",
            "attacker-profiles.json",
            "campaigns.json",
            "baseline.json",
            "playbook-log.json",
            "threat-feeds.json",
        ];

        for pattern in patterns {
            let check = match pattern {
                "responses.json"
                | "attacker-profiles.json"
                | "campaigns.json"
                | "baseline.json"
                | "playbook-log.json"
                | "threat-feeds.json" => data_dir.join(pattern).exists(),
                _ => {
                    // For glob patterns, check if any matching file exists
                    if let Ok(entries) = fs::read_dir(data_dir) {
                        let prefix = pattern.split('*').next().unwrap_or("");
                        let suffix = pattern.split('*').next_back().unwrap_or("");
                        entries.filter_map(|e| e.ok()).any(|e| {
                            let name = e.file_name().to_string_lossy().to_string();
                            name.starts_with(prefix) && name.ends_with(suffix)
                        })
                    } else {
                        false
                    }
                }
            };
            if check {
                return true;
            }
        }
        false
    }

    /// Run the full migration from legacy storage.
    ///
    /// Migrates incidents JSONL, decisions JSONL, graph snapshots, and
    /// JSON state blobs into SQLite. Malformed lines are skipped with
    /// a warning. After migration, files are moved to `legacy-archive/`.
    pub fn migrate_from_legacy(&self, data_dir: &Path) -> Result<MigrationReport> {
        info!(
            data_dir = %data_dir.display(),
            "legacy migration: checking for files to migrate"
        );

        let mut report = MigrationReport::default();
        let mut files_to_archive: Vec<std::path::PathBuf> = Vec::new();

        // 1. Migrate incidents JSONL
        migrate_incidents_jsonl(self, data_dir, &mut report, &mut files_to_archive);

        // 2. Migrate decisions JSONL
        migrate_decisions_jsonl(self, data_dir, &mut report, &mut files_to_archive);

        // 3. Migrate graph snapshots
        migrate_graph_snapshots(self, data_dir, &mut report, &mut files_to_archive);

        // 4. Migrate JSON state blobs
        migrate_state_blobs(self, data_dir, &mut report, &mut files_to_archive);

        // 5. Archive legacy files
        archive_files(data_dir, &files_to_archive, &mut report);

        info!(
            incidents = report.incidents_migrated,
            decisions = report.decisions_migrated,
            snapshots = report.graph_snapshots_migrated,
            blobs = report.state_blobs_migrated,
            archived = report.files_archived,
            "legacy migration complete"
        );

        Ok(report)
    }
}

/// Find files matching a prefix/suffix pattern in a directory.
fn find_matching_files(data_dir: &Path, prefix: &str, suffix: &str) -> Vec<std::path::PathBuf> {
    let mut files = Vec::new();
    if let Ok(entries) = fs::read_dir(data_dir) {
        for entry in entries.filter_map(|e| e.ok()) {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with(prefix) && name.ends_with(suffix) {
                files.push(entry.path());
            }
        }
    }
    files.sort();
    files
}

/// Migrate incidents-*.jsonl files.
fn migrate_incidents_jsonl(
    store: &Store,
    data_dir: &Path,
    report: &mut MigrationReport,
    files_to_archive: &mut Vec<std::path::PathBuf>,
) {
    let files = find_matching_files(data_dir, "incidents-", ".jsonl");
    for path in files {
        let fname = path.file_name().unwrap_or_default().to_string_lossy().to_string();
        match fs::File::open(&path) {
            Ok(file) => {
                let reader = BufReader::new(file);
                for (line_num, line) in reader.lines().enumerate() {
                    let line = match line {
                        Ok(l) => l,
                        Err(e) => {
                            warn!(file = %fname, line = line_num + 1, "read error: {e}");
                            report.incidents_skipped += 1;
                            continue;
                        }
                    };
                    let line = line.trim();
                    if line.is_empty() {
                        continue;
                    }
                    match serde_json::from_str::<innerwarden_core::incident::Incident>(line) {
                        Ok(incident) => {
                            match store.insert_incident(&incident) {
                                Ok(_) => report.incidents_migrated += 1,
                                Err(e) => {
                                    warn!(file = %fname, line = line_num + 1, "insert error: {e}");
                                    report.incidents_skipped += 1;
                                }
                            }
                        }
                        Err(e) => {
                            warn!(file = %fname, line = line_num + 1, "parse error: {e}");
                            report.incidents_skipped += 1;
                        }
                    }
                }
                files_to_archive.push(path);
            }
            Err(e) => {
                warn!(file = %fname, "failed to open: {e}");
            }
        }
    }
}

/// Migrate decisions-*.jsonl files.
fn migrate_decisions_jsonl(
    store: &Store,
    data_dir: &Path,
    report: &mut MigrationReport,
    files_to_archive: &mut Vec<std::path::PathBuf>,
) {
    let files = find_matching_files(data_dir, "decisions-", ".jsonl");
    for path in files {
        let fname = path.file_name().unwrap_or_default().to_string_lossy().to_string();
        match fs::File::open(&path) {
            Ok(file) => {
                let reader = BufReader::new(file);
                for (line_num, line) in reader.lines().enumerate() {
                    let line = match line {
                        Ok(l) => l,
                        Err(e) => {
                            warn!(file = %fname, line = line_num + 1, "read error: {e}");
                            report.decisions_skipped += 1;
                            continue;
                        }
                    };
                    let trimmed = line.trim();
                    if trimmed.is_empty() {
                        continue;
                    }
                    match serde_json::from_str::<serde_json::Value>(trimmed) {
                        Ok(val) => {
                            let row = DecisionRow {
                                ts: val
                                    .get("ts")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("")
                                    .to_string(),
                                incident_id: val
                                    .get("incident_id")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("")
                                    .to_string(),
                                action_type: val
                                    .get("action_type")
                                    .or_else(|| val.get("action"))
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("")
                                    .to_string(),
                                target_ip: val
                                    .get("target_ip")
                                    .or_else(|| val.get("ip"))
                                    .and_then(|v| v.as_str())
                                    .map(String::from),
                                target_user: val
                                    .get("target_user")
                                    .or_else(|| val.get("user"))
                                    .and_then(|v| v.as_str())
                                    .map(String::from),
                                confidence: val
                                    .get("confidence")
                                    .and_then(|v| v.as_f64())
                                    .unwrap_or(0.0),
                                auto_executed: val
                                    .get("auto_executed")
                                    .and_then(|v| v.as_bool())
                                    .unwrap_or(false),
                                reason: val
                                    .get("reason")
                                    .and_then(|v| v.as_str())
                                    .map(String::from),
                                data: trimmed.to_string(),
                            };
                            match store.insert_decision(&row) {
                                Ok(_) => report.decisions_migrated += 1,
                                Err(e) => {
                                    warn!(file = %fname, line = line_num + 1, "insert error: {e}");
                                    report.decisions_skipped += 1;
                                }
                            }
                        }
                        Err(e) => {
                            warn!(file = %fname, line = line_num + 1, "parse error: {e}");
                            report.decisions_skipped += 1;
                        }
                    }
                }
                files_to_archive.push(path);
            }
            Err(e) => {
                warn!(file = %fname, "failed to open: {e}");
            }
        }
    }
}

/// Migrate graph-snapshot-*.json files.
fn migrate_graph_snapshots(
    store: &Store,
    data_dir: &Path,
    report: &mut MigrationReport,
    files_to_archive: &mut Vec<std::path::PathBuf>,
) {
    let files = find_matching_files(data_dir, "graph-snapshot-", ".json");
    for path in files {
        let fname = path.file_name().unwrap_or_default().to_string_lossy().to_string();
        // Extract date from filename: graph-snapshot-YYYY-MM-DD.json
        let date = fname
            .strip_prefix("graph-snapshot-")
            .and_then(|s| s.strip_suffix(".json"))
            .unwrap_or("unknown");

        match fs::read(&path) {
            Ok(bytes) => {
                // Count nodes/edges from JSON
                let (nodes, edges) = count_graph_nodes_edges(&bytes);
                match store.save_graph_snapshot(date, &bytes, nodes, edges) {
                    Ok(()) => {
                        report.graph_snapshots_migrated += 1;
                        files_to_archive.push(path);
                    }
                    Err(e) => {
                        warn!(file = %fname, "save error: {e}");
                    }
                }
            }
            Err(e) => {
                warn!(file = %fname, "read error: {e}");
            }
        }
    }
}

/// Count nodes and edges from graph snapshot JSON bytes.
fn count_graph_nodes_edges(bytes: &[u8]) -> (usize, usize) {
    match serde_json::from_slice::<serde_json::Value>(bytes) {
        Ok(val) => {
            let nodes = val
                .get("nodes")
                .and_then(|v| v.as_array())
                .map(|a| a.len())
                .or_else(|| val.get("nodes").and_then(|v| v.as_object()).map(|o| o.len()))
                .unwrap_or(0);
            let edges = val
                .get("edges")
                .and_then(|v| v.as_array())
                .map(|a| a.len())
                .or_else(|| val.get("edges").and_then(|v| v.as_object()).map(|o| o.len()))
                .unwrap_or(0);
            (nodes, edges)
        }
        Err(_) => (0, 0),
    }
}

/// Mapping of legacy JSON files to blob names.
const STATE_BLOB_MAPPINGS: &[(&str, &str)] = &[
    ("responses.json", "responses"),
    ("attacker-profiles.json", "attacker_profiles"),
    ("campaigns.json", "campaigns"),
    ("baseline.json", "baseline"),
    ("playbook-log.json", "playbook_log"),
    ("threat-feeds.json", "threat_feeds"),
];

/// Migrate JSON state files to blobs.
fn migrate_state_blobs(
    store: &Store,
    data_dir: &Path,
    report: &mut MigrationReport,
    files_to_archive: &mut Vec<std::path::PathBuf>,
) {
    for &(filename, blob_name) in STATE_BLOB_MAPPINGS {
        let path = data_dir.join(filename);
        if !path.exists() {
            continue;
        }
        match fs::read_to_string(&path) {
            Ok(content) => {
                let content = content.trim();
                if content.is_empty() {
                    files_to_archive.push(path);
                    continue;
                }
                match store.set_blob(blob_name, content) {
                    Ok(()) => {
                        report.state_blobs_migrated += 1;
                        files_to_archive.push(path);
                    }
                    Err(e) => {
                        warn!(file = filename, "blob write error: {e}");
                    }
                }
            }
            Err(e) => {
                warn!(file = filename, "read error: {e}");
            }
        }
    }
}

/// Move migrated files to legacy-archive/ directory.
fn archive_files(
    data_dir: &Path,
    files: &[std::path::PathBuf],
    report: &mut MigrationReport,
) {
    if files.is_empty() {
        return;
    }

    let archive_dir = data_dir.join("legacy-archive");
    if let Err(e) = fs::create_dir_all(&archive_dir) {
        warn!("failed to create legacy-archive dir: {e}");
        return;
    }

    for src in files {
        if let Some(fname) = src.file_name() {
            let dest = archive_dir.join(fname);
            match fs::rename(src, &dest) {
                Ok(()) => report.files_archived += 1,
                Err(e) => {
                    warn!(file = %src.display(), "archive failed: {e}");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_has_legacy_files_empty_dir() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!Store::has_legacy_files(dir.path()));
    }

    #[test]
    fn test_has_legacy_files_with_jsonl() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("incidents-2026-04-12.jsonl"), b"fake").unwrap();
        assert!(Store::has_legacy_files(dir.path()));
    }

    #[test]
    fn test_has_legacy_files_with_responses() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("responses.json"), b"{}").unwrap();
        assert!(Store::has_legacy_files(dir.path()));
    }

    #[test]
    fn test_migrate_incidents_jsonl() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();

        // Write a JSONL file with 2 valid lines + 1 bad line
        let line1 = serde_json::json!({
            "ts": "2026-04-12T10:00:00Z",
            "host": "srv1",
            "incident_id": "ssh:bruteforce:2026-04-12T10:00:00",
            "severity": "high",
            "title": "SSH Brute Force",
            "summary": "Multiple failed logins",
            "evidence": {"attempts": 50},
            "recommended_checks": ["check_auth_log"],
            "tags": ["ssh"],
            "entities": []
        });
        let line2 = serde_json::json!({
            "ts": "2026-04-12T11:00:00Z",
            "host": "srv1",
            "incident_id": "sensor:port_scan:2026-04-12T11:00:00",
            "severity": "medium",
            "title": "Port Scan",
            "summary": "Sequential port scan detected",
            "evidence": {"ports": [22, 80, 443]},
            "recommended_checks": [],
            "tags": ["scan"],
            "entities": []
        });
        let content = format!(
            "{}\nthis is not valid json\n{}\n",
            serde_json::to_string(&line1).unwrap(),
            serde_json::to_string(&line2).unwrap()
        );
        fs::write(
            dir.path().join("incidents-2026-04-12.jsonl"),
            content,
        )
        .unwrap();

        let report = store.migrate_from_legacy(dir.path()).unwrap();
        assert_eq!(report.incidents_migrated, 2);
        assert_eq!(report.incidents_skipped, 1);
        assert_eq!(store.incidents_count().unwrap(), 2);
    }

    #[test]
    fn test_migrate_decisions_jsonl() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();

        let line1 = serde_json::json!({
            "ts": "2026-04-12T10:00:00Z",
            "incident_id": "inc-1",
            "action_type": "block_ip",
            "target_ip": "1.2.3.4",
            "confidence": 0.95,
            "auto_executed": true,
            "reason": "test"
        });
        let content = format!("{}\n", serde_json::to_string(&line1).unwrap());
        fs::write(
            dir.path().join("decisions-2026-04-12.jsonl"),
            content,
        )
        .unwrap();

        let report = store.migrate_from_legacy(dir.path()).unwrap();
        assert_eq!(report.decisions_migrated, 1);
        assert_eq!(store.decisions_count().unwrap(), 1);
    }

    #[test]
    fn test_migrate_state_blob() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();

        let json = r#"{"active_blocks": 5, "ips": ["1.2.3.4"]}"#;
        fs::write(dir.path().join("responses.json"), json).unwrap();

        let report = store.migrate_from_legacy(dir.path()).unwrap();
        assert_eq!(report.state_blobs_migrated, 1);

        let blob = store.get_blob("responses").unwrap().unwrap();
        assert_eq!(blob, json);
    }

    #[test]
    fn test_migrate_graph_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();

        let snapshot = serde_json::json!({
            "nodes": [{"id": "a"}, {"id": "b"}],
            "edges": [{"from": "a", "to": "b"}]
        });
        fs::write(
            dir.path().join("graph-snapshot-2026-04-12.json"),
            serde_json::to_string(&snapshot).unwrap(),
        )
        .unwrap();

        let report = store.migrate_from_legacy(dir.path()).unwrap();
        assert_eq!(report.graph_snapshots_migrated, 1);

        let loaded = store.load_graph_snapshot("2026-04-12").unwrap();
        assert!(loaded.is_some());

        let snapshots = store.list_graph_snapshots().unwrap();
        assert_eq!(snapshots.len(), 1);
        assert_eq!(snapshots[0].nodes_count, 2);
        assert_eq!(snapshots[0].edges_count, 1);
    }

    #[test]
    fn test_files_archived() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();

        fs::write(dir.path().join("responses.json"), r#"{"x":1}"#).unwrap();
        fs::write(dir.path().join("baseline.json"), r#"{"y":2}"#).unwrap();

        let report = store.migrate_from_legacy(dir.path()).unwrap();
        assert_eq!(report.files_archived, 2);

        // Original files should be gone
        assert!(!dir.path().join("responses.json").exists());
        assert!(!dir.path().join("baseline.json").exists());

        // Should exist in legacy-archive/
        let archive = dir.path().join("legacy-archive");
        assert!(archive.join("responses.json").exists());
        assert!(archive.join("baseline.json").exists());
    }

    #[test]
    fn test_idempotency() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();

        // Create an incident JSONL
        let line = serde_json::json!({
            "ts": "2026-04-12T10:00:00Z",
            "host": "srv1",
            "incident_id": "ssh:bruteforce:2026-04-12T10:00:00",
            "severity": "high",
            "title": "SSH Brute Force",
            "summary": "Multiple failed logins",
            "evidence": {},
            "recommended_checks": [],
            "tags": [],
            "entities": []
        });
        let content = format!("{}\n", serde_json::to_string(&line).unwrap());
        fs::write(
            dir.path().join("incidents-2026-04-12.jsonl"),
            &content,
        )
        .unwrap();

        // First migration
        let r1 = store.migrate_from_legacy(dir.path()).unwrap();
        assert_eq!(r1.incidents_migrated, 1);
        assert_eq!(r1.files_archived, 1);

        // File is now in legacy-archive, so running again does nothing
        let r2 = store.migrate_from_legacy(dir.path()).unwrap();
        assert_eq!(r2.incidents_migrated, 0);
        assert_eq!(r2.files_archived, 0);

        // Only 1 incident in the store (INSERT OR IGNORE would handle dupes anyway)
        assert_eq!(store.incidents_count().unwrap(), 1);
    }

    #[test]
    fn test_migrate_empty_dir() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();

        let report = store.migrate_from_legacy(dir.path()).unwrap();
        assert_eq!(report.incidents_migrated, 0);
        assert_eq!(report.decisions_migrated, 0);
        assert_eq!(report.graph_snapshots_migrated, 0);
        assert_eq!(report.state_blobs_migrated, 0);
        assert_eq!(report.files_archived, 0);
    }

    #[test]
    fn test_count_graph_nodes_edges() {
        let json = serde_json::json!({
            "nodes": [1, 2, 3],
            "edges": [{"a": "b"}, {"c": "d"}]
        });
        let bytes = serde_json::to_vec(&json).unwrap();
        let (n, e) = count_graph_nodes_edges(&bytes);
        assert_eq!(n, 3);
        assert_eq!(e, 2);

        // Invalid JSON returns 0,0
        let (n, e) = count_graph_nodes_edges(b"not json");
        assert_eq!(n, 0);
        assert_eq!(e, 0);
    }
}
