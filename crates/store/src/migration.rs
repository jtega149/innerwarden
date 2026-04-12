//! One-time migration from legacy storage (JSONL + redb + JSON files).
//!
//! Runs on first startup when legacy files are detected alongside SQLite.
//! Old files are archived to `legacy-archive/` (not deleted).
//!
//! Full implementation deferred to Phase 7.

use std::path::Path;

use tracing::info;

use crate::error::Result;
use crate::Store;

/// Report of what was migrated.
#[derive(Debug, Default)]
pub struct MigrationReport {
    pub events_migrated: u64,
    pub incidents_migrated: u64,
    pub decisions_migrated: u64,
    pub kv_entries_migrated: u64,
    pub graph_snapshots_migrated: u64,
    pub state_blobs_migrated: u64,
    pub files_archived: u64,
}

impl Store {
    /// Check if legacy files exist that should be migrated.
    pub fn has_legacy_files(data_dir: &Path) -> bool {
        // Check for any of the legacy storage artifacts
        let patterns = [
            "events-*.jsonl",
            "incidents-*.jsonl",
            "decisions-*.jsonl",
            "agent-state.redb",
            "graph-snapshot-*.json",
            "responses.json",
        ];

        for pattern in patterns {
            // Simple check: look for the most common files
            let check = match pattern {
                "agent-state.redb" => data_dir.join("agent-state.redb").exists(),
                "responses.json" => data_dir.join("responses.json").exists(),
                _ => {
                    // For glob patterns, check if any matching file exists
                    if let Ok(entries) = std::fs::read_dir(data_dir) {
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
    /// **Phase 7 implementation**: This is a stub. The full migration
    /// will import JSONL events/incidents/decisions, redb state, graph
    /// snapshots, and JSON state files into SQLite.
    pub fn migrate_from_legacy(data_dir: &Path) -> Result<MigrationReport> {
        info!(
            data_dir = %data_dir.display(),
            "legacy migration: checking for files to migrate"
        );

        let report = MigrationReport::default();

        // Phase 7 will implement:
        // 1. migrate_redb_state(store, data_dir)
        // 2. migrate_decisions_jsonl(store, data_dir) — preserve hash chain
        // 3. migrate_incidents_jsonl(store, data_dir)
        // 4. migrate_graph_snapshots(store, data_dir)
        // 5. migrate_json_state_files(store, data_dir)
        // 6. archive_legacy_files(data_dir)

        info!(
            events = report.events_migrated,
            incidents = report.incidents_migrated,
            decisions = report.decisions_migrated,
            "legacy migration complete (stub — Phase 7)"
        );

        Ok(report)
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
    fn test_has_legacy_files_with_redb() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("agent-state.redb"), b"fake").unwrap();
        assert!(Store::has_legacy_files(dir.path()));
    }

    #[test]
    fn test_has_legacy_files_with_jsonl() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("events-2026-04-12.jsonl"), b"fake").unwrap();
        assert!(Store::has_legacy_files(dir.path()));
    }

    #[test]
    fn test_migrate_stub() {
        let dir = tempfile::tempdir().unwrap();
        let report = Store::migrate_from_legacy(dir.path()).unwrap();
        assert_eq!(report.events_migrated, 0);
    }
}
