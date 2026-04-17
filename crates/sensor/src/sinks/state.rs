use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Persistent cursor state for all collectors.
/// Stored as state.json in the data directory.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct State {
    /// Collector cursors keyed by collector name.
    /// Values are collector-specific (byte offset, journal cursor string, etc.)
    pub cursors: HashMap<String, serde_json::Value>,
}

impl State {
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read state: {}", path.display()))?;
        serde_json::from_str(&content).with_context(|| "failed to parse state.json")
    }

    /// Atomic save: write to .tmp then rename to avoid partial writes.
    pub fn save(&self, path: &Path) -> Result<()> {
        let tmp = temp_state_path(path);
        let content = serde_json::to_string_pretty(self)?;
        std::fs::write(&tmp, &content)
            .with_context(|| format!("failed to write {}", tmp.display()))?;
        std::fs::rename(&tmp, path)
            .with_context(|| format!("failed to rename state file to {}", path.display()))?;
        Ok(())
    }

    pub fn get_cursor(&self, collector: &str) -> Option<&serde_json::Value> {
        self.cursors.get(collector)
    }

    pub fn set_cursor(&mut self, collector: &str, value: serde_json::Value) {
        self.cursors.insert(collector.to_string(), value);
    }
}

fn temp_state_path(path: &Path) -> PathBuf {
    path.with_extension("json.tmp")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_test_dir() -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("innerwarden-sensor-state-tests-{nanos}"));
        std::fs::create_dir_all(&path).expect("test temp dir must be creatable");
        path
    }

    #[test]
    fn temp_state_path_uses_json_tmp_extension() {
        // Verifies atomic-save temp file naming stays consistent with rename path.
        let path = Path::new("/var/lib/innerwarden/state.json");
        assert_eq!(
            temp_state_path(path),
            PathBuf::from("/var/lib/innerwarden/state.json.tmp")
        );
    }

    #[test]
    fn load_returns_default_when_state_file_is_missing() {
        // Covers bootstrap path where sensor starts before any cursor has been persisted.
        let dir = unique_test_dir();
        let missing = dir.join("missing-state.json");
        let state = State::load(&missing).expect("missing file should return default state");
        assert!(state.cursors.is_empty());
    }

    #[test]
    fn save_and_load_round_trip_preserves_cursor_values() {
        // Ensures cursor persistence survives save/load cycles for collector resume behavior.
        let dir = unique_test_dir();
        let path = dir.join("state.json");
        let mut state = State::default();
        state.set_cursor("auth_log", serde_json::json!(123u64));
        state.set_cursor("journald", serde_json::json!("s=abc123"));
        state.save(&path).expect("state save should succeed");

        let loaded = State::load(&path).expect("saved state must parse");
        assert_eq!(
            loaded.get_cursor("auth_log"),
            Some(&serde_json::json!(123u64))
        );
        assert_eq!(
            loaded.get_cursor("journald"),
            Some(&serde_json::json!("s=abc123"))
        );
    }
}
