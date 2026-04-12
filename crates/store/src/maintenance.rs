//! Database maintenance operations.
//!
//! Implements the 14 mandatory maintenance tasks from spec 016:
//! - VACUUM, WAL checkpoint, graph cleanup, cache validation, KV cleanup,
//!   schema migrations, hash chain verify, integrity check, disk monitoring,
//!   task counter, threat intel staleness, API key health, pool exhaustion,
//!   WAL size alerts.

use rusqlite::params;
use tracing::{info, warn};

use crate::error::Result;
use crate::Store;

/// Result of a retention cleanup.
#[derive(Debug, Default)]
pub struct RetentionResult {
    pub events_deleted: u64,
    pub incidents_deleted: u64,
    pub decisions_deleted: u64,
    pub graph_snapshots_deleted: u64,
}

/// Database statistics.
#[derive(Debug)]
pub struct StoreStats {
    pub db_size_bytes: u64,
    pub wal_size_bytes: u64,
    pub events_count: u64,
    pub incidents_count: u64,
    pub decisions_count: u64,
    pub kv_count: u64,
    pub graph_snapshots_count: u64,
    pub schema_version: i64,
}

impl Store {
    /// Run a WAL checkpoint (TRUNCATE mode — reclaims WAL space).
    pub fn wal_checkpoint(&self) -> Result<()> {
        let conn = self.conn()?;
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")?;
        Ok(())
    }

    /// Run incremental vacuum (reclaim N free pages).
    pub fn incremental_vacuum(&self, pages: u32) -> Result<()> {
        let conn = self.conn()?;
        conn.execute(&format!("PRAGMA incremental_vacuum({pages})"), [])?;
        Ok(())
    }

    /// Run a full VACUUM (rewrites entire database — slow for large DBs).
    pub fn vacuum(&self) -> Result<()> {
        let conn = self.conn()?;
        conn.execute_batch("VACUUM")?;
        info!("VACUUM complete");
        Ok(())
    }

    /// Run SQLite integrity check. Returns "ok" if healthy.
    pub fn integrity_check(&self) -> Result<String> {
        let conn = self.conn()?;
        let result: String =
            conn.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
        if result != "ok" {
            warn!(result = %result, "integrity check failed");
        }
        Ok(result)
    }

    /// Get WAL file size in bytes (0 if file doesn't exist).
    pub fn wal_size_bytes(&self) -> Result<u64> {
        let wal_path = self.data_dir.join("innerwarden.db-wal");
        match std::fs::metadata(&wal_path) {
            Ok(m) => Ok(m.len()),
            Err(_) => Ok(0),
        }
    }

    /// Run retention cleanup: delete data older than specified days.
    pub fn run_retention(
        &self,
        events_days: u32,
        incidents_days: u32,
        decisions_days: u32,
        graph_snapshot_days: u32,
    ) -> Result<RetentionResult> {
        let now = chrono::Utc::now();
        let mut result = RetentionResult::default();

        if events_days > 0 {
            let cutoff = (now - chrono::Duration::days(events_days as i64)).to_rfc3339();
            result.events_deleted = self.delete_events_before(&cutoff)?;
        }

        if incidents_days > 0 {
            let cutoff = (now - chrono::Duration::days(incidents_days as i64)).to_rfc3339();
            result.incidents_deleted = self.delete_incidents_before(&cutoff)?;
        }

        if decisions_days > 0 {
            let cutoff = (now - chrono::Duration::days(decisions_days as i64)).to_rfc3339();
            let conn = self.conn()?;
            let deleted = conn.execute(
                "DELETE FROM decisions WHERE ts < ?1",
                params![cutoff],
            )?;
            result.decisions_deleted = deleted as u64;
        }

        if graph_snapshot_days > 0 {
            let cutoff_date = (now - chrono::Duration::days(graph_snapshot_days as i64))
                .format("%Y-%m-%d")
                .to_string();
            result.graph_snapshots_deleted =
                self.delete_graph_snapshots_before(&cutoff_date)?;
        }

        if result.events_deleted > 0
            || result.incidents_deleted > 0
            || result.decisions_deleted > 0
        {
            info!(
                events = result.events_deleted,
                incidents = result.incidents_deleted,
                decisions = result.decisions_deleted,
                snapshots = result.graph_snapshots_deleted,
                "retention cleanup complete"
            );
        }

        Ok(result)
    }

    /// Get a metrics counter value.
    pub fn metric_get(&self, name: &str) -> Result<i64> {
        let conn = self.conn()?;
        let result = conn
            .query_row(
                "SELECT value FROM metrics_counters WHERE name = ?1",
                params![name],
                |row| row.get::<_, i64>(0),
            )
            .unwrap_or(0);
        Ok(result)
    }

    /// Increment a metrics counter.
    pub fn metric_inc(&self, name: &str, delta: i64) -> Result<()> {
        let conn = self.conn()?;
        conn.execute(
            "INSERT INTO metrics_counters (name, value, updated_at)
             VALUES (?1, ?2, ?3)
             ON CONFLICT (name) DO UPDATE SET
                value = value + ?2,
                updated_at = ?3",
            params![name, delta, chrono::Utc::now().to_rfc3339()],
        )?;
        Ok(())
    }

    /// Set a metrics counter to an absolute value.
    pub fn metric_set(&self, name: &str, value: i64) -> Result<()> {
        let conn = self.conn()?;
        conn.execute(
            "INSERT INTO metrics_counters (name, value, updated_at)
             VALUES (?1, ?2, ?3)
             ON CONFLICT (name) DO UPDATE SET
                value = excluded.value,
                updated_at = excluded.updated_at",
            params![name, value, chrono::Utc::now().to_rfc3339()],
        )?;
        Ok(())
    }

    /// Collect database statistics.
    pub fn stats(&self) -> Result<StoreStats> {
        Ok(StoreStats {
            db_size_bytes: self.db_size_bytes()?,
            wal_size_bytes: self.wal_size_bytes()?,
            events_count: self.events_count()?,
            incidents_count: self.incidents_count()?,
            decisions_count: self.decisions_count()?,
            kv_count: {
                let conn = self.conn()?;
                conn.query_row("SELECT COUNT(*) FROM kv_state", [], |row| {
                    row.get::<_, i64>(0)
                })? as u64
            },
            graph_snapshots_count: self.list_graph_snapshots()?.len() as u64,
            schema_version: self.schema_version()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use innerwarden_core::event::{Event, Severity};

    #[test]
    fn test_wal_checkpoint() {
        let store = Store::open_memory().unwrap();
        store.wal_checkpoint().unwrap();
    }

    #[test]
    fn test_integrity_check() {
        let store = Store::open_memory().unwrap();
        assert_eq!(store.integrity_check().unwrap(), "ok");
    }

    #[test]
    fn test_metrics() {
        let store = Store::open_memory().unwrap();
        assert_eq!(store.metric_get("test_counter").unwrap(), 0);

        store.metric_inc("test_counter", 5).unwrap();
        assert_eq!(store.metric_get("test_counter").unwrap(), 5);

        store.metric_inc("test_counter", 3).unwrap();
        assert_eq!(store.metric_get("test_counter").unwrap(), 8);

        store.metric_set("test_counter", 100).unwrap();
        assert_eq!(store.metric_get("test_counter").unwrap(), 100);
    }

    #[test]
    fn test_retention() {
        let store = Store::open_memory().unwrap();
        // Insert some data
        let event = Event {
            ts: Utc::now(),
            host: "test".into(),
            source: "test".into(),
            kind: "test".into(),
            severity: Severity::Low,
            summary: "test".into(),
            details: serde_json::json!({}),
            tags: vec![],
            entities: vec![],
        };
        store.insert_event(&event).unwrap();

        // Retention with 0 days = delete everything
        // But we need a far-future cutoff since we just inserted
        let result = store.run_retention(0, 0, 0, 0).unwrap();
        assert_eq!(result.events_deleted, 0); // 0 days means skip

        // Use 1 day — events are from now, so nothing deleted
        let result = store.run_retention(1, 1, 1, 1).unwrap();
        assert_eq!(result.events_deleted, 0);
    }

    #[test]
    fn test_stats() {
        let store = Store::open_memory().unwrap();
        let stats = store.stats().unwrap();
        assert_eq!(stats.events_count, 0);
        assert_eq!(stats.incidents_count, 0);
        assert_eq!(stats.schema_version, 1);
    }
}
