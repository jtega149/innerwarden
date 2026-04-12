//! Graph snapshot storage (replaces graph-snapshot-*.json files).
//!
//! The knowledge graph lives in-memory for hot-path performance.
//! SQLite stores periodic snapshots for persistence across restarts.

use rusqlite::params;

use crate::error::Result;
use crate::Store;

/// Metadata about a stored graph snapshot.
#[derive(Debug, Clone)]
pub struct SnapshotInfo {
    pub date: String,
    pub nodes_count: usize,
    pub edges_count: usize,
    pub created_at: String,
    pub size_bytes: usize,
}

impl Store {
    /// Save a graph snapshot for a given date (upsert).
    /// `snapshot` is the serialized graph bytes (JSON or compressed).
    pub fn save_graph_snapshot(
        &self,
        date: &str,
        snapshot: &[u8],
        nodes_count: usize,
        edges_count: usize,
    ) -> Result<()> {
        let conn = self.conn()?;
        conn.execute(
            "INSERT INTO graph_snapshots (date, snapshot, nodes_count, edges_count, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT (date) DO UPDATE SET
                snapshot = excluded.snapshot,
                nodes_count = excluded.nodes_count,
                edges_count = excluded.edges_count,
                created_at = excluded.created_at",
            params![
                date,
                snapshot,
                nodes_count as i64,
                edges_count as i64,
                chrono::Utc::now().to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    /// Load the most recent graph snapshot. Returns `(date, bytes)`.
    pub fn load_latest_graph_snapshot(&self) -> Result<Option<(String, Vec<u8>)>> {
        let conn = self.conn()?;
        let result = conn
            .query_row(
                "SELECT date, snapshot FROM graph_snapshots ORDER BY date DESC LIMIT 1",
                [],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .ok();
        Ok(result)
    }

    /// Load a snapshot for a specific date.
    pub fn load_graph_snapshot(&self, date: &str) -> Result<Option<Vec<u8>>> {
        let conn = self.conn()?;
        let result = conn
            .query_row(
                "SELECT snapshot FROM graph_snapshots WHERE date = ?1",
                params![date],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .ok();
        Ok(result)
    }

    /// List all snapshot dates with metadata.
    pub fn list_graph_snapshots(&self) -> Result<Vec<SnapshotInfo>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT date, nodes_count, edges_count, created_at, LENGTH(snapshot)
             FROM graph_snapshots ORDER BY date DESC",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(SnapshotInfo {
                date: row.get(0)?,
                nodes_count: row.get::<_, i64>(1)? as usize,
                edges_count: row.get::<_, i64>(2)? as usize,
                created_at: row.get(3)?,
                size_bytes: row.get::<_, i64>(4)? as usize,
            })
        })?;
        let mut results = Vec::new();
        for row in rows {
            results.push(row?);
        }
        Ok(results)
    }

    /// Delete snapshots older than `before_date` (YYYY-MM-DD). Returns count deleted.
    pub fn delete_graph_snapshots_before(&self, before_date: &str) -> Result<u64> {
        let conn = self.conn()?;
        let deleted = conn.execute(
            "DELETE FROM graph_snapshots WHERE date < ?1",
            params![before_date],
        )?;
        Ok(deleted as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_save_and_load() {
        let store = Store::open_memory().unwrap();
        let data = b"serialized graph data here";

        store
            .save_graph_snapshot("2026-04-12", data, 100, 500)
            .unwrap();
        store
            .save_graph_snapshot("2026-04-11", b"older data", 80, 400)
            .unwrap();

        // Latest
        let (date, bytes) = store.load_latest_graph_snapshot().unwrap().unwrap();
        assert_eq!(date, "2026-04-12");
        assert_eq!(bytes, data);

        // By date
        let bytes = store.load_graph_snapshot("2026-04-11").unwrap().unwrap();
        assert_eq!(bytes, b"older data");

        // Not found
        assert!(store.load_graph_snapshot("2026-01-01").unwrap().is_none());
    }

    #[test]
    fn test_upsert() {
        let store = Store::open_memory().unwrap();
        store
            .save_graph_snapshot("2026-04-12", b"v1", 10, 20)
            .unwrap();
        store
            .save_graph_snapshot("2026-04-12", b"v2", 15, 30)
            .unwrap();

        let (_, bytes) = store.load_latest_graph_snapshot().unwrap().unwrap();
        assert_eq!(bytes, b"v2");

        let snapshots = store.list_graph_snapshots().unwrap();
        assert_eq!(snapshots.len(), 1);
        assert_eq!(snapshots[0].nodes_count, 15);
    }

    #[test]
    fn test_retention() {
        let store = Store::open_memory().unwrap();
        for d in 1..=10 {
            store
                .save_graph_snapshot(&format!("2026-04-{d:02}"), b"data", 10, 20)
                .unwrap();
        }
        assert_eq!(store.list_graph_snapshots().unwrap().len(), 10);

        let deleted = store
            .delete_graph_snapshots_before("2026-04-05")
            .unwrap();
        assert_eq!(deleted, 4); // days 01-04
        assert_eq!(store.list_graph_snapshots().unwrap().len(), 6);
    }
}
