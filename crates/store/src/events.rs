//! Event storage operations.

use innerwarden_core::event::Event;
use rusqlite::params;

use crate::error::Result;
use crate::Store;

impl Store {
    /// Insert an event. Returns the rowid (monotonic cursor).
    pub fn insert_event(&self, event: &Event) -> Result<i64> {
        let conn = self.conn()?;
        let data = serde_json::to_string(event)?;
        conn.execute(
            "INSERT INTO events (ts, host, source, kind, severity, summary, data)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                event.ts.to_rfc3339(),
                event.host,
                event.source,
                event.kind,
                format!("{:?}", event.severity).to_lowercase(),
                event.summary,
                data,
            ],
        )?;
        Ok(conn.last_insert_rowid())
    }

    /// Insert a batch of events in a single transaction.
    pub fn insert_events_batch(&self, events: &[Event]) -> Result<()> {
        let conn = self.conn()?;
        let tx = conn.unchecked_transaction()?;
        {
            let mut stmt = tx.prepare_cached(
                "INSERT INTO events (ts, host, source, kind, severity, summary, data)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            )?;
            for event in events {
                let data = serde_json::to_string(event)?;
                stmt.execute(params![
                    event.ts.to_rfc3339(),
                    event.host,
                    event.source,
                    event.kind,
                    format!("{:?}", event.severity).to_lowercase(),
                    event.summary,
                    data,
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Stream event `(kind, src_ip)` tuples since `since_ts_iso`, up to `limit`,
    /// in ascending `ts` order. Used by nightly autoencoder training — the
    /// full `Event` payload is never needed there, so we return the two fields
    /// that matter (kind for feature index, ip for blocked-IP filtering) and
    /// avoid deserialising the rest.
    ///
    /// The JSONL-based training path read events sequentially from per-day
    /// files. After spec 016 the raw events only live in SQLite, so this is
    /// the sole source of training data on current production.
    pub fn events_for_training(
        &self,
        since_ts_iso: &str,
        limit: usize,
    ) -> Result<Vec<(String, Option<String>)>> {
        let conn = self.conn()?;
        let mut stmt = conn
            .prepare_cached("SELECT kind, data FROM events WHERE ts >= ?1 ORDER BY ts LIMIT ?2")?;
        let rows = stmt.query_map(params![since_ts_iso, limit as i64], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;

        let mut out = Vec::new();
        for row in rows {
            let (kind, data) = row?;
            let ip = serde_json::from_str::<serde_json::Value>(&data)
                .ok()
                .and_then(|v| {
                    v.get("details").and_then(|d| {
                        d.get("src_ip")
                            .or_else(|| d.get("ip"))
                            .and_then(|s| s.as_str())
                            .map(|s| s.to_string())
                    })
                });
            out.push((kind, ip));
        }
        Ok(out)
    }

    /// Read events with rowid > `after_id`, up to `limit`.
    /// Returns `(rowid, Event)` pairs for cursor tracking.
    pub fn events_since(&self, after_id: i64, limit: usize) -> Result<Vec<(i64, Event)>> {
        let conn = self.conn()?;
        let mut stmt =
            conn.prepare_cached("SELECT id, data FROM events WHERE id > ?1 ORDER BY id LIMIT ?2")?;
        let rows = stmt.query_map(params![after_id, limit as i64], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
        })?;

        let mut results = Vec::new();
        for row in rows {
            let (id, data) = row?;
            match serde_json::from_str::<Event>(&data) {
                Ok(event) => results.push((id, event)),
                Err(e) => {
                    tracing::warn!(id, error = %e, "skipping malformed event row");
                }
            }
        }
        Ok(results)
    }

    /// Count total events.
    pub fn events_count(&self) -> Result<u64> {
        let conn = self.conn()?;
        let count: i64 = conn.query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))?;
        Ok(count as u64)
    }

    /// Delete events with ts < `before_ts` (ISO 8601). Returns rows deleted.
    pub fn delete_events_before(&self, before_ts: &str) -> Result<u64> {
        let conn = self.conn()?;
        let deleted = conn.execute("DELETE FROM events WHERE ts < ?1", params![before_ts])?;
        Ok(deleted as u64)
    }

    /// Get the maximum rowid in the events table (0 if empty).
    pub fn events_max_id(&self) -> Result<i64> {
        let conn = self.conn()?;
        let max: i64 = conn.query_row("SELECT COALESCE(MAX(id), 0) FROM events", [], |row| {
            row.get(0)
        })?;
        Ok(max)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use innerwarden_core::event::Severity;

    fn sample_event(kind: &str) -> Event {
        Event {
            ts: Utc::now(),
            host: "test-host".into(),
            source: "test".into(),
            kind: kind.into(),
            severity: Severity::Medium,
            summary: "test event".into(),
            details: serde_json::json!({"key": "value"}),
            tags: vec!["test".into()],
            entities: vec![],
        }
    }

    #[test]
    fn test_insert_and_query() {
        let store = Store::open_memory().unwrap();
        let id1 = store.insert_event(&sample_event("ssh_bruteforce")).unwrap();
        let id2 = store.insert_event(&sample_event("port_scan")).unwrap();
        assert!(id2 > id1);

        let events = store.events_since(0, 100).unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].1.kind, "ssh_bruteforce");
        assert_eq!(events[1].1.kind, "port_scan");

        // Cursor: only events after id1
        let events = store.events_since(id1, 100).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].1.kind, "port_scan");
    }

    #[test]
    fn test_batch_insert() {
        let store = Store::open_memory().unwrap();
        let events: Vec<Event> = (0..100)
            .map(|i| sample_event(&format!("kind_{i}")))
            .collect();
        store.insert_events_batch(&events).unwrap();
        assert_eq!(store.events_count().unwrap(), 100);
    }

    #[test]
    fn test_delete_before() {
        let store = Store::open_memory().unwrap();
        store.insert_event(&sample_event("old")).unwrap();
        // Delete everything before far future
        let deleted = store.delete_events_before("2099-01-01T00:00:00Z").unwrap();
        assert_eq!(deleted, 1);
        assert_eq!(store.events_count().unwrap(), 0);
    }

    #[test]
    fn test_events_for_training_streams_kind_and_ip() {
        let store = Store::open_memory().unwrap();
        let mut ev = sample_event("ssh.login_failed");
        ev.details = serde_json::json!({"src_ip": "1.2.3.4", "user": "root"});
        store.insert_event(&ev).unwrap();
        let mut ev2 = sample_event("http.request");
        ev2.details = serde_json::json!({"ip": "5.6.7.8"});
        store.insert_event(&ev2).unwrap();
        let mut ev3 = sample_event("file.read_access");
        ev3.details = serde_json::json!({"path": "/etc/passwd"});
        store.insert_event(&ev3).unwrap();

        let rows = store
            .events_for_training("1970-01-01T00:00:00Z", 100)
            .unwrap();
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0], ("ssh.login_failed".into(), Some("1.2.3.4".into())));
        assert_eq!(rows[1], ("http.request".into(), Some("5.6.7.8".into())));
        assert_eq!(rows[2].0, "file.read_access");
        assert_eq!(rows[2].1, None);
    }

    #[test]
    fn test_events_for_training_respects_window_cutoff() {
        let store = Store::open_memory().unwrap();
        store.insert_event(&sample_event("a")).unwrap();
        let far_future = "2099-01-01T00:00:00Z";
        let rows = store.events_for_training(far_future, 100).unwrap();
        assert!(rows.is_empty(), "events older than cutoff must be skipped");
    }

    #[test]
    fn test_events_max_id() {
        let store = Store::open_memory().unwrap();
        assert_eq!(store.events_max_id().unwrap(), 0);
        store.insert_event(&sample_event("a")).unwrap();
        let max = store.events_max_id().unwrap();
        assert!(max > 0);
    }
}
