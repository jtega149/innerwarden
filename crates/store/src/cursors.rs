//! Cursor tracking for incremental reading.
//!
//! Agent cursors track the last-read rowid for events/incidents.
//! Sensor cursors track per-collector state (arbitrary JSON).

use rusqlite::params;

use crate::error::Result;
use crate::Store;

impl Store {
    // ── Agent cursors ──────────────────────────────────────────────

    /// Get the last-read rowid for a named stream (e.g. "events", "incidents").
    /// Returns 0 if no cursor exists.
    pub fn get_agent_cursor(&self, name: &str) -> Result<i64> {
        let conn = self.conn()?;
        let result = conn
            .query_row(
                "SELECT last_id FROM agent_cursors WHERE name = ?1",
                params![name],
                |row| row.get::<_, i64>(0),
            )
            .unwrap_or(0);
        Ok(result)
    }

    /// Set the last-read rowid for a named stream.
    pub fn set_agent_cursor(&self, name: &str, last_id: i64) -> Result<()> {
        let conn = self.conn()?;
        conn.execute(
            "INSERT INTO agent_cursors (name, last_id, updated_at)
             VALUES (?1, ?2, ?3)
             ON CONFLICT (name) DO UPDATE SET
                last_id = excluded.last_id,
                updated_at = excluded.updated_at",
            params![name, last_id, chrono::Utc::now().to_rfc3339()],
        )?;
        Ok(())
    }

    // ── Sensor cursors ─────────────────────────────────────────────

    /// Get a sensor collector's cursor state (JSON blob).
    pub fn get_sensor_cursor(&self, collector: &str) -> Result<Option<String>> {
        let conn = self.conn()?;
        let result = conn
            .query_row(
                "SELECT cursor_data FROM sensor_cursors WHERE collector = ?1",
                params![collector],
                |row| row.get::<_, String>(0),
            )
            .ok();
        Ok(result)
    }

    /// Set a sensor collector's cursor state.
    pub fn set_sensor_cursor(&self, collector: &str, data: &str) -> Result<()> {
        let conn = self.conn()?;
        conn.execute(
            "INSERT INTO sensor_cursors (collector, cursor_data, updated_at)
             VALUES (?1, ?2, ?3)
             ON CONFLICT (collector) DO UPDATE SET
                cursor_data = excluded.cursor_data,
                updated_at = excluded.updated_at",
            params![collector, data, chrono::Utc::now().to_rfc3339()],
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_agent_cursor() {
        let store = Store::open_memory().unwrap();

        assert_eq!(store.get_agent_cursor("events").unwrap(), 0);

        store.set_agent_cursor("events", 42).unwrap();
        assert_eq!(store.get_agent_cursor("events").unwrap(), 42);

        store.set_agent_cursor("events", 100).unwrap();
        assert_eq!(store.get_agent_cursor("events").unwrap(), 100);

        // Different cursor names are isolated
        assert_eq!(store.get_agent_cursor("incidents").unwrap(), 0);
    }

    #[test]
    fn test_sensor_cursor() {
        let store = Store::open_memory().unwrap();

        assert!(store.get_sensor_cursor("auth_log").unwrap().is_none());

        store
            .set_sensor_cursor("auth_log", r#"{"offset": 12345}"#)
            .unwrap();
        let data = store.get_sensor_cursor("auth_log").unwrap().unwrap();
        assert!(data.contains("12345"));
    }
}
