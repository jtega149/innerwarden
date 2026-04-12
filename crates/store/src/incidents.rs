//! Incident storage operations.

use innerwarden_core::incident::Incident;
use rusqlite::params;

use crate::error::Result;
use crate::Store;

impl Store {
    /// Insert an incident. Returns the rowid.
    pub fn insert_incident(&self, incident: &Incident) -> Result<i64> {
        let conn = self.conn()?;
        let data = serde_json::to_string(incident)?;
        // Extract detector from incident_id (format: "source:kind:datetime")
        let detector = incident
            .incident_id
            .split(':')
            .take(2)
            .collect::<Vec<_>>()
            .join(":");
        conn.execute(
            "INSERT OR IGNORE INTO incidents
             (ts, host, incident_id, severity, detector, title, summary, data)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                incident.ts.to_rfc3339(),
                incident.host,
                incident.incident_id,
                format!("{:?}", incident.severity).to_lowercase(),
                detector,
                incident.title,
                incident.summary,
                data,
            ],
        )?;
        Ok(conn.last_insert_rowid())
    }

    /// Read incidents with rowid > `after_id`, up to `limit`.
    pub fn incidents_since(&self, after_id: i64, limit: usize) -> Result<Vec<(i64, Incident)>> {
        let conn = self.conn()?;
        let mut stmt = conn
            .prepare_cached("SELECT id, data FROM incidents WHERE id > ?1 ORDER BY id LIMIT ?2")?;
        let rows = stmt.query_map(params![after_id, limit as i64], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
        })?;

        let mut results = Vec::new();
        for row in rows {
            let (id, data) = row?;
            match serde_json::from_str::<Incident>(&data) {
                Ok(incident) => results.push((id, incident)),
                Err(e) => {
                    tracing::warn!(id, error = %e, "skipping malformed incident row");
                }
            }
        }
        Ok(results)
    }

    /// Look up a single incident by its `incident_id`.
    pub fn get_incident(&self, incident_id: &str) -> Result<Option<Incident>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare_cached("SELECT data FROM incidents WHERE incident_id = ?1")?;
        let result = stmt
            .query_row(params![incident_id], |row| row.get::<_, String>(0))
            .optional()?;

        match result {
            Some(data) => Ok(Some(serde_json::from_str(&data)?)),
            None => Ok(None),
        }
    }

    /// Count total incidents.
    pub fn incidents_count(&self) -> Result<u64> {
        let conn = self.conn()?;
        let count: i64 = conn.query_row("SELECT COUNT(*) FROM incidents", [], |row| row.get(0))?;
        Ok(count as u64)
    }

    /// Delete incidents with ts < `before_ts`. Returns rows deleted.
    pub fn delete_incidents_before(&self, before_ts: &str) -> Result<u64> {
        let conn = self.conn()?;
        let deleted = conn.execute("DELETE FROM incidents WHERE ts < ?1", params![before_ts])?;
        Ok(deleted as u64)
    }

    /// Get the maximum rowid (0 if empty).
    pub fn incidents_max_id(&self) -> Result<i64> {
        let conn = self.conn()?;
        let max: i64 = conn.query_row("SELECT COALESCE(MAX(id), 0) FROM incidents", [], |row| {
            row.get(0)
        })?;
        Ok(max)
    }
}

/// Extension trait for optional query results.
trait OptionalExt<T> {
    fn optional(self) -> std::result::Result<Option<T>, rusqlite::Error>;
}

impl<T> OptionalExt<T> for std::result::Result<T, rusqlite::Error> {
    fn optional(self) -> std::result::Result<Option<T>, rusqlite::Error> {
        match self {
            Ok(v) => Ok(Some(v)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use innerwarden_core::event::Severity;

    fn sample_incident(id: &str) -> Incident {
        Incident {
            ts: Utc::now(),
            host: "test-host".into(),
            incident_id: id.into(),
            severity: Severity::High,
            title: "Test incident".into(),
            summary: "Summary".into(),
            evidence: serde_json::json!({"detail": "value"}),
            recommended_checks: vec!["check_1".into()],
            tags: vec!["test".into()],
            entities: vec![],
        }
    }

    #[test]
    fn test_insert_and_query() {
        let store = Store::open_memory().unwrap();
        let id1 = store
            .insert_incident(&sample_incident("ssh:bruteforce:2026-04-12"))
            .unwrap();
        let id2 = store
            .insert_incident(&sample_incident("sensor:port_scan:2026-04-12"))
            .unwrap();
        assert!(id2 > id1);

        let incidents = store.incidents_since(0, 100).unwrap();
        assert_eq!(incidents.len(), 2);
    }

    #[test]
    fn test_get_by_incident_id() {
        let store = Store::open_memory().unwrap();
        store
            .insert_incident(&sample_incident("ssh:bruteforce:2026-04-12"))
            .unwrap();

        let found = store.get_incident("ssh:bruteforce:2026-04-12").unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().title, "Test incident");

        let not_found = store.get_incident("nonexistent").unwrap();
        assert!(not_found.is_none());
    }

    #[test]
    fn test_duplicate_incident_id_ignored() {
        let store = Store::open_memory().unwrap();
        store
            .insert_incident(&sample_incident("ssh:bruteforce:2026-04-12"))
            .unwrap();
        // Second insert with same incident_id should be ignored (INSERT OR IGNORE)
        store
            .insert_incident(&sample_incident("ssh:bruteforce:2026-04-12"))
            .unwrap();
        assert_eq!(store.incidents_count().unwrap(), 1);
    }
}
