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

    /// Read every incident whose `ts` is at or after `start_ts`, ordered by
    /// timestamp ascending, up to `limit`.
    ///
    /// Spec 049 PR18 — drives the boot-time KG replay. The agent's
    /// in-memory `KnowledgeGraph` is rehydrated from a periodic
    /// snapshot, which is at best minutes old and at worst a full day
    /// old (when the operator deploys a new release before the daily
    /// snapshot has captured the day's traffic). The replay walks the
    /// canonical `incidents` table for the current day and re-ingests
    /// every row into the graph so the dashboard's Cases panel stops
    /// shrinking on every restart. Comparison with `incidents_since`:
    /// that scans by monotonic rowid (the agent's hot-path cursor);
    /// this one scans by `ts` so callers can ask "everything since
    /// 00:00 UTC today" without juggling cursor state.
    ///
    /// `start_ts` is matched lexicographically against the `ts` column,
    /// which is the same RFC-3339 string the writer persists — so a
    /// caller passing `"2026-05-13T00:00:00+00:00"` gets every incident
    /// from midnight UTC onward. Garbage in (`"not-a-ts"`) returns an
    /// empty set without surprising the caller.
    pub fn incidents_since_ts(&self, start_ts: &str, limit: usize) -> Result<Vec<Incident>> {
        let conn = self.conn()?;
        let mut stmt = conn
            .prepare_cached("SELECT data FROM incidents WHERE ts >= ?1 ORDER BY ts ASC LIMIT ?2")?;
        let rows = stmt.query_map(params![start_ts, limit as i64], |row| {
            row.get::<_, String>(0)
        })?;

        let mut results = Vec::new();
        for row in rows {
            let data = row?;
            match serde_json::from_str::<Incident>(&data) {
                Ok(incident) => results.push(incident),
                Err(e) => {
                    tracing::warn!(error = %e, "incidents_since_ts: skipping malformed row");
                }
            }
        }
        Ok(results)
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

    /// Phase 7 (audit RC-2): mark an incident as allowlisted by an
    /// operator's trust rule. Called from the agent fast loop's
    /// SkipAllowlisted branch in `process/incidents.rs`. Persists the
    /// match outcome at write-time so the dashboard's overview path
    /// can render allowlisted attackers in their own group instead of
    /// inflating "Needs attention" by counting decision-less rows.
    ///
    /// Idempotent: if the row is already flagged the UPDATE is a noop.
    /// Returns the number of rows affected (0 if the incident_id does
    /// not exist, 1 on success).
    pub fn set_incident_allowlisted(&self, incident_id: &str) -> Result<usize> {
        let conn = self.conn()?;
        let n = conn.execute(
            "UPDATE incidents SET is_allowlisted = 1 WHERE incident_id = ?1",
            params![incident_id],
        )?;
        Ok(n)
    }

    /// Phase 7B (audit RC-2 / 2026-04-29): find incidents older than
    /// `before_ts` that have no decision row joined and are not
    /// flagged is_allowlisted. The agent's slow_loop runs this every
    /// 10 minutes and writes a `dismiss` decision for each, so the
    /// dashboard's "Stuck >1h" pending bucket trends down across
    /// ticks instead of accumulating dead-weight forever.
    ///
    /// Returns up to `limit` rows of `(incident_id, ts_iso, data_json)`
    /// ordered oldest-first. The agent caller writes the dismiss
    /// decision via the standard `decisions::append_chained` so the
    /// hash chain stays intact and the audit log is honest about
    /// which provider made the call (`ai_provider="orphan-recovery"`).
    pub fn find_orphan_incidents(
        &self,
        before_ts: &str,
        limit: usize,
    ) -> Result<Vec<(String, String, String)>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare_cached(
            "SELECT i.incident_id, i.ts, i.data \
             FROM incidents i \
             LEFT JOIN decisions d ON d.incident_id = i.incident_id \
             WHERE d.id IS NULL \
               AND i.ts < ?1 \
               AND i.is_allowlisted = 0 \
             ORDER BY i.ts ASC \
             LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![before_ts, limit as i64], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?;
        let mut results = Vec::new();
        for row in rows {
            results.push(row?);
        }
        Ok(results)
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

    fn incident_at(id: &str, ts: chrono::DateTime<Utc>) -> Incident {
        let mut inc = sample_incident(id);
        inc.ts = ts;
        inc
    }

    #[test]
    fn incidents_since_ts_returns_rows_at_or_after_start() {
        // Spec 049 PR18 — boot replay anchor. Operator-visible promise:
        // after agent restart, the Cases panel must show every incident
        // the sensor produced since the start of the day. This anchor
        // exercises the lexicographic boundary so a future refactor
        // that changes `>=` to `>` (off-by-one) regresses immediately.
        let store = Store::open_memory().unwrap();
        let day = chrono::NaiveDate::from_ymd_opt(2026, 5, 13).unwrap();
        let midnight = day.and_hms_opt(0, 0, 0).unwrap().and_utc();

        // 23:59 of the prior day — must be excluded by `>= midnight`.
        store
            .insert_incident(&incident_at(
                "prior-day",
                midnight - chrono::Duration::seconds(60),
            ))
            .unwrap();
        // Exact midnight — must be included (boundary case).
        store
            .insert_incident(&incident_at("boundary-midnight", midnight))
            .unwrap();
        // Mid-morning — included.
        store
            .insert_incident(&incident_at(
                "morning",
                midnight + chrono::Duration::hours(8),
            ))
            .unwrap();

        let rows = store
            .incidents_since_ts(&midnight.to_rfc3339(), 1_000)
            .expect("query must succeed");

        let ids: Vec<&str> = rows.iter().map(|i| i.incident_id.as_str()).collect();
        assert!(
            !ids.contains(&"prior-day"),
            "23:59 of the prior day must NOT cross into today's replay"
        );
        assert!(
            ids.contains(&"boundary-midnight"),
            "exact midnight must be included so a midnight-edge incident is never lost on restart"
        );
        assert!(
            ids.contains(&"morning"),
            "the regular hot-path case must work"
        );
    }

    #[test]
    fn incidents_since_ts_returns_ordered_by_ts() {
        // Boot replay calls ingest_incident in iteration order; the
        // graph carries `ts` as the visible field, so out-of-order
        // replay would not corrupt the KG but it would make the
        // ingestion log hard to read. Cheap to pin; cheap to honour.
        let store = Store::open_memory().unwrap();
        let base = chrono::NaiveDate::from_ymd_opt(2026, 5, 13)
            .unwrap()
            .and_hms_opt(0, 0, 0)
            .unwrap()
            .and_utc();
        store
            .insert_incident(&incident_at("third", base + chrono::Duration::seconds(3)))
            .unwrap();
        store
            .insert_incident(&incident_at("first", base + chrono::Duration::seconds(1)))
            .unwrap();
        store
            .insert_incident(&incident_at("second", base + chrono::Duration::seconds(2)))
            .unwrap();

        let rows = store
            .incidents_since_ts(&base.to_rfc3339(), 100)
            .expect("query must succeed");
        let ids: Vec<&str> = rows.iter().map(|i| i.incident_id.as_str()).collect();
        assert_eq!(ids, vec!["first", "second", "third"]);
    }

    #[test]
    fn incidents_since_ts_respects_limit() {
        // Boot replay caps at a large number so a pathological day
        // can't pin a runtime. The cap must be honoured.
        let store = Store::open_memory().unwrap();
        let base = chrono::NaiveDate::from_ymd_opt(2026, 5, 13)
            .unwrap()
            .and_hms_opt(0, 0, 0)
            .unwrap()
            .and_utc();
        for n in 0..10 {
            store
                .insert_incident(&incident_at(
                    &format!("inc-{n}"),
                    base + chrono::Duration::seconds(n),
                ))
                .unwrap();
        }
        let rows = store.incidents_since_ts(&base.to_rfc3339(), 4).unwrap();
        assert_eq!(rows.len(), 4, "limit must clamp the row count");
    }

    #[test]
    fn incidents_since_ts_returns_empty_for_malformed_timestamp() {
        // `ts >= ?1` is a TEXT comparison — passing a bogus string
        // must not panic and must not match every row. Lexicographic
        // sort puts arbitrary text after numeric prefixes; the
        // important invariant is "no crash, no surprise inflation".
        let store = Store::open_memory().unwrap();
        let now = chrono::Utc::now();
        store
            .insert_incident(&incident_at("real-row", now))
            .unwrap();

        // `not-a-ts` sorts AFTER any RFC-3339 timestamp lexicographically
        // (digits < letters), so the result is correctly empty rather
        // than accidentally matching the row.
        let rows = store
            .incidents_since_ts("not-a-ts", 100)
            .expect("garbage input must not error");
        assert!(rows.is_empty());
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
    fn set_incident_allowlisted_flips_column() {
        let store = Store::open_memory().unwrap();
        let id = store
            .insert_incident(&sample_incident("ssh:bf:2026-04-12"))
            .unwrap();

        // Default: not allowlisted. Drop conn before calling other
        // store methods so the r2d2 pool doesn't deadlock.
        let initial: i64 = {
            let conn = store.conn().unwrap();
            conn.query_row(
                "SELECT is_allowlisted FROM incidents WHERE id = ?1",
                params![id],
                |r| r.get(0),
            )
            .unwrap()
        };
        assert_eq!(initial, 0);

        let n = store.set_incident_allowlisted("ssh:bf:2026-04-12").unwrap();
        assert_eq!(n, 1);

        let after: i64 = {
            let conn = store.conn().unwrap();
            conn.query_row(
                "SELECT is_allowlisted FROM incidents WHERE id = ?1",
                params![id],
                |r| r.get(0),
            )
            .unwrap()
        };
        assert_eq!(after, 1);

        // Idempotent — setting twice is fine.
        let n2 = store.set_incident_allowlisted("ssh:bf:2026-04-12").unwrap();
        assert_eq!(n2, 1);

        // Unknown incident_id returns 0 rows affected.
        let n3 = store.set_incident_allowlisted("nonexistent").unwrap();
        assert_eq!(n3, 0);
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
