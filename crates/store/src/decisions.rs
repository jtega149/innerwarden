//! Decision audit trail with SHA-256 hash chain.
//!
//! Each decision row contains `prev_hash` (hash of previous row's `row_hash`)
//! and `row_hash` (SHA-256 of `prev_hash || data`). This enables tamper
//! detection: if any row is modified, the chain breaks.

use rusqlite::params;
use sha2::{Digest, Sha256};

use crate::error::Result;
use crate::Store;

/// Result of hash chain verification.
#[derive(Debug, Clone)]
pub struct HashChainResult {
    /// Number of rows verified.
    pub verified: u64,
    /// If the chain is broken, the seq at which it broke.
    pub broken_at: Option<i64>,
    /// True if the entire chain is intact.
    pub intact: bool,
}

/// A decision entry for insertion. The store computes the hash chain
/// automatically — callers do not set `prev_hash` or `row_hash`.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct DecisionRow {
    pub ts: String,
    pub incident_id: String,
    pub action_type: String,
    pub target_ip: Option<String>,
    pub target_user: Option<String>,
    pub confidence: f64,
    pub auto_executed: bool,
    pub reason: Option<String>,
    /// Full JSON of the original DecisionEntry (canonical serialization).
    pub data: String,
}

impl Store {
    /// Insert a decision with automatic hash chaining.
    ///
    /// The caller provides the canonical JSON `data` string. The store
    /// reads the last `row_hash`, computes `new_hash = SHA-256(prev_hash || data)`,
    /// and inserts the row atomically.
    pub fn insert_decision(&self, row: &DecisionRow) -> Result<i64> {
        let conn = self.conn()?;
        // Use a transaction to ensure atomicity of read-last-hash + insert
        let tx = conn.unchecked_transaction()?;

        let prev_hash: Option<String> = tx
            .query_row(
                "SELECT row_hash FROM decisions ORDER BY id DESC LIMIT 1",
                [],
                |r| r.get(0),
            )
            .ok();

        let row_hash = compute_hash(prev_hash.as_deref(), &row.data);

        tx.execute(
            "INSERT INTO decisions
             (ts, incident_id, action_type, target_ip, target_user,
              confidence, auto_executed, reason, prev_hash, row_hash, data)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                row.ts,
                row.incident_id,
                row.action_type,
                row.target_ip,
                row.target_user,
                row.confidence,
                row.auto_executed as i32,
                row.reason,
                prev_hash,
                row_hash,
                row.data,
            ],
        )?;
        let id = tx.last_insert_rowid();
        tx.commit()?;
        Ok(id)
    }

    /// Get the hash of the last decision in the chain (None if empty).
    pub fn last_decision_hash(&self) -> Result<Option<String>> {
        let conn = self.conn()?;
        let result = conn
            .query_row(
                "SELECT row_hash FROM decisions ORDER BY id DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .ok();
        Ok(result)
    }

    /// Verify the entire hash chain. Returns verification result.
    pub fn verify_hash_chain(&self) -> Result<HashChainResult> {
        let conn = self.conn()?;
        let mut stmt =
            conn.prepare("SELECT id, prev_hash, row_hash, data FROM decisions ORDER BY id")?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, Option<String>>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
            ))
        })?;

        let mut prev_computed: Option<String> = None;
        let mut verified: u64 = 0;

        for row in rows {
            let (seq, stored_prev, stored_hash, data) = row?;

            // Check prev_hash matches our running state
            if stored_prev != prev_computed {
                return Ok(HashChainResult {
                    verified,
                    broken_at: Some(seq),
                    intact: false,
                });
            }

            // Recompute hash and verify
            let expected_hash = compute_hash(prev_computed.as_deref(), &data);
            if stored_hash != expected_hash {
                return Ok(HashChainResult {
                    verified,
                    broken_at: Some(seq),
                    intact: false,
                });
            }

            prev_computed = Some(stored_hash);
            verified += 1;
        }

        Ok(HashChainResult {
            verified,
            broken_at: None,
            intact: true,
        })
    }

    /// Read decisions with id > `after_id`, up to `limit`.
    pub fn decisions_since(&self, after_id: i64, limit: usize) -> Result<Vec<(i64, String)>> {
        let conn = self.conn()?;
        let mut stmt = conn
            .prepare_cached("SELECT id, data FROM decisions WHERE id > ?1 ORDER BY id LIMIT ?2")?;
        let rows = stmt.query_map(params![after_id, limit as i64], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
        })?;

        let mut results = Vec::new();
        for row in rows {
            results.push(row?);
        }
        Ok(results)
    }

    /// Read all decisions for a given incident_id.
    pub fn decisions_for_incident(&self, incident_id: &str) -> Result<Vec<String>> {
        let conn = self.conn()?;
        let mut stmt =
            conn.prepare_cached("SELECT data FROM decisions WHERE incident_id = ?1 ORDER BY id")?;
        let rows = stmt.query_map(params![incident_id], |row| row.get::<_, String>(0))?;
        let mut results = Vec::new();
        for row in rows {
            results.push(row?);
        }
        Ok(results)
    }

    /// Count total decisions.
    pub fn decisions_count(&self) -> Result<u64> {
        let conn = self.conn()?;
        let count: i64 = conn.query_row("SELECT COUNT(*) FROM decisions", [], |row| row.get(0))?;
        Ok(count as u64)
    }
}

/// Compute SHA-256 hash for hash chain: `SHA-256(prev_hash || data)`.
fn compute_hash(prev_hash: Option<&str>, data: &str) -> String {
    let mut hasher = Sha256::new();
    if let Some(ph) = prev_hash {
        hasher.update(ph.as_bytes());
    }
    hasher.update(data.as_bytes());
    format!("{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_decision(incident: &str, action: &str) -> DecisionRow {
        let data = serde_json::json!({
            "ts": "2026-04-12T10:00:00Z",
            "incident_id": incident,
            "action_type": action,
            "confidence": 0.95,
            "auto_executed": true,
            "reason": "test decision",
        });
        DecisionRow {
            ts: "2026-04-12T10:00:00Z".into(),
            incident_id: incident.into(),
            action_type: action.into(),
            target_ip: Some("1.2.3.4".into()),
            target_user: None,
            confidence: 0.95,
            auto_executed: true,
            reason: Some("test decision".into()),
            data: serde_json::to_string(&data).unwrap(),
        }
    }

    #[test]
    fn test_insert_and_chain() {
        let store = Store::open_memory().unwrap();

        let id1 = store
            .insert_decision(&sample_decision("inc-1", "block_ip"))
            .unwrap();
        let id2 = store
            .insert_decision(&sample_decision("inc-2", "ignore"))
            .unwrap();
        let id3 = store
            .insert_decision(&sample_decision("inc-3", "monitor"))
            .unwrap();

        assert!(id3 > id2);
        assert!(id2 > id1);
        assert_eq!(store.decisions_count().unwrap(), 3);

        // Hash chain should be intact
        let result = store.verify_hash_chain().unwrap();
        assert!(result.intact);
        assert_eq!(result.verified, 3);
        assert!(result.broken_at.is_none());
    }

    #[test]
    fn test_chain_detects_tampering() {
        let store = Store::open_memory().unwrap();
        store
            .insert_decision(&sample_decision("inc-1", "block_ip"))
            .unwrap();
        store
            .insert_decision(&sample_decision("inc-2", "ignore"))
            .unwrap();

        // Tamper with the first row's data
        {
            let conn = store.conn().unwrap();
            conn.execute("UPDATE decisions SET data = 'tampered' WHERE id = 1", [])
                .unwrap();
        }

        let result = store.verify_hash_chain().unwrap();
        assert!(!result.intact);
        assert_eq!(result.broken_at, Some(1));
    }

    #[test]
    fn test_last_hash() {
        let store = Store::open_memory().unwrap();
        assert!(store.last_decision_hash().unwrap().is_none());

        store
            .insert_decision(&sample_decision("inc-1", "block_ip"))
            .unwrap();
        let hash = store.last_decision_hash().unwrap();
        assert!(hash.is_some());
        assert_eq!(hash.unwrap().len(), 64); // SHA-256 hex
    }

    #[test]
    fn test_decisions_for_incident() {
        let store = Store::open_memory().unwrap();
        store
            .insert_decision(&sample_decision("inc-1", "block_ip"))
            .unwrap();
        store
            .insert_decision(&sample_decision("inc-1", "monitor"))
            .unwrap();
        store
            .insert_decision(&sample_decision("inc-2", "ignore"))
            .unwrap();

        let for_inc1 = store.decisions_for_incident("inc-1").unwrap();
        assert_eq!(for_inc1.len(), 2);

        let for_inc2 = store.decisions_for_incident("inc-2").unwrap();
        assert_eq!(for_inc2.len(), 1);
    }
}
