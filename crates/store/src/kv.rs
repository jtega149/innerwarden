//! Namespaced key-value store (replaces redb tables).
//!
//! Each redb table becomes a namespace:
//!   - `ip_reputations`
//!   - `decision_cooldowns`
//!   - `notification_cooldowns`
//!   - `block_counts`
//!   - `xdp_block_times`
//!   - `trust_rules`
//!   - `attacker_profiles`

use rusqlite::params;

use crate::error::Result;
use crate::Store;

impl Store {
    /// Get a value by namespace + key. Returns None if not found.
    pub fn kv_get(&self, namespace: &str, key: &str) -> Result<Option<Vec<u8>>> {
        let conn = self.conn()?;
        let result = conn
            .query_row(
                "SELECT value FROM kv_state WHERE namespace = ?1 AND key = ?2",
                params![namespace, key],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .ok();
        Ok(result)
    }

    /// Get a value as a UTF-8 string.
    pub fn kv_get_str(&self, namespace: &str, key: &str) -> Result<Option<String>> {
        match self.kv_get(namespace, key)? {
            Some(bytes) => Ok(Some(String::from_utf8_lossy(&bytes).into_owned())),
            None => Ok(None),
        }
    }

    /// Set a value (upsert). Optional TTL via `expires_at` (ISO 8601).
    pub fn kv_set(&self, namespace: &str, key: &str, value: &[u8]) -> Result<()> {
        self.kv_set_with_expiry(namespace, key, value, None)
    }

    /// Set a value with optional expiry timestamp.
    pub fn kv_set_with_expiry(
        &self,
        namespace: &str,
        key: &str,
        value: &[u8],
        expires_at: Option<&str>,
    ) -> Result<()> {
        let conn = self.conn()?;
        conn.execute(
            "INSERT INTO kv_state (namespace, key, value, expires_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT (namespace, key) DO UPDATE SET
                value = excluded.value,
                expires_at = excluded.expires_at,
                updated_at = excluded.updated_at",
            params![
                namespace,
                key,
                value,
                expires_at,
                chrono::Utc::now().to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    /// Delete a key. Returns true if the key existed.
    pub fn kv_delete(&self, namespace: &str, key: &str) -> Result<bool> {
        let conn = self.conn()?;
        let deleted = conn.execute(
            "DELETE FROM kv_state WHERE namespace = ?1 AND key = ?2",
            params![namespace, key],
        )?;
        Ok(deleted > 0)
    }

    /// List all key-value pairs in a namespace.
    pub fn kv_list(&self, namespace: &str) -> Result<Vec<(String, Vec<u8>)>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare_cached(
            "SELECT key, value FROM kv_state WHERE namespace = ?1 ORDER BY key",
        )?;
        let rows = stmt.query_map(params![namespace], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
        })?;
        let mut results = Vec::new();
        for row in rows {
            results.push(row?);
        }
        Ok(results)
    }

    /// Count entries in a namespace.
    pub fn kv_count(&self, namespace: &str) -> Result<usize> {
        let conn = self.conn()?;
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM kv_state WHERE namespace = ?1",
            params![namespace],
            |row| row.get(0),
        )?;
        Ok(count as usize)
    }

    /// Delete all entries in a namespace.
    pub fn kv_clear(&self, namespace: &str) -> Result<usize> {
        let conn = self.conn()?;
        let deleted = conn.execute(
            "DELETE FROM kv_state WHERE namespace = ?1",
            params![namespace],
        )?;
        Ok(deleted)
    }

    /// Delete expired entries across all namespaces. Returns count deleted.
    pub fn kv_cleanup_expired(&self) -> Result<usize> {
        let conn = self.conn()?;
        let now = chrono::Utc::now().to_rfc3339();
        let deleted = conn.execute(
            "DELETE FROM kv_state WHERE expires_at IS NOT NULL AND expires_at < ?1",
            params![now],
        )?;
        Ok(deleted)
    }

    /// Trim a namespace to at most `max_entries`, keeping the most recently updated.
    pub fn kv_trim(&self, namespace: &str, max_entries: usize) -> Result<usize> {
        let count = self.kv_count(namespace)?;
        if count <= max_entries {
            return Ok(0);
        }
        let conn = self.conn()?;
        let to_delete = count - max_entries;
        let deleted = conn.execute(
            "DELETE FROM kv_state WHERE namespace = ?1 AND rowid IN (
                SELECT rowid FROM kv_state WHERE namespace = ?1
                ORDER BY updated_at ASC LIMIT ?2
             )",
            params![namespace, to_delete as i64],
        )?;
        Ok(deleted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_set_delete() {
        let store = Store::open_memory().unwrap();

        assert!(store.kv_get("test_ns", "key1").unwrap().is_none());

        store.kv_set("test_ns", "key1", b"value1").unwrap();
        let val = store.kv_get("test_ns", "key1").unwrap().unwrap();
        assert_eq!(val, b"value1");

        // Upsert
        store.kv_set("test_ns", "key1", b"value2").unwrap();
        let val = store.kv_get("test_ns", "key1").unwrap().unwrap();
        assert_eq!(val, b"value2");

        assert!(store.kv_delete("test_ns", "key1").unwrap());
        assert!(store.kv_get("test_ns", "key1").unwrap().is_none());
        assert!(!store.kv_delete("test_ns", "key1").unwrap());
    }

    #[test]
    fn test_list_and_count() {
        let store = Store::open_memory().unwrap();
        store.kv_set("ns", "a", b"1").unwrap();
        store.kv_set("ns", "b", b"2").unwrap();
        store.kv_set("ns", "c", b"3").unwrap();
        store.kv_set("other", "x", b"y").unwrap();

        assert_eq!(store.kv_count("ns").unwrap(), 3);
        assert_eq!(store.kv_count("other").unwrap(), 1);

        let items = store.kv_list("ns").unwrap();
        assert_eq!(items.len(), 3);
        assert_eq!(items[0].0, "a");
    }

    #[test]
    fn test_trim() {
        let store = Store::open_memory().unwrap();
        for i in 0..10 {
            store
                .kv_set("trim_ns", &format!("key{i}"), format!("val{i}").as_bytes())
                .unwrap();
        }
        assert_eq!(store.kv_count("trim_ns").unwrap(), 10);

        let trimmed = store.kv_trim("trim_ns", 5).unwrap();
        assert_eq!(trimmed, 5);
        assert_eq!(store.kv_count("trim_ns").unwrap(), 5);
    }

    #[test]
    fn test_cleanup_expired() {
        let store = Store::open_memory().unwrap();
        // Set with past expiry
        store
            .kv_set_with_expiry("ns", "expired", b"old", Some("2020-01-01T00:00:00Z"))
            .unwrap();
        // Set with future expiry
        store
            .kv_set_with_expiry("ns", "valid", b"new", Some("2099-01-01T00:00:00Z"))
            .unwrap();
        // Set without expiry
        store.kv_set("ns", "permanent", b"forever").unwrap();

        let deleted = store.kv_cleanup_expired().unwrap();
        assert_eq!(deleted, 1);
        assert_eq!(store.kv_count("ns").unwrap(), 2);
    }

    #[test]
    fn test_namespaces_isolated() {
        let store = Store::open_memory().unwrap();
        store.kv_set("ns_a", "key1", b"a").unwrap();
        store.kv_set("ns_b", "key1", b"b").unwrap();

        let a = store.kv_get("ns_a", "key1").unwrap().unwrap();
        let b = store.kv_get("ns_b", "key1").unwrap().unwrap();
        assert_eq!(a, b"a");
        assert_eq!(b, b"b");

        store.kv_clear("ns_a").unwrap();
        assert_eq!(store.kv_count("ns_a").unwrap(), 0);
        assert_eq!(store.kv_count("ns_b").unwrap(), 1);
    }

    #[test]
    fn test_kv_get_str() {
        let store = Store::open_memory().unwrap();
        let json = serde_json::json!({"risk_score": 85}).to_string();
        store.kv_set("profiles", "1.2.3.4", json.as_bytes()).unwrap();

        let val = store.kv_get_str("profiles", "1.2.3.4").unwrap().unwrap();
        assert!(val.contains("risk_score"));
    }
}
