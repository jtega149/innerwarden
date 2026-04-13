//! Named JSON state blobs (replaces responses.json, campaigns.json, etc.).

use rusqlite::params;

use crate::error::Result;
use crate::Store;

impl Store {
    /// Get a named state blob as a JSON string.
    pub fn get_blob(&self, name: &str) -> Result<Option<String>> {
        let conn = self.conn()?;
        let result = conn
            .query_row(
                "SELECT data FROM state_blobs WHERE name = ?1",
                params![name],
                |row| row.get::<_, String>(0),
            )
            .ok();
        Ok(result)
    }

    /// Set a named state blob (upsert).
    pub fn set_blob(&self, name: &str, json: &str) -> Result<()> {
        let conn = self.conn()?;
        conn.execute(
            "INSERT INTO state_blobs (name, data, updated_at)
             VALUES (?1, ?2, ?3)
             ON CONFLICT (name) DO UPDATE SET
                data = excluded.data,
                updated_at = excluded.updated_at",
            params![name, json, chrono::Utc::now().to_rfc3339()],
        )?;
        Ok(())
    }

    /// Delete a named state blob. Returns true if it existed.
    pub fn delete_blob(&self, name: &str) -> Result<bool> {
        let conn = self.conn()?;
        let deleted = conn.execute("DELETE FROM state_blobs WHERE name = ?1", params![name])?;
        Ok(deleted > 0)
    }

    /// List all blob names.
    pub fn list_blobs(&self) -> Result<Vec<String>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare("SELECT name FROM state_blobs ORDER BY name")?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
        let mut names = Vec::new();
        for row in rows {
            names.push(row?);
        }
        Ok(names)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blob_roundtrip() {
        let store = Store::open_memory().unwrap();
        let json = r#"{"active_blocks": 5}"#;

        assert!(store.get_blob("responses").unwrap().is_none());

        store.set_blob("responses", json).unwrap();
        let val = store.get_blob("responses").unwrap().unwrap();
        assert_eq!(val, json);

        // Upsert
        store
            .set_blob("responses", r#"{"active_blocks": 10}"#)
            .unwrap();
        let val = store.get_blob("responses").unwrap().unwrap();
        assert!(val.contains("10"));
    }

    #[test]
    fn test_blob_delete() {
        let store = Store::open_memory().unwrap();
        store.set_blob("baseline", "{}").unwrap();
        assert!(store.delete_blob("baseline").unwrap());
        assert!(!store.delete_blob("baseline").unwrap());
        assert!(store.get_blob("baseline").unwrap().is_none());
    }

    #[test]
    fn test_list_blobs() {
        let store = Store::open_memory().unwrap();
        store.set_blob("baseline", "{}").unwrap();
        store.set_blob("campaigns", "[]").unwrap();
        store.set_blob("responses", "{}").unwrap();

        let names = store.list_blobs().unwrap();
        assert_eq!(names, vec!["baseline", "campaigns", "responses"]);
    }
}
