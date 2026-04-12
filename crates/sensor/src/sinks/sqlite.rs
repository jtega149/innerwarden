//! SQLite sink for sensor events and incidents.
//!
//! Writes directly to `innerwarden.db` via the unified store crate.
//! Runs alongside the JSONL sink during the transition period.
//! No buffering needed — SQLite WAL handles durability.

use std::path::Path;

use innerwarden_core::{event::Event, incident::Incident};
use innerwarden_store::Store;
use tracing::warn;

pub struct SqliteWriter {
    store: Store,
}

impl SqliteWriter {
    /// Open or create the SQLite database at `data_dir/innerwarden.db`.
    pub fn new(data_dir: &Path) -> anyhow::Result<Self> {
        let store = Store::open(data_dir)?;
        Ok(Self { store })
    }

    /// Write an event to the events table.
    pub fn write_event(&self, event: &Event) {
        if let Err(e) = self.store.insert_event(event) {
            warn!(kind = %event.kind, "sqlite write_event failed: {e:#}");
        }
    }

    /// Write an incident to the incidents table.
    pub fn write_incident(&self, incident: &Incident) {
        if let Err(e) = self.store.insert_incident(incident) {
            warn!(incident_id = %incident.incident_id, "sqlite write_incident failed: {e:#}");
        }
    }
}
