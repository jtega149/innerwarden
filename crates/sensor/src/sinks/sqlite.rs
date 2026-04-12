//! SQLite sink for sensor events and incidents.
//!
//! Writes directly to `innerwarden.db` via the unified store crate.
//! Primary and only event/incident sink since spec 016 cleanup.
//! No buffering needed — SQLite WAL handles durability.

use std::path::Path;

use innerwarden_core::{event::Event, incident::Incident};
use innerwarden_store::Store;
use tracing::warn;

pub struct SqliteWriter {
    store: Store,
    write_events: bool,
}

impl SqliteWriter {
    /// Open or create the SQLite database at `data_dir/innerwarden.db`.
    /// When `write_events` is false, `write_event` is a no-op (incidents
    /// are always written).
    pub fn new(data_dir: &Path, write_events: bool) -> anyhow::Result<Self> {
        let store = Store::open(data_dir)?;
        Ok(Self {
            store,
            write_events,
        })
    }

    /// Returns the data directory path (used by the main loop for loading
    /// feedback files like blocked-ips.txt).
    pub fn data_dir(&self) -> &Path {
        self.store.data_dir()
    }

    /// Write an event to the events table.
    pub fn write_event(&self, event: &Event) {
        if !self.write_events {
            return;
        }
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
