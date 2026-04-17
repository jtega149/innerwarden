use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use chrono::{Local, NaiveDate};
use innerwarden_core::{event::Event, incident::Incident};
use tracing::warn;

/// Hard ceiling for a single day's events file.  Incidents and decisions
/// are exempt - they are tiny and operationally critical.
/// Bumped from 200 MB → 1 GB to accommodate eBPF + tcp_stream + http_capture
/// volume (graph ingestion needs all events, not just a sample).
const MAX_EVENTS_FILE_BYTES: u64 = 1024 * 1024 * 1024; // 1 GB

pub struct JsonlWriter {
    data_dir: PathBuf,
    write_events: bool,
    events_writer: Option<DatedWriter>,
    incidents_writer: Option<DatedWriter>,
    /// Tracks whether we already logged the size-limit warning for today's
    /// events file so we don't spam the log.
    events_limit_warned: Option<NaiveDate>,
}

struct DatedWriter {
    writer: BufWriter<File>,
    date: NaiveDate,
}

impl JsonlWriter {
    pub fn new(data_dir: impl Into<PathBuf>, write_events: bool) -> Result<Self> {
        let data_dir = data_dir.into();
        std::fs::create_dir_all(&data_dir)
            .with_context(|| format!("failed to create data dir: {}", data_dir.display()))?;
        Ok(Self {
            data_dir,
            write_events,
            events_writer: None,
            incidents_writer: None,
            events_limit_warned: None,
        })
    }

    pub fn write_event(&mut self, event: &Event) -> Result<()> {
        if !self.write_events {
            return Ok(());
        }
        let today = Local::now().date_naive();

        // ── Disk-exhaustion guard ───────────────────────────────────────
        let path = events_file_path(&self.data_dir, today);
        if let Ok(meta) = std::fs::metadata(&path) {
            if is_events_file_at_capacity(meta.len()) {
                if self.events_limit_warned != Some(today) {
                    warn!(
                        "events file exceeded 200MB - pausing event writes to prevent disk exhaustion"
                    );
                    self.events_limit_warned = Some(today);
                }
                return Ok(());
            }
        }

        let line = serde_json::to_string(event)?;
        if line.len() > 16_384 {
            warn!(kind = %event.kind, size = line.len(), "event exceeds 16KB limit, skipping");
            return Ok(());
        }
        let w = self.events_writer(today)?;
        writeln!(w.writer, "{line}")?;
        Ok(())
    }

    pub fn write_incident(&mut self, incident: &Incident) -> Result<()> {
        let today = Local::now().date_naive();
        let w = self.incidents_writer(today)?;
        let line = serde_json::to_string(incident)?;
        writeln!(w.writer, "{line}")?;
        Ok(())
    }

    /// Returns the data directory path (used by the main loop for loading
    /// feedback files like blocked-ips.txt).
    pub fn data_dir(&self) -> &std::path::Path {
        &self.data_dir
    }

    pub fn flush(&mut self) -> Result<()> {
        if let Some(w) = &mut self.events_writer {
            w.writer.flush()?;
        }
        if let Some(w) = &mut self.incidents_writer {
            w.writer.flush()?;
        }
        Ok(())
    }

    fn events_writer(&mut self, today: NaiveDate) -> Result<&mut DatedWriter> {
        if self.events_writer.as_ref().is_none_or(|w| w.date != today) {
            let path = events_file_path(&self.data_dir, today);
            self.events_writer = Some(DatedWriter::open(path, today)?);
        }
        Ok(self.events_writer.as_mut().unwrap())
    }

    fn incidents_writer(&mut self, today: NaiveDate) -> Result<&mut DatedWriter> {
        if self
            .incidents_writer
            .as_ref()
            .is_none_or(|w| w.date != today)
        {
            let path = incidents_file_path(&self.data_dir, today);
            self.incidents_writer = Some(DatedWriter::open(path, today)?);
        }
        Ok(self.incidents_writer.as_mut().unwrap())
    }
}

impl Drop for JsonlWriter {
    fn drop(&mut self) {
        let _ = self.flush();
    }
}

impl DatedWriter {
    fn open(path: PathBuf, date: NaiveDate) -> Result<Self> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .with_context(|| format!("failed to open {}", path.display()))?;
        Ok(Self {
            writer: BufWriter::new(file),
            date,
        })
    }
}

fn events_file_path(data_dir: &Path, today: NaiveDate) -> PathBuf {
    data_dir.join(format!("events-{}.jsonl", today.format("%Y-%m-%d")))
}

fn incidents_file_path(data_dir: &Path, today: NaiveDate) -> PathBuf {
    data_dir.join(format!("incidents-{}.jsonl", today.format("%Y-%m-%d")))
}

fn is_events_file_at_capacity(current_size: u64) -> bool {
    current_size >= MAX_EVENTS_FILE_BYTES
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_test_dir() -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("innerwarden-sensor-jsonl-tests-{nanos}"));
        std::fs::create_dir_all(&path).expect("test temp dir must be creatable");
        path
    }

    #[test]
    fn file_path_helpers_build_date_partitioned_jsonl_names() {
        // Ensures daily file partition naming stays stable for downstream ingestion jobs.
        let date = NaiveDate::from_ymd_opt(2026, 4, 17).expect("valid calendar date");
        let root = Path::new("/var/lib/innerwarden");
        assert_eq!(
            events_file_path(root, date),
            PathBuf::from("/var/lib/innerwarden/events-2026-04-17.jsonl")
        );
        assert_eq!(
            incidents_file_path(root, date),
            PathBuf::from("/var/lib/innerwarden/incidents-2026-04-17.jsonl")
        );
    }

    #[test]
    fn events_capacity_guard_trips_at_or_above_limit() {
        // Covers disk-safety boundary that pauses event writes when the daily file is too large.
        assert!(!is_events_file_at_capacity(MAX_EVENTS_FILE_BYTES - 1));
        assert!(is_events_file_at_capacity(MAX_EVENTS_FILE_BYTES));
        assert!(is_events_file_at_capacity(MAX_EVENTS_FILE_BYTES + 1));
    }

    #[test]
    fn new_creates_data_dir_and_exposes_it_via_accessor() {
        // Verifies sink initialization keeps writer rooted in the requested data directory.
        let data_dir = unique_test_dir().join("nested").join("sink");
        let writer =
            JsonlWriter::new(&data_dir, true).expect("writer init should create data directory");
        assert_eq!(writer.data_dir(), data_dir.as_path());
        assert!(data_dir.exists());
    }
}
