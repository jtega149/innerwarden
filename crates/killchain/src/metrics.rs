//! Simple atomic counters for operational metrics.

use std::sync::atomic::{AtomicU64, Ordering};
use tracing::info;

/// Operational metrics tracked via lock-free atomic counters.
pub struct Metrics {
    pub events_processed: AtomicU64,
    pub chains_detected: AtomicU64,
    pub pre_chains_emitted: AtomicU64,
    pub lsm_blocked_processed: AtomicU64,
    pub incidents_published: AtomicU64,
    pub c2_ips_extracted: AtomicU64,
}

impl Metrics {
    /// Create a new metrics instance with all counters set to zero.
    pub fn new() -> Self {
        Self {
            events_processed: AtomicU64::new(0),
            chains_detected: AtomicU64::new(0),
            pre_chains_emitted: AtomicU64::new(0),
            lsm_blocked_processed: AtomicU64::new(0),
            incidents_published: AtomicU64::new(0),
            c2_ips_extracted: AtomicU64::new(0),
        }
    }

    /// Log a summary of all counters at INFO level.
    pub fn log_summary(&self) {
        info!(
            events_processed = self.events_processed.load(Ordering::Relaxed),
            chains_detected = self.chains_detected.load(Ordering::Relaxed),
            pre_chains_emitted = self.pre_chains_emitted.load(Ordering::Relaxed),
            lsm_blocked_processed = self.lsm_blocked_processed.load(Ordering::Relaxed),
            incidents_published = self.incidents_published.load(Ordering::Relaxed),
            c2_ips_extracted = self.c2_ips_extracted.load(Ordering::Relaxed),
            "Metrics summary"
        );
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}
