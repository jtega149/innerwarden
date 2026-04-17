use std::collections::VecDeque;
use std::path::Path;
use std::sync::{Arc, RwLock};

use crate::{config, dashboard::AdvisoryEntry, process, reader, AgentState};

pub(crate) async fn run_incident_tick(
    data_dir: &Path,
    cursor: &mut reader::AgentCursor,
    cfg: &config::AgentConfig,
    state: &mut AgentState,
    advisory_cache: &Arc<RwLock<VecDeque<AdvisoryEntry>>>,
) {
    process::incidents::process_incidents(data_dir, cursor, cfg, state, advisory_cache).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use tempfile::TempDir;

    #[tokio::test]
    async fn run_incident_tick_handles_empty_state_without_panicking() {
        let dir = TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let mut cursor = reader::AgentCursor::default();
        let cfg = config::AgentConfig::default();
        let advisory_cache = Arc::new(RwLock::new(VecDeque::new()));

        run_incident_tick(dir.path(), &mut cursor, &cfg, &mut state, &advisory_cache).await;
    }

    #[tokio::test]
    async fn run_incident_tick_processes_sqlite_incidents_path() {
        let dir = TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let store = crate::tests::test_sqlite_store(dir.path());
        crate::tests::insert_test_incident(&store, &crate::tests::test_incident("198.51.100.40"));
        state.sqlite_store = Some(store);
        let mut cursor = reader::AgentCursor::default();
        let mut cfg = config::AgentConfig::default();
        cfg.ai.enabled = false;
        let advisory_cache = Arc::new(RwLock::new(VecDeque::new()));

        run_incident_tick(dir.path(), &mut cursor, &cfg, &mut state, &advisory_cache).await;
    }

    #[tokio::test]
    async fn run_incident_tick_with_neural_incidents_still_executes_pipeline() {
        let dir = TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        state
            .neural_incidents
            .push(crate::tests::test_incident("203.0.113.41"));
        let mut cursor = reader::AgentCursor::default();
        let mut cfg = config::AgentConfig::default();
        cfg.ai.enabled = false;
        let advisory_cache = Arc::new(RwLock::new(VecDeque::new()));

        run_incident_tick(dir.path(), &mut cursor, &cfg, &mut state, &advisory_cache).await;
    }
}
