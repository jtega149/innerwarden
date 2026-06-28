//! Operator-action drain (2026-06-10).
//!
//! The dashboard's `POST /api/action/unblock-ip` does NOT touch the firewall
//! synchronously. It writes an `operator_unblock_request` decision row and
//! returns immediately. This module is the agent-loop counterpart that drains
//! those requests on the slow loop and performs the real revert through
//! `response_lifecycle`.
//!
//! Why go through the agent loop instead of unblocking from the dashboard
//! handler directly:
//!
//! * The dashboard server holds NO `response_lifecycle` handle (it is a
//!   read-mostly snapshot of agent state). Removing a firewall rule from the
//!   dashboard would leave the lifecycle's `active` entry in place.
//! * The spec-076 block-enforcement reconciler runs every 5 min and RE-APPLIES
//!   any active-but-dropped block. A dashboard-side rule removal would be
//!   silently re-applied within minutes — the operator would think they
//!   un-blocked an IP while the agent quietly re-blocked it. Reverting through
//!   the lifecycle (so the entry leaves `active`) is the only way the
//!   reconciler will not fight the operator.
//!
//! Idempotency: the drain selects incidents whose LATEST decision is
//! `operator_unblock_request`. Once it writes the terminal `operator_unblock`
//! row (a higher id), that incident's latest decision is no longer the request,
//! so the next sweep skips it.

use crate::decisions::DecisionEntry;
use crate::AgentState;
use chrono::Utc;
use std::path::Path;
use tracing::{info, warn};

/// Look back this far when scanning for pending unblock requests. Requests are
/// freshly queued by the operator, so a 1-day window bounds the table scan (the
/// prod decisions table can hold hundreds of thousands of rows) while still
/// covering any request that has not yet been drained.
const PENDING_LOOKBACK_SECS: i64 = 86_400;

/// Best-effort machine hostname for the decision row's `host` field. Mirrors
/// the helpers in `orphan_recovery`/`dashboard::actions` so drain decisions
/// look identical to operator-initiated ones in the audit log.
fn hostname() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::fs::read_to_string("/etc/hostname").map(|s| s.trim().to_string()))
        .unwrap_or_else(|_| "unknown".to_string())
}

/// Query the SQLite decisions table for incidents whose LATEST decision is an
/// `operator_unblock_request` (i.e. queued by the operator, not yet drained).
/// Returns `(incident_id, ip)` pairs; rows with no `target_ip` are skipped.
fn find_pending_unblocks(
    store: &innerwarden_store::Store,
    cutoff_iso: &str,
) -> Vec<(String, String)> {
    let Ok(conn) = store.conn() else {
        return Vec::new();
    };
    let Ok(mut stmt) = conn.prepare_cached(
        "SELECT incident_id, target_ip FROM ( \
             SELECT incident_id, target_ip, action_type, \
                    ROW_NUMBER() OVER (PARTITION BY incident_id ORDER BY id DESC) AS rn \
             FROM decisions WHERE ts >= ?1 \
         ) WHERE rn = 1 AND action_type = 'operator_unblock_request' \
           AND target_ip IS NOT NULL",
    ) else {
        return Vec::new();
    };
    let rows = stmt.query_map([cutoff_iso], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    rows.filter_map(|r| r.ok())
        .filter_map(|(iid, ip)| ip.map(|ip| (iid, ip)))
        .collect()
}

/// Run one operator-unblock drain. Returns the number of terminal decisions
/// written (== requests processed). Best-effort: store errors are logged and do
/// not propagate. Safe to call every slow-loop tick — when no requests are
/// pending it does one bounded SQL scan and returns 0.
pub(crate) async fn run_unblock_drain(
    state: &mut AgentState,
    data_dir: &Path,
    dry_run: bool,
) -> usize {
    // Clone the Arc so the pending query does not hold a borrow of `state`
    // across the mutating loop below.
    let Some(store) = state.sqlite_store.clone() else {
        return 0;
    };
    let now = Utc::now();
    let cutoff_iso = (now - chrono::Duration::seconds(PENDING_LOOKBACK_SECS)).to_rfc3339();
    let pending = find_pending_unblocks(&store, &cutoff_iso);
    if pending.is_empty() {
        return 0;
    }

    let mut written = 0usize;
    for (incident_id, ip) in pending {
        // Revert every live lifecycle block for this IP through the proper
        // request_manual_revert -> execute_revert -> mark_reverted flow. In
        // dry_run we change nothing (no lifecycle transition, no firewall call,
        // no record clear) — just record the simulated terminal.
        let mut revert_ok = true;
        let mut reverted = 0usize;
        if !dry_run {
            let block_ids = state.response_lifecycle.active_block_ids_for_ip(&ip);
            for id in &block_ids {
                if let Some(action) = state.response_lifecycle.request_manual_revert(id) {
                    match crate::response_lifecycle::execute_revert(&action, false).await {
                        Ok(()) => {
                            state
                                .response_lifecycle
                                .mark_reverted(id, "operator_unblock");
                            reverted += 1;
                        }
                        Err(e) => {
                            warn!(ip = %ip, id = %id, error = %e, "operator unblock: revert failed");
                            revert_ok = false;
                            let _ = state.response_lifecycle.mark_revert_failed(id, e);
                        }
                    }
                }
            }
            // Clear the persisted block records ONLY on a successful revert.
            // Clearing them while the firewall rule is still live would show
            // "not blocked" on the dashboard while traffic is still dropped —
            // exactly the kind of record-vs-reality lie spec 076 forbids.
            if revert_ok {
                state.store.remove_xdp_block_time(&ip);
                if let Some(s) = state.sqlite_store.as_ref() {
                    let _ = s.kv_delete("xdp_block_times", &ip);
                }
                state.blocklist.remove(&ip);
            }
        }

        let (execution_result, reason) = if dry_run {
            (
                "ok (dry_run)".to_string(),
                format!("Operator-requested unblock of {ip} simulated (responder dry_run)."),
            )
        } else if revert_ok {
            (
                format!("ok (reverted {reverted} rule(s))"),
                format!(
                    "Operator-requested unblock of {ip} processed: {reverted} firewall rule(s) \
                     reverted and block records cleared."
                ),
            )
        } else {
            (
                "failed: firewall revert did not complete; block left in place".to_string(),
                format!(
                    "Operator-requested unblock of {ip} could NOT be completed — at least one \
                     firewall revert failed, so the block is left in place. Records were NOT \
                     cleared (the IP is still blocked)."
                ),
            )
        };

        let entry = DecisionEntry {
            ts: now,
            incident_id: incident_id.clone(),
            host: hostname(),
            ai_provider: "dashboard:operator".to_string(),
            action_type: "operator_unblock".to_string(),
            target_ip: Some(ip.clone()),
            target_user: None,
            skill_id: Some("operator_unblock".to_string()),
            confidence: 1.0,
            auto_executed: !dry_run && revert_ok,
            dry_run,
            reason,
            estimated_threat: "manual".to_string(),
            execution_result,
            prev_hash: None,
            decision_layer: Some("manual_operator".to_string()),
        };
        match crate::decisions::append_chained(data_dir, &entry, Some(&store)) {
            Ok(()) => written += 1,
            Err(e) => warn!(
                incident_id = %incident_id,
                error = %e,
                "operator unblock: failed to write terminal decision"
            ),
        }
    }

    if written > 0 {
        info!(written, "operator_actions: drained unblock requests");
    }
    written
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::response_lifecycle::{ResponseBackend, ResponseType};

    /// Build an AgentState backed by a temp dir + a real on-disk SQLite store.
    fn build_state(
        tmp: &tempfile::TempDir,
    ) -> (crate::AgentState, std::sync::Arc<innerwarden_store::Store>) {
        let mut state = crate::tests::triage_test_state(tmp.path());
        let store =
            std::sync::Arc::new(innerwarden_store::Store::open(tmp.path()).expect("open store"));
        state.sqlite_store = Some(store.clone());
        (state, store)
    }

    /// Append an `operator_unblock_request` decision the way the dashboard
    /// handler does, so the drain's SQL picks it up.
    fn queue_request(
        data_dir: &Path,
        store: &std::sync::Arc<innerwarden_store::Store>,
        incident_id: &str,
        ip: &str,
    ) {
        let entry = DecisionEntry {
            ts: Utc::now(),
            incident_id: incident_id.to_string(),
            host: "h".to_string(),
            ai_provider: "dashboard:operator".to_string(),
            action_type: "operator_unblock_request".to_string(),
            target_ip: Some(ip.to_string()),
            target_user: None,
            skill_id: Some("operator_unblock".to_string()),
            confidence: 1.0,
            auto_executed: false,
            dry_run: false,
            reason: "operator clicked unblock".to_string(),
            estimated_threat: "manual".to_string(),
            execution_result: "queued".to_string(),
            prev_hash: None,
            decision_layer: Some("manual_operator".to_string()),
        };
        crate::decisions::append_chained(data_dir, &entry, Some(store)).unwrap();
    }

    fn latest_action_type(store: &innerwarden_store::Store, incident_id: &str) -> Option<String> {
        let rows = store.decisions_for_incident(incident_id).unwrap();
        // decisions_for_incident returns oldest-first JSON blobs; take the last.
        rows.last().and_then(|s| {
            serde_json::from_str::<serde_json::Value>(s)
                .ok()
                .and_then(|v| {
                    v.get("action_type")
                        .and_then(|a| a.as_str())
                        .map(|s| s.to_string())
                })
        })
    }

    #[tokio::test]
    async fn drain_no_pending_returns_zero() {
        let tmp = tempfile::tempdir().unwrap();
        let (mut state, _store) = build_state(&tmp);
        assert_eq!(run_unblock_drain(&mut state, tmp.path(), false).await, 0);
    }

    #[tokio::test]
    async fn drain_reverts_block_clears_records_and_writes_terminal() {
        let tmp = tempfile::tempdir().unwrap();
        let (mut state, store) = build_state(&tmp);
        let ip = "203.0.113.50";
        // Register a live block. Use the Container backend so `execute_revert`
        // returns Ok without shelling out to sudo/ufw in the test.
        state.response_lifecycle.register(
            ResponseType::BlockIp,
            ResponseBackend::Container,
            ip,
            "threat_intel:203.0.113.50:1:t",
            3600,
            None,
        );
        state.blocklist.insert(ip);
        // Persisted block record the dashboard reads for the enforcement panel.
        let payload = serde_json::json!({
            "blocked_at_ms": Utc::now().timestamp_millis(),
            "ttl_secs": 3600,
        });
        store
            .kv_set(
                "xdp_block_times",
                ip,
                &serde_json::to_vec(&payload).unwrap(),
            )
            .unwrap();
        queue_request(tmp.path(), &store, "threat_intel:203.0.113.50:1:t", ip);

        let written = run_unblock_drain(&mut state, tmp.path(), false).await;
        assert_eq!(written, 1);

        // Lifecycle block reverted -> no longer actively blocked.
        assert!(
            !state
                .response_lifecycle
                .is_ip_actively_blocked(ip, Utc::now()),
            "block must be reverted after a successful drain"
        );
        // Dashboard record cleared (enforcement panel will stop showing blocked).
        assert!(
            store.kv_get("xdp_block_times", ip).unwrap().is_none(),
            "xdp_block_times must be cleared on successful revert"
        );
        assert!(!state.blocklist.contains(ip), "blocklist entry removed");
        // Terminal row written; case leaves the blocked bucket.
        assert_eq!(
            latest_action_type(&store, "threat_intel:203.0.113.50:1:t").as_deref(),
            Some("operator_unblock"),
        );
    }

    #[tokio::test]
    async fn drain_is_idempotent_after_terminal_written() {
        let tmp = tempfile::tempdir().unwrap();
        let (mut state, store) = build_state(&tmp);
        let ip = "203.0.113.51";
        state.response_lifecycle.register(
            ResponseType::BlockIp,
            ResponseBackend::Container,
            ip,
            "threat_intel:203.0.113.51:1:t",
            3600,
            None,
        );
        queue_request(tmp.path(), &store, "threat_intel:203.0.113.51:1:t", ip);

        assert_eq!(run_unblock_drain(&mut state, tmp.path(), false).await, 1);
        // Second run: latest decision is now operator_unblock, not the request,
        // so nothing is re-processed.
        assert_eq!(run_unblock_drain(&mut state, tmp.path(), false).await, 0);
    }

    #[tokio::test]
    async fn drain_dry_run_simulates_without_clearing_records() {
        let tmp = tempfile::tempdir().unwrap();
        let (mut state, store) = build_state(&tmp);
        let ip = "203.0.113.52";
        state.response_lifecycle.register(
            ResponseType::BlockIp,
            ResponseBackend::Container,
            ip,
            "threat_intel:203.0.113.52:1:t",
            3600,
            None,
        );
        state.blocklist.insert(ip);
        store
            .kv_set(
                "xdp_block_times",
                ip,
                b"{\"blocked_at_ms\":1,\"ttl_secs\":3600}",
            )
            .unwrap();
        queue_request(tmp.path(), &store, "threat_intel:203.0.113.52:1:t", ip);

        let written = run_unblock_drain(&mut state, tmp.path(), true).await;
        assert_eq!(written, 1);
        // dry_run: nothing actually reverted/cleared.
        assert!(
            state
                .response_lifecycle
                .is_ip_actively_blocked(ip, Utc::now()),
            "dry_run must NOT revert the live block"
        );
        assert!(
            store.kv_get("xdp_block_times", ip).unwrap().is_some(),
            "dry_run must NOT clear the block record"
        );
        assert!(
            state.blocklist.contains(ip),
            "dry_run must NOT touch blocklist"
        );
        // But it still writes a terminal so the request is not re-processed.
        let rows = store
            .decisions_for_incident("threat_intel:203.0.113.52:1:t")
            .unwrap();
        let last: serde_json::Value = serde_json::from_str(rows.last().unwrap()).unwrap();
        assert_eq!(
            last.get("action_type").and_then(|v| v.as_str()),
            Some("operator_unblock")
        );
        assert_eq!(
            last.get("execution_result").and_then(|v| v.as_str()),
            Some("ok (dry_run)")
        );
    }

    #[tokio::test]
    async fn drain_processes_request_even_with_no_active_block() {
        // Drift case: the operator queued an unblock but the lifecycle has no
        // active entry for the IP (e.g. it already expired). The drain must
        // still write a terminal so the request is cleared and the case leaves
        // the blocked bucket — it must not loop forever on an un-revertable IP.
        let tmp = tempfile::tempdir().unwrap();
        let (mut state, store) = build_state(&tmp);
        let ip = "203.0.113.53";
        queue_request(tmp.path(), &store, "threat_intel:203.0.113.53:1:t", ip);

        assert_eq!(run_unblock_drain(&mut state, tmp.path(), false).await, 1);
        assert_eq!(
            latest_action_type(&store, "threat_intel:203.0.113.53:1:t").as_deref(),
            Some("operator_unblock"),
        );
    }

    #[tokio::test]
    async fn drain_returns_zero_when_store_is_none() {
        let tmp = tempfile::tempdir().unwrap();
        let mut state = crate::tests::triage_test_state(tmp.path());
        assert!(state.sqlite_store.is_none());
        assert_eq!(run_unblock_drain(&mut state, tmp.path(), false).await, 0);
    }

    #[tokio::test]
    async fn drain_keeps_records_when_firewall_revert_fails() {
        // The revert-FAILURE path: if `execute_revert` errors, the block must be
        // left in place and the persisted records must NOT be cleared — showing
        // "not blocked" while the rule is still live is the lie spec 076 forbids.
        // An Nftables entry with no stored revert_handle makes `execute_revert`
        // return Err without shelling out.
        let tmp = tempfile::tempdir().unwrap();
        let (mut state, store) = build_state(&tmp);
        let ip = "203.0.113.54";
        state.response_lifecycle.register(
            ResponseType::BlockIp,
            ResponseBackend::Nftables,
            ip,
            "threat_intel:203.0.113.54:1:t",
            3600,
            None, // no handle -> execute_revert errors
        );
        state.blocklist.insert(ip);
        store
            .kv_set(
                "xdp_block_times",
                ip,
                b"{\"blocked_at_ms\":1,\"ttl_secs\":3600}",
            )
            .unwrap();
        queue_request(tmp.path(), &store, "threat_intel:203.0.113.54:1:t", ip);

        let written = run_unblock_drain(&mut state, tmp.path(), false).await;
        assert_eq!(
            written, 1,
            "a terminal is still written (request not re-looped)"
        );
        // Records preserved — the IP is still blocked because the revert failed.
        assert!(
            store.kv_get("xdp_block_times", ip).unwrap().is_some(),
            "block record must NOT be cleared when the revert failed"
        );
        assert!(
            state.blocklist.contains(ip),
            "blocklist entry must remain when the revert failed"
        );
        // Terminal records the honest failure.
        let rows = store
            .decisions_for_incident("threat_intel:203.0.113.54:1:t")
            .unwrap();
        let last: serde_json::Value = serde_json::from_str(rows.last().unwrap()).unwrap();
        assert_eq!(
            last.get("action_type").and_then(|v| v.as_str()),
            Some("operator_unblock")
        );
        assert!(
            last.get("execution_result")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .starts_with("failed"),
            "execution_result must record the failure honestly"
        );
    }
}
