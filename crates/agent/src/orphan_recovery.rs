//! Phase 7B (audit RC-2 / 2026-04-29): orphan-incident recovery sweep.
//!
//! Why this module exists:
//!
//! The agent's standard incident processing path (`process/incidents.rs`)
//! reads incidents via a SQLite cursor (`agent_cursors` table), runs them
//! through the AI router, and writes a decision row. When the agent
//! restarts (deploy, crash, manual restart), the cursor advances past
//! incidents that were in-flight at the moment of restart but never got
//! their decision committed. Those incidents stay in the `incidents`
//! table forever without a corresponding `decisions` row — orphans.
//!
//! Pre-Phase-7 these orphans were invisible to the operator: the dashboard
//! read from the lossy in-memory KG which TTL-evicted them after ~12h.
//! Phase 7 surfaced them as the "Stuck >1h" pending-breakdown bucket —
//! useful health signal, but the bucket grows unboundedly because nothing
//! ever clears the orphans. The dashboard ended up showing "AI pipeline
//! may be wedged" with 37 stuck incidents while the AI was healthily
//! processing the steady stream.
//!
//! The recovery pass closes the loop:
//! 1. Every 10 minutes, query SQLite for incidents whose `ts` is >1h ago
//!    and have no `decisions` row joined.
//! 2. For each, write a decision with `ai_provider="orphan-recovery"` and a
//!    clear reason. **Severity-gated (Spec 062 invariant):** Low/Medium/Info
//!    orphans are `dismiss`ed (safe noise cleanup); **High/Critical orphans
//!    are RETRIED through the decider once (spec 071 Part C) — a pure-verdict
//!    close resolves them, otherwise they are routed to `needs_review`, never
//!    silently dismissed** — they stay visible/audited and the needs_review
//!    timeout sweep leaves High/Critical in needs_review forever. The hash chain
//!    stays intact (the standard `decisions::append_chained` is used) and the
//!    audit trail is honest.
//! 3. The Stuck bucket on the next dashboard tick reflects only NEW
//!    >1h-old orphans (which themselves get swept within 10 minutes).
//!
//! Bounded scope:
//! - Limited to 200 orphans per sweep so the dashboard's stuck count
//!   trends down across multiple ticks rather than disappearing in one
//!   burst (operator-visible behaviour: "stuck went from 37 to 0
//!   instantly" looks like a bug; "stuck went 37 → 17 → 0" reads as a
//!   cleanup pass running).
//! - Skips allowlisted incidents (those already have their own group).
//! - Skips incidents that already have a decision (idempotent).

use crate::ai::{AiAction, AiDecision, DecisionContext, SkillInfo};
use crate::decisions::DecisionEntry;
use crate::AgentState;
use chrono::Utc;
use innerwarden_core::incident::Incident;
use std::path::Path;
use tracing::{info, warn};

/// Spec 071 Part C: a High/Critical orphan is often not "undecidable" — it
/// merely missed `decide()` because the agent restarted or the provider had a
/// transient skip. Before routing it to `needs_review`, retry the decision once
/// here. We ACCEPT only a pure-verdict close (`dismiss`/`ignore`): those resolve
/// the orphan with nothing left to execute. Anything that implies an action —
/// `monitor`, block/kill/suspend/honeypot, or a needs-human surface
/// (`RequestConfirmation`, e.g. when the Context Gate surfaces a low-confidence
/// high/crit) — falls through to the existing `needs_review` fallback so the
/// human still adjudicates a stale action on an old incident.
fn is_passive_resolution(action: &AiAction) -> bool {
    matches!(action, AiAction::Dismiss { .. } | AiAction::Ignore { .. })
}

/// Re-run the decider on an orphan reconstructed from its stored incident JSON.
/// Returns the decision only if it deserialized and the provider succeeded.
/// Best-effort: any failure (bad JSON, provider error) yields `None` and the
/// caller falls back to `needs_review`.
async fn retry_decide(
    provider: &dyn crate::ai::AiProvider,
    incident_data_json: &str,
    available_skills: &[SkillInfo],
    already_blocked: &[String],
) -> Option<AiDecision> {
    let incident: Incident = serde_json::from_str(incident_data_json).ok()?;
    let ctx = DecisionContext {
        incident: &incident,
        recent_events: Vec::new(),
        related_incidents: Vec::new(),
        already_blocked: already_blocked.to_vec(),
        available_skills: available_skills.to_vec(),
        ip_reputation: None,
        ip_geo: None,
        ip_dshield: None,
        host_posture: None,
        prior_decisions: None,
        graph_context: None,
        graph_subgraph: None,
        playbook_outcome: None,
    };
    provider.decide(&ctx).await.ok()
}

/// Best-effort machine hostname for the decision row's `host` field.
/// Mirrors the helper in `dashboard::actions::hostname` so the
/// orphan-recovery decisions look identical to operator-initiated
/// ones in the audit log.
fn hostname() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::fs::read_to_string("/etc/hostname").map(|s| s.trim().to_string()))
        .unwrap_or_else(|_| "unknown".to_string())
}

/// Threshold: incidents older than this with no decision are
/// considered orphans. Same value the dashboard uses for the "Stuck"
/// bucket, kept in sync intentionally — if the dashboard says stuck=N,
/// the recovery pass will sweep the same N.
const ORPHAN_AGE_SECS: i64 = 3600;

/// Cap per sweep. Set high enough to clear typical operator backlogs
/// in a single sweep — when the operator deploys after a multi-day
/// gap or a misbehaving classifier accumulates orphans, they want
/// the count cleared NOW, not over multiple ticks. The original
/// 2026-04-29 17:25 incident on prod surfaced 4701 orphans accrued
/// before Phase 7B was deployed; with the prior cap of 200 it would
/// have taken ~4 hours to clear at one sweep / 10min. Bumped to
/// 5000 so a single sweep handles realistic backlogs in seconds.
const ORPHAN_SWEEP_LIMIT: usize = 5000;

/// AI-provider label written on the dismiss decision so the audit
/// trail clearly shows which decisions came from the recovery pass
/// (vs. the standard AI router or the noise gate).
pub(crate) const ORPHAN_AI_PROVIDER: &str = "orphan-recovery";

/// Run one orphan-recovery sweep. Returns the number of decisions
/// written. Best-effort: SQL or store errors are logged at `warn!` and
/// do not propagate.
pub(crate) async fn run_sweep(state: &mut AgentState, data_dir: &Path) -> usize {
    // Part C: gather owned handles up front so the retry's `.await` never holds
    // a borrow of `state`. `escalation_decider` returns an owned Arc; skills and
    // the blocklist are cloned into owned Vecs.
    let decider = state.ai_router.escalation_decider();
    let available_skills: Vec<SkillInfo> = state
        .skill_registry
        .infos()
        .into_iter()
        .map(|s| SkillInfo {
            id: s.id.clone(),
            applicable_to: s.applicable_to.clone(),
        })
        .collect();
    let already_blocked = state.blocklist.as_vec();

    let Some(store) = state.sqlite_store.as_ref() else {
        return 0;
    };
    let now = Utc::now();
    let cutoff = now - chrono::Duration::seconds(ORPHAN_AGE_SECS);
    let cutoff_iso = cutoff.to_rfc3339();

    // Query all orphans via the store crate's typed helper.
    // (incident_id, severity, ts_iso, data_json)
    let orphans: Vec<(String, String, String, String)> =
        match store.find_orphan_incidents(&cutoff_iso, ORPHAN_SWEEP_LIMIT) {
            Ok(rs) => rs,
            Err(e) => {
                warn!(error = %e, "orphan_recovery: failed to query orphans");
                return 0;
            }
        };

    if orphans.is_empty() {
        return 0;
    }

    let mut written = 0usize;
    for (incident_id, severity, incident_ts_iso, incident_data_json) in orphans {
        // Extract target_ip from incident JSON entities (best-effort —
        // missing target IP is acceptable, the decision still records).
        let target_ip = extract_target_ip(&incident_data_json);
        let age_seconds = chrono::DateTime::parse_from_rfc3339(&incident_ts_iso)
            .map(|t| (now - t.with_timezone(&Utc)).num_seconds())
            .unwrap_or(0);
        let age_human = format!("{}h{}m", age_seconds / 3600, (age_seconds % 3600) / 60);

        // Spec 062 invariant: a High/Critical incident that NObody (AI or a
        // deterministic gate) ever decided must NEVER be silently auto-dismissed
        // by this cleanup sweep. Route it to `needs_review` instead — a visible,
        // audited decision. The needs_review timeout sweep leaves High/Critical
        // in needs_review forever (only Low/Medium auto-close on timeout), so the
        // operator still sees it. Low/Medium/Info/Debug orphans are safe noise to
        // dismiss, which is exactly what this sweep exists for.
        let high_impact = matches!(
            severity.trim().to_ascii_lowercase().as_str(),
            "high" | "critical"
        );

        // Spec 071 Part C: before routing a High/Critical orphan to
        // needs_review, retry the decision once. A pure-verdict close
        // (dismiss/ignore) resolves the orphan with a real decision; anything
        // else falls through to the needs_review fallback below.
        if high_impact {
            if let Some(provider) = decider.as_deref() {
                if let Some(decision) = retry_decide(
                    provider,
                    &incident_data_json,
                    &available_skills,
                    &already_blocked,
                )
                .await
                {
                    if is_passive_resolution(&decision.action) {
                        let entry = DecisionEntry {
                            ts: now,
                            incident_id: incident_id.clone(),
                            host: hostname(),
                            ai_provider: provider.name().to_string(),
                            action_type: decision.action.name().to_string(),
                            target_ip: target_ip.clone(),
                            target_user: None,
                            skill_id: None,
                            confidence: decision.confidence,
                            // The recovery sweep records the verdict; it does not
                            // run response skills (a dismiss/ignore has none).
                            auto_executed: false,
                            dry_run: false,
                            reason: format!(
                                "Orphan-recovery retry: re-decided a {severity}-severity \
                                 incident that missed its decision ({age_human} old). \
                                 {} returned {} (conf {:.2}) — a pure-verdict close, so the \
                                 orphan is resolved instead of parked for a human.",
                                provider.name(),
                                decision.action.name(),
                                decision.confidence
                            ),
                            estimated_threat: decision.estimated_threat.clone(),
                            execution_result: "redecided".to_string(),
                            prev_hash: None,
                            decision_layer: Some("orphan_redecide".to_string()),
                        };
                        match crate::decisions::append_chained(data_dir, &entry, Some(store)) {
                            Ok(()) => written += 1,
                            Err(e) => warn!(
                                incident_id = %incident_id,
                                error = %e,
                                "orphan_recovery: failed to write retry decision"
                            ),
                        }
                        continue;
                    }
                }
            }
        }

        // Truthful-containment guard (operator report 2026-06-10 +
        // [[project_block_enforcement_verify_live]]): a High/Critical orphan
        // whose IP is ALREADY live-blocked at the firewall is a *contained*
        // threat, not one that "needs your attention". Routing it to
        // needs_review made the dashboard cry for operator action on a
        // neutralised IP (the prod symptom: 4 threat_intel IPs that nft was
        // already dropping showed up under "Needs your attention"). Before the
        // needs_review fallback, verify LIVE — mirroring the fast-loop churn
        // guard in `incident_flow` (block-mitigated detector AND a TTL-valid
        // live block) — and record a truthful `block_ip`/contained decision
        // instead. This consults `response_lifecycle::is_ip_actively_blocked`
        // (the in-memory, TTL-accurate view the write path trusts), never a
        // static record. Spec 062 is preserved for everything NOT live-blocked:
        // those still route to needs_review and stay visible/audited.
        if high_impact {
            if let Some(ip) = target_ip.as_deref() {
                if crate::incident_flow::is_block_mitigated_detector(&incident_id)
                    && state.response_lifecycle.is_ip_actively_blocked(ip, now)
                {
                    let entry = DecisionEntry {
                        ts: now,
                        incident_id: incident_id.clone(),
                        host: hostname(),
                        ai_provider: ORPHAN_AI_PROVIDER.to_string(),
                        // Classifies as Contained (block_ip + a success
                        // execution_result) via threat_contract, so the case
                        // leaves "Needs your attention" and reads as the
                        // already-enforced block it actually is.
                        action_type: "block_ip".to_string(),
                        target_ip: target_ip.clone(),
                        target_user: None,
                        skill_id: None,
                        confidence: 1.0,
                        // No skill ran: orphan-recovery only verified an
                        // existing live block; it applied no new firewall rule.
                        auto_executed: false,
                        dry_run: false,
                        reason: format!(
                            "Orphan-recovery: {severity}-severity incident is {age_human} old; \
                                 its IP {ip} is tracked as blocked by the response lifecycle \
                                 (TTL-accurate in-memory view; not a live firewall re-check). \
                                 Threat is treated as contained — recorded as contained instead of \
                                 needs_review. No new firewall rule applied."
                        ),
                        estimated_threat: severity.clone(),
                        execution_result: "blocked (per response lifecycle)".to_string(),
                        prev_hash: None,
                        decision_layer: Some("observation_verifier".to_string()),
                    };
                    match crate::decisions::append_chained(data_dir, &entry, Some(store)) {
                        Ok(()) => written += 1,
                        Err(e) => warn!(
                            incident_id = %incident_id,
                            error = %e,
                            "orphan_recovery: failed to write contained (already-blocked) decision"
                        ),
                    }
                    continue;
                }
            }
        }

        let (action_type, execution_result, estimated_threat, reason): (
            &str,
            &str,
            String,
            String,
        ) = if high_impact {
            (
                "needs_review",
                "awaiting_human",
                severity.clone(),
                format!(
                    "Orphan-recovery: {severity}-severity incident is {age_human} old with no \
                         AI decision (deploy orphan or AI provider skip). High/Critical is never \
                         auto-dismissed — routed to needs_review for the operator (Spec 062 \
                         invariant)."
                ),
            )
        } else {
            (
                "dismiss",
                "dismissed",
                "none".to_string(),
                format!(
                    "Auto-dismissed by orphan-recovery sweep: {severity}-severity incident is \
                         {age_human} old with no AI decision. Likely deploy orphan or AI provider \
                         skip. Operator can re-trigger manual review via Threats list."
                ),
            )
        };
        let entry = DecisionEntry {
            ts: now,
            incident_id: incident_id.clone(),
            host: hostname(),
            ai_provider: ORPHAN_AI_PROVIDER.to_string(),
            action_type: action_type.to_string(),
            target_ip,
            target_user: None,
            skill_id: None,
            confidence: 1.0,
            // needs_review parks the incident for a human; it is not "executed".
            auto_executed: !high_impact,
            dry_run: false,
            reason,
            estimated_threat,
            execution_result: execution_result.to_string(),
            prev_hash: None,
            decision_layer: Some(
                (if high_impact {
                    "observation_verifier"
                } else {
                    "auto_rule"
                })
                .to_string(),
            ),
        };
        match crate::decisions::append_chained(data_dir, &entry, Some(store)) {
            Ok(()) => written += 1,
            Err(e) => warn!(
                incident_id = %incident_id,
                error = %e,
                "orphan_recovery: failed to write dismiss decision"
            ),
        }
    }

    if written > 0 {
        info!(
            written,
            "orphan_recovery: swept abandoned incidents (Low/Med -> dismiss, High/Crit -> needs_review)"
        );
    }
    written
}

/// Extract the first IP entity from the incident's JSON `data` blob.
/// Returns `None` when the JSON is malformed or has no IP entity (the
/// dismiss decision is still written without a target IP).
pub(crate) fn extract_target_ip(incident_data_json: &str) -> Option<String> {
    let parsed: serde_json::Value = serde_json::from_str(incident_data_json).ok()?;
    let entities = parsed.get("entities")?.as_array()?;
    for entity in entities {
        let kind = entity.get("type")?.as_str()?;
        if kind.eq_ignore_ascii_case("ip") {
            let value = entity.get("value")?.as_str()?;
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_target_ip_finds_first_external_ip() {
        let json = serde_json::json!({
            "entities": [
                {"type": "user", "value": "alice"},
                {"type": "ip", "value": "203.0.113.10"},
                {"type": "ip", "value": "203.0.113.20"},
            ]
        })
        .to_string();
        assert_eq!(extract_target_ip(&json), Some("203.0.113.10".to_string()));
    }

    #[test]
    fn extract_target_ip_returns_none_when_no_ip() {
        let json = serde_json::json!({
            "entities": [{"type": "user", "value": "alice"}]
        })
        .to_string();
        assert_eq!(extract_target_ip(&json), None);
    }

    #[test]
    fn extract_target_ip_returns_none_on_malformed_json() {
        assert_eq!(extract_target_ip("not json"), None);
    }

    #[test]
    fn extract_target_ip_returns_none_when_entities_missing() {
        // Valid JSON but no `entities` field at all → None.
        let json = serde_json::json!({"summary": "no entities here"}).to_string();
        assert_eq!(extract_target_ip(&json), None);
    }

    #[test]
    fn extract_target_ip_returns_none_when_entities_is_not_array() {
        // `entities` is present but not an array → None (as_array() fails).
        let json = serde_json::json!({"entities": "not-an-array"}).to_string();
        assert_eq!(extract_target_ip(&json), None);
    }

    #[test]
    fn extract_target_ip_skips_empty_value_strings() {
        // The `if !value.is_empty()` guard skips an IP entity with an
        // empty value and falls through to the next one. Pins the
        // contract that "first IP entity, but not a blank one" is what
        // the dismiss-decision rows record as `target_ip`.
        let json = serde_json::json!({
            "entities": [
                {"type": "ip", "value": ""},
                {"type": "ip", "value": "198.51.100.7"},
            ]
        })
        .to_string();
        assert_eq!(extract_target_ip(&json), Some("198.51.100.7".to_string()));
    }

    #[test]
    fn extract_target_ip_is_case_insensitive_on_kind() {
        // The store records EntityRef kinds as lowercase ("ip"), but
        // the orphan-recovery extractor uses `eq_ignore_ascii_case`
        // so a future schema change that capitalises the type wouldn't
        // silently drop target_ip from every dismiss row.
        let json = serde_json::json!({
            "entities": [{"type": "IP", "value": "203.0.113.99"}]
        })
        .to_string();
        assert_eq!(extract_target_ip(&json), Some("203.0.113.99".to_string()));
    }

    #[test]
    fn hostname_prefers_env_var_when_set() {
        // The function tries HOSTNAME env var first; setting it makes
        // the result deterministic regardless of /etc/hostname on the
        // test box. Mirrors the precedent in
        // `bot_helpers::local_hostname_for_audit_reads_env_var_when_set`
        // which mutates the same env var the same way.
        // SAFETY: cargo test parallelises across test cases but no
        // other test in this binary touches HOSTNAME concurrently
        // (verified by `rg "HOSTNAME" crates/agent/src/`); we restore
        // the original below.
        let prev = std::env::var("HOSTNAME").ok();
        unsafe {
            std::env::set_var("HOSTNAME", "orphan-recovery-test-host");
        }
        let h = hostname();
        unsafe {
            match prev {
                Some(v) => std::env::set_var("HOSTNAME", v),
                None => std::env::remove_var("HOSTNAME"),
            }
        }
        assert_eq!(h, "orphan-recovery-test-host");
        // Round-trip the contract the DecisionEntry::host field
        // relies on: never empty.
        assert!(!h.is_empty());
    }

    /// Build a minimal AgentState backed by a temp dir + a pre-seeded
    /// SQLite store. Returns (state, data_dir tempdir handle, store
    /// handle) so tests can both inspect post-sweep store state and
    /// keep the tempdir alive for the duration of the test.
    fn build_state_with_store(
        tmp: &tempfile::TempDir,
    ) -> (crate::AgentState, std::sync::Arc<innerwarden_store::Store>) {
        let mut state = crate::tests::triage_test_state(tmp.path());
        // triage_test_state leaves sqlite_store = None. Open a real
        // on-disk store inside the tempdir so the
        // `decisions::append_chained` JSONL path and the SQLite mirror
        // both exercise their happy paths under run_sweep.
        let store = std::sync::Arc::new(
            innerwarden_store::Store::open(tmp.path()).expect("open sqlite store"),
        );
        state.sqlite_store = Some(store.clone());
        (state, store)
    }

    fn make_orphan(
        id: &str,
        ts: chrono::DateTime<chrono::Utc>,
    ) -> innerwarden_core::incident::Incident {
        // Low severity by default so the orphan-recovery dismiss path (Low/Med)
        // is the one exercised. High/Critical now routes to needs_review (see
        // `make_orphan_sev` + the needs_review tests).
        make_orphan_sev(id, ts, innerwarden_core::event::Severity::Low)
    }

    fn make_orphan_sev(
        id: &str,
        ts: chrono::DateTime<chrono::Utc>,
        severity: innerwarden_core::event::Severity,
    ) -> innerwarden_core::incident::Incident {
        use innerwarden_core::entities::EntityRef;
        innerwarden_core::incident::Incident {
            ts,
            host: "h".into(),
            incident_id: id.into(),
            severity,
            title: "t".into(),
            summary: "s".into(),
            evidence: serde_json::json!({}),
            recommended_checks: vec![],
            tags: vec![],
            entities: vec![EntityRef::ip("203.0.113.10")],
        }
    }

    #[tokio::test]
    async fn run_sweep_returns_zero_when_sqlite_store_is_none() {
        // Before the agent's slow_loop has finished its boot it can
        // tick run_sweep with `state.sqlite_store == None` (e.g. the
        // sqlite-reopen retry path). The function MUST early-return 0
        // without panicking and without touching disk.
        let tmp = tempfile::tempdir().unwrap();
        let mut state = crate::tests::triage_test_state(tmp.path());
        assert!(state.sqlite_store.is_none());
        let written = run_sweep(&mut state, tmp.path()).await;
        assert_eq!(written, 0, "no store → no decisions written");
        // The triage_test_state DecisionWriter already creates an
        // empty decisions-*.jsonl on construction; the early-return
        // path must NOT have written any new content into it.
        // (If a future change adds an unconditional write before the
        // sqlite_store gate, every JSONL we discover here would have
        // a non-zero size and this assertion would catch it.)
        for entry in std::fs::read_dir(tmp.path()).unwrap().flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if name_str.starts_with("decisions-") && name_str.ends_with(".jsonl") {
                let len = std::fs::metadata(entry.path()).unwrap().len();
                assert_eq!(
                    len, 0,
                    "decisions JSONL must be empty when run_sweep early-returns: {name_str} has {len} bytes"
                );
            }
        }
    }

    #[tokio::test]
    async fn run_sweep_returns_zero_when_store_has_no_orphans() {
        // Empty store → the inner `find_orphan_incidents` returns an
        // empty vec → run_sweep early-returns 0 BEFORE the loop body
        // and skips the info! log. Pins the empty-bucket fast path so
        // a future refactor that always allocates a DecisionEntry
        // shows up as a coverage regression here.
        let tmp = tempfile::tempdir().unwrap();
        let (mut state, store) = build_state_with_store(&tmp);
        let written = run_sweep(&mut state, tmp.path()).await;
        assert_eq!(written, 0);
        assert_eq!(
            store.decisions_count().unwrap(),
            0,
            "empty store → no decisions appended"
        );
    }

    #[tokio::test]
    async fn run_sweep_writes_dismiss_decision_for_old_orphan() {
        // End-to-end happy path:
        // (1) old orphan inserted, no decision row;
        // (2) run_sweep returns 1;
        // (3) the SQLite mirror grew by exactly 1 decision row;
        // (4) the new decision is for the right incident_id and
        //     carries the orphan-recovery `ai_provider` label and
        //     dismiss `action_type` so the audit log is honest about
        //     who took the action.
        let tmp = tempfile::tempdir().unwrap();
        let (mut state, store) = build_state_with_store(&tmp);
        let two_hours_ago = chrono::Utc::now() - chrono::Duration::hours(2);
        store
            .insert_incident(&make_orphan("old:orphan-1", two_hours_ago))
            .unwrap();

        let written = run_sweep(&mut state, tmp.path()).await;

        assert_eq!(written, 1, "exactly one orphan should have been swept");
        assert_eq!(store.decisions_count().unwrap(), 1);

        let rows = store.decisions_for_incident("old:orphan-1").unwrap();
        assert_eq!(rows.len(), 1);
        let parsed: serde_json::Value = serde_json::from_str(&rows[0]).unwrap();
        assert_eq!(
            parsed.get("ai_provider").and_then(|v| v.as_str()),
            Some(ORPHAN_AI_PROVIDER),
            "audit log must label this row as orphan-recovery"
        );
        assert_eq!(
            parsed.get("action_type").and_then(|v| v.as_str()),
            Some("dismiss"),
        );
        // The reason text encodes age in `<H>h<M>m` form; pin the
        // shape so a future format change is visible.
        let reason = parsed.get("reason").and_then(|v| v.as_str()).unwrap_or("");
        assert!(
            reason.contains("orphan-recovery sweep"),
            "reason must mention the sweep so the operator can grep for it: {reason}"
        );
        assert!(
            reason.contains("h") && reason.contains("m"),
            "reason must include the age-human <H>h<M>m fragment: {reason}"
        );
        // Decision JSONL file should also exist on disk (the agent
        // operator-facing audit trail).
        let today = chrono::Local::now()
            .date_naive()
            .format("%Y-%m-%d")
            .to_string();
        let jsonl = tmp.path().join(format!("decisions-{today}.jsonl"));
        assert!(jsonl.exists(), "decisions JSONL must be written");
    }

    #[tokio::test]
    async fn run_sweep_high_severity_orphan_routes_to_needs_review() {
        // Spec 062 invariant: a High/Critical orphan must NOT be silently
        // dismissed — it routes to needs_review (visible, audited, never
        // auto-closed by the needs_review timeout sweep).
        let tmp = tempfile::tempdir().unwrap();
        let (mut state, store) = build_state_with_store(&tmp);
        let two_hours_ago = chrono::Utc::now() - chrono::Duration::hours(2);
        store
            .insert_incident(&make_orphan_sev(
                "old:critical-orphan",
                two_hours_ago,
                innerwarden_core::event::Severity::Critical,
            ))
            .unwrap();

        let written = run_sweep(&mut state, tmp.path()).await;
        assert_eq!(written, 1);

        let rows = store.decisions_for_incident("old:critical-orphan").unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&rows[0]).unwrap();
        assert_eq!(
            parsed.get("action_type").and_then(|v| v.as_str()),
            Some("needs_review"),
            "High/Critical orphan must route to needs_review, never silent dismiss"
        );
        assert_eq!(
            parsed.get("ai_provider").and_then(|v| v.as_str()),
            Some(ORPHAN_AI_PROVIDER),
        );
        let reason = parsed.get("reason").and_then(|v| v.as_str()).unwrap_or("");
        assert!(
            reason.contains("needs_review") && reason.contains("never auto-dismissed"),
            "reason must explain the needs_review routing: {reason}"
        );
    }

    #[tokio::test]
    async fn run_sweep_low_severity_orphan_is_dismissed() {
        // The complement: Low/Medium orphans stay on the dismiss path — that
        // is what the cleanup sweep is for.
        let tmp = tempfile::tempdir().unwrap();
        let (mut state, store) = build_state_with_store(&tmp);
        let two_hours_ago = chrono::Utc::now() - chrono::Duration::hours(2);
        store
            .insert_incident(&make_orphan_sev(
                "old:low-orphan",
                two_hours_ago,
                innerwarden_core::event::Severity::Low,
            ))
            .unwrap();

        run_sweep(&mut state, tmp.path()).await;
        let rows = store.decisions_for_incident("old:low-orphan").unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&rows[0]).unwrap();
        assert_eq!(
            parsed.get("action_type").and_then(|v| v.as_str()),
            Some("dismiss"),
            "Low-severity orphan stays on the dismiss path"
        );
    }

    #[tokio::test]
    async fn run_sweep_extracts_target_ip_from_incident_data() {
        // The dismiss decision should carry the first IP entity of
        // the orphan's stored JSON as `target_ip` so attacker-IP
        // dashboards correctly attribute the auto-dismissed row.
        // This pins the integration between extract_target_ip + the
        // data column round-trip via SQLite.
        let tmp = tempfile::tempdir().unwrap();
        let (mut state, store) = build_state_with_store(&tmp);
        let two_hours_ago = chrono::Utc::now() - chrono::Duration::hours(2);
        store
            .insert_incident(&make_orphan("old:orphan-with-ip", two_hours_ago))
            .unwrap();

        let written = run_sweep(&mut state, tmp.path()).await;
        assert_eq!(written, 1);

        let rows = store.decisions_for_incident("old:orphan-with-ip").unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&rows[0]).unwrap();
        assert_eq!(
            parsed.get("target_ip").and_then(|v| v.as_str()),
            Some("203.0.113.10"),
            "target_ip must round-trip from the orphan's first IP entity"
        );
    }

    #[tokio::test]
    async fn run_sweep_skips_fresh_and_decided_and_allowlisted_incidents() {
        // Mirrors the SoT contract on `find_orphan_incidents` from one
        // layer up: run_sweep must NOT touch incidents that are
        // (a) fresh, (b) already have a decision, or (c) flagged
        // is_allowlisted. Without this anchor a future bug that
        // widens the SQL filter would silently auto-dismiss real
        // pending-AI work.
        let tmp = tempfile::tempdir().unwrap();
        let (mut state, store) = build_state_with_store(&tmp);
        let now = chrono::Utc::now();
        let two_hours_ago = now - chrono::Duration::hours(2);
        let two_min_ago = now - chrono::Duration::minutes(2);

        // (a) Fresh, decisionless → must be skipped.
        store
            .insert_incident(&make_orphan("fresh:1", two_min_ago))
            .unwrap();

        // (b) Old, but already has a decision → must be skipped.
        store
            .insert_incident(&make_orphan("old:already-decided", two_hours_ago))
            .unwrap();
        let pre_existing = innerwarden_store::decisions::DecisionRow {
            ts: now.to_rfc3339(),
            incident_id: "old:already-decided".into(),
            action_type: "block_ip".into(),
            target_ip: Some("203.0.113.10".into()),
            target_user: None,
            confidence: 1.0,
            auto_executed: true,
            reason: Some("preexisting".into()),
            data: "{}".to_string(),
        };
        store.insert_decision(&pre_existing).unwrap();

        // (c) Old, decisionless, but allowlisted → must be skipped.
        store
            .insert_incident(&make_orphan("old:trusted", two_hours_ago))
            .unwrap();
        store.set_incident_allowlisted("old:trusted").unwrap();

        // (d) Old, decisionless, NOT allowlisted → MUST be swept.
        store
            .insert_incident(&make_orphan("old:real-orphan", two_hours_ago))
            .unwrap();

        let written = run_sweep(&mut state, tmp.path()).await;
        assert_eq!(
            written, 1,
            "only the (d) row qualifies; sweep wrote {written} decision(s)"
        );

        // Verify the decision touched only "old:real-orphan".
        assert_eq!(
            store
                .decisions_for_incident("old:real-orphan")
                .unwrap()
                .len(),
            1
        );
        assert!(
            store.decisions_for_incident("fresh:1").unwrap().is_empty(),
            "fresh incident must not get a recovery decision"
        );
        assert!(
            store
                .decisions_for_incident("old:trusted")
                .unwrap()
                .is_empty(),
            "allowlisted incident must not get a recovery decision"
        );
        // The pre-existing decision on "old:already-decided" remains
        // the ONLY decision row for that incident — orphan-recovery
        // must not stack a second one.
        assert_eq!(
            store
                .decisions_for_incident("old:already-decided")
                .unwrap()
                .len(),
            1,
        );
    }

    // Spec 071 Part C: the retry-before-needs_review path.
    struct DismissStub;
    #[async_trait::async_trait]
    impl crate::ai::AiProvider for DismissStub {
        fn name(&self) -> &'static str {
            "dismiss-stub"
        }
        fn capabilities(&self) -> crate::ai::AiCapabilities {
            crate::ai::AiCapabilities::from_slice(&[crate::ai::Capability::Decide])
        }
        async fn decide(&self, _ctx: &DecisionContext<'_>) -> anyhow::Result<AiDecision> {
            Ok(AiDecision {
                action: AiAction::Dismiss {
                    reason: "stub".into(),
                },
                confidence: 0.92,
                auto_execute: true,
                reason: "stub".into(),
                alternatives: vec![],
                estimated_threat: "low".into(),
            })
        }
        async fn chat(&self, _: &str, _: &str) -> anyhow::Result<String> {
            Ok(String::new())
        }
    }

    #[test]
    fn is_passive_resolution_accepts_only_pure_verdicts() {
        assert!(is_passive_resolution(&AiAction::Dismiss {
            reason: "x".into()
        }));
        assert!(is_passive_resolution(&AiAction::Ignore {
            reason: "x".into()
        }));
        // Monitor implies an action to execute; an orphan retry must NOT treat
        // it as a resolution (it falls through to needs_review).
        assert!(!is_passive_resolution(&AiAction::Monitor {
            ip: "1.1.1.1".into()
        }));
        assert!(!is_passive_resolution(&AiAction::BlockIp {
            ip: "1.1.1.1".into(),
            skill_id: "s".into()
        }));
    }

    #[tokio::test]
    async fn retry_decide_resolves_high_crit_orphan_with_dismiss() {
        let inc = make_orphan_sev(
            "privesc:x:1:t",
            chrono::Utc::now(),
            innerwarden_core::event::Severity::Critical,
        );
        let json = serde_json::to_string(&inc).unwrap();
        let decision = retry_decide(&DismissStub, &json, &[], &[])
            .await
            .expect("stub provider returns a decision");
        assert!(
            is_passive_resolution(&decision.action),
            "a dismiss verdict must resolve the orphan instead of routing to needs_review"
        );
    }

    #[tokio::test]
    async fn retry_decide_returns_none_on_unparseable_incident() {
        // Bad JSON must yield None so the caller safely falls back to needs_review.
        assert!(retry_decide(&DismissStub, "{not valid", &[], &[])
            .await
            .is_none());
    }

    #[tokio::test]
    async fn run_sweep_retries_high_crit_orphan_and_resolves_instead_of_needs_review() {
        // End-to-end Part C: with a decider present, a High/Critical orphan is
        // re-decided; a pure-verdict dismiss resolves it (NOT needs_review).
        let tmp = tempfile::tempdir().unwrap();
        let (mut state, store) = build_state_with_store(&tmp);
        // Inject a decider that returns a dismiss into the LLM (escalation) slot.
        state.ai_router =
            crate::ai::AiRouter::new(None, Some(std::sync::Arc::new(DismissStub))).unwrap();
        let two_hours_ago = chrono::Utc::now() - chrono::Duration::hours(2);
        store
            .insert_incident(&make_orphan_sev(
                "privesc:rogue:1:t",
                two_hours_ago,
                innerwarden_core::event::Severity::Critical,
            ))
            .unwrap();

        let written = run_sweep(&mut state, tmp.path()).await;
        assert_eq!(written, 1, "the orphan should be resolved by the retry");

        let rows = store.decisions_for_incident("privesc:rogue:1:t").unwrap();
        assert_eq!(rows.len(), 1);
        let parsed: serde_json::Value = serde_json::from_str(&rows[0]).unwrap();
        // Resolved by the retry, NOT parked: needs_review would carry
        // ai_provider="orphan-recovery" + action_type="needs_review".
        assert_eq!(
            parsed.get("action_type").and_then(|v| v.as_str()),
            Some("dismiss"),
            "a passive retry verdict must resolve the orphan"
        );
        assert_eq!(
            parsed.get("ai_provider").and_then(|v| v.as_str()),
            Some("dismiss-stub"),
            "the audit row must attribute the verdict to the retry decider, not orphan-recovery"
        );
    }

    #[tokio::test]
    async fn run_sweep_keeps_needs_review_when_retry_unavailable() {
        // No decider (escalation_decider == None) → retry skipped → the
        // High/Critical orphan still routes to needs_review (Spec 062 invariant).
        let tmp = tempfile::tempdir().unwrap();
        let (mut state, store) = build_state_with_store(&tmp);
        let two_hours_ago = chrono::Utc::now() - chrono::Duration::hours(2);
        store
            .insert_incident(&make_orphan_sev(
                "privesc:rogue:2:t",
                two_hours_ago,
                innerwarden_core::event::Severity::Critical,
            ))
            .unwrap();
        let _ = run_sweep(&mut state, tmp.path()).await;
        let rows = store.decisions_for_incident("privesc:rogue:2:t").unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&rows[0]).unwrap();
        assert_eq!(
            parsed.get("action_type").and_then(|v| v.as_str()),
            Some("needs_review")
        );
    }

    // ── Truthful-containment guard (operator report 2026-06-10) ──────
    // A High/Critical orphan whose IP is ALREADY live-blocked at the
    // firewall must be recorded as Contained (block_ip), not parked in
    // needs_review — otherwise the dashboard cries "Needs your attention"
    // for a neutralised threat. The guard fires ONLY when both hold:
    // (a) the detector is one a firewall block fully mitigates AND
    // (b) the IP has a TTL-valid live block in the response lifecycle.

    #[tokio::test]
    async fn run_sweep_high_crit_orphan_already_blocked_records_contained_not_needs_review() {
        use crate::response_lifecycle::{ResponseBackend, ResponseType};
        let tmp = tempfile::tempdir().unwrap();
        let (mut state, store) = build_state_with_store(&tmp);
        // Register a live block on the orphan's IP (make_orphan_sev pins the
        // entity IP to 203.0.113.10) with a block-mitigated detector prefix.
        state.response_lifecycle.register(
            ResponseType::BlockIp,
            ResponseBackend::Ufw,
            "203.0.113.10",
            "threat_intel:203.0.113.10:1:t",
            3600,
            None,
        );
        let two_hours_ago = chrono::Utc::now() - chrono::Duration::hours(2);
        store
            .insert_incident(&make_orphan_sev(
                "threat_intel:203.0.113.10:1:t",
                two_hours_ago,
                innerwarden_core::event::Severity::Critical,
            ))
            .unwrap();

        let written = run_sweep(&mut state, tmp.path()).await;
        assert_eq!(written, 1);

        let rows = store
            .decisions_for_incident("threat_intel:203.0.113.10:1:t")
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&rows[0]).unwrap();
        assert_eq!(
            parsed.get("action_type").and_then(|v| v.as_str()),
            Some("block_ip"),
            "already-blocked High/Crit orphan must record Contained, never needs_review"
        );
        assert_eq!(
            parsed.get("ai_provider").and_then(|v| v.as_str()),
            Some(ORPHAN_AI_PROVIDER),
        );
        let exec = parsed
            .get("execution_result")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        assert!(
            exec.starts_with("blocked"),
            "execution_result must classify as contained (blocked*): {exec}"
        );
        // auto_executed must be false: we verified an existing block, we did
        // not apply a new firewall rule. Honesty over vanity.
        assert_eq!(
            parsed.get("auto_executed").and_then(|v| v.as_bool()),
            Some(false),
        );
        let reason = parsed.get("reason").and_then(|v| v.as_str()).unwrap_or("");
        // Honest text: it must NOT claim "verified live" (it only checks the
        // in-memory lifecycle, not the live firewall) and must say no new rule
        // was applied.
        assert!(
            !reason.contains("verified live"),
            "reason must NOT overclaim 'verified live' (no live firewall re-check happens): {reason}"
        );
        assert!(
            reason.contains("response lifecycle") && reason.contains("No new firewall rule"),
            "reason must be honest about the in-memory lifecycle source + no new rule: {reason}"
        );
    }

    #[tokio::test]
    async fn run_sweep_high_crit_orphan_block_mitigated_but_not_live_blocked_routes_needs_review() {
        // Condition (b) fails: detector is block-mitigated but there is NO
        // live block for the IP. Must fall through to needs_review (Spec 062).
        let tmp = tempfile::tempdir().unwrap();
        let (mut state, store) = build_state_with_store(&tmp);
        let two_hours_ago = chrono::Utc::now() - chrono::Duration::hours(2);
        store
            .insert_incident(&make_orphan_sev(
                "threat_intel:203.0.113.10:1:t",
                two_hours_ago,
                innerwarden_core::event::Severity::Critical,
            ))
            .unwrap();

        run_sweep(&mut state, tmp.path()).await;
        let rows = store
            .decisions_for_incident("threat_intel:203.0.113.10:1:t")
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&rows[0]).unwrap();
        assert_eq!(
            parsed.get("action_type").and_then(|v| v.as_str()),
            Some("needs_review"),
            "block-mitigated detector with NO live block must still route to needs_review"
        );
    }

    #[tokio::test]
    async fn run_sweep_high_crit_orphan_blocked_but_active_harm_detector_routes_needs_review() {
        // Condition (a) fails: the IP is live-blocked, but the detector
        // (privesc) is NOT one a firewall block mitigates — a block does not
        // stop an in-progress privilege escalation, so the human must still
        // review it. Mirrors the fast-loop churn guard's active-harm carve-out.
        use crate::response_lifecycle::{ResponseBackend, ResponseType};
        let tmp = tempfile::tempdir().unwrap();
        let (mut state, store) = build_state_with_store(&tmp);
        state.response_lifecycle.register(
            ResponseType::BlockIp,
            ResponseBackend::Ufw,
            "203.0.113.10",
            "privesc:203.0.113.10:1:t",
            3600,
            None,
        );
        let two_hours_ago = chrono::Utc::now() - chrono::Duration::hours(2);
        store
            .insert_incident(&make_orphan_sev(
                "privesc:203.0.113.10:1:t",
                two_hours_ago,
                innerwarden_core::event::Severity::Critical,
            ))
            .unwrap();

        run_sweep(&mut state, tmp.path()).await;
        let rows = store
            .decisions_for_incident("privesc:203.0.113.10:1:t")
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&rows[0]).unwrap();
        assert_eq!(
            parsed.get("action_type").and_then(|v| v.as_str()),
            Some("needs_review"),
            "active-harm detector must route to needs_review even when the IP is blocked"
        );
    }

    #[test]
    fn find_orphan_incidents_returns_only_decisionless_old_rows() {
        // The store-level helper is what the slow_loop sweep iterates.
        // Anchor end-to-end here so a future schema change to incidents
        // or decisions surfaces as a test failure instead of as a
        // silently-broken recovery pass on prod.
        use innerwarden_core::entities::EntityRef;
        use innerwarden_core::event::Severity;
        use innerwarden_core::incident::Incident;

        let store = innerwarden_store::Store::open_memory().expect("open_memory");
        let now = chrono::Utc::now();
        let two_hours_ago = now - chrono::Duration::hours(2);
        let two_min_ago = now - chrono::Duration::minutes(2);

        let make = |id: &str, ts: chrono::DateTime<chrono::Utc>| Incident {
            ts,
            host: "h".into(),
            incident_id: id.into(),
            severity: Severity::High,
            title: "t".into(),
            summary: "s".into(),
            evidence: serde_json::json!({}),
            recommended_checks: vec![],
            tags: vec![],
            entities: vec![EntityRef::ip("203.0.113.10")],
        };

        // Old orphan -> SHOULD be returned.
        store
            .insert_incident(&make("old:orphan", two_hours_ago))
            .unwrap();

        // Old, but already has a decision -> SHOULD NOT be returned.
        store
            .insert_incident(&make("old:decided", two_hours_ago))
            .unwrap();
        let decided = innerwarden_store::decisions::DecisionRow {
            ts: now.to_rfc3339(),
            incident_id: "old:decided".into(),
            action_type: "block_ip".into(),
            target_ip: Some("203.0.113.10".into()),
            target_user: None,
            confidence: 1.0,
            auto_executed: true,
            reason: Some("test".into()),
            data: "{}".to_string(),
        };
        store.insert_decision(&decided).expect("insert decision");

        // Fresh, decisionless -> SHOULD NOT be returned (still in-flight).
        store
            .insert_incident(&make("fresh:1", two_min_ago))
            .unwrap();

        // Old, decisionless, but allowlisted -> SHOULD NOT be returned.
        store
            .insert_incident(&make("old:trusted", two_hours_ago))
            .unwrap();
        store.set_incident_allowlisted("old:trusted").unwrap();

        let cutoff = (now - chrono::Duration::hours(1)).to_rfc3339();
        let orphans = store.find_orphan_incidents(&cutoff, 100).unwrap();
        let ids: Vec<&str> = orphans.iter().map(|(id, _, _, _)| id.as_str()).collect();
        assert_eq!(
            ids,
            vec!["old:orphan"],
            "only old + decisionless + non-allowlisted incidents qualify"
        );
    }
}
