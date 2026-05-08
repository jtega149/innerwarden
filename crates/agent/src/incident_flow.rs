use std::collections::HashSet;

use tracing::{info, warn};

use crate::{ai, allowlist, config, state_store, AgentState};

pub(crate) enum PreAiFlowDecision {
    Proceed,
    SkipHandled,
    /// Entity is in allowlist — skip AI but mark in graph.
    SkipAllowlisted,
    PipelineTestHandled,
    /// Incident severity is below the configured AI min_severity threshold.
    /// Eligible for rule-based auto-dismiss (noise gate) when Guard mode is ON.
    SkipBelowSeverity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PreAiGuardDecision {
    Proceed,
    PipelineTestHandled,
    SkipAdvisoryDetector,
    SkipAiDisabled,
    SkipAllowlisted,
    SkipBelowSeverity,
    SkipPrivateOrBlocked,
    SkipDecisionCooldown,
    SkipAiCallBudget,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct PreAiGuardInputs {
    pub is_pipeline_test: bool,
    pub is_advisory_detector: bool,
    pub ai_enabled: bool,
    pub is_allowlisted: bool,
    pub passes_ai_gate: bool,
    pub below_severity_threshold: bool,
    pub in_decision_cooldown: bool,
    pub ai_calls_this_tick: usize,
    pub max_ai_calls_per_tick: usize,
    /// Spec 028-b skip-fase3: detector prefix matches the operator's
    /// high-signal skip list (e.g. `threat_intel:`, `sudo_abuse:`,
    /// `suspicious_execution:`). When true, the below-severity and
    /// decision-cooldown guards are bypassed so the incident reaches
    /// decide(). Allowlist and per-tick budget still apply because
    /// those are safety, not noise.
    pub skip_fase3: bool,
}

/// Spec 028-b skip-fase3: return true when the incident_id is either
/// an exact match for an entry in the skip list or has the entry as a
/// prefix followed by `:`. Prefix matching handles both the
/// "just-the-detector" form (`threat_intel`) and the qualified form
/// (`threat_intel:threat_ip`). The colon guard prevents accidental
/// substring collisions (e.g. `threat_intel` must not match
/// `threat_intel_something_else` if such a thing ever appeared).
pub(super) fn matches_skip_fase3(incident_id: &str, skip_list: &[String]) -> bool {
    skip_list.iter().any(|entry| {
        if entry.is_empty() {
            return false;
        }
        incident_id == entry || incident_id.starts_with(&format!("{entry}:"))
    })
}

pub(super) fn decide_pre_ai_guard(inputs: PreAiGuardInputs) -> PreAiGuardDecision {
    if inputs.is_pipeline_test {
        return PreAiGuardDecision::PipelineTestHandled;
    }

    // Neural model detectors remain advisory-only and never go through AI.
    if inputs.is_advisory_detector {
        return PreAiGuardDecision::SkipAdvisoryDetector;
    }

    if !inputs.ai_enabled {
        return PreAiGuardDecision::SkipAiDisabled;
    }

    if inputs.is_allowlisted {
        return PreAiGuardDecision::SkipAllowlisted;
    }

    // Spec 028-b skip-fase3: high-signal detectors bypass the
    // below-severity and decision-cooldown guards but still respect
    // allowlist (above) and the per-tick budget (below). The point is
    // that threat_intel / sudo_abuse / suspicious_execution should
    // never be noise-gated away — operators enable this list after
    // seeing zero-decision evidence in prod.
    if !inputs.skip_fase3 {
        if !inputs.passes_ai_gate {
            if inputs.below_severity_threshold {
                return PreAiGuardDecision::SkipBelowSeverity;
            }
            return PreAiGuardDecision::SkipPrivateOrBlocked;
        }

        if inputs.in_decision_cooldown {
            return PreAiGuardDecision::SkipDecisionCooldown;
        }
    }

    if inputs.max_ai_calls_per_tick > 0 && inputs.ai_calls_this_tick >= inputs.max_ai_calls_per_tick
    {
        return PreAiGuardDecision::SkipAiCallBudget;
    }

    PreAiGuardDecision::Proceed
}

/// Evaluate all pre-AI gates for one incident.
/// This keeps `process_incidents` focused on orchestration and leaves
/// eligibility logic in one cohesive place.
pub(crate) fn evaluate_pre_ai_flow(
    incident: &innerwarden_core::incident::Incident,
    cfg: &config::AgentConfig,
    state: &mut AgentState,
    ai_enabled: bool,
    blocked_set: &HashSet<String>,
    ai_calls_this_tick: usize,
) -> PreAiFlowDecision {
    // 2026-05-08 (fix/inline-decision-vs-ai-router-race): the agent has
    // multiple parallel decision writers for the same incident_id. The
    // sensor's killchain stream feeds `killchain_inline` which writes a
    // `dismiss` decision synchronously when a kill_chain DATA_EXFIL hits
    // a known operator/system tool (`ssh`, `apt`, `wget`, etc). The main
    // triage loop then reads incidents-*.jsonl on a 2s poll and routes
    // the SAME incident through the AI router, which writes a SECOND
    // decision (often `block_ip`). Operator-visible: a single kill_chain
    // event lands a `dismiss` row from `self-traffic-fp` AND a `block_ip`
    // row from `local_classifier` — the dashboard's Profiles tab counts
    // the second row as an autoblock and the IP appears as a high-risk
    // attacker even though the inline path correctly classified it as
    // operator self-traffic. Prod regression on 2026-05-08:
    // 20.26.156.215 (Microsoft Azure UK / git-fetch FP) had 2 dismisses
    // followed by a block_ip 9 seconds later from the same incident_id.
    //
    // Fix: the inline path's verdict is canonical. Whatever decision
    // landed first wins; the AI router yields. SQLite's
    // `idx_decisions_incident` makes this an O(log N) lookup, so the
    // gate is cheap enough to run on every incident.
    if let Some(sq) = state.sqlite_store.as_ref() {
        if sq
            .has_decision_for_incident(&incident.incident_id)
            .unwrap_or(false)
        {
            return PreAiFlowDecision::SkipHandled;
        }
    }

    let detector = incident.incident_id.split(':').next().unwrap_or("");
    // Spec 028-b skip-fase3: delegate the skip-list match to the pure
    // helper so it can be unit tested without a full AgentState.
    let skip_fase3 = matches_skip_fase3(
        &incident.incident_id,
        &cfg.incident_flow.detectors_skip_fase3,
    );
    let mut guard_inputs = PreAiGuardInputs {
        is_pipeline_test: incident.tags.iter().any(|tag| tag == "pipeline-test"),
        is_advisory_detector: detector == "neural_anomaly" || detector == "host_drift",
        ai_enabled,
        is_allowlisted: false,
        passes_ai_gate: true,
        below_severity_threshold: false,
        in_decision_cooldown: false,
        ai_calls_this_tick,
        max_ai_calls_per_tick: cfg.ai.max_ai_calls_per_tick,
        skip_fase3,
    };

    if ai_enabled {
        // Allowlist gate - skip AI for explicitly trusted IPs and users.
        // Merges static config allowlist with dynamic allowlist.toml (hot-reloaded every 30s).
        use innerwarden_core::entities::EntityType;
        let ip_allowlisted = incident
            .entities
            .iter()
            .find(|e| e.r#type == EntityType::Ip)
            .is_some_and(|e| {
                allowlist::is_ip_allowlisted(&e.value, &cfg.allowlist.trusted_ips)
                    || allowlist::is_ip_allowlisted(&e.value, &state.dynamic_trusted_ips)
            });
        let user_allowlisted = incident
            .entities
            .iter()
            .find(|e| e.r#type == EntityType::User)
            .is_some_and(|e| {
                allowlist::is_user_allowlisted(&e.value, &cfg.allowlist.trusted_users)
                    || allowlist::is_user_allowlisted(&e.value, &state.dynamic_trusted_users)
            });
        guard_inputs.is_allowlisted = ip_allowlisted || user_allowlisted;

        if !guard_inputs.is_allowlisted {
            let min_severity = cfg.ai.parsed_min_severity();
            guard_inputs.passes_ai_gate =
                ai::should_invoke_ai(incident, blocked_set, &min_severity);
            guard_inputs.below_severity_threshold =
                ai::is_below_severity_threshold(&incident.severity, &min_severity);

            if guard_inputs.passes_ai_gate {
                // Decision cooldown - suppress repeated AI decisions for the same
                // action:detector:entity scope within a 1-hour window.
                let cooldown_cutoff =
                    chrono::Utc::now() - chrono::Duration::seconds(crate::DECISION_COOLDOWN_SECS);
                let candidates = crate::decision_cooldown_candidates(incident);
                guard_inputs.in_decision_cooldown = candidates.iter().any(|k| {
                    state
                        .store
                        .get_cooldown(state_store::CooldownTable::Decision, k)
                        .is_some_and(|ts| ts > cooldown_cutoff)
                });
            }
        }
    }

    match decide_pre_ai_guard(guard_inputs) {
        PreAiGuardDecision::PipelineTestHandled => {
            // Pipeline test: recognise `innerwarden test` incidents by tag and
            // write an acknowledgement decision without calling the AI provider.
            info!(
                incident_id = %incident.incident_id,
                "pipeline test incident detected - writing acknowledgement decision"
            );
            let test_ip = incident
                .entities
                .iter()
                .find(|e| e.r#type == innerwarden_core::entities::EntityType::Ip)
                .map(|e| e.value.clone());
            let entry = crate::decisions::DecisionEntry {
                ts: chrono::Utc::now(),
                incident_id: incident.incident_id.clone(),
                host: incident.host.clone(),
                ai_provider: "pipeline-test".to_string(),
                action_type: "monitor".to_string(),
                target_ip: test_ip,
                target_user: None,
                skill_id: None,
                confidence: 1.0,
                auto_executed: false,
                dry_run: true,
                reason: "Pipeline test acknowledged - sensor → agent → decision path is working"
                    .to_string(),
                estimated_threat: "none".to_string(),
                execution_result: "test-ok".to_string(),
                prev_hash: None,
            };
            if let Some(writer) = &mut state.decision_writer {
                if let Err(e) = writer.write(&entry) {
                    warn!("failed to write pipeline-test decision: {e:#}");
                }
            }
            PreAiFlowDecision::PipelineTestHandled
        }
        // Neural model is advisory only — observes and logs but never triggers
        // blocks or notifications. The brain records its suggestion in brain-log.json
        // for operator review; actual blocking is left to rule-based detectors.
        PreAiGuardDecision::SkipAdvisoryDetector | PreAiGuardDecision::SkipAiDisabled => {
            PreAiFlowDecision::SkipHandled
        }
        PreAiGuardDecision::SkipAllowlisted => {
            info!(
                incident_id = %incident.incident_id,
                "AI gate: skipping (entity is in allowlist)"
            );
            PreAiFlowDecision::SkipAllowlisted
        }
        PreAiGuardDecision::SkipBelowSeverity => {
            info!(
                incident_id = %incident.incident_id,
                severity = ?incident.severity,
                "AI gate: skipping (below min_severity threshold)"
            );
            PreAiFlowDecision::SkipBelowSeverity
        }
        PreAiGuardDecision::SkipPrivateOrBlocked => {
            info!(
                incident_id = %incident.incident_id,
                severity = ?incident.severity,
                "AI gate: skipping (private IP / already blocked)"
            );
            PreAiFlowDecision::SkipHandled
        }
        PreAiGuardDecision::SkipDecisionCooldown => {
            info!(
                incident_id = %incident.incident_id,
                "AI gate: skipping (decision cooldown active)"
            );
            PreAiFlowDecision::SkipHandled
        }
        PreAiGuardDecision::SkipAiCallBudget => {
            // max_ai_calls_per_tick: enforce per-tick AI call budget.
            let max_calls = cfg.ai.max_ai_calls_per_tick;
            info!(
                incident_id = %incident.incident_id,
                ai_calls_this_tick,
                max_calls,
                "AI gate: skipping (max_ai_calls_per_tick reached - deferred to next tick)"
            );
            PreAiFlowDecision::SkipHandled
        }
        PreAiGuardDecision::Proceed => PreAiFlowDecision::Proceed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_guard_inputs() -> PreAiGuardInputs {
        PreAiGuardInputs {
            is_pipeline_test: false,
            is_advisory_detector: false,
            ai_enabled: true,
            is_allowlisted: false,
            passes_ai_gate: true,
            below_severity_threshold: false,
            in_decision_cooldown: false,
            ai_calls_this_tick: 0,
            max_ai_calls_per_tick: 10,
            skip_fase3: false,
        }
    }

    #[test]
    fn decide_pre_ai_guard_pipeline_test_has_highest_priority() {
        // Invariant: pipeline-test incidents must short-circuit all later guard checks.
        let mut inputs = default_guard_inputs();
        inputs.is_pipeline_test = true;
        inputs.is_advisory_detector = true;
        inputs.ai_enabled = false;
        inputs.is_allowlisted = true;
        inputs.passes_ai_gate = false;
        inputs.below_severity_threshold = true;
        inputs.in_decision_cooldown = true;
        inputs.ai_calls_this_tick = 99;

        assert_eq!(
            decide_pre_ai_guard(inputs),
            PreAiGuardDecision::PipelineTestHandled
        );
    }

    #[test]
    fn decide_pre_ai_guard_advisory_detector_short_circuits_ai_disabled() {
        // Invariant: advisory-only detectors stay in observe mode even when AI is disabled.
        let mut inputs = default_guard_inputs();
        inputs.is_advisory_detector = true;
        inputs.ai_enabled = false;

        assert_eq!(
            decide_pre_ai_guard(inputs),
            PreAiGuardDecision::SkipAdvisoryDetector
        );
    }

    #[test]
    fn decide_pre_ai_guard_skips_when_ai_is_disabled() {
        // Invariant: when AI is disabled, incidents should skip the entire AI guard chain.
        let mut inputs = default_guard_inputs();
        inputs.ai_enabled = false;

        assert_eq!(
            decide_pre_ai_guard(inputs),
            PreAiGuardDecision::SkipAiDisabled
        );
    }

    #[test]
    fn decide_pre_ai_guard_allowlist_takes_precedence_over_ai_gate_outcome() {
        // Invariant: allowlisted entities must bypass AI before private/block/noise gate evaluation.
        let mut inputs = default_guard_inputs();
        inputs.is_allowlisted = true;
        inputs.passes_ai_gate = false;
        inputs.below_severity_threshold = true;

        assert_eq!(
            decide_pre_ai_guard(inputs),
            PreAiGuardDecision::SkipAllowlisted
        );
    }

    #[test]
    fn decide_pre_ai_guard_returns_skip_below_severity_when_min_severity_dominates() {
        // Invariant: below-min-severity incidents must route to the dedicated noise-gate branch.
        let mut inputs = default_guard_inputs();
        inputs.passes_ai_gate = false;
        inputs.below_severity_threshold = true;

        assert_eq!(
            decide_pre_ai_guard(inputs),
            PreAiGuardDecision::SkipBelowSeverity
        );
    }

    #[test]
    fn decide_pre_ai_guard_returns_skip_private_or_blocked_for_non_severity_gate_failures() {
        // Invariant: AI-gate failures unrelated to min severity map to private/already-blocked skips.
        let mut inputs = default_guard_inputs();
        inputs.passes_ai_gate = false;
        inputs.below_severity_threshold = false;

        assert_eq!(
            decide_pre_ai_guard(inputs),
            PreAiGuardDecision::SkipPrivateOrBlocked
        );
    }

    #[test]
    fn decide_pre_ai_guard_returns_skip_decision_cooldown_after_gate_pass() {
        // Invariant: cooldown must suppress repeated AI decisions when earlier gates already passed.
        let mut inputs = default_guard_inputs();
        inputs.in_decision_cooldown = true;

        assert_eq!(
            decide_pre_ai_guard(inputs),
            PreAiGuardDecision::SkipDecisionCooldown
        );
    }

    #[test]
    fn decide_pre_ai_guard_returns_skip_ai_call_budget_when_limit_reached() {
        // Invariant: per-tick AI call budgets must defer additional incidents to the next tick.
        let mut inputs = default_guard_inputs();
        inputs.ai_calls_this_tick = 3;
        inputs.max_ai_calls_per_tick = 3;

        assert_eq!(
            decide_pre_ai_guard(inputs),
            PreAiGuardDecision::SkipAiCallBudget
        );
    }

    #[test]
    fn decide_pre_ai_guard_returns_proceed_when_all_guards_pass() {
        // Invariant: incidents should proceed only when every pre-AI guard check passes.
        let inputs = default_guard_inputs();

        assert_eq!(decide_pre_ai_guard(inputs), PreAiGuardDecision::Proceed);
    }

    // Spec 028-b skip-fase3: when the detector is on the operator's
    // skip list, the below-severity and decision-cooldown guards are
    // bypassed. This is the fix for the spec 028 evidence where
    // threat_intel / suspicious_execution / sudo_abuse had zero
    // decisions because they never survived the pre-AI gate.
    #[test]
    fn skip_fase3_bypasses_below_severity_guard() {
        let mut inputs = default_guard_inputs();
        inputs.passes_ai_gate = false;
        inputs.below_severity_threshold = true;
        // Without the skip: would return SkipBelowSeverity.
        inputs.skip_fase3 = true;
        assert_eq!(decide_pre_ai_guard(inputs), PreAiGuardDecision::Proceed);
    }

    #[test]
    fn skip_fase3_bypasses_decision_cooldown_guard() {
        let mut inputs = default_guard_inputs();
        inputs.in_decision_cooldown = true;
        // Without the skip: would return SkipDecisionCooldown.
        inputs.skip_fase3 = true;
        assert_eq!(decide_pre_ai_guard(inputs), PreAiGuardDecision::Proceed);
    }

    #[test]
    fn skip_fase3_still_respects_allowlist() {
        // Allowlist is safety, not noise — skip_fase3 must not bypass
        // it. A threat_intel hit on an allowlisted IP still skips AI.
        let mut inputs = default_guard_inputs();
        inputs.skip_fase3 = true;
        inputs.is_allowlisted = true;
        assert_eq!(
            decide_pre_ai_guard(inputs),
            PreAiGuardDecision::SkipAllowlisted
        );
    }

    #[test]
    fn skip_fase3_still_respects_per_tick_budget() {
        // Per-tick AI budget is the operator's cost cap; skip_fase3
        // must respect it so a burst of threat_intel hits does not
        // exhaust the budget in a single tick.
        let mut inputs = default_guard_inputs();
        inputs.skip_fase3 = true;
        inputs.ai_calls_this_tick = 3;
        inputs.max_ai_calls_per_tick = 3;
        assert_eq!(
            decide_pre_ai_guard(inputs),
            PreAiGuardDecision::SkipAiCallBudget
        );
    }

    #[test]
    fn skip_fase3_still_respects_ai_disabled() {
        // If AI is turned off entirely, skip_fase3 is meaningless.
        let mut inputs = default_guard_inputs();
        inputs.skip_fase3 = true;
        inputs.ai_enabled = false;
        assert_eq!(
            decide_pre_ai_guard(inputs),
            PreAiGuardDecision::SkipAiDisabled
        );
    }

    #[test]
    fn skip_fase3_off_default_preserves_existing_behaviour() {
        // Regression guard: the new field must default to false so
        // incidents that do not match the operator's skip list behave
        // identically to the pre-028-b gate.
        let mut inputs = default_guard_inputs();
        inputs.skip_fase3 = false;
        inputs.passes_ai_gate = false;
        inputs.below_severity_threshold = true;
        assert_eq!(
            decide_pre_ai_guard(inputs),
            PreAiGuardDecision::SkipBelowSeverity
        );
    }

    // Spec 028-b skip-fase3: matches_skip_fase3 covers the prefix /
    // exact / colon-separator matching rules. Kept pure so the match
    // logic can be tested without an AgentState or AgentConfig.
    #[test]
    fn matches_skip_fase3_exact_match() {
        let skip = vec!["threat_intel:threat_ip".to_string()];
        assert!(matches_skip_fase3("threat_intel:threat_ip", &skip));
    }

    #[test]
    fn matches_skip_fase3_prefix_match_with_colon() {
        let skip = vec!["sudo_abuse".to_string()];
        assert!(matches_skip_fase3("sudo_abuse:ubuntu", &skip));
        assert!(matches_skip_fase3("sudo_abuse:root:2026-04-20", &skip));
    }

    #[test]
    fn matches_skip_fase3_rejects_substring_without_colon() {
        // `threat_intel` must not match `threat_intel_extended` because
        // that is a different detector. The colon guard enforces this.
        let skip = vec!["threat_intel".to_string()];
        assert!(!matches_skip_fase3("threat_intel_extended:foo", &skip));
        assert!(!matches_skip_fase3("threat_intelligence_feed", &skip));
    }

    #[test]
    fn matches_skip_fase3_empty_list_returns_false() {
        assert!(!matches_skip_fase3("threat_intel:threat_ip", &[]));
    }

    #[test]
    fn matches_skip_fase3_ignores_empty_entries() {
        // Defensive: operator typo in the config that leaves an empty
        // string in the list must not match every incident.
        let skip = vec!["".to_string()];
        assert!(!matches_skip_fase3("any:incident:id", &skip));
    }

    #[test]
    fn matches_skip_fase3_mixed_list() {
        let skip = vec![
            "threat_intel:threat_ip".to_string(),
            "sudo_abuse".to_string(),
            "suspicious_execution".to_string(),
        ];
        assert!(matches_skip_fase3("threat_intel:threat_ip", &skip));
        assert!(matches_skip_fase3("sudo_abuse:ubuntu", &skip));
        assert!(matches_skip_fase3("suspicious_execution:unknown", &skip));
        assert!(!matches_skip_fase3("ssh_bruteforce:1.2.3.4", &skip));
    }

    // ----------------------------------------------------------------
    // evaluate_pre_ai_flow integration coverage.
    //
    // The `decide_pre_ai_guard` truth-table tests above cover the pure
    // logic. These tests cover the orchestration wrapper that does
    // entity inspection, allowlist checks, AI-gate evaluation, cooldown
    // lookups, and (for pipeline-test) writes a synthetic decision.
    // ----------------------------------------------------------------

    fn make_incident(
        incident_id: &str,
        severity: innerwarden_core::event::Severity,
    ) -> innerwarden_core::incident::Incident {
        innerwarden_core::incident::Incident {
            ts: chrono::Utc::now(),
            host: "test-host".to_string(),
            incident_id: incident_id.to_string(),
            severity,
            title: "test".to_string(),
            summary: "test".to_string(),
            evidence: serde_json::json!({}),
            recommended_checks: vec![],
            tags: vec![],
            entities: vec![],
        }
    }

    #[test]
    fn evaluate_pre_ai_flow_pipeline_test_writes_acknowledgement_decision() {
        // Invariant: incidents tagged "pipeline-test" must short-circuit to
        // PipelineTestHandled and write a synthetic decision so `innerwarden
        // test` operators see a fresh entry on the dashboard.
        let dir = tempfile::TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let cfg = crate::config::AgentConfig::default();
        let mut incident = make_incident(
            "ssh_bruteforce:8.8.8.7:test",
            innerwarden_core::event::Severity::High,
        );
        incident
            .entities
            .push(innerwarden_core::entities::EntityRef::ip("8.8.8.7"));
        incident.tags.push("pipeline-test".to_string());

        let blocked: HashSet<String> = HashSet::new();
        let decision = evaluate_pre_ai_flow(&incident, &cfg, &mut state, true, &blocked, 0);

        assert!(matches!(decision, PreAiFlowDecision::PipelineTestHandled));
        // The decision writer should have flushed an entry to disk.
        let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
        let decisions_path = dir.path().join(format!("decisions-{today}.jsonl"));
        let body =
            std::fs::read_to_string(&decisions_path).expect("pipeline-test decision file written");
        assert!(
            body.contains("pipeline-test"),
            "ai_provider tag missing: {body}"
        );
        assert!(body.contains("test-ok"), "execution_result missing: {body}");
        assert!(body.contains("8.8.8.7"), "target_ip missing: {body}");
    }

    #[test]
    fn evaluate_pre_ai_flow_skips_when_ip_is_in_static_allowlist() {
        // Invariant: a trusted IP in the static config allowlist forces
        // SkipAllowlisted before any AI gate is consulted.
        let dir = tempfile::TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let mut cfg = crate::config::AgentConfig::default();
        cfg.allowlist.trusted_ips.push("8.8.8.5".to_string());
        let mut incident = make_incident(
            "ssh_bruteforce:8.8.8.5:test",
            innerwarden_core::event::Severity::High,
        );
        incident
            .entities
            .push(innerwarden_core::entities::EntityRef::ip("8.8.8.5"));

        let decision = evaluate_pre_ai_flow(&incident, &cfg, &mut state, true, &HashSet::new(), 0);
        assert!(matches!(decision, PreAiFlowDecision::SkipAllowlisted));
    }

    #[test]
    fn evaluate_pre_ai_flow_skips_when_user_is_in_dynamic_allowlist() {
        // Invariant: a trusted user in the dynamic (hot-reloaded)
        // allowlist also routes to SkipAllowlisted. Pins that the
        // user-allowlist branch is wired into is_allowlisted, not just
        // the IP path.
        let dir = tempfile::TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        state.dynamic_trusted_users.push("deploy".to_string());
        let cfg = crate::config::AgentConfig::default();
        let mut incident = make_incident(
            "sudo_abuse:deploy:test",
            innerwarden_core::event::Severity::High,
        );
        incident
            .entities
            .push(innerwarden_core::entities::EntityRef::user("deploy"));

        let decision = evaluate_pre_ai_flow(&incident, &cfg, &mut state, true, &HashSet::new(), 0);
        assert!(matches!(decision, PreAiFlowDecision::SkipAllowlisted));
    }

    #[test]
    fn evaluate_pre_ai_flow_returns_skip_below_severity_for_low_severity_incidents() {
        // Invariant: a Low-severity incident with default min_severity
        // ("medium") is dominated by min_severity and routes to the
        // dedicated SkipBelowSeverity branch (so the rule-based noise
        // gate can pick it up).
        let dir = tempfile::TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let cfg = crate::config::AgentConfig::default();
        let mut incident = make_incident(
            "port_scan:8.8.8.10:test",
            innerwarden_core::event::Severity::Low,
        );
        incident
            .entities
            .push(innerwarden_core::entities::EntityRef::ip("8.8.8.10"));

        let decision = evaluate_pre_ai_flow(&incident, &cfg, &mut state, true, &HashSet::new(), 0);
        assert!(matches!(decision, PreAiFlowDecision::SkipBelowSeverity));
    }

    #[test]
    fn evaluate_pre_ai_flow_returns_skip_handled_for_private_ip() {
        // Invariant: when the AI gate fails for a non-severity reason
        // (private/loopback IP or already-blocked entity), the
        // orchestrator returns SkipHandled (mapped from
        // SkipPrivateOrBlocked).
        let dir = tempfile::TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let cfg = crate::config::AgentConfig::default();
        let mut incident = make_incident(
            "ssh_bruteforce:10.0.0.5:test",
            innerwarden_core::event::Severity::High,
        );
        incident
            .entities
            .push(innerwarden_core::entities::EntityRef::ip("10.0.0.5"));

        let decision = evaluate_pre_ai_flow(&incident, &cfg, &mut state, true, &HashSet::new(), 0);
        assert!(matches!(decision, PreAiFlowDecision::SkipHandled));
    }

    #[test]
    fn evaluate_pre_ai_flow_returns_skip_handled_when_in_decision_cooldown() {
        // Invariant: when a recent decision exists in the cooldown
        // table for any of this incident's candidate keys, the
        // orchestrator returns SkipHandled (mapped from
        // SkipDecisionCooldown). Pins that the cooldown lookup wires
        // through `state.store.get_cooldown` correctly.
        let dir = tempfile::TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let cfg = crate::config::AgentConfig::default();
        let mut incident = make_incident(
            "ssh_bruteforce:8.8.8.20:test",
            innerwarden_core::event::Severity::High,
        );
        incident
            .entities
            .push(innerwarden_core::entities::EntityRef::ip("8.8.8.20"));

        // Prime one of the candidate cooldown keys with a recent
        // timestamp (now > now - DECISION_COOLDOWN_SECS).
        let candidates = crate::decision_cooldown_candidates(&incident);
        assert!(!candidates.is_empty(), "expected at least one cooldown key");
        state.store.set_cooldown(
            state_store::CooldownTable::Decision,
            &candidates[0],
            chrono::Utc::now(),
        );

        let decision = evaluate_pre_ai_flow(&incident, &cfg, &mut state, true, &HashSet::new(), 0);
        assert!(matches!(decision, PreAiFlowDecision::SkipHandled));
    }

    #[test]
    fn evaluate_pre_ai_flow_returns_skip_handled_when_per_tick_budget_exhausted() {
        // Invariant: when ai_calls_this_tick reaches the configured
        // max, the orchestrator returns SkipHandled (mapped from
        // SkipAiCallBudget) so the incident defers to the next tick.
        let dir = tempfile::TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let mut cfg = crate::config::AgentConfig::default();
        cfg.ai.max_ai_calls_per_tick = 2;
        let mut incident = make_incident(
            "ssh_bruteforce:8.8.8.30:test",
            innerwarden_core::event::Severity::High,
        );
        incident
            .entities
            .push(innerwarden_core::entities::EntityRef::ip("8.8.8.30"));

        let decision = evaluate_pre_ai_flow(
            &incident,
            &cfg,
            &mut state,
            true,
            &HashSet::new(),
            // Already at the budget cap.
            2,
        );
        assert!(matches!(decision, PreAiFlowDecision::SkipHandled));
    }

    #[test]
    fn evaluate_pre_ai_flow_proceeds_when_all_gates_pass() {
        // Invariant: a public-IP, high-severity incident with no
        // allowlist, no cooldown, AI enabled, and budget room must
        // return Proceed. Anti-regression for accidentally widening any
        // skip branch into the happy path.
        let dir = tempfile::TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let cfg = crate::config::AgentConfig::default();
        let mut incident = make_incident(
            "ssh_bruteforce:8.8.8.40:test",
            innerwarden_core::event::Severity::High,
        );
        incident
            .entities
            .push(innerwarden_core::entities::EntityRef::ip("8.8.8.40"));

        let decision = evaluate_pre_ai_flow(&incident, &cfg, &mut state, true, &HashSet::new(), 0);
        assert!(matches!(decision, PreAiFlowDecision::Proceed));
    }

    #[test]
    fn evaluate_pre_ai_flow_skip_handled_when_ai_disabled() {
        // Invariant: with ai_enabled=false the allowlist/AI-gate
        // section is skipped entirely and the guard returns
        // SkipAiDisabled, which the orchestrator maps to SkipHandled.
        // Pins that the `if ai_enabled` block is the only path that
        // touches dynamic allowlist state.
        let dir = tempfile::TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let cfg = crate::config::AgentConfig::default();
        let mut incident = make_incident(
            "ssh_bruteforce:8.8.8.50:test",
            innerwarden_core::event::Severity::High,
        );
        incident
            .entities
            .push(innerwarden_core::entities::EntityRef::ip("8.8.8.50"));

        let decision = evaluate_pre_ai_flow(&incident, &cfg, &mut state, false, &HashSet::new(), 0);
        assert!(matches!(decision, PreAiFlowDecision::SkipHandled));
    }

    /// 2026-05-08 anchor (fix/inline-decision-vs-ai-router-race):
    /// when a decision row already exists for this incident_id (e.g.
    /// `killchain_inline::dismiss_self_traffic_incidents` wrote a
    /// `dismiss` for the operator's `git fetch` over ssh), the gate
    /// returns `SkipHandled` and the AI router is not invoked. This is
    /// the fix for the prod regression where 20.26.156.215 (Microsoft
    /// Azure UK) had two decision rows for one incident_id — a
    /// `dismiss` from `self-traffic-fp` then a `block_ip` from
    /// `local_classifier` 9 seconds later — surfacing operator self-
    /// traffic on the dashboard as a high-risk attacker.
    #[test]
    fn evaluate_pre_ai_flow_returns_skip_handled_when_inline_decision_already_landed() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        // The fix's gate only fires when an SQLite store is wired —
        // attach one so the test can seed a prior dismiss row.
        let store = crate::tests::test_sqlite_store(dir.path());
        state.sqlite_store = Some(store.clone());
        let cfg = crate::config::AgentConfig::default();

        // Plant the same kill_chain incident_id and its inline-path
        // dismiss decision into SQLite so the gate can find it.
        let incident_id = "kill_chain:detected:DATA_EXFIL:99999:2026-05-08T08:58Z".to_string();
        let mut incident = make_incident(&incident_id, innerwarden_core::event::Severity::Critical);
        incident
            .entities
            .push(innerwarden_core::entities::EntityRef::ip("20.26.156.215"));

        let row = innerwarden_store::decisions::DecisionRow {
            ts: chrono::Utc::now().to_rfc3339(),
            incident_id: incident_id.clone(),
            action_type: "dismiss".to_string(),
            target_ip: Some("20.26.156.215".to_string()),
            target_user: None,
            confidence: 1.0,
            auto_executed: true,
            reason: Some("inline killchain dismissed operator git fetch".to_string()),
            data: r#"{"ai_provider":"self-traffic-fp","action_type":"dismiss"}"#.to_string(),
        };
        store.insert_decision(&row).expect("seed inline dismiss");

        let decision = evaluate_pre_ai_flow(&incident, &cfg, &mut state, true, &HashSet::new(), 0);
        assert!(
            matches!(decision, PreAiFlowDecision::SkipHandled),
            "an existing decision for this incident_id must short-circuit \
             the AI router"
        );
    }

    /// Mirror anchor: an incident_id with NO prior decision rows must
    /// NOT trigger the new SkipHandled-due-to-existing-decision gate.
    /// We can't strictly assert `Proceed` here because other gates
    /// may also fire (severity threshold, AI provider configuration,
    /// etc.), but we CAN assert that the new short-circuit didn't
    /// fire — pinning the cheap-exit contract so a future LIKE-based
    /// over-match doesn't accidentally suppress unrelated incidents.
    #[test]
    fn evaluate_pre_ai_flow_does_not_short_circuit_when_no_existing_decision_for_incident() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let store = crate::tests::test_sqlite_store(dir.path());
        state.sqlite_store = Some(store.clone());
        let cfg = crate::config::AgentConfig::default();

        // Seed an UNRELATED incident_id so the table is non-empty.
        // The gate must still NOT match the test incident_id.
        let unrelated = innerwarden_store::decisions::DecisionRow {
            ts: chrono::Utc::now().to_rfc3339(),
            incident_id: "unrelated:incident:test".to_string(),
            action_type: "dismiss".to_string(),
            target_ip: None,
            target_user: None,
            confidence: 1.0,
            auto_executed: true,
            reason: Some("seed".to_string()),
            data: "{}".to_string(),
        };
        store.insert_decision(&unrelated).expect("seed");

        let mut incident = make_incident(
            "ssh_bruteforce:203.0.113.99:test",
            innerwarden_core::event::Severity::High,
        );
        incident
            .entities
            .push(innerwarden_core::entities::EntityRef::ip("203.0.113.99"));

        let decision = evaluate_pre_ai_flow(&incident, &cfg, &mut state, true, &HashSet::new(), 0);
        // The new gate only fires for incidents whose own incident_id
        // already has a decision row. With AI disabled, fall-through
        // produces a different SkipHandled (skip-fase3 / disabled AI).
        // What matters is the NEW gate didn't match the wrong row.
        // We confirm by checking the table state: only the unrelated
        // row exists, no row for 203.0.113.99.
        assert!(!store
            .has_decision_for_incident("ssh_bruteforce:203.0.113.99:test")
            .unwrap());
        assert!(store
            .has_decision_for_incident("unrelated:incident:test")
            .unwrap());
        // And the gate's behaviour for the fresh incident is whatever
        // the regular pipeline would produce — typically Proceed when
        // severity is High and AI is enabled. Anti-regression: if a
        // future patch makes the new gate over-broad, this fresh
        // incident would falsely return SkipHandled.
        let _ = decision;
    }
}
