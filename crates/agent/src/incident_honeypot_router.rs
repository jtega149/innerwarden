use std::collections::HashSet;
use std::path::Path;

use tracing::{info, warn};

use crate::{
    ai, allowlist, config, decision_cooldown_key_for_decision, decisions, execute_decision,
    state_store, AgentState,
};

/// Honeypot smart routing gate: route selected attackers to honeypot listener
/// instead of immediate block to collect more intelligence.
/// Returns true when the incident is fully handled by this gate.
pub(crate) async fn try_handle_honeypot_routing(
    incident: &innerwarden_core::incident::Incident,
    data_dir: &Path,
    cfg: &config::AgentConfig,
    state: &mut AgentState,
    blocked_set: &HashSet<String>,
) -> bool {
    if cfg.honeypot.mode != "listener" || !cfg.responder.enabled {
        return false;
    }

    let detector = detector_from_incident_id(&incident.incident_id);
    let primary_ip = primary_ip_from_incident(incident);
    let Some(ip) = primary_ip else {
        return false;
    };

    let is_new_attacker = !state.blocklist.contains(&ip)
        && !blocked_set.contains(&ip)
        && state.store.get_block_count(&ip) == 0;

    // suspicious_login = brute-force followed by success -> HIGH VALUE.
    // Route to honeypot to observe what they do with access.
    let should_honeypot = should_route_to_honeypot(
        detector,
        is_new_attacker,
        allowlist::is_ip_allowlisted(&ip, &cfg.ai.protected_ips),
        &ip,
    );

    if !should_honeypot {
        return false;
    }

    info!(
        incident_id = %incident.incident_id,
        ip,
        detector,
        "honeypot routing: interesting attacker -> redirecting to honeypot"
    );

    let honeypot_decision = ai::AiDecision {
        action: ai::AiAction::Honeypot { ip: ip.clone() },
        confidence: 0.95,
        auto_execute: true,
        reason: format!(
            "Smart routing: {} - interesting attacker redirected to honeypot for intel gathering",
            detector
        ),
        alternatives: vec![],
        estimated_threat: "high".into(),
    };

    if let Some(key) = decision_cooldown_key_for_decision(incident, &honeypot_decision) {
        state.store.set_cooldown(
            state_store::CooldownTable::Decision,
            &key,
            chrono::Utc::now(),
        );
    }

    let (execution_result, _) = if cfg.responder.enabled {
        execute_decision(&honeypot_decision, incident, data_dir, cfg, state).await
    } else {
        ("skipped: responder disabled".to_string(), false)
    };

    if let Some(writer) = &mut state.decision_writer {
        let entry = decisions::build_entry(
            &incident.incident_id,
            &incident.host,
            "honeypot-router",
            &honeypot_decision,
            cfg.responder.dry_run,
            &execution_result,
        );
        if let Err(e) = writer.write(&entry) {
            warn!("failed to write honeypot routing decision: {e:#}");
        }
    }

    true
}

fn detector_from_incident_id(incident_id: &str) -> &str {
    incident_id.split(':').next().unwrap_or("")
}

fn primary_ip_from_incident(incident: &innerwarden_core::incident::Incident) -> Option<String> {
    incident
        .entities
        .iter()
        .find(|e| e.r#type == innerwarden_core::entities::EntityType::Ip)
        .map(|e| e.value.clone())
}

fn should_route_to_honeypot(
    detector: &str,
    is_new_attacker: bool,
    is_allowlisted: bool,
    ip: &str,
) -> bool {
    (detector == "suspicious_login" && is_new_attacker)
        || (detector == "ssh_bruteforce"
            && is_new_attacker
            && !is_allowlisted
            && should_sample_ssh_attacker_for_honeypot(ip))
}

fn should_sample_ssh_attacker_for_honeypot(ip: &str) -> bool {
    ip.as_bytes().last().copied().unwrap_or(0) % 5 == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::skills::SkillRegistry;
    use innerwarden_core::{entities::EntityRef, event::Severity, incident::Incident};

    fn sample_incident(incident_id: &str, entities: Vec<EntityRef>) -> Incident {
        Incident {
            ts: chrono::Utc::now(),
            host: "host".to_string(),
            incident_id: incident_id.to_string(),
            severity: Severity::High,
            title: "title".to_string(),
            summary: "summary".to_string(),
            evidence: serde_json::json!({}),
            recommended_checks: vec![],
            tags: vec![],
            entities,
        }
    }

    /// Builds an `AgentConfig` wired so `try_handle_honeypot_routing` enters its
    /// active branch (mode = "listener" + responder enabled). Tests that want
    /// the early-return branch override these afterwards.
    fn listener_config() -> crate::config::AgentConfig {
        let mut cfg = crate::config::AgentConfig::default();
        cfg.honeypot.mode = "listener".to_string();
        cfg.responder.enabled = true;
        cfg.responder.dry_run = true;
        cfg
    }

    #[test]
    fn detector_from_incident_id_uses_prefix_before_colon() {
        // Ensures detector routing stays aligned with incident-id naming convention.
        assert_eq!(
            detector_from_incident_id("suspicious_login:2026-04-17"),
            "suspicious_login"
        );
        assert_eq!(
            detector_from_incident_id("ssh_bruteforce"),
            "ssh_bruteforce"
        );
    }

    #[test]
    fn primary_ip_from_incident_returns_ip_entity_only() {
        // Verifies honeypot routing only uses canonical IP entities as routing targets.
        let incident = sample_incident(
            "ssh_bruteforce:1",
            vec![EntityRef::user("alice"), EntityRef::ip("203.0.113.10")],
        );
        assert_eq!(
            primary_ip_from_incident(&incident),
            Some("203.0.113.10".to_string())
        );
    }

    #[test]
    fn should_route_to_honeypot_prioritizes_new_suspicious_login_attackers() {
        // Covers high-value suspicious-login branch that always routes new attackers to honeypot.
        assert!(should_route_to_honeypot(
            "suspicious_login",
            true,
            false,
            "198.51.100.21"
        ));
        assert!(!should_route_to_honeypot(
            "suspicious_login",
            false,
            false,
            "198.51.100.21"
        ));
    }

    #[test]
    fn should_route_to_honeypot_samples_ssh_attackers_and_respects_allowlist() {
        // Ensures SSH routing keeps the 20% sampling behavior and never routes allowlisted IPs.
        assert!(should_route_to_honeypot(
            "ssh_bruteforce",
            true,
            false,
            "203.0.113.102"
        ));
        assert!(!should_route_to_honeypot(
            "ssh_bruteforce",
            true,
            true,
            "203.0.113.102"
        ));
        assert!(!should_route_to_honeypot(
            "ssh_bruteforce",
            true,
            false,
            "203.0.113.101"
        ));
    }

    #[tokio::test]
    async fn try_handle_honeypot_routing_short_circuits_when_mode_is_not_listener() {
        // The smart-routing gate must be a no-op outside `mode = "listener"` so
        // demo/always_on deploys never have decisions silently rewritten.
        let dir = tempfile::tempdir().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let mut cfg = listener_config();
        cfg.honeypot.mode = "demo".to_string();
        let incident = sample_incident("suspicious_login:1", vec![EntityRef::ip("198.51.100.50")]);
        let blocked: HashSet<String> = HashSet::new();

        let handled =
            try_handle_honeypot_routing(&incident, dir.path(), &cfg, &mut state, &blocked).await;

        assert!(!handled, "non-listener mode must return false");
    }

    #[tokio::test]
    async fn try_handle_honeypot_routing_short_circuits_when_responder_disabled() {
        // Mode-only opt-in is not enough: the router must also see
        // `responder.enabled` so a passive (alert-only) deploy never executes
        // the honeypot decision.
        let dir = tempfile::tempdir().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let mut cfg = listener_config();
        cfg.responder.enabled = false;
        let incident = sample_incident("suspicious_login:1", vec![EntityRef::ip("198.51.100.50")]);
        let blocked: HashSet<String> = HashSet::new();

        let handled =
            try_handle_honeypot_routing(&incident, dir.path(), &cfg, &mut state, &blocked).await;

        assert!(!handled, "responder-disabled deploy must return false");
    }

    #[tokio::test]
    async fn try_handle_honeypot_routing_returns_false_when_incident_has_no_ip_entity() {
        // Incident-without-IP path: the gate must bail before building any
        // decision — the original bug class is "synthetic decision built for an
        // incident that has no routable target".
        let dir = tempfile::tempdir().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let cfg = listener_config();
        let incident = sample_incident("suspicious_login:1", vec![EntityRef::user("alice")]);
        let blocked: HashSet<String> = HashSet::new();

        let handled =
            try_handle_honeypot_routing(&incident, dir.path(), &cfg, &mut state, &blocked).await;

        assert!(!handled, "absent IP entity must short-circuit the router");
    }

    #[tokio::test]
    async fn try_handle_honeypot_routing_returns_false_for_already_blocked_attacker() {
        // Operator invariant: an IP already on the in-memory blocklist is NOT
        // a "new attacker", so even a high-value detector must not redirect the
        // session to the honeypot (we already know about them, going to block).
        let dir = tempfile::tempdir().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let cfg = listener_config();
        // Prime the in-memory blocklist so `is_new_attacker` evaluates to false.
        state.blocklist.insert("198.51.100.99".to_string());
        let incident = sample_incident(
            "suspicious_login:test",
            vec![EntityRef::ip("198.51.100.99")],
        );
        let blocked: HashSet<String> = HashSet::new();

        let handled =
            try_handle_honeypot_routing(&incident, dir.path(), &cfg, &mut state, &blocked).await;

        assert!(!handled, "previously-blocked IP must not be re-routed");
    }

    #[tokio::test]
    async fn try_handle_honeypot_routing_returns_false_when_caller_blocked_set_already_contains_ip()
    {
        // The `blocked_set` parameter mirrors the caller's per-tick already-acted
        // bag. A hit there must still suppress routing even when the persistent
        // blocklist is empty (covers the OR branch of `is_new_attacker`).
        let dir = tempfile::tempdir().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let cfg = listener_config();
        let incident = sample_incident(
            "suspicious_login:test",
            vec![EntityRef::ip("198.51.100.77")],
        );
        let mut blocked: HashSet<String> = HashSet::new();
        blocked.insert("198.51.100.77".to_string());

        let handled =
            try_handle_honeypot_routing(&incident, dir.path(), &cfg, &mut state, &blocked).await;

        assert!(!handled, "blocked_set hit must short-circuit the router");
    }

    #[tokio::test]
    async fn try_handle_honeypot_routing_returns_false_when_router_declines_detector() {
        // Detector that is neither `suspicious_login` nor `ssh_bruteforce` must
        // fall through `should_route_to_honeypot` and never trigger the active
        // branch (otherwise unrelated detectors like web_scan would steal a
        // honeypot slot).
        let dir = tempfile::tempdir().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let cfg = listener_config();
        let incident = sample_incident("web_scan:test", vec![EntityRef::ip("198.51.100.40")]);
        let blocked: HashSet<String> = HashSet::new();

        let handled =
            try_handle_honeypot_routing(&incident, dir.path(), &cfg, &mut state, &blocked).await;

        assert!(!handled, "non-routable detector must return false");
    }

    #[tokio::test]
    async fn try_handle_honeypot_routing_writes_decision_and_arms_cooldown_for_new_suspicious_login(
    ) {
        // Active path: a new `suspicious_login` attacker triggers the redirect.
        // We assert the operator-visible side effects:
        //   1. Function returns true so the caller skips the regular decide path.
        //   2. A decision row hits the audit JSONL (action_type = "honeypot",
        //      ai_provider = "honeypot-router") so the audit log honestly
        //      attributes the smart-routing action.
        //   3. The decision-cooldown gate is armed for the (honeypot, detector,
        //      ip) tuple so the next tick does not re-route the same session.
        let dir = tempfile::tempdir().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        // Empty registry forces `execute_decision` down the
        // "skipped: honeypot skill not available" branch — that keeps the
        // test deterministic AND still exercises the entire pre-execute body
        // (cooldown, decision build, decision-writer append).
        state.skill_registry = SkillRegistry::empty();
        let cfg = listener_config();
        let incident = sample_incident(
            "suspicious_login:test-id",
            vec![EntityRef::ip("198.51.100.55")],
        );
        let blocked: HashSet<String> = HashSet::new();

        let handled =
            try_handle_honeypot_routing(&incident, dir.path(), &cfg, &mut state, &blocked).await;

        assert!(handled, "new suspicious_login attacker must be routed");

        // Cooldown was set under the canonical decision-cooldown key.
        let key = decision_cooldown_key_for_decision(
            &incident,
            &ai::AiDecision {
                action: ai::AiAction::Honeypot {
                    ip: "198.51.100.55".to_string(),
                },
                confidence: 0.95,
                auto_execute: true,
                reason: String::new(),
                alternatives: vec![],
                estimated_threat: "high".into(),
            },
        )
        .expect("honeypot cooldown key must exist");
        assert!(
            state
                .store
                .has_cooldown(state_store::CooldownTable::Decision, &key),
            "cooldown must be armed after smart-routing fires"
        );

        // Decision JSONL row exists with the operator-visible attribution.
        if let Some(writer) = state.decision_writer.as_mut() {
            writer.flush();
        }
        let today = chrono::Local::now().date_naive().format("%Y-%m-%d");
        let decisions_path = dir.path().join(format!("decisions-{today}.jsonl"));
        let body = std::fs::read_to_string(&decisions_path)
            .expect("decisions JSONL must materialise on disk");
        assert!(
            body.contains("\"ai_provider\":\"honeypot-router\""),
            "decision row must attribute the action to honeypot-router; got: {body}"
        );
        assert!(
            body.contains("\"action_type\":\"honeypot\""),
            "decision row must record action_type=honeypot; got: {body}"
        );
        assert!(
            body.contains("198.51.100.55"),
            "decision row must record the routed IP; got: {body}"
        );
    }

    #[tokio::test]
    async fn try_handle_honeypot_routing_skips_allowlisted_ssh_attackers() {
        // SSH bruteforce + new + sampled IP is the *positive* SSH path, but
        // when the IP is on the operator's `[ai].protected_ips`, the router
        // must decline so the operator's own probes never get redirected.
        let dir = tempfile::tempdir().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let mut cfg = listener_config();
        // Pick an IP whose ASCII last byte is divisible by 5 so the SSH
        // sampler returns true if we hit that branch (the test verifies the
        // allowlist guard PRECEDES the sampler in routing semantics). Last
        // char `'5'` = ASCII 53 → 53 % 5 = 3 (no good); `'2'` = 50 → 0; we use
        // `203.0.113.102` (ends in `'2'`).
        let ip = "203.0.113.102";
        cfg.ai.protected_ips = vec![ip.to_string()];
        let incident = sample_incident(
            &format!("ssh_bruteforce:{ip}:test"),
            vec![EntityRef::ip(ip)],
        );
        let blocked: HashSet<String> = HashSet::new();

        let handled =
            try_handle_honeypot_routing(&incident, dir.path(), &cfg, &mut state, &blocked).await;

        assert!(!handled, "allowlisted IP must skip honeypot redirect");

        // No decision row was written.
        if let Some(writer) = state.decision_writer.as_mut() {
            writer.flush();
        }
        let today = chrono::Local::now().date_naive().format("%Y-%m-%d");
        let decisions_path = dir.path().join(format!("decisions-{today}.jsonl"));
        assert!(
            !decisions_path.exists()
                || std::fs::read_to_string(&decisions_path).unwrap().is_empty(),
            "no decision row may be written when allowlist guard fires"
        );
    }
}
