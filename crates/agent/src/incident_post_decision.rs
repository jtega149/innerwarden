use std::collections::HashSet;

use innerwarden_core::event::Severity;
use tracing::{info, warn};

use crate::{
    adaptive_block_ttl_secs, ai, allowlist, config, decision_cooldown_key_for_decision,
    incident_untouchable, state_store, AgentState, LocalIpReputation,
};

/// Apply post-decision safeguards and state updates before execution.
/// Includes protected-IP sandboxing, decision cooldown registration,
/// per-tick dedup state updates, and repeat-offender annotation.
pub(crate) fn apply_post_decision_safeguards(
    incident: &innerwarden_core::incident::Incident,
    cfg: &config::AgentConfig,
    state: &mut AgentState,
    decision: &mut ai::AiDecision,
    blocked_set: &mut HashSet<String>,
) {
    // Untouchable detector class override (2026-05-01 dashboard QA
    // audit finding 1.3). If the AI proposes Dismiss/Ignore on an
    // incident whose detector class is "untouchable" (kill_chain,
    // reverse_shell with eBPF evidence, ransomware, data_exfil_ebpf,
    // multi-stage cross-layer chain) AND severity is Critical, the
    // agent overrides to RequestConfirmation so the operator sees
    // it. Auto-dismissing kernel-level evidence at 100% confidence
    // is the failure mode the audit caught (AI dismissed
    // kill_chain DATA_EXFIL + reverse_shell with rationale "ssh is
    // a known operator/system tool").
    //
    // Mode is operator-configurable: enforce | shadow | off. Default
    // is enforce. Shadow logs the would-have-fired override without
    // touching the decision so a 24h diff against enforce is
    // possible before flipping a classifier rule.
    let mode = cfg.ai.untouchable_override_mode.as_str();
    if mode != "off" {
        if let Some(class) = incident_untouchable::classify(incident) {
            let proposed_dismiss = incident_untouchable::is_dismiss_like(&decision.action);
            let critical = matches!(incident.severity, Severity::Critical);
            if proposed_dismiss && critical {
                let proposed_action = decision.action.name();
                if mode == "shadow" {
                    warn!(
                        incident_id = %incident.incident_id,
                        class = class.as_str(),
                        proposed_action,
                        confidence = decision.confidence,
                        "ai_untouchable_override: would force RequestConfirmation (shadow mode, decision unchanged)"
                    );
                } else {
                    warn!(
                        incident_id = %incident.incident_id,
                        class = class.as_str(),
                        proposed_action,
                        confidence = decision.confidence,
                        "ai_untouchable_override: forcing RequestConfirmation over Critical kernel-level evidence"
                    );
                    incident_untouchable::override_to_confirmation(
                        decision,
                        class,
                        &incident.incident_id,
                    );
                }
            }
        }
    }

    // Protected IP sandbox: if AI tries to block a protected IP (RFC 1918,
    // loopback, or operator-configured ranges), downgrade to ignore.
    if let ai::AiAction::BlockIp { ip, .. } = &decision.action {
        if allowlist::is_ip_allowlisted(ip, &cfg.ai.protected_ips) {
            warn!(
                ip = %ip,
                incident_id = %incident.incident_id,
                "AI tried to block protected IP {ip} - downgraded to ignore"
            );
            *decision = ai::AiDecision {
                action: ai::AiAction::Ignore {
                    reason: format!(
                        "protected IP: AI recommended blocking {ip} but it matches a protected range"
                    ),
                },
                confidence: decision.confidence,
                auto_execute: false,
                reason: format!(
                    "{} [BLOCKED: target IP {ip} is in protected range]",
                    decision.reason
                ),
                alternatives: decision.alternatives.clone(),
                estimated_threat: decision.estimated_threat.clone(),
            };
        }
    }

    // Update the in-memory blocked_set immediately after a BlockIp decision.
    // This prevents a second incident from the same IP (arriving in the same 2s tick)
    // from triggering a duplicate AI call. The actual blocklist persists separately;
    // this is only a per-tick deduplication guard.
    if let ai::AiAction::BlockIp { ip, .. } = &decision.action {
        blocked_set.insert(ip.clone());
    }

    // Record decision cooldown so the same action:detector:entity scope is not
    // re-evaluated by AI within the cooldown window (default 1h).
    if let Some(key) = decision_cooldown_key_for_decision(incident, decision) {
        state.store.set_cooldown(
            state_store::CooldownTable::Decision,
            &key,
            chrono::Utc::now(),
        );
    }

    // Update in-memory blocklist immediately for BlockIp decisions so subsequent
    // ticks don't re-evaluate the same IP even when the responder is disabled or
    // dry_run is true. Without this, state.blocklist is only updated inside
    // execute_decision (which is skipped when responder.enabled = false), leaving
    // cross-tick deduplication to the cooldown alone - which breaks on restart if
    // the decision was not yet flushed to the decisions file.
    if let ai::AiAction::BlockIp { ip, .. } = &decision.action {
        state.blocklist.insert(ip.clone());

        // Track repeat offenders: increment the block count for this IP.
        // When an IP has been blocked more than once, annotate the decision
        // reason so it surfaces in the audit trail and notifications.
        let block_count = state.store.increment_block_count(ip);

        // Update local IP reputation - record incident + block.
        let rep = state
            .ip_reputations
            .entry(ip.clone())
            .or_insert_with(LocalIpReputation::new);
        rep.record_incident();
        rep.record_block();
        let ttl_secs = adaptive_block_ttl_secs(rep.total_blocks);
        let ttl_label = match ttl_secs {
            t if t >= 604800 => format!("{} days", t / 86400),
            t if t >= 86400 => format!("{} hours", t / 3600),
            t => format!("{} hours", t / 3600),
        };
        info!(
            ip = %ip,
            total_blocks = rep.total_blocks,
            reputation_score = rep.reputation_score,
            ttl = ttl_label,
            "adaptive TTL applied"
        );

        if block_count > 1 {
            warn!(ip = %ip, block_count, "repeat offender detected");
            decision.reason = format!(
                "{} [repeat offender - blocked {} times, TTL {}]",
                decision.reason, block_count, ttl_label
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use innerwarden_core::event::Severity;
    use tempfile::TempDir;

    fn base_decision(action: ai::AiAction) -> ai::AiDecision {
        ai::AiDecision {
            action,
            confidence: 0.95,
            auto_execute: true,
            reason: "ai rationale".to_string(),
            alternatives: vec!["monitor".to_string()],
            estimated_threat: "high".to_string(),
        }
    }

    fn dismiss_decision() -> ai::AiDecision {
        ai::AiDecision {
            action: ai::AiAction::Dismiss {
                reason: "ssh is a known operator/system tool".to_string(),
            },
            confidence: 1.0,
            auto_execute: true,
            reason: "looks benign".to_string(),
            alternatives: vec!["block_ip".to_string()],
            estimated_threat: "low".to_string(),
        }
    }

    /// Build a Critical kill_chain incident — classifies as Untouchable.
    fn untouchable_kill_chain_incident() -> innerwarden_core::incident::Incident {
        innerwarden_core::incident::Incident {
            ts: chrono::Utc::now(),
            host: "test-host".to_string(),
            incident_id: "kill_chain:CHAIN-0040:CL-008".to_string(),
            severity: Severity::Critical,
            title: "kill chain detected".to_string(),
            summary: "multi-stage kill chain".to_string(),
            evidence: serde_json::json!({}),
            recommended_checks: vec![],
            tags: vec!["kill_chain".to_string()],
            entities: vec![],
        }
    }

    #[test]
    fn untouchable_override_mode_off_skips_override_entirely() {
        // When operator disables the override (mode = "off") even a
        // Critical kill_chain dismiss must NOT be flipped — operator
        // explicitly opted out, so we trust the AI verbatim.
        let dir = TempDir::new().unwrap();
        let mut state = crate::tests::triage_test_state(dir.path());
        let mut cfg = config::AgentConfig::default();
        cfg.ai.untouchable_override_mode = "off".to_string();

        let incident = untouchable_kill_chain_incident();
        let mut decision = dismiss_decision();
        let mut blocked_set: HashSet<String> = HashSet::new();

        apply_post_decision_safeguards(
            &incident,
            &cfg,
            &mut state,
            &mut decision,
            &mut blocked_set,
        );

        // Decision unchanged: still Dismiss.
        assert!(matches!(decision.action, ai::AiAction::Dismiss { .. }));
        assert!(!decision.reason.contains("overridden"));
    }

    #[test]
    fn untouchable_override_mode_shadow_logs_but_leaves_decision_unchanged() {
        // Shadow mode is the safe-deploy diff window: log every
        // would-have-fired override for 24h before flipping to enforce.
        // Decision MUST be unchanged so the live action path is identical
        // to mode = "off".
        let dir = TempDir::new().unwrap();
        let mut state = crate::tests::triage_test_state(dir.path());
        let mut cfg = config::AgentConfig::default();
        cfg.ai.untouchable_override_mode = "shadow".to_string();

        let incident = untouchable_kill_chain_incident();
        let mut decision = dismiss_decision();
        let original_reason = decision.reason.clone();
        let mut blocked_set: HashSet<String> = HashSet::new();

        apply_post_decision_safeguards(
            &incident,
            &cfg,
            &mut state,
            &mut decision,
            &mut blocked_set,
        );

        assert!(matches!(decision.action, ai::AiAction::Dismiss { .. }));
        assert_eq!(
            decision.reason, original_reason,
            "shadow mode must NOT touch the decision"
        );
    }

    #[test]
    fn untouchable_override_mode_enforce_flips_dismiss_to_request_confirmation() {
        // Enforce mode (the default) on a Critical untouchable +
        // dismiss-like action MUST flip to RequestConfirmation so the
        // operator sees it. Audit invariant from 2026-05-01 finding 1.3.
        let dir = TempDir::new().unwrap();
        let mut state = crate::tests::triage_test_state(dir.path());
        let cfg = config::AgentConfig::default(); // enforce by default

        let incident = untouchable_kill_chain_incident();
        let mut decision = dismiss_decision();
        let mut blocked_set: HashSet<String> = HashSet::new();

        apply_post_decision_safeguards(
            &incident,
            &cfg,
            &mut state,
            &mut decision,
            &mut blocked_set,
        );

        assert!(matches!(
            decision.action,
            ai::AiAction::RequestConfirmation { .. }
        ));
        assert!(!decision.auto_execute);
        assert_eq!(decision.estimated_threat, "critical");
        // Original AI rationale must survive in suffix for the audit trail.
        assert!(
            decision.reason.contains("looks benign"),
            "original reason should survive: {}",
            decision.reason
        );
        assert!(
            decision.reason.contains("untouchable=kill_chain"),
            "override annotation missing: {}",
            decision.reason
        );
    }

    #[test]
    fn untouchable_override_skipped_when_severity_below_critical() {
        // Severity High on the same kill_chain class is legitimately
        // triagable by AI — only Critical triggers the override.
        let dir = TempDir::new().unwrap();
        let mut state = crate::tests::triage_test_state(dir.path());
        let cfg = config::AgentConfig::default();

        let mut incident = untouchable_kill_chain_incident();
        incident.severity = Severity::High;
        let mut decision = dismiss_decision();
        let mut blocked_set: HashSet<String> = HashSet::new();

        apply_post_decision_safeguards(
            &incident,
            &cfg,
            &mut state,
            &mut decision,
            &mut blocked_set,
        );

        assert!(matches!(decision.action, ai::AiAction::Dismiss { .. }));
    }

    #[test]
    fn untouchable_override_skipped_when_action_is_not_dismiss_like() {
        // AI proposed Monitor (not Dismiss/Ignore) on a Critical
        // untouchable — that is not the failure mode we are guarding
        // against, so the override does NOT fire.
        let dir = TempDir::new().unwrap();
        let mut state = crate::tests::triage_test_state(dir.path());
        let cfg = config::AgentConfig::default();

        let incident = untouchable_kill_chain_incident();
        let mut decision = base_decision(ai::AiAction::Monitor {
            ip: "203.0.113.7".to_string(),
        });
        let mut blocked_set: HashSet<String> = HashSet::new();

        apply_post_decision_safeguards(
            &incident,
            &cfg,
            &mut state,
            &mut decision,
            &mut blocked_set,
        );

        assert!(matches!(decision.action, ai::AiAction::Monitor { .. }));
    }

    #[test]
    fn protected_ip_block_is_downgraded_to_ignore() {
        // 10.0.0.5 sits in the default 10.0.0.0/8 protected range.
        // AI proposing BlockIp on it MUST be downgraded to Ignore so
        // the agent never firewalls operator infrastructure.
        let dir = TempDir::new().unwrap();
        let mut state = crate::tests::triage_test_state(dir.path());
        let cfg = config::AgentConfig::default();

        let incident = crate::tests::test_incident("10.0.0.5");
        let mut decision = base_decision(ai::AiAction::BlockIp {
            ip: "10.0.0.5".to_string(),
            skill_id: "block-ip-ufw".to_string(),
        });
        let original_confidence = decision.confidence;
        let original_alternatives = decision.alternatives.clone();
        let mut blocked_set: HashSet<String> = HashSet::new();

        apply_post_decision_safeguards(
            &incident,
            &cfg,
            &mut state,
            &mut decision,
            &mut blocked_set,
        );

        // Action flipped to Ignore.
        match &decision.action {
            ai::AiAction::Ignore { reason } => {
                assert!(
                    reason.contains("protected IP"),
                    "ignore reason must say protected IP: {reason}"
                );
                assert!(reason.contains("10.0.0.5"));
            }
            other => panic!("expected Ignore, got {other:?}"),
        }
        // auto_execute forced false.
        assert!(!decision.auto_execute);
        // Confidence and alternatives preserved.
        assert!((decision.confidence - original_confidence).abs() < f32::EPSILON);
        assert_eq!(decision.alternatives, original_alternatives);
        // Annotation appended to reason.
        assert!(
            decision.reason.contains("BLOCKED") && decision.reason.contains("protected range"),
            "reason must annotate the block: {}",
            decision.reason
        );
        // Because the action is no longer BlockIp, blocked_set / blocklist
        // must NOT contain the IP.
        assert!(!blocked_set.contains("10.0.0.5"));
        assert!(!state.blocklist.contains("10.0.0.5"));
    }

    #[test]
    fn first_block_of_external_ip_updates_state_without_repeat_annotation() {
        // External IP, never blocked before — block_count becomes 1, so
        // the "repeat offender" suffix MUST NOT be appended. State must
        // reflect: blocked_set + state.blocklist + ip_reputations all
        // updated, and a Decision cooldown is registered.
        let dir = TempDir::new().unwrap();
        let mut state = crate::tests::triage_test_state(dir.path());
        let cfg = config::AgentConfig::default();

        let ip = "203.0.113.10";
        let incident = crate::tests::test_incident(ip);
        let mut decision = base_decision(ai::AiAction::BlockIp {
            ip: ip.to_string(),
            skill_id: "block-ip-ufw".to_string(),
        });
        let original_reason = decision.reason.clone();
        let mut blocked_set: HashSet<String> = HashSet::new();

        apply_post_decision_safeguards(
            &incident,
            &cfg,
            &mut state,
            &mut decision,
            &mut blocked_set,
        );

        // BlockIp survived (not protected).
        assert!(matches!(decision.action, ai::AiAction::BlockIp { .. }));
        // Per-tick dedup set updated.
        assert!(blocked_set.contains(ip));
        // In-memory blocklist updated.
        assert!(state.blocklist.contains(ip));
        // Local IP reputation tracked: incident + block recorded.
        let rep = state
            .ip_reputations
            .get(ip)
            .expect("ip reputation should be inserted");
        assert_eq!(rep.total_incidents, 1);
        assert_eq!(rep.total_blocks, 1);
        // Decision cooldown registered (block_ip:<detector>:ip:<ip>).
        let key = decision_cooldown_key_for_decision(&incident, &decision)
            .expect("BlockIp must produce a cooldown key");
        assert!(
            state
                .store
                .has_cooldown(state_store::CooldownTable::Decision, &key),
            "cooldown should be registered for key {key}"
        );
        // First block — no repeat-offender annotation.
        assert_eq!(
            decision.reason, original_reason,
            "first block must NOT append repeat-offender annotation"
        );
    }

    #[test]
    fn second_block_of_same_ip_appends_repeat_offender_annotation() {
        // Pre-seed block count (= 1) in the persistent SQLite store and a
        // matching in-memory reputation (total_blocks = 1). After the
        // safeguards run: SQLite count -> 2 (drives "blocked 2 times"),
        // in-memory total_blocks -> 2 (drives the TTL = 4 hours label
        // via adaptive_block_ttl_secs(2)).
        let dir = TempDir::new().unwrap();
        let mut state = crate::tests::triage_test_state(dir.path());
        let cfg = config::AgentConfig::default();

        let ip = "203.0.113.20";
        // Pre-seed SQLite counter.
        state.store.increment_block_count(ip);
        // Pre-seed in-memory reputation so the entry already exists with
        // total_blocks = 1 — the safeguards path bumps it to 2.
        let mut rep = LocalIpReputation::new();
        rep.record_block();
        state.ip_reputations.insert(ip.to_string(), rep);

        let incident = crate::tests::test_incident(ip);
        let mut decision = base_decision(ai::AiAction::BlockIp {
            ip: ip.to_string(),
            skill_id: "block-ip-ufw".to_string(),
        });
        let original_reason = decision.reason.clone();
        let mut blocked_set: HashSet<String> = HashSet::new();

        apply_post_decision_safeguards(
            &incident,
            &cfg,
            &mut state,
            &mut decision,
            &mut blocked_set,
        );

        assert_ne!(
            decision.reason, original_reason,
            "second block must mutate reason"
        );
        assert!(
            decision.reason.contains("repeat offender"),
            "reason must mention repeat offender: {}",
            decision.reason
        );
        assert!(
            decision.reason.contains("blocked 2 times"),
            "reason must surface the count: {}",
            decision.reason
        );
        // adaptive_block_ttl_secs(2) = 14400s = 4 hours.
        assert!(
            decision.reason.contains("TTL 4 hours"),
            "reason must surface adaptive TTL label: {}",
            decision.reason
        );
    }

    #[test]
    fn non_block_action_does_not_touch_blocklist_or_reputation() {
        // Monitor / Ignore / Dismiss / Honeypot etc. must not write to
        // blocklist, ip_reputations, or blocked_set — those are gated on
        // BlockIp specifically. Monitor MAY register a cooldown though,
        // so we assert the right cooldown key is set and the wrong ones
        // are not.
        let dir = TempDir::new().unwrap();
        let mut state = crate::tests::triage_test_state(dir.path());
        let cfg = config::AgentConfig::default();

        let ip = "203.0.113.30";
        let incident = crate::tests::test_incident(ip);
        let mut decision = base_decision(ai::AiAction::Monitor { ip: ip.to_string() });
        let mut blocked_set: HashSet<String> = HashSet::new();

        apply_post_decision_safeguards(
            &incident,
            &cfg,
            &mut state,
            &mut decision,
            &mut blocked_set,
        );

        assert!(
            blocked_set.is_empty(),
            "Monitor must not insert into blocked_set"
        );
        assert!(
            !state.blocklist.contains(ip),
            "Monitor must not insert into the in-memory blocklist"
        );
        assert!(
            !state.ip_reputations.contains_key(ip),
            "Monitor must not record IP reputation"
        );
        // Monitor cooldown should be registered.
        let key = decision_cooldown_key_for_decision(&incident, &decision)
            .expect("Monitor must produce a cooldown key");
        assert!(state
            .store
            .has_cooldown(state_store::CooldownTable::Decision, &key));
    }

    #[test]
    fn ignore_decision_registers_no_cooldown() {
        // Ignore / Dismiss / RequestConfirmation deliberately yield None
        // from decision_cooldown_key_for_decision. The post-decision
        // safeguards branch must therefore not register any cooldown.
        let dir = TempDir::new().unwrap();
        let mut state = crate::tests::triage_test_state(dir.path());
        let cfg = config::AgentConfig::default();

        let incident = crate::tests::test_incident("203.0.113.40");
        let mut decision = base_decision(ai::AiAction::Ignore {
            reason: "false positive".to_string(),
        });
        let mut blocked_set: HashSet<String> = HashSet::new();

        apply_post_decision_safeguards(
            &incident,
            &cfg,
            &mut state,
            &mut decision,
            &mut blocked_set,
        );

        // No cooldown key was produced, nothing was written.
        assert!(decision_cooldown_key_for_decision(&incident, &decision).is_none());
        assert!(blocked_set.is_empty());
        assert!(!state.blocklist.contains("203.0.113.40"));
    }

    #[test]
    fn protected_ip_block_does_not_register_blockip_cooldown() {
        // After downgrade, the action is Ignore, so cooldown lookup must
        // also return None — the protected-IP guard must take effect
        // BEFORE the cooldown registration so we don't suppress real
        // future block attempts on the same IP via a stale cooldown key.
        let dir = TempDir::new().unwrap();
        let mut state = crate::tests::triage_test_state(dir.path());
        let cfg = config::AgentConfig::default();

        let incident = crate::tests::test_incident("10.0.0.5");
        let mut decision = base_decision(ai::AiAction::BlockIp {
            ip: "10.0.0.5".to_string(),
            skill_id: "block-ip-ufw".to_string(),
        });
        let mut blocked_set: HashSet<String> = HashSet::new();

        apply_post_decision_safeguards(
            &incident,
            &cfg,
            &mut state,
            &mut decision,
            &mut blocked_set,
        );

        // Decision is now Ignore, so no cooldown key is produced.
        assert!(decision_cooldown_key_for_decision(&incident, &decision).is_none());
        // Reputation untouched — protected IP should never enter the
        // local-rep ledger as a "blocked" actor.
        assert!(
            !state.ip_reputations.contains_key("10.0.0.5"),
            "protected IP must NOT be tracked as a blocked actor"
        );
    }

    #[test]
    fn fourth_block_uses_seven_day_ttl_label() {
        // adaptive_block_ttl_secs(4+) = 604800s. TTL is computed from
        // the IN-MEMORY rep.total_blocks (which is bumped by
        // record_block() in this call). Pre-seed both the SQLite
        // counter (drives "blocked 4 times") AND the in-memory
        // reputation (so total_blocks reaches 4 after record_block()).
        // The annotation must surface "7 days" (the >= 604800 arm).
        let dir = TempDir::new().unwrap();
        let mut state = crate::tests::triage_test_state(dir.path());
        let cfg = config::AgentConfig::default();

        let ip = "203.0.113.50";
        // SQLite: 3 prior blocks so increment_block_count returns 4.
        for _ in 0..3 {
            state.store.increment_block_count(ip);
        }
        // In-memory: 3 prior blocks so record_block() inside the
        // safeguards path bumps total_blocks to 4.
        let mut rep = LocalIpReputation::new();
        rep.record_block();
        rep.record_block();
        rep.record_block();
        state.ip_reputations.insert(ip.to_string(), rep);

        let incident = crate::tests::test_incident(ip);
        let mut decision = base_decision(ai::AiAction::BlockIp {
            ip: ip.to_string(),
            skill_id: "block-ip-ufw".to_string(),
        });
        let mut blocked_set: HashSet<String> = HashSet::new();

        apply_post_decision_safeguards(
            &incident,
            &cfg,
            &mut state,
            &mut decision,
            &mut blocked_set,
        );

        assert!(
            decision.reason.contains("blocked 4 times"),
            "reason must reflect 4 blocks: {}",
            decision.reason
        );
        assert!(
            decision.reason.contains("TTL 7 days"),
            "TTL label must come from the 604800-second arm: {}",
            decision.reason
        );
    }

    #[test]
    fn third_block_uses_24_hour_ttl_label() {
        // adaptive_block_ttl_secs(3) = 86400s → "24 hours" via the
        // >= 86400 arm. Distinct from the 4 hours / 7 days arms so
        // we exercise all three TTL formatting branches. Same
        // pre-seeding scheme as the 4th-block test (SQLite counter
        // separate from in-memory total_blocks).
        let dir = TempDir::new().unwrap();
        let mut state = crate::tests::triage_test_state(dir.path());
        let cfg = config::AgentConfig::default();

        let ip = "203.0.113.60";
        for _ in 0..2 {
            state.store.increment_block_count(ip);
        }
        let mut rep = LocalIpReputation::new();
        rep.record_block();
        rep.record_block();
        state.ip_reputations.insert(ip.to_string(), rep);

        let incident = crate::tests::test_incident(ip);
        let mut decision = base_decision(ai::AiAction::BlockIp {
            ip: ip.to_string(),
            skill_id: "block-ip-ufw".to_string(),
        });
        let mut blocked_set: HashSet<String> = HashSet::new();

        apply_post_decision_safeguards(
            &incident,
            &cfg,
            &mut state,
            &mut decision,
            &mut blocked_set,
        );

        assert!(
            decision.reason.contains("blocked 3 times"),
            "reason must reflect 3 blocks: {}",
            decision.reason
        );
        assert!(
            decision.reason.contains("TTL 24 hours"),
            "TTL label must come from the 86400-second arm: {}",
            decision.reason
        );
    }
}
