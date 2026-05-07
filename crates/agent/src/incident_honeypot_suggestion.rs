use tracing::{info, warn};

use crate::{ai, config, decisions, AgentState, PendingHoneypotChoice};

/// Handle honeypot operator suggestion flow via Telegram.
/// Returns true when the incident is deferred to operator choice.
pub(crate) async fn maybe_defer_honeypot_to_operator(
    incident: &innerwarden_core::incident::Incident,
    provider_name: &str,
    decision: &ai::AiDecision,
    cfg: &config::AgentConfig,
    state: &mut AgentState,
) -> bool {
    let ai::AiAction::Honeypot { ip } = &decision.action else {
        return false;
    };

    let should_auto = decision.auto_execute && decision.confidence >= cfg.ai.confidence_threshold;
    if should_auto {
        // Auto-execute honeypot - same as operator clicking "Honeypot".
        info!(
            ip = %ip,
            confidence = decision.confidence,
            "AI auto-activating honeypot (high confidence)"
        );
        // Fall through to normal execution below (don't defer to Telegram).
        return false;
    }

    let Some(ref tg) = state.telegram_client else {
        return false;
    };

    let ttl = cfg.telegram.approval_ttl_secs;
    let tg_clone = tg.clone();
    let reason = decision.reason.clone();
    let confidence = decision.confidence;
    let incident_clone = incident.clone();
    let ip_clone = ip.clone();

    match tg_clone
        .send_honeypot_suggestion(&incident_clone, &ip_clone, &reason, confidence, "honeypot")
        .await
    {
        Ok(_msg_id) => {
            let expires_at = chrono::Utc::now() + chrono::Duration::seconds(ttl as i64);
            state.pending_honeypot_choices.insert(
                ip_clone.clone(),
                PendingHoneypotChoice {
                    ip: ip_clone.clone(),
                    incident_id: incident.incident_id.clone(),
                    incident: incident_clone,
                    expires_at,
                },
            );

            // Write an audit entry noting the operator was asked.
            if let Some(writer) = &mut state.decision_writer {
                let entry = decisions::build_entry(
                    &incident.incident_id,
                    &incident.host,
                    provider_name,
                    decision,
                    cfg.responder.dry_run,
                    "pending: operator honeypot choice requested via Telegram",
                );
                if let Err(e) = writer.write(&entry) {
                    state.telemetry.observe_error("decision_writer");
                    warn!("failed to write honeypot-pending decision: {e:#}");
                }
            }
            true
        }
        Err(e) => {
            warn!(
                incident_id = %incident.incident_id,
                "Telegram honeypot suggestion failed: {e:#} - falling through to auto-execute"
            );
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ai::{AiAction, AiDecision};
    use crate::tests::{test_incident, triage_test_state};
    use std::sync::{Arc, Mutex};
    use tempfile::TempDir;

    /// Process-wide guard for `INNERWARDEN_MOCK_TELEGRAM*` env vars. The
    /// `TelegramClient::new` constructor reads these to decide whether to
    /// route `sendMessage` through a JSONL outbox, and parallel tests must
    /// not race on the read.
    static MOCK_ENV_LOCK: Mutex<()> = Mutex::new(());

    fn honeypot_decision(ip: &str, confidence: f32, auto: bool) -> AiDecision {
        AiDecision {
            action: AiAction::Honeypot { ip: ip.to_string() },
            confidence,
            auto_execute: auto,
            reason: "AI thinks this attacker is worth studying".to_string(),
            alternatives: vec!["block".to_string()],
            estimated_threat: "high".to_string(),
        }
    }

    fn block_ip_decision(ip: &str) -> AiDecision {
        AiDecision {
            action: AiAction::BlockIp {
                ip: ip.to_string(),
                skill_id: "block-ip-ufw".to_string(),
            },
            confidence: 0.95,
            auto_execute: true,
            reason: "obvious threat".to_string(),
            alternatives: vec![],
            estimated_threat: "high".to_string(),
        }
    }

    /// Build a `TelegramClient` whose `sendMessage` is intercepted into a
    /// JSONL outbox file inside `dir` instead of hitting the real API. The
    /// client is constructed under `MOCK_ENV_LOCK` to keep the env-var read
    /// in `mock_outbox_from_env` race-free, and the env vars are restored
    /// before the lock is released.
    fn telegram_client_with_mock_outbox(dir: &std::path::Path) -> crate::telegram::TelegramClient {
        let outbox = dir.join("telegram-outbox.jsonl");
        let _guard = MOCK_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let prev_enabled = std::env::var("INNERWARDEN_MOCK_TELEGRAM").ok();
        let prev_path = std::env::var("INNERWARDEN_MOCK_TELEGRAM_PATH").ok();
        std::env::set_var("INNERWARDEN_MOCK_TELEGRAM", "1");
        std::env::set_var("INNERWARDEN_MOCK_TELEGRAM_PATH", &outbox);
        let client = crate::telegram::TelegramClient::new("test-token", "chat-1", None)
            .expect("mock telegram client");
        match prev_enabled {
            Some(v) => std::env::set_var("INNERWARDEN_MOCK_TELEGRAM", v),
            None => std::env::remove_var("INNERWARDEN_MOCK_TELEGRAM"),
        }
        match prev_path {
            Some(v) => std::env::set_var("INNERWARDEN_MOCK_TELEGRAM_PATH", v),
            None => std::env::remove_var("INNERWARDEN_MOCK_TELEGRAM_PATH"),
        }
        client
    }

    #[tokio::test]
    async fn returns_false_when_action_is_not_honeypot() {
        let dir = TempDir::new().unwrap();
        let cfg = config::AgentConfig::default();
        let mut state = triage_test_state(dir.path());
        let incident = test_incident("198.51.100.7");
        let decision = block_ip_decision("198.51.100.7");

        let deferred =
            maybe_defer_honeypot_to_operator(&incident, "mock", &decision, &cfg, &mut state).await;

        assert!(!deferred, "non-Honeypot actions must never defer");
        assert!(
            state.pending_honeypot_choices.is_empty(),
            "no pending choice should be created for BlockIp"
        );
    }

    #[tokio::test]
    async fn auto_executes_when_high_confidence_and_auto_execute() {
        // auto_execute=true AND confidence >= ai.confidence_threshold:
        // function logs the auto-activation and returns false so the
        // caller falls through to normal honeypot execution (no
        // deferral, no pending entry, no Telegram call required).
        let dir = TempDir::new().unwrap();
        let mut cfg = config::AgentConfig::default();
        cfg.ai.confidence_threshold = 0.5; // generous threshold to make the branch deterministic
        let mut state = triage_test_state(dir.path());
        // Make sure a Telegram client *would* be available so we prove
        // the auto-execute branch returns before consulting it.
        let dir2 = TempDir::new().unwrap();
        state.telegram_client = Some(Arc::new(telegram_client_with_mock_outbox(dir2.path())));
        let incident = test_incident("198.51.100.8");
        let decision = honeypot_decision("198.51.100.8", 0.92, true);

        let deferred =
            maybe_defer_honeypot_to_operator(&incident, "mock", &decision, &cfg, &mut state).await;

        assert!(
            !deferred,
            "auto-execute path must return false (don't defer)"
        );
        assert!(
            state.pending_honeypot_choices.is_empty(),
            "auto-execute must not write a pending choice"
        );
    }

    #[tokio::test]
    async fn returns_false_when_no_telegram_client() {
        // auto_execute=false (or low confidence) and no Telegram client
        // configured: the function returns false and the caller will
        // fall through to whatever honeypot fallback exists.
        let dir = TempDir::new().unwrap();
        let cfg = config::AgentConfig::default();
        let mut state = triage_test_state(dir.path());
        assert!(
            state.telegram_client.is_none(),
            "triage_test_state must start with no telegram client"
        );
        let incident = test_incident("198.51.100.9");
        let decision = honeypot_decision("198.51.100.9", 0.40, false);

        let deferred =
            maybe_defer_honeypot_to_operator(&incident, "mock", &decision, &cfg, &mut state).await;

        assert!(
            !deferred,
            "with no telegram client there is nothing to defer to"
        );
        assert!(
            state.pending_honeypot_choices.is_empty(),
            "no telegram client must mean no pending choice"
        );
    }

    #[tokio::test]
    async fn defers_to_operator_when_telegram_succeeds() {
        // auto_execute=false AND telegram client present AND
        // sendMessage succeeds: the function inserts a pending choice
        // keyed by the attacker IP, writes a `pending: operator
        // honeypot choice requested via Telegram` audit decision, and
        // returns true so the caller skips inline execution.
        let dir = TempDir::new().unwrap();
        let mut cfg = config::AgentConfig::default();
        cfg.telegram.approval_ttl_secs = 600;
        cfg.responder.dry_run = false;

        let mut state = triage_test_state(dir.path());
        state.telegram_client = Some(Arc::new(telegram_client_with_mock_outbox(dir.path())));

        let ip = "203.0.113.42";
        let incident = test_incident(ip);
        let incident_id = incident.incident_id.clone();
        let decision = honeypot_decision(ip, 0.40, false);
        let now = chrono::Utc::now();

        let deferred =
            maybe_defer_honeypot_to_operator(&incident, "mock", &decision, &cfg, &mut state).await;

        assert!(
            deferred,
            "successful Telegram path must defer (return true)"
        );
        let pending = state
            .pending_honeypot_choices
            .get(ip)
            .expect("pending choice must be inserted under the attacker IP");
        assert_eq!(pending.ip, ip, "pending.ip must equal the attacker IP");
        assert_eq!(
            pending.incident_id, incident_id,
            "pending.incident_id must equal the originating incident"
        );
        assert_eq!(
            pending.incident.incident_id, incident_id,
            "pending.incident must be a clone of the original"
        );
        let expected_min = now + chrono::Duration::seconds(599);
        let expected_max = now + chrono::Duration::seconds(601);
        assert!(
            pending.expires_at > expected_min && pending.expires_at < expected_max,
            "expires_at must be ttl seconds in the future (got {} vs window [{}, {}])",
            pending.expires_at,
            expected_min,
            expected_max
        );

        // Audit entry must be written into today's decisions JSONL.
        if let Some(w) = &mut state.decision_writer {
            w.flush();
        }
        let today = chrono::Local::now()
            .date_naive()
            .format("%Y-%m-%d")
            .to_string();
        let decisions_path = dir.path().join(format!("decisions-{today}.jsonl"));
        let lines: Vec<String> = std::fs::read_to_string(&decisions_path)
            .expect("decisions JSONL must be readable")
            .lines()
            .map(str::to_string)
            .collect();
        assert_eq!(
            lines.len(),
            1,
            "one audit entry must be written for the deferral"
        );
        let audit: serde_json::Value = serde_json::from_str(&lines[0]).expect("valid JSON");
        assert_eq!(audit["incident_id"], incident_id);
        assert_eq!(audit["ai_provider"], "mock");
        assert_eq!(audit["action_type"], "honeypot");
        assert_eq!(audit["target_ip"], ip);
        assert_eq!(audit["dry_run"], false);
        assert_eq!(
            audit["execution_result"],
            "pending: operator honeypot choice requested via Telegram"
        );

        // The mock telegram outbox must have captured the sendMessage.
        let outbox_path = dir.path().join("telegram-outbox.jsonl");
        let outbox = std::fs::read_to_string(&outbox_path)
            .expect("mock telegram outbox file must exist after a successful send");
        assert!(
            outbox.contains("sendMessage"),
            "outbox must record the sendMessage method (got {outbox})"
        );
        assert!(
            outbox.contains(ip),
            "outbox payload must reference the attacker IP {ip}"
        );
    }

    #[tokio::test]
    async fn defers_with_dry_run_flag_propagated_to_audit() {
        // Same happy path as above, but dry_run=true so the audit
        // entry's `dry_run` field flips. Pinned because the audit log
        // is the only operator-visible record of "mode at decision
        // time" and a regression here silently mismatches what the
        // operator was told the agent was doing.
        let dir = TempDir::new().unwrap();
        let mut cfg = config::AgentConfig::default();
        cfg.responder.dry_run = true;
        cfg.telegram.approval_ttl_secs = 120;

        let mut state = triage_test_state(dir.path());
        state.telegram_client = Some(Arc::new(telegram_client_with_mock_outbox(dir.path())));

        let ip = "203.0.113.43";
        let incident = test_incident(ip);
        let decision = honeypot_decision(ip, 0.30, false);

        let deferred =
            maybe_defer_honeypot_to_operator(&incident, "mock", &decision, &cfg, &mut state).await;

        assert!(deferred);
        if let Some(w) = &mut state.decision_writer {
            w.flush();
        }
        let today = chrono::Local::now()
            .date_naive()
            .format("%Y-%m-%d")
            .to_string();
        let decisions_path = dir.path().join(format!("decisions-{today}.jsonl"));
        let raw = std::fs::read_to_string(&decisions_path).unwrap();
        let audit: serde_json::Value = serde_json::from_str(raw.lines().next().unwrap()).unwrap();
        assert_eq!(
            audit["dry_run"], true,
            "dry_run flag must propagate into the audit row"
        );
    }

    #[tokio::test]
    async fn defers_without_audit_when_decision_writer_is_none() {
        // The function uses `if let Some(writer)` to gate the audit
        // write, so a state with no decision writer must still defer
        // and insert the pending choice without panicking.
        let dir = TempDir::new().unwrap();
        let cfg = config::AgentConfig::default();
        let mut state = triage_test_state(dir.path());
        state.decision_writer = None;
        state.telegram_client = Some(Arc::new(telegram_client_with_mock_outbox(dir.path())));

        let ip = "203.0.113.44";
        let incident = test_incident(ip);
        let decision = honeypot_decision(ip, 0.20, false);

        let deferred =
            maybe_defer_honeypot_to_operator(&incident, "mock", &decision, &cfg, &mut state).await;

        assert!(
            deferred,
            "deferral must succeed even when no decision writer is wired"
        );
        assert!(
            state.pending_honeypot_choices.contains_key(ip),
            "pending choice must still be inserted"
        );
        // The decisions JSONL is opened by `triage_test_state` (the file
        // exists), but with `decision_writer = None` no audit row should
        // ever be appended for this deferral.
        let today = chrono::Local::now()
            .date_naive()
            .format("%Y-%m-%d")
            .to_string();
        let decisions_path = dir.path().join(format!("decisions-{today}.jsonl"));
        let body = std::fs::read_to_string(&decisions_path).unwrap_or_default();
        assert!(
            body.is_empty(),
            "no audit row should be written when decision_writer is None (got: {body:?})"
        );
    }

    #[tokio::test]
    async fn auto_execute_skipped_when_confidence_below_threshold() {
        // auto_execute=true but confidence < threshold: the auto-execute
        // branch is skipped (its `should_auto` test fails) and the
        // function falls through to the Telegram-defer path. With a
        // Telegram client present this returns true.
        let dir = TempDir::new().unwrap();
        let mut cfg = config::AgentConfig::default();
        cfg.ai.confidence_threshold = 0.90;
        let mut state = triage_test_state(dir.path());
        state.telegram_client = Some(Arc::new(telegram_client_with_mock_outbox(dir.path())));

        let ip = "203.0.113.45";
        let incident = test_incident(ip);
        // auto_execute=true, but confidence (0.50) < threshold (0.90).
        let decision = honeypot_decision(ip, 0.50, true);

        let deferred =
            maybe_defer_honeypot_to_operator(&incident, "mock", &decision, &cfg, &mut state).await;

        assert!(
            deferred,
            "low-confidence auto-execute must NOT short-circuit; Telegram defer must run"
        );
        assert!(state.pending_honeypot_choices.contains_key(ip));
    }
}
