use tracing::warn;

use crate::{ai, config, decisions, AgentState};

/// Handle AI provider failure for one incident and record a fallback audit entry.
pub(crate) fn handle_ai_decision_failure(
    incident: &innerwarden_core::incident::Incident,
    provider_name: &str,
    cfg: &config::AgentConfig,
    state: &mut AgentState,
    error: &anyhow::Error,
) {
    state.telemetry.observe_error("ai_provider");
    state.telemetry.observe_ai_decision(
        &ai::AiAction::Ignore {
            reason: "ai_error".to_string(),
        },
        0,
    );
    warn!(incident_id = %incident.incident_id, "AI decision failed: {error:#}");

    // Write a fallback decision so the audit trail records the failure.
    if let Some(ref mut writer) = state.decision_writer {
        let entry = build_ai_failure_entry(
            incident,
            provider_name,
            cfg.responder.dry_run,
            &format!("{error:#}"),
            chrono::Utc::now(),
        );
        if let Err(writer_err) = writer.write(&entry) {
            warn!("failed to write fallback decision: {writer_err:#}");
        }
    }
}

fn build_ai_failure_entry(
    incident: &innerwarden_core::incident::Incident,
    provider_name: &str,
    dry_run: bool,
    reason: &str,
    ts: chrono::DateTime<chrono::Utc>,
) -> decisions::DecisionEntry {
    decisions::DecisionEntry {
        ts,
        incident_id: incident.incident_id.clone(),
        host: incident.host.clone(),
        ai_provider: provider_name.to_string(),
        action_type: "error".to_string(),
        target_ip: None,
        target_user: None,
        skill_id: None,
        confidence: 0.0,
        auto_executed: false,
        dry_run,
        reason: reason.to_string(),
        estimated_threat: "unknown".to_string(),
        execution_result: "ai_error".to_string(),
        prev_hash: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use innerwarden_core::{event::Severity, incident::Incident};

    fn sample_incident() -> Incident {
        Incident {
            ts: chrono::Utc::now(),
            host: "host-a".to_string(),
            incident_id: "ssh_bruteforce:1".to_string(),
            severity: Severity::High,
            title: "title".to_string(),
            summary: "summary".to_string(),
            evidence: serde_json::json!({}),
            recommended_checks: vec![],
            tags: vec![],
            entities: vec![],
        }
    }

    #[test]
    fn build_ai_failure_entry_sets_provider_and_error_action_type() {
        // Ensures fallback decision rows are clearly marked as provider errors.
        let incident = sample_incident();
        let ts = chrono::Utc
            .with_ymd_and_hms(2026, 4, 17, 10, 0, 0)
            .single()
            .expect("valid timestamp");
        let entry = build_ai_failure_entry(&incident, "openai", false, "boom", ts);
        assert_eq!(entry.ai_provider, "openai");
        assert_eq!(entry.action_type, "error");
        assert_eq!(entry.execution_result, "ai_error");
    }

    #[test]
    fn build_ai_failure_entry_preserves_incident_identity_fields() {
        // Verifies audit entries keep incident ID and host for traceability.
        let incident = sample_incident();
        let entry =
            build_ai_failure_entry(&incident, "anthropic", true, "timeout", chrono::Utc::now());
        assert_eq!(entry.incident_id, incident.incident_id);
        assert_eq!(entry.host, incident.host);
        assert!(entry.dry_run);
    }

    #[test]
    fn build_ai_failure_entry_keeps_reason_and_sets_unknown_threat() {
        // Covers reason propagation so operators can inspect the exact AI failure message.
        let incident = sample_incident();
        let entry = build_ai_failure_entry(
            &incident,
            "ollama",
            false,
            "network unreachable",
            chrono::Utc::now(),
        );
        assert!(entry.reason.contains("network unreachable"));
        assert_eq!(entry.estimated_threat, "unknown");
        assert_eq!(entry.confidence, 0.0);
    }
}
