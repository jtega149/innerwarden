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

    /// Read every JSONL line from `decisions-*.jsonl` under `dir` and parse to JSON values.
    /// Helper for the `handle_ai_decision_failure` tests that need to verify the
    /// fallback audit row landed on disk.
    fn read_decision_entries(dir: &std::path::Path) -> Vec<serde_json::Value> {
        let mut out = Vec::new();
        let read = match std::fs::read_dir(dir) {
            Ok(r) => r,
            Err(_) => return out,
        };
        for entry in read.flatten() {
            let path = entry.path();
            let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
            if !name.starts_with("decisions-") || !name.ends_with(".jsonl") {
                continue;
            }
            let body = match std::fs::read_to_string(&path) {
                Ok(b) => b,
                Err(_) => continue,
            };
            for line in body.lines() {
                if line.trim().is_empty() {
                    continue;
                }
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
                    out.push(v);
                }
            }
        }
        out
    }

    #[test]
    fn handle_ai_decision_failure_writes_fallback_audit_entry_to_jsonl() {
        // Pins the audit-trail contract: when AI fails for an incident, a
        // `decisions-*.jsonl` row MUST be written so operators can see the
        // failure happened. Without this row the failure is invisible past
        // the in-memory telemetry counters.
        let dir = tempfile::tempdir().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let cfg = crate::config::AgentConfig::default();
        let incident = sample_incident();
        let err = anyhow::anyhow!("upstream 503");

        handle_ai_decision_failure(&incident, "openai", &cfg, &mut state, &err);

        // Flush the BufWriter so the JSONL bytes are visible to the
        // reader helper. `write` itself flushes via the locked-append
        // path, but `flush()` is the public contract for "force to disk".
        if let Some(ref mut writer) = state.decision_writer {
            writer.flush();
        }

        let rows = read_decision_entries(dir.path());
        assert_eq!(
            rows.len(),
            1,
            "exactly one fallback decision must be written; got {rows:?}"
        );
        let row = &rows[0];
        assert_eq!(row["incident_id"], "ssh_bruteforce:1");
        assert_eq!(row["host"], "host-a");
        assert_eq!(row["ai_provider"], "openai");
        assert_eq!(row["action_type"], "error");
        assert_eq!(row["execution_result"], "ai_error");
        assert_eq!(row["estimated_threat"], "unknown");
        // The reason field carries the formatted error so operators
        // can read the exact upstream failure that happened.
        let reason = row["reason"].as_str().unwrap_or("");
        assert!(
            reason.contains("upstream 503"),
            "reason must propagate the AI provider error message, got: {reason}"
        );
    }

    #[test]
    fn handle_ai_decision_failure_records_telemetry_error_and_ignore_decision() {
        // Pins the in-memory observability contract:
        // (1) `errors_by_component["ai_provider"]` increments so the
        //     `/metrics` endpoint and dashboard show the failure as an
        //     ai-provider error, not an "unknown" bucket.
        // (2) `decisions_by_action["ignore"]` increments because the
        //     fallback shape is an `Ignore { reason: "ai_error" }`.
        let dir = tempfile::tempdir().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let cfg = crate::config::AgentConfig::default();
        let incident = sample_incident();
        let err = anyhow::anyhow!("rate limited");

        handle_ai_decision_failure(&incident, "anthropic", &cfg, &mut state, &err);

        let snap = state.telemetry.snapshot("test");
        assert_eq!(
            snap.errors_by_component.get("ai_provider").copied(),
            Some(1),
            "ai_provider error counter must increment exactly once"
        );
        assert_eq!(
            snap.decisions_by_action.get("ignore").copied(),
            Some(1),
            "fallback Ignore decision must be tallied under decisions_by_action[ignore]"
        );
        assert_eq!(
            snap.ai_decision_count, 1,
            "the fallback ignore counts as one observed AI decision"
        );
    }

    #[test]
    fn handle_ai_decision_failure_propagates_dry_run_flag_into_audit_row() {
        // Pins the dry_run contract: the audit row's `dry_run` column
        // mirrors `cfg.responder.dry_run` so the operator can tell at
        // audit time whether the responder would have acted on this
        // incident if AI had succeeded.
        let dir = tempfile::tempdir().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let mut cfg = crate::config::AgentConfig::default();
        cfg.responder.dry_run = true;
        let incident = sample_incident();
        let err = anyhow::anyhow!("timeout");

        handle_ai_decision_failure(&incident, "ollama", &cfg, &mut state, &err);

        if let Some(ref mut writer) = state.decision_writer {
            writer.flush();
        }

        let rows = read_decision_entries(dir.path());
        assert_eq!(rows.len(), 1, "expected one audit row, got {rows:?}");
        assert_eq!(
            rows[0]["dry_run"], true,
            "dry_run must mirror cfg.responder.dry_run"
        );
        assert_eq!(rows[0]["ai_provider"], "ollama");
    }

    #[test]
    fn handle_ai_decision_failure_no_writer_still_records_telemetry_and_skips_disk() {
        // Pins the "writer absent" branch of the if-let: when
        // `state.decision_writer` is `None` (e.g. early-boot or
        // alternate sink configurations), telemetry must still
        // observe the failure but no JSONL file must be created.
        let dir = tempfile::tempdir().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        // Drop the writer so the `if let Some(...)` arm is skipped.
        state.decision_writer = None;
        let cfg = crate::config::AgentConfig::default();
        let incident = sample_incident();
        let err = anyhow::anyhow!("provider misconfigured");

        handle_ai_decision_failure(&incident, "openai", &cfg, &mut state, &err);

        // Telemetry side-effects MUST still fire — observability is
        // the point of this fallback even when the audit log is off.
        let snap = state.telemetry.snapshot("test");
        assert_eq!(
            snap.errors_by_component.get("ai_provider").copied(),
            Some(1),
            "telemetry must observe ai_provider error even with no decision_writer"
        );
        assert_eq!(snap.ai_decision_count, 1);

        // No decisions-*.jsonl must have been created. The temp dir
        // should be empty of decision files.
        let rows = read_decision_entries(dir.path());
        assert!(
            rows.is_empty(),
            "no JSONL row may be written when decision_writer is None; got {rows:?}"
        );
    }
}
