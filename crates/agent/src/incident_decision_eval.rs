use std::path::Path;

use tracing::{info, warn};

use crate::{ai, config, correlation, defender_brain, AgentState};

/// Apply correlation confidence boost, query defender brain, and emit the canonical decision log.
pub(crate) fn apply_correlation_boost_and_log_decision(
    incident: &innerwarden_core::incident::Incident,
    cfg: &config::AgentConfig,
    state: &mut AgentState,
    decision: &mut ai::AiDecision,
    data_dir: &Path,
) {
    // If the same IP triggered multiple distinct detectors within the
    // correlation window, boost the confidence.
    let (boosted_confidence, correlated_detectors) = if cfg.correlation.enabled {
        let (b, k) = correlation::cross_detector_boost(
            &mut state.correlator,
            incident,
            decision.confidence as f64,
        );
        (b as f32, k)
    } else {
        (decision.confidence, vec![])
    };

    if boosted_confidence > decision.confidence {
        info!(
            incident_id = %incident.incident_id,
            base_confidence = decision.confidence,
            boosted_confidence,
            correlated_detectors = ?correlated_detectors,
            "cross-detector correlation boost applied"
        );
        decision.confidence = boosted_confidence;
        decision.reason = format!(
            "{} [correlated: {}]",
            decision.reason,
            correlated_detectors.join(", ")
        );
    }

    info!(
        incident_id = %incident.incident_id,
        action = ?decision.action,
        confidence = decision.confidence,
        auto_execute = decision.auto_execute,
        reason = %decision.reason,
        "AI decision"
    );

    // Query defender brain for a second opinion (AlphaZero-trained model).
    // Logs the suggestion and records to history for dashboard + FP audit.
    if state.defender_brain.is_loaded() {
        let features = build_brain_features(incident, state);
        if let Some(suggestion) = state.defender_brain.suggest(&features) {
            let ai_action_str = format!("{:?}", decision.action);
            let brain_agrees = {
                let ba = suggestion.action_name;
                let aa = &ai_action_str;
                (ba == "block_ip" && aa.contains("BlockIp"))
                || (ba == "kill_process" && aa.contains("KillProcess"))
                || (ba == "observe" && (aa.contains("Ignore") || aa.contains("Monitor")))
                || (ba == "alert" && aa.contains("Monitor"))
                || (ba == "escalate" && aa.contains("Escalate"))
            };

            info!(
                incident_id = %incident.incident_id,
                brain_action = suggestion.action_name,
                brain_confidence = format!("{:.1}%", suggestion.confidence * 100.0),
                brain_value = format!("{:.2}", suggestion.value),
                agreed = brain_agrees,
                "defender brain suggestion"
            );

            let det = incident.incident_id.split(':').next().unwrap_or("unknown");
            let log_entry = defender_brain::BrainLogEntry {
                ts: chrono::Utc::now(),
                incident_id: incident.incident_id.clone(),
                detector: det.to_string(),
                severity: format!("{:?}", incident.severity),
                brain_action: suggestion.action_name,
                brain_confidence: suggestion.confidence,
                brain_value: suggestion.value,
                brain_top3: suggestion.top_actions.clone(),
                ai_action: ai_action_str,
                ai_confidence: decision.confidence,
                agreed: brain_agrees,
                feedback: None,
            };

            // Persist to file for dashboard access
            let log_path = data_dir.join("brain-log.json");
            let mut entries: Vec<serde_json::Value> = std::fs::read_to_string(&log_path)
                .ok()
                .and_then(|s| serde_json::from_str(&s).ok())
                .unwrap_or_default();
            if let Ok(v) = serde_json::to_value(&log_entry) {
                entries.push(v);
                // Keep last 500 entries
                if entries.len() > 500 {
                    entries.drain(0..entries.len() - 500);
                }
                if let Err(e) = std::fs::write(&log_path, serde_json::to_string(&entries).unwrap_or_default()) {
                    warn!("failed to write brain-log.json: {e}");
                }
            }

            state.brain_history.record(log_entry);
        }
    }
}

/// Build 72-dim feature vector for the defender brain from incident + agent state.
fn build_brain_features(
    incident: &innerwarden_core::incident::Incident,
    state: &AgentState,
) -> [f32; 72] {
    use innerwarden_core::event::Severity;

    let mut f = [0.0f32; 72];

    // [0-3] severity
    match incident.severity {
        Severity::Low | Severity::Info | Severity::Debug => f[0] = 1.0,
        Severity::Medium => f[1] = 1.0,
        Severity::High => f[2] = 1.0,
        Severity::Critical => f[3] = 1.0,
    }

    // [5] composite score — use next_chain_id as proxy for chains detected
    // (completed_chains is private, but chain_id counter reflects activity)
    f[5] = 0.0; // Will be enriched when scoring integration is complete

    // [12-17] detector flags from incident_id prefix
    let det = incident.incident_id.split(':').next().unwrap_or("");
    f[12] = if det == "ssh_bruteforce" { 1.0 } else { 0.0 };
    f[13] = if det == "reverse_shell" { 1.0 } else { 0.0 };
    f[14] = if det == "privesc" { 1.0 } else { 0.0 };
    f[15] = if det == "ransomware" { 1.0 } else { 0.0 };
    f[16] = if det == "log_tampering" { 1.0 } else { 0.0 };
    f[17] = if det == "web_shell" { 1.0 } else { 0.0 };

    f
}
