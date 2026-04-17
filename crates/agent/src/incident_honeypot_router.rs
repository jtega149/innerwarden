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
}
