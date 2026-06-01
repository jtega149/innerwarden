use std::path::Path;

use crate::{bot_helpers, config, knowledge_graph, telegram};

pub(crate) fn incident_detector(incident_id: &str) -> &str {
    incident_id.split(':').next().unwrap_or("unknown")
}

/// Returns the current guardian mode based on responder configuration.
pub(crate) fn guardian_mode(cfg: &config::AgentConfig) -> telegram::GuardianMode {
    if !cfg.responder.enabled {
        telegram::GuardianMode::Watch
    } else if cfg.responder.dry_run {
        telegram::GuardianMode::DryRun
    } else {
        telegram::GuardianMode::Guard
    }
}

/// Builds a rich system-state context string injected into every AI chat call.
/// The AI uses this to answer self-awareness questions accurately and give
/// correct configuration advice.
pub(crate) fn build_agent_context(
    cfg: &config::AgentConfig,
    data_dir: &Path,
    kg: &std::sync::Arc<std::sync::RwLock<knowledge_graph::KnowledgeGraph>>,
) -> String {
    let mode = guardian_mode(cfg);
    let today = chrono::Local::now()
        .date_naive()
        .format("%Y-%m-%d")
        .to_string();
    let incident_count = bot_helpers::graph_count(kg, "incidents");
    // Canonical decisions-today count (restart-robust); the KG decision
    // count resets on reboot. See NUMBER_CONSISTENCY "decisions made today".
    let decision_count = crate::decisions::count_decisions_for_date(data_dir, &today);
    let host = std::env::var("HOSTNAME")
        .or_else(|_| std::fs::read_to_string("/etc/hostname").map(|s| s.trim().to_string()))
        .unwrap_or_else(|_| "unknown".to_string());

    let skills_list = cfg.responder.allowed_skills.join(", ");
    let block_backend = &cfg.responder.block_backend;
    let ai_status = if cfg.ai.enabled {
        format!(
            "ENABLED - provider={}, model={}",
            cfg.ai.provider, cfg.ai.model
        )
    } else {
        "DISABLED".to_string()
    };
    let responder_status = if !cfg.responder.enabled {
        "DISABLED (watch-only mode)".to_string()
    } else if cfg.responder.dry_run {
        "ENABLED - dry-run (simulates actions, no real execution)".to_string()
    } else {
        format!("ENABLED - live mode (backend={block_backend})")
    };
    let telegram_status = if cfg.telegram.enabled {
        "ENABLED"
    } else {
        "DISABLED"
    };
    let abuseipdb_status = if cfg.abuseipdb.enabled {
        "ENABLED"
    } else {
        "DISABLED"
    };
    let geoip_status = if cfg.geoip.enabled {
        "ENABLED"
    } else {
        "DISABLED"
    };
    let slack_status = if cfg.slack.enabled {
        "ENABLED"
    } else {
        "DISABLED"
    };
    let cloudflare_status = if cfg.cloudflare.enabled {
        "ENABLED"
    } else {
        "DISABLED"
    };

    format!(
        "=== INNERWARDEN SYSTEM STATE ===\n\
         Host: {host}\n\
         Version: {version}\n\
         Mode: {mode_label} - {mode_desc}\n\
         Data dir: {data_dir}\n\
         \n\
         Today ({today}): {incident_count} intrusion attempts, {decision_count} actions taken\n\
         \n\
         === ACTIVE CONFIGURATION ===\n\
         Responder: {responder_status}\n\
         Allowed skills: {skills_list}\n\
         AI analysis: {ai_status}\n\
         Telegram bot: {telegram_status}\n\
         AbuseIPDB enrichment: {abuseipdb_status}\n\
         GeoIP enrichment: {geoip_status}\n\
         Slack notifications: {slack_status}\n\
         Cloudflare edge blocking: {cloudflare_status}\n\
         \n\
         Capabilities are managed with `innerwarden enable/disable <id>`; `innerwarden status` shows the full overview. (The live server pulse follows below.)\n\
         ",
        host = host,
        version = env!("CARGO_PKG_VERSION"),
        mode_label = mode.label(),
        mode_desc = mode.description(),
        data_dir = data_dir.display(),
    )
}

/// The live server "pulse" injected into the chat context (spec 067 Phase 4)
/// so the AI answers with the authority of something that lives on the box, not
/// a config recital. Carries the host's actual defensive posture and who is
/// attacking right now. Empty when there is nothing live to report.
pub(crate) fn live_server_context(
    posture: &crate::posture::HostPosture,
    attacker_profiles: &std::collections::HashMap<String, crate::attacker_intel::AttackerProfile>,
    baseline: &crate::baseline::BaselineStore,
) -> String {
    let mut body = String::new();
    if let Some(p) = crate::posture::ai_context_line(posture) {
        body.push_str(&format!("Host posture: {p}\n"));
    }
    let mut atk: Vec<(&str, u8)> = attacker_profiles
        .iter()
        .map(|(ip, p)| (ip.as_str(), p.risk_score))
        .filter(|(_, r)| *r > 0)
        .collect();
    atk.sort_by(|a, b| b.1.cmp(&a.1));
    let top: Vec<String> = atk
        .iter()
        .take(5)
        .map(|(ip, r)| format!("{ip} (risk {r})"))
        .collect();
    if !top.is_empty() {
        body.push_str(&format!(
            "Top attackers tracked right now: {}\n",
            top.join(", ")
        ));
    }

    // Baseline: what is normal for THIS host, and what stood out lately. The
    // resident's "this is unusual for us" sense. Skipped on a brand-new store
    // with nothing learned and no anomalies, so the pulse stays empty until
    // there is something real to report.
    if baseline.is_mature()
        || baseline.total_observations() > 0
        || !baseline.recent_anomalies.is_empty()
    {
        let maturity = if baseline.is_mature() {
            "trained".to_string()
        } else {
            format!("learning (day {})", baseline.training_days())
        };
        body.push_str(&format!(
            "Baseline: {maturity}, {} events learned",
            baseline.total_observations()
        ));
        let unusual: Vec<String> = baseline
            .recent_anomalies
            .iter()
            .rev()
            .take(3)
            .map(|a| a.description.clone())
            .collect();
        if !unusual.is_empty() {
            body.push_str(&format!(
                "; unusual for this host lately: {}",
                unusual.join("; ")
            ));
        }
        body.push('\n');
    }

    if body.is_empty() {
        String::new()
    } else {
        format!("=== LIVE SERVER PULSE ===\n{}", body.trim_end())
    }
}

/// Merge a persona string, the runtime snapshot, recent incidents, and recent
/// decisions into one system prompt. Empty-string inputs are skipped so the
/// prompt never carries dangling "RECENT INCIDENTS:" headers with no body.
/// Centralised here so every chat surface (Telegram bot, dashboard briefing,
/// dashboard explain) composes the same prompt shape.
pub(crate) fn compose_system_prompt(
    persona: &str,
    runtime_snapshot: &str,
    recent_incidents: &str,
    recent_decisions: &str,
) -> String {
    let mut out = String::with_capacity(
        persona.len()
            + runtime_snapshot.len()
            + recent_incidents.len()
            + recent_decisions.len()
            + 128,
    );
    out.push_str(persona.trim_end());
    if !runtime_snapshot.is_empty() {
        out.push_str("\n\n");
        out.push_str(runtime_snapshot.trim_end());
    }
    if !recent_incidents.is_empty() {
        out.push_str("\n\nRECENT INCIDENTS:\n");
        out.push_str(recent_incidents.trim_end());
    }
    if !recent_decisions.is_empty() {
        out.push_str("\n\nRECENT DECISIONS:\n");
        out.push_str(recent_decisions.trim_end());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::knowledge_graph::types::Node;

    #[test]
    fn incident_detector_parses_prefix() {
        assert_eq!(
            incident_detector("ssh_bruteforce:1.2.3.4:abc"),
            "ssh_bruteforce"
        );
        assert_eq!(incident_detector("singleword"), "singleword");
    }

    #[test]
    fn guardian_mode_maps_responder_state() {
        let mut cfg = config::AgentConfig::default();
        cfg.responder.enabled = false;
        assert!(matches!(guardian_mode(&cfg), telegram::GuardianMode::Watch));

        cfg.responder.enabled = true;
        cfg.responder.dry_run = true;
        assert!(matches!(
            guardian_mode(&cfg),
            telegram::GuardianMode::DryRun
        ));

        cfg.responder.dry_run = false;
        assert!(matches!(guardian_mode(&cfg), telegram::GuardianMode::Guard));
    }

    #[test]
    fn build_agent_context_includes_runtime_snapshot() {
        let mut cfg = config::AgentConfig::default();
        cfg.ai.enabled = true;
        cfg.ai.provider = "openai".to_string();
        cfg.ai.model = "gpt-5".to_string();
        cfg.responder.enabled = true;
        cfg.responder.dry_run = false;
        cfg.responder.block_backend = "ufw".to_string();
        cfg.responder.allowed_skills = vec!["block-ip-ufw".to_string(), "honeypot".to_string()];
        cfg.telegram.enabled = true;
        cfg.abuseipdb.enabled = true;
        cfg.geoip.enabled = true;
        cfg.slack.enabled = true;
        cfg.cloudflare.enabled = true;

        let mut graph = knowledge_graph::KnowledgeGraph::new();
        let now = chrono::Utc::now();
        graph.add_node(Node::Incident {
            incident_id: "ssh_bruteforce:198.51.100.10:1".to_string(),
            detector: "ssh_bruteforce".to_string(),
            severity: "high".to_string(),
            title: "SSH brute-force".to_string(),
            summary: "many attempts".to_string(),
            ts: now,
            mitre_ids: vec![],
            decision: Some("block_ip".to_string()),
            confidence: Some(0.95),
            decision_reason: Some("clear brute force".to_string()),
            decision_target: Some("198.51.100.10".to_string()),
            auto_executed: true,
            is_allowlisted: false,
            false_positive: false,
            fp_reporter: None,
            fp_reported_at: None,
            research_only: false,
        });
        graph.add_node(Node::Incident {
            incident_id: "port_scan:198.51.100.11:2".to_string(),
            detector: "port_scan".to_string(),
            severity: "medium".to_string(),
            title: "Port scan".to_string(),
            summary: "multiple ports".to_string(),
            ts: now,
            mitre_ids: vec![],
            decision: None,
            confidence: None,
            decision_reason: None,
            decision_target: None,
            auto_executed: false,
            is_allowlisted: false,
            false_positive: false,
            fp_reporter: None,
            fp_reported_at: None,
            research_only: false,
        });
        let kg = std::sync::Arc::new(std::sync::RwLock::new(graph));

        // "actions taken" now reads the canonical decisions log (not the KG
        // node count), so seed one decision for today's date.
        let dir = tempfile::tempdir().expect("tempdir");
        let today = chrono::Local::now()
            .date_naive()
            .format("%Y-%m-%d")
            .to_string();
        std::fs::write(
            dir.path().join(format!("decisions-{today}.jsonl")),
            "{\"action_type\":\"block_ip\"}\n",
        )
        .expect("write decisions log");

        let context = build_agent_context(&cfg, dir.path(), &kg);

        assert!(context.contains("INNERWARDEN SYSTEM STATE"));
        assert!(context.contains("Mode: 🟢 GUARD"));
        assert!(context.contains("intrusion attempts, 1 actions taken"));
        assert!(context.contains("AI analysis: ENABLED - provider=openai, model=gpt-5"));
        assert!(context.contains("Telegram bot: ENABLED"));
        assert!(context.contains("Cloudflare edge blocking: ENABLED"));
        assert!(context.contains("Allowed skills: block-ip-ufw, honeypot"));
    }

    #[test]
    fn compose_system_prompt_includes_persona_only_when_others_empty() {
        let out = compose_system_prompt("persona-body", "", "", "");
        assert_eq!(out, "persona-body");
    }

    #[test]
    fn compose_system_prompt_appends_runtime_when_present() {
        let out = compose_system_prompt("p", "SNAP", "", "");
        assert!(out.starts_with("p"));
        assert!(out.contains("SNAP"));
        assert!(!out.contains("RECENT INCIDENTS"));
        assert!(!out.contains("RECENT DECISIONS"));
    }

    #[test]
    fn compose_system_prompt_labels_recent_sections() {
        let out = compose_system_prompt(
            "p",
            "SNAP",
            "[high] title - summary",
            "- block_ip 1.2.3.4 (auto)",
        );
        assert!(out.contains("RECENT INCIDENTS:\n[high] title - summary"));
        assert!(out.contains("RECENT DECISIONS:\n- block_ip 1.2.3.4 (auto)"));
        // Sections must appear in the stable order persona -> snapshot -> incidents -> decisions.
        let idx_snap = out.find("SNAP").unwrap();
        let idx_inc = out.find("RECENT INCIDENTS").unwrap();
        let idx_dec = out.find("RECENT DECISIONS").unwrap();
        assert!(idx_snap < idx_inc && idx_inc < idx_dec);
    }

    #[test]
    fn compose_system_prompt_omits_headers_for_empty_sections() {
        // An empty decisions string should not leave a dangling "RECENT
        // DECISIONS:" header in the prompt.
        let out = compose_system_prompt("p", "", "[high] x - y", "");
        assert!(out.contains("RECENT INCIDENTS"));
        assert!(!out.contains("RECENT DECISIONS"));
    }

    #[test]
    fn test_incident_detector_edge_cases() {
        assert_eq!(incident_detector(""), "");
        assert_eq!(incident_detector(":"), "");
        assert_eq!(incident_detector("ssh:brute:force"), "ssh");
    }

    #[test]
    fn test_guardian_mode_default_state() {
        let cfg = config::AgentConfig::default();
        // default responder.enabled is false
        assert!(matches!(guardian_mode(&cfg), telegram::GuardianMode::Watch));
    }

    #[test]
    fn test_build_agent_context_all_disabled() {
        let mut cfg = config::AgentConfig::default();
        // Explicitly disable things that might be enabled by default in AgentConfig::default()
        cfg.firmware.enabled = false;
        cfg.hypervisor.enabled = false;
        cfg.killchain.enabled = false;
        cfg.dna.enabled = false;
        cfg.shield.enabled = false;
        cfg.narrative.enabled = false;
        cfg.briefing.enabled = false;

        let graph = knowledge_graph::KnowledgeGraph::new();
        let kg = std::sync::Arc::new(std::sync::RwLock::new(graph));

        let context = build_agent_context(&cfg, std::path::Path::new("/var/lib/innerwarden"), &kg);

        assert!(context.contains("Mode: 🔵 WATCH"));
        assert!(context.contains("AI analysis: DISABLED"));
        assert!(context.contains("Telegram bot: DISABLED"));
        assert!(context.contains("AbuseIPDB enrichment: DISABLED"));
        assert!(context.contains("GeoIP enrichment: DISABLED"));
        assert!(context.contains("Slack notifications: DISABLED"));
        assert!(context.contains("Cloudflare edge blocking: DISABLED"));
    }

    #[test]
    fn live_server_context_carries_posture_and_top_attackers_sorted() {
        use crate::posture::{sshd, HostPosture};
        let mut p = HostPosture::default();
        p.sshd.probe_state = sshd::ProbeState::Ok;
        p.sshd.password_authentication = sshd::SshdToggle::No;

        let mut profiles = std::collections::HashMap::new();
        let mut hi = crate::attacker_intel::new_profile("45.148.10.99", chrono::Utc::now());
        hi.risk_score = 90;
        profiles.insert("45.148.10.99".to_string(), hi);
        let mut lo = crate::attacker_intel::new_profile("1.2.3.4", chrono::Utc::now());
        lo.risk_score = 50;
        profiles.insert("1.2.3.4".to_string(), lo);

        let ctx = live_server_context(&p, &profiles, &crate::baseline::BaselineStore::new());
        assert!(ctx.contains("LIVE SERVER PULSE"));
        assert!(
            ctx.contains("PasswordAuthentication=No"),
            "posture must be carried"
        );
        assert!(ctx.contains("45.148.10.99 (risk 90)"));
        let pos_hi = ctx.find("45.148.10.99").unwrap();
        let pos_lo = ctx.find("1.2.3.4").unwrap();
        assert!(pos_hi < pos_lo, "higher-risk attacker listed first");
    }

    #[test]
    fn live_server_context_empty_when_nothing_live() {
        // Default posture (Pending probe), no attackers, fresh baseline.
        let p = crate::posture::HostPosture::default();
        let profiles = std::collections::HashMap::new();
        let baseline = crate::baseline::BaselineStore::new();
        assert!(live_server_context(&p, &profiles, &baseline).is_empty());
    }

    #[test]
    fn live_server_context_surfaces_baseline_anomalies() {
        // Spec 067 Phase 4b: the pulse carries "what is unusual for THIS host".
        let p = crate::posture::HostPosture::default();
        let profiles = std::collections::HashMap::new();
        let mut baseline = crate::baseline::BaselineStore::new();
        let report = crate::baseline::AnomalyReport {
            anomaly_type: crate::baseline::AnomalyType::ProcessLineage,
            description: "nginx spawned a shell (never seen before)".to_string(),
            expected: "nginx -> worker".to_string(),
            observed: "nginx -> sh".to_string(),
            confidence: 0.9,
            severity: innerwarden_core::event::Severity::High,
        };
        baseline.record_anomaly(&report, None);

        let ctx = live_server_context(&p, &profiles, &baseline);
        assert!(ctx.contains("LIVE SERVER PULSE"));
        assert!(ctx.contains("Baseline:"), "baseline line missing");
        assert!(
            ctx.contains("unusual for this host lately: nginx spawned a shell"),
            "baseline anomaly must surface; got:\n{ctx}"
        );
    }
}
