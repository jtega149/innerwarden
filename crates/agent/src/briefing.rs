//! Daily AI Intelligence Briefing — generates structured threat summary from knowledge graph.

use chrono::{DateTime, Utc};
use serde::Serialize;
use std::sync::{Arc, RwLock};

use crate::knowledge_graph::types::{Node, NodeType, Relation};
use crate::knowledge_graph::KnowledgeGraph;

/// The generated briefing result.
#[derive(Debug, Clone, Serialize)]
pub struct Briefing {
    pub generated_at: DateTime<Utc>,
    pub date: String,
    pub threat_level: String,
    pub summary: String,
}

/// Build the structured context from the knowledge graph for LLM consumption.
/// Separates contained (resolved) from unresolved, marks internal IPs,
/// and shows actions already taken.
pub fn build_briefing_context(kg: &Arc<RwLock<KnowledgeGraph>>) -> String {
    let graph = kg.read().unwrap();

    let incident_nodes = graph.nodes_of_type(NodeType::Incident);

    // Categorize incidents
    let mut contained = 0usize;
    let mut ignored = 0usize;
    let mut unresolved = 0usize;
    let mut unresolved_high_crit = 0usize;
    let mut by_detector: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();
    let mut by_severity: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();
    let mut actions_taken: Vec<String> = Vec::new();
    let mut unresolved_list: Vec<(String, String, String)> = Vec::new(); // (severity, title, entity)

    for &id in &incident_nodes {
        if let Some(Node::Incident {
            detector,
            severity,
            title,
            decision,
            decision_target,
            auto_executed,
            ..
        }) = graph.get_node(id)
        {
            *by_detector.entry(detector.clone()).or_default() += 1;
            *by_severity.entry(severity.to_lowercase()).or_default() += 1;

            match decision.as_deref() {
                Some("block_ip") => {
                    contained += 1;
                    let target = decision_target.as_deref().unwrap_or("?");
                    let mode = if *auto_executed {
                        "auto-blocked"
                    } else {
                        "manual"
                    };
                    actions_taken.push(format!("Blocked IP {} ({}) — {}", target, mode, title));
                }
                Some("monitor") => {
                    contained += 1;
                }
                Some("honeypot") => {
                    contained += 1;
                }
                Some("kill_process") => {
                    contained += 1;
                    actions_taken.push(format!("Killed process — {}", title));
                }
                Some("suspend_user_sudo") => {
                    contained += 1;
                    actions_taken.push(format!("Suspended sudo — {}", title));
                }
                Some("ignore") => {
                    ignored += 1;
                }
                Some(_) => {
                    contained += 1;
                }
                None => {
                    unresolved += 1;
                    let sev = severity.to_lowercase();
                    if sev == "high" || sev == "critical" {
                        unresolved_high_crit += 1;
                        let entity = graph
                            .outgoing_edges(id)
                            .iter()
                            .find(|e| e.relation == Relation::TriggeredBy)
                            .and_then(|e| graph.get_node(e.to))
                            .map(|n| n.label())
                            .unwrap_or_default();
                        if unresolved_list.len() < 10 {
                            unresolved_list.push((sev, title.clone(), entity));
                        }
                    }
                }
            }
        }
    }

    // Top attackers — ONLY external IPs, annotate if already blocked
    let mut ip_data: std::collections::HashMap<String, (usize, Vec<String>, bool)> =
        std::collections::HashMap::new();
    for &inc_id in &incident_nodes {
        if let Some(Node::Incident {
            detector,
            decision,
            decision_target,
            ..
        }) = graph.get_node(inc_id)
        {
            for edge in graph.outgoing_edges(inc_id) {
                if edge.relation != Relation::TriggeredBy {
                    continue;
                }
                if let Some(Node::Ip {
                    addr, is_internal, ..
                }) = graph.get_node(edge.to)
                {
                    if *is_internal {
                        continue;
                    } // Skip server's own IPs
                    let entry = ip_data
                        .entry(addr.clone())
                        .or_insert((0, Vec::new(), false));
                    entry.0 += 1;
                    if !entry.1.contains(detector) {
                        entry.1.push(detector.clone());
                    }
                    if decision.as_deref() == Some("block_ip")
                        && decision_target.as_deref() == Some(addr.as_str())
                    {
                        entry.2 = true; // Already blocked
                    }
                }
            }
        }
    }
    let mut top_attackers: Vec<_> = ip_data.into_iter().collect();
    top_attackers.sort_by(|a, b| b.1 .0.cmp(&a.1 .0));
    top_attackers.truncate(10);

    // Detectors sorted
    let mut sorted_detectors: Vec<_> = by_detector.into_iter().collect();
    sorted_detectors.sort_by(|a, b| b.1.cmp(&a.1));
    sorted_detectors.truncate(10);

    // Threat level — based on UNRESOLVED, not total
    let _threat_level = if unresolved_high_crit > 5 {
        "CRITICAL"
    } else if unresolved_high_crit > 0 {
        "ELEVATED"
    } else if unresolved > 10 {
        "MODERATE"
    } else {
        "LOW"
    };

    // Build context
    let total = incident_nodes.len();
    let mut ctx = format!(
        "SECURITY INTELLIGENCE CONTEXT — {}\n\n\
         SITUATION STATUS:\n\
         - Total incidents today: {}\n\
         - CONTAINED (AI blocked/monitored/responded): {} — these are RESOLVED, not active threats\n\
         - IGNORED by AI (noise/false positives): {} — confirmed non-threats\n\
         - UNRESOLVED (no AI decision yet): {} — of which {} are high/critical severity\n\
         - The system is in GUARD mode: AI auto-blocks high-confidence threats\n\n\
         IMPORTANT: {} of {} incidents are already handled. The system is actively defending.\n\
         Only {} incident{} need{} human attention.\n\n",
        Utc::now().format("%Y-%m-%d"),
        total,
        contained,
        ignored,
        unresolved, unresolved_high_crit,
        contained + ignored, total,
        unresolved_high_crit,
        if unresolved_high_crit == 1 { "" } else { "s" },
        if unresolved_high_crit == 1 { "s" } else { "" },
    );

    if !actions_taken.is_empty() {
        ctx.push_str("ACTIONS ALREADY TAKEN BY AI:\n");
        for (i, action) in actions_taken.iter().take(10).enumerate() {
            ctx.push_str(&format!("  {}. {}\n", i + 1, action));
        }
        if actions_taken.len() > 10 {
            ctx.push_str(&format!(
                "  ... and {} more actions\n",
                actions_taken.len() - 10
            ));
        }
        ctx.push('\n');
    }

    if !unresolved_list.is_empty() {
        ctx.push_str("UNRESOLVED THREATS NEEDING ATTENTION:\n");
        for (sev, title, entity) in &unresolved_list {
            ctx.push_str(&format!(
                "  - [{}] {} ({})\n",
                sev.to_uppercase(),
                title,
                entity
            ));
        }
        ctx.push('\n');
    }

    ctx.push_str("TOP ATTACKERS (external IPs only):\n");
    for (ip, (count, dets, blocked)) in &top_attackers {
        let status = if *blocked { " [ALREADY BLOCKED]" } else { "" };
        ctx.push_str(&format!(
            "  - {} — {} incidents, detectors: {}{}\n",
            ip,
            count,
            dets.join(", "),
            status
        ));
    }

    ctx.push_str("\nDETECTOR ACTIVITY:\n");
    for (det, count) in &sorted_detectors {
        ctx.push_str(&format!("  - {}: {}\n", det, count));
    }

    ctx.push_str(&format!(
        "\nKNOWLEDGE GRAPH: {} nodes, {} edges\n\
         EVENTS INGESTED: {}\n",
        graph.metrics().node_count,
        graph.metrics().edge_count,
        graph.total_events_ingested,
    ));

    ctx
}

/// The LLM prompt for generating the briefing.
pub fn briefing_prompt(context: &str) -> String {
    format!(
        "You are a senior security analyst writing a daily briefing for a server operator.\n\
         \n\
         CRITICAL RULES:\n\
         - Incidents marked CONTAINED are RESOLVED — do NOT treat them as active threats\n\
         - Incidents marked IGNORED are confirmed noise — do NOT recommend action on them\n\
         - Only UNRESOLVED incidents need attention\n\
         - IPs marked [ALREADY BLOCKED] are handled — do NOT recommend blocking them again\n\
         - Internal IPs (10.x, 192.168.x, 127.x) are the server itself — NOT attackers\n\
         - The system AUTO-BLOCKS threats. Most detections are already handled.\n\
         \n\
         Write a concise briefing with these sections:\n\
         1. **THREAT LEVEL** — one word + one sentence. Base it on UNRESOLVED count, not total.\n\
         2. **EXECUTIVE SUMMARY** — 2-3 sentences. Be accurate about what's resolved vs active.\n\
         3. **WHAT WAS HANDLED** — bullet list of AI actions taken (blocks, kills, monitors)\n\
         4. **NEEDS ATTENTION** — only UNRESOLVED high/critical threats with specific actions\n\
         5. **RECOMMENDATIONS** — 2-3 actionable steps for TODAY\n\
         \n\
         Be accurate. Do not exaggerate. If most threats are contained, say so.\n\
         \n\
         ---\n\
         \n\
         {context}"
    )
}

/// Parse the LLM response into a structured Briefing.
pub fn parse_briefing(llm_response: &str, context_threat_level: &str) -> Briefing {
    Briefing {
        generated_at: Utc::now(),
        date: Utc::now().format("%Y-%m-%d").to_string(),
        threat_level: context_threat_level.to_string(),
        summary: llm_response.to_string(),
    }
}
