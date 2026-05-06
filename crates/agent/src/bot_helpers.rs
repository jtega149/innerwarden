use std::path::Path;

use tracing::{info, warn};

use crate::{config, decisions, knowledge_graph, telegram, two_factor, AgentState};

// ---------------------------------------------------------------------------
// Phase 6B: Graph-based bot helpers (no JSONL reads)
// ---------------------------------------------------------------------------

/// Count incidents or decisions from the knowledge graph.
/// `count_type` selects what to count: "incidents" or "decisions".
pub(crate) fn graph_count(
    kg: &std::sync::Arc<std::sync::RwLock<knowledge_graph::KnowledgeGraph>>,
    count_type: &str,
) -> usize {
    use knowledge_graph::types::{Node, NodeType};
    let graph = kg.read().unwrap();
    match count_type {
        "incidents" => graph.nodes_of_type(NodeType::Incident).len(),
        "decisions" => {
            let mut n = 0;
            for id in graph.nodes_of_type(NodeType::Incident) {
                if let Some(Node::Incident {
                    decision: Some(_), ..
                }) = graph.get_node(id)
                {
                    n += 1;
                }
            }
            n
        }
        _ => 0,
    }
}

/// Read the last N incidents from graph, formatted for Telegram display.
pub(crate) fn graph_last_incidents(
    kg: &std::sync::Arc<std::sync::RwLock<knowledge_graph::KnowledgeGraph>>,
    n: usize,
) -> String {
    use knowledge_graph::types::{Node, NodeType, Relation};
    let graph = kg.read().unwrap();

    let mut items: Vec<(chrono::DateTime<chrono::Utc>, String, String, String)> = Vec::new();

    for id in graph.nodes_of_type(NodeType::Incident) {
        if let Some(Node::Incident {
            severity,
            title,
            ts,
            ..
        }) = graph.get_node(id)
        {
            // Find first entity via TriggeredBy
            let entity = graph
                .outgoing_edges(id)
                .iter()
                .find(|e| e.relation == Relation::TriggeredBy)
                .and_then(|e| graph.get_node(e.to))
                .map(|n| n.label())
                .unwrap_or_else(|| "?".to_string());

            items.push((*ts, severity.to_lowercase(), title.clone(), entity));
        }
    }

    if items.is_empty() {
        return "\u{1f507} Clean slate - no intrusion attempts today.".to_string();
    }

    // Sort by ts descending, take last N
    items.sort_by(|a, b| b.0.cmp(&a.0));
    items.truncate(n);

    let now = chrono::Utc::now();
    let sev_icon = |s: &str| match s {
        "critical" => "\u{1f534}",
        "high" => "\u{1f7e0}",
        "medium" => "\u{1f7e1}",
        "low" => "\u{1f7e2}",
        _ => "\u{26aa}",
    };

    let formatted: Vec<String> = items
        .into_iter()
        .map(|(ts, severity, title, entity)| {
            let icon = sev_icon(&severity);
            let mins = now.signed_duration_since(ts).num_minutes();
            let age = if mins < 1 {
                "just now".to_string()
            } else if mins < 60 {
                format!("{mins}m ago")
            } else {
                format!("{}h ago", mins / 60)
            };
            format!("{icon} {title}\n   <code>{entity}</code> \u{b7} {age}")
        })
        .collect();

    format!(
        "\u{1f6a8} <b>Recent threats</b> (last {})\n\n{}",
        formatted.len(),
        formatted.join("\n\n")
    )
}

/// Row collected for the Telegram "last decisions" summary:
/// (timestamp, action, target, confidence, auto_executed).
type DecisionRow = (
    chrono::DateTime<chrono::Utc>,
    String,
    String,
    Option<f32>,
    bool,
);

/// Read the last N decisions from graph, formatted for Telegram display.
pub(crate) fn graph_last_decisions(
    kg: &std::sync::Arc<std::sync::RwLock<knowledge_graph::KnowledgeGraph>>,
    n: usize,
) -> String {
    use knowledge_graph::types::{Node, NodeType};
    let graph = kg.read().unwrap();

    let mut items: Vec<DecisionRow> = Vec::new();

    for id in graph.nodes_of_type(NodeType::Incident) {
        if let Some(Node::Incident {
            ts,
            decision: Some(action),
            decision_target,
            confidence,
            auto_executed,
            ..
        }) = graph.get_node(id)
        {
            let target = decision_target.as_deref().unwrap_or("?").to_string();
            items.push((*ts, action.clone(), target, *confidence, *auto_executed));
        }
    }

    if items.is_empty() {
        return "\u{2696}\u{fe0f} No decisions yet today - standing by.".to_string();
    }

    items.sort_by(|a, b| b.0.cmp(&a.0));
    items.truncate(n);

    let action_icon = |a: &str| {
        if a.contains("block") {
            "\u{1f6ab}"
        } else if a.contains("suspend") {
            "\u{1f451}"
        } else if a.contains("honeypot") {
            "\u{1f36f}"
        } else if a.contains("monitor") {
            "\u{1f441}"
        } else if a.contains("kill") {
            "\u{1f480}"
        } else if a.contains("ignore") {
            "\u{1f648}"
        } else {
            "\u{26a1}"
        }
    };

    let formatted: Vec<String> = items
        .into_iter()
        .map(|(_, action, target, confidence, auto_executed)| {
            let icon = action_icon(&action);
            let pct = (confidence.unwrap_or(0.0) * 100.0) as u32;
            let mode = if auto_executed { "live" } else { "sim" };
            format!("{icon} {action} <code>{target}</code>\n   {pct}% confidence \u{b7} {mode}")
        })
        .collect();

    format!(
        "\u{2696}\u{fe0f} <b>Recent decisions</b> (last {})\n\n{}",
        formatted.len(),
        formatted.join("\n\n")
    )
}

/// Spec 043 Phase 2 — deep KG-derived context for the operator's `/ask`
/// (Telegram `__ask__:` branch in `bot_commands.rs`). Pre-Phase-2 the
/// /ask prompt only carried the last 3 incident titles + last 5 decision
/// targets, which produced operator-reported "muito basico" answers
/// because the LLM had no signal beyond manchetes. This helper enriches
/// the prompt with the graph data already ingested but unused:
///
/// 1. Recent incidents enriched with severity, title, summary, IP risk
///    score (from AbuseIPDB), threat-intel datasets that matched, and
///    YARA matches on related files.
/// 2. Recent decisions (action + target + auto/proposed mode).
/// 3. High-risk entities snapshot — IPs with risk_score > 70 OR with
///    related campaign membership. Helps the LLM ground "is this IP
///    known to us?" questions without a separate tool-call.
/// 4. Subgraph-for-question — when the question text mentions an IP
///    (regex match on dotted-quad), pull the IP's depth-1 neighborhood
///    and attach it as a compact entity → relation list.
///
/// Hard 8000-char cap on the entire output. Truncates from the end of
/// section 4 → 3 → 2 → 1 (most expendable first). The cap protects
/// LLM cost on hosts where the operator runs paid Anthropic / OpenAI;
/// Ollama on `ollama` is free but the cap still guards latency.
///
/// No config gate — pure prompt enrichment, zero behavior change. Used
/// as a drop-in for the legacy `graph_last_incidents_raw` +
/// `graph_last_decisions_raw` pair at the `/ask` call site only.
pub(crate) fn ask_context_deep(
    kg: &std::sync::Arc<std::sync::RwLock<knowledge_graph::KnowledgeGraph>>,
    question: &str,
    budget_chars: usize,
) -> String {
    use knowledge_graph::types::{Node, NodeType, Relation};
    let graph = kg.read().unwrap();

    // ── Section 1: recent incidents (top 5) with KG-derived enrichment.
    // Tuple is (ts, severity, title, summary, related_ip_risk, related_ip_datasets).
    // Factored to a local type alias to keep clippy::type_complexity quiet.
    type IncidentRow = (
        chrono::DateTime<chrono::Utc>,
        String,
        String,
        String,
        Option<u8>,
        Vec<String>,
    );
    let mut incidents: Vec<IncidentRow> = Vec::new();
    for id in graph.nodes_of_type(NodeType::Incident) {
        if let Some(Node::Incident {
            severity,
            title,
            summary,
            ts,
            ..
        }) = graph.get_node(id)
        {
            // Look up the related IP (outgoing TriggeredBy → IP) for
            // risk score + datasets enrichment.
            let mut related_risk: Option<u8> = None;
            let mut related_datasets: Vec<String> = Vec::new();
            for edge in graph.outgoing_edges(id) {
                if edge.relation != Relation::TriggeredBy {
                    continue;
                }
                if let Some(Node::Ip {
                    risk_score,
                    datasets,
                    ..
                }) = graph.get_node(edge.to)
                {
                    related_risk = Some(*risk_score);
                    related_datasets = datasets.clone();
                    break;
                }
            }
            let short: String = summary.chars().take(120).collect();
            incidents.push((
                *ts,
                severity.to_lowercase(),
                title.clone(),
                short,
                related_risk,
                related_datasets,
            ));
        }
    }
    incidents.sort_by(|a, b| b.0.cmp(&a.0));
    incidents.truncate(5);

    let section_1: String = if incidents.is_empty() {
        String::new()
    } else {
        let lines: Vec<String> = incidents
            .into_iter()
            .map(|(_, sev, title, summary, risk, datasets)| {
                let mut line = format!("[{sev}] {title} - {summary}");
                if let Some(r) = risk {
                    if r > 0 {
                        line.push_str(&format!(" (ip_risk={r})"));
                    }
                }
                if !datasets.is_empty() {
                    line.push_str(&format!(" (intel: {})", datasets.join(",")));
                }
                line
            })
            .collect();
        lines.join("\n")
    };

    // ── Section 2: recent decisions (top 5).
    let section_2 = {
        let mut items: Vec<(chrono::DateTime<chrono::Utc>, String, String, bool)> = Vec::new();
        for id in graph.nodes_of_type(NodeType::Incident) {
            if let Some(Node::Incident {
                ts,
                decision: Some(action),
                decision_target,
                auto_executed,
                ..
            }) = graph.get_node(id)
            {
                let target = decision_target.as_deref().unwrap_or("?").to_string();
                items.push((*ts, action.clone(), target, *auto_executed));
            }
        }
        items.sort_by(|a, b| b.0.cmp(&a.0));
        items.truncate(5);
        if items.is_empty() {
            String::new()
        } else {
            items
                .into_iter()
                .map(|(_, action, target, auto)| {
                    let mode = if auto { "auto" } else { "proposed" };
                    format!("- {action} {target} ({mode})")
                })
                .collect::<Vec<_>>()
                .join("\n")
        }
    };

    // ── Section 3: high-risk entities (IPs with risk > 70 OR
    // campaign membership).
    let section_3 = {
        let mut entries: Vec<(String, u8, u32)> = Vec::new();
        for id in graph.nodes_of_type(NodeType::Ip) {
            if let Some(Node::Ip {
                addr, risk_score, ..
            }) = graph.get_node(id)
            {
                let campaigns = graph
                    .outgoing_edges(id)
                    .iter()
                    .filter(|e| e.relation == Relation::MemberOf)
                    .count() as u32;
                if *risk_score > 70 || campaigns > 0 {
                    entries.push((addr.clone(), *risk_score, campaigns));
                }
            }
        }
        entries.sort_by(|a, b| b.1.cmp(&a.1).then(b.2.cmp(&a.2)));
        entries.truncate(10);
        if entries.is_empty() {
            String::new()
        } else {
            entries
                .into_iter()
                .map(|(ip, risk, campaigns)| {
                    if campaigns > 0 {
                        format!("- {ip} risk={risk} campaigns={campaigns}")
                    } else {
                        format!("- {ip} risk={risk}")
                    }
                })
                .collect::<Vec<_>>()
                .join("\n")
        }
    };

    // ── Section 4: subgraph for IPs mentioned in the question.
    // Only triggered when the question text contains a dotted-quad
    // that maps to an existing Ip node in the graph. Renders depth-1
    // neighborhood as compact entity → relation lines.
    let section_4 = {
        let ip_re = regex::Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").ok();
        let mut chunks: Vec<String> = Vec::new();
        if let Some(re) = ip_re {
            for cap in re.captures_iter(question).take(3) {
                let ip = cap.get(0).map(|m| m.as_str()).unwrap_or("");
                if ip.is_empty() {
                    continue;
                }
                if let Some(ip_id) = graph.find_by_ip(ip) {
                    let mut lines: Vec<String> = Vec::new();
                    for edge in graph.outgoing_edges(ip_id).iter().take(8) {
                        if let Some(other) = graph.get_node(edge.to) {
                            lines.push(format!("  -[{:?}]-> {}", edge.relation, node_label(other)));
                        }
                    }
                    for edge in graph.incoming_edges(ip_id).iter().take(8) {
                        if let Some(other) = graph.get_node(edge.from) {
                            lines.push(format!("  <-[{:?}]- {}", edge.relation, node_label(other)));
                        }
                    }
                    if !lines.is_empty() {
                        chunks.push(format!("{}:\n{}", ip, lines.join("\n")));
                    }
                }
            }
        }
        chunks.join("\n\n")
    };

    drop(graph);

    // ── Assemble with budget cap. Truncate sections most-expendable-first
    // (subgraph → high-risk → decisions → incidents) so the LLM always
    // keeps the highest-signal context (recent incidents).
    assemble_within_budget(&section_1, &section_2, &section_3, &section_4, budget_chars)
}

fn node_label(node: &knowledge_graph::types::Node) -> String {
    use knowledge_graph::types::Node;
    match node {
        Node::Process { comm, pid, .. } => format!("Process({comm}/{pid})"),
        Node::Ip {
            addr, risk_score, ..
        } => format!("Ip({addr}/risk={risk_score})"),
        Node::File { path, .. } => format!("File({})", path.chars().take(40).collect::<String>()),
        Node::User { name, .. } => format!("User({name})"),
        Node::Domain { name, .. } => format!("Domain({name})"),
        Node::Port { number, protocol } => format!("Port({number}/{protocol})"),
        Node::Container { container_id, .. } => {
            format!(
                "Container({})",
                &container_id.chars().take(12).collect::<String>()
            )
        }
        Node::Device {
            vendor, product, ..
        } => format!("Device({vendor}/{product})"),
        Node::System { hostname, .. } => format!("System({hostname})"),
        Node::Incident { incident_id, .. } => format!(
            "Incident({})",
            incident_id.chars().take(40).collect::<String>()
        ),
        Node::Campaign { campaign_id, .. } => format!("Campaign({campaign_id})"),
    }
}

/// Concatenate the four sections under `budget_chars`. Drops sections
/// from the end (subgraph first, incidents last) when over budget so
/// the highest-signal context survives. Each section gets a header so
/// the LLM can address them by name.
fn assemble_within_budget(
    incidents: &str,
    decisions: &str,
    high_risk: &str,
    subgraph: &str,
    budget_chars: usize,
) -> String {
    // Section ordering — keep highest signal first so LLM sees it even
    // if a buggy upstream truncates the prompt mid-string.
    let mut sections: Vec<(&str, &str)> = Vec::new();
    if !incidents.is_empty() {
        sections.push(("RECENT INCIDENTS", incidents));
    }
    if !decisions.is_empty() {
        sections.push(("RECENT DECISIONS", decisions));
    }
    if !high_risk.is_empty() {
        sections.push(("HIGH-RISK ENTITIES", high_risk));
    }
    if !subgraph.is_empty() {
        sections.push(("SUBGRAPH FOR QUESTION", subgraph));
    }

    // Pop most-expendable sections (end of list) until we fit.
    loop {
        let total: usize = sections
            .iter()
            .map(|(h, b)| h.len() + 2 + b.len() + 2)
            .sum();
        if total <= budget_chars || sections.is_empty() {
            break;
        }
        sections.pop();
    }

    sections
        .into_iter()
        .map(|(h, b)| format!("{h}:\n{b}"))
        .collect::<Vec<_>>()
        .join("\n\n")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TelegramTriageAction<'a> {
    AllowProc(&'a str),
    AllowIp(&'a str),
    ReportFp(&'a str),
}

pub(crate) fn parse_telegram_triage_action(incident_id: &str) -> Option<TelegramTriageAction<'_>> {
    if let Some(rest) = incident_id.strip_prefix("__allow_proc__:") {
        Some(TelegramTriageAction::AllowProc(rest))
    } else if let Some(rest) = incident_id.strip_prefix("__allow_ip__:") {
        Some(TelegramTriageAction::AllowIp(rest))
    } else {
        incident_id
            .strip_prefix("__fp__:")
            .map(TelegramTriageAction::ReportFp)
    }
}

pub(crate) fn sanitize_allowlist_process_name(raw: &str) -> Option<String> {
    let cleaned = raw.replace('"', "").replace('\n', " ").trim().to_string();
    (!cleaned.is_empty()).then_some(cleaned)
}

/// Handle triage sentinels from Telegram callbacks:
/// "__allow_proc__", "__allow_ip__", "__fp__".
/// Returns true when a triage callback was matched and handled.
pub(crate) fn handle_telegram_triage_action(
    result: &telegram::ApprovalResult,
    data_dir: &Path,
    cfg: &config::AgentConfig,
    state: &mut AgentState,
) -> bool {
    let Some(action) = parse_telegram_triage_action(&result.incident_id) else {
        return false;
    };

    match action {
        TelegramTriageAction::AllowProc(comm_raw) => {
            let Some(comm) = sanitize_allowlist_process_name(comm_raw) else {
                write_telegram_triage_audit(
                    state,
                    &result.incident_id,
                    &result.operator_name,
                    "allowlist_add",
                    None,
                    Some("process:(empty)".to_string()),
                    format!(
                        "Operator {} attempted to add empty process allowlist via Telegram",
                        result.operator_name
                    ),
                    "skipped:empty_process_name".to_string(),
                );
                tg_reply(state, "⚠️ Could not add empty process name to allowlist.");
                return true;
            };
            // 2FA gate: if enabled, store pending and ask for TOTP code
            if check_2fa_gate(
                state,
                cfg,
                &result.operator_name,
                two_factor::PendingActionType::AllowlistProcess(comm.clone()),
            ) {
                return true;
            }

            let allowlist_path = Path::new("/etc/innerwarden/allowlist.toml");
            let ts = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ");
            let reason = format!("Allowed via Telegram ({ts})");
            match telegram::append_to_allowlist(allowlist_path, "processes", &comm, &reason) {
                Ok(()) => {
                    // Log to allowlist history for undo support
                    telegram::log_allowlist_change(
                        data_dir,
                        &comm,
                        "processes",
                        &result.operator_name,
                        "add",
                    );
                    write_telegram_triage_audit(
                        state,
                        &result.incident_id,
                        &result.operator_name,
                        "allowlist_add",
                        None,
                        Some(format!("process:{comm}")),
                        format!(
                            "Operator {} added process '{}' to allowlist via Telegram",
                            result.operator_name, comm
                        ),
                        format!("allowlist_process_added:{comm}"),
                    );
                    info!(
                        operator = %result.operator_name,
                        comm = %comm,
                        path = %allowlist_path.display(),
                        "Telegram triage allowlist (process) applied"
                    );

                    // 2FA nudge if not enabled
                    let two_fa_enabled = cfg
                        .security
                        .as_ref()
                        .map(|s| s.two_factor_method != "none")
                        .unwrap_or(false);
                    let confirmation_suffix = if two_fa_enabled {
                        " (verified by TOTP)"
                    } else {
                        ""
                    };
                    let mut msg = format!(
                        "\u{2705} Allowed <code>{comm}</code>{confirmation_suffix}. Sensor will pick this up in up to 60s."
                    );
                    if !two_fa_enabled {
                        msg.push_str(
                            "\n\n\u{26a0}\u{fe0f} Allowlist changes are not protected by 2FA.\n\
                             Anyone with your bot token can silence alerts.",
                        );
                    }
                    if two_fa_enabled {
                        tg_reply(state, msg);
                    } else if let Some(ref tg) = state.telegram_client {
                        let tg = tg.clone();
                        tokio::spawn(async move {
                            let keyboard = serde_json::json!([
                                [
                                    { "text": "\u{1f510} Enable 2FA", "callback_data": "enable2fa" },
                                    { "text": "\u{1f44d} Dismiss", "callback_data": "dismiss2fa" }
                                ]
                            ]);
                            let _ = tg.send_text_with_keyboard(&msg, keyboard).await;
                        });
                    }
                }
                Err(e) => {
                    write_telegram_triage_audit(
                        state,
                        &result.incident_id,
                        &result.operator_name,
                        "allowlist_add",
                        None,
                        Some(format!("process:{comm}")),
                        format!(
                            "Operator {} failed to add process '{}' to allowlist via Telegram",
                            result.operator_name, comm
                        ),
                        format!(
                            "failed:{}",
                            e.to_string().chars().take(180).collect::<String>()
                        ),
                    );
                    warn!(
                        operator = %result.operator_name,
                        comm = %comm,
                        error = %e,
                        "failed to append process allowlist entry from Telegram"
                    );
                    tg_reply(
                        state,
                        format!(
                            "❌ Failed to allowlist <code>{comm}</code>: {}",
                            e.to_string().chars().take(180).collect::<String>()
                        ),
                    );
                }
            }
        }
        TelegramTriageAction::AllowIp(ip_raw) => {
            let ip = ip_raw.trim().to_string();
            if ip.parse::<std::net::IpAddr>().is_err() {
                write_telegram_triage_audit(
                    state,
                    &result.incident_id,
                    &result.operator_name,
                    "allowlist_add",
                    Some(ip.clone()),
                    None,
                    format!(
                        "Operator {} attempted to add invalid IP '{}' to allowlist via Telegram",
                        result.operator_name, ip
                    ),
                    "skipped:invalid_ip".to_string(),
                );
                warn!(
                    operator = %result.operator_name,
                    ip = %ip,
                    "invalid ip in Telegram allowlist callback"
                );
                tg_reply(
                    state,
                    format!("⚠️ Invalid IP for allowlist: <code>{ip}</code>"),
                );
                return true;
            }
            // 2FA gate: if enabled, store pending and ask for TOTP code
            if check_2fa_gate(
                state,
                cfg,
                &result.operator_name,
                two_factor::PendingActionType::AllowlistIp(ip.clone()),
            ) {
                return true;
            }

            let allowlist_path = Path::new("/etc/innerwarden/allowlist.toml");
            let ts = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ");
            let reason = format!("Allowed via Telegram ({ts})");
            match telegram::append_to_allowlist(allowlist_path, "ips", &ip, &reason) {
                Ok(()) => {
                    // Log to allowlist history for undo support
                    telegram::log_allowlist_change(
                        data_dir,
                        &ip,
                        "ips",
                        &result.operator_name,
                        "add",
                    );
                    write_telegram_triage_audit(
                        state,
                        &result.incident_id,
                        &result.operator_name,
                        "allowlist_add",
                        Some(ip.clone()),
                        None,
                        format!(
                            "Operator {} added IP '{}' to allowlist via Telegram",
                            result.operator_name, ip
                        ),
                        format!("allowlist_ip_added:{ip}"),
                    );
                    info!(
                        operator = %result.operator_name,
                        ip = %ip,
                        path = %allowlist_path.display(),
                        "Telegram triage allowlist (ip) applied"
                    );

                    // 2FA nudge if not enabled
                    let two_fa_enabled = cfg
                        .security
                        .as_ref()
                        .map(|s| s.two_factor_method != "none")
                        .unwrap_or(false);
                    let confirmation_suffix = if two_fa_enabled {
                        " (verified by TOTP)"
                    } else {
                        ""
                    };
                    let mut msg = format!(
                        "\u{2705} Allowed <code>{ip}</code>{confirmation_suffix}. Sensor will pick this up in up to 60s."
                    );
                    if !two_fa_enabled {
                        msg.push_str(
                            "\n\n\u{26a0}\u{fe0f} Allowlist changes are not protected by 2FA.\n\
                             Anyone with your bot token can silence alerts.",
                        );
                    }
                    if two_fa_enabled {
                        tg_reply(state, msg);
                    } else if let Some(ref tg) = state.telegram_client {
                        let tg = tg.clone();
                        tokio::spawn(async move {
                            let keyboard = serde_json::json!([
                                [
                                    { "text": "\u{1f510} Enable 2FA", "callback_data": "enable2fa" },
                                    { "text": "\u{1f44d} Dismiss", "callback_data": "dismiss2fa" }
                                ]
                            ]);
                            let _ = tg.send_text_with_keyboard(&msg, keyboard).await;
                        });
                    }
                }
                Err(e) => {
                    write_telegram_triage_audit(
                        state,
                        &result.incident_id,
                        &result.operator_name,
                        "allowlist_add",
                        Some(ip.clone()),
                        None,
                        format!(
                            "Operator {} failed to add IP '{}' to allowlist via Telegram",
                            result.operator_name, ip
                        ),
                        format!(
                            "failed:{}",
                            e.to_string().chars().take(180).collect::<String>()
                        ),
                    );
                    warn!(
                        operator = %result.operator_name,
                        ip = %ip,
                        error = %e,
                        "failed to append ip allowlist entry from Telegram"
                    );
                    tg_reply(
                        state,
                        format!(
                            "❌ Failed to allowlist <code>{ip}</code>: {}",
                            e.to_string().chars().take(180).collect::<String>()
                        ),
                    );
                }
            }
        }
        TelegramTriageAction::ReportFp(raw_incident_id) => {
            let incident_id = raw_incident_id.trim();
            if incident_id.is_empty() {
                write_telegram_triage_audit(
                    state,
                    &result.incident_id,
                    &result.operator_name,
                    "fp_report",
                    None,
                    None,
                    format!(
                        "Operator {} attempted to report FP with empty incident id",
                        result.operator_name
                    ),
                    "skipped:empty_incident_id".to_string(),
                );
                tg_reply(
                    state,
                    "⚠️ Could not report false positive: missing incident id.",
                );
                return true;
            }
            let detector = incident_id.split(':').next().unwrap_or("unknown");
            telegram::log_false_positive(data_dir, incident_id, detector, &result.operator_name);
            // Phase 7 Gap 1: mark incident as FP in the knowledge graph
            {
                let mut graph = state.knowledge_graph.write().unwrap();
                if let Some(node_id) = graph.find_by_incident(incident_id) {
                    graph.mark_false_positive(node_id, &result.operator_name);
                }
            }
            write_telegram_triage_audit(
                state,
                incident_id,
                &result.operator_name,
                "fp_report",
                None,
                None,
                format!(
                    "Operator {} reported incident '{}' as false positive via Telegram",
                    result.operator_name, incident_id
                ),
                format!("reported_fp:{detector}"),
            );
            info!(
                operator = %result.operator_name,
                incident_id = %incident_id,
                detector = %detector,
                "Telegram triage false-positive reported"
            );
            tg_reply(state, "📝 Reported. Thanks for the feedback.");
        }
    }

    true
}

// ---------------------------------------------------------------------------
// 2FA gate — intercepts sensitive actions when TOTP is enabled
// ---------------------------------------------------------------------------

/// Check if 2FA is enabled in config.
pub(crate) fn is_2fa_enabled(cfg: &config::AgentConfig) -> bool {
    cfg.security
        .as_ref()
        .map(|s| s.two_factor_method == "totp")
        .unwrap_or(false)
}

/// Get the TOTP secret from config (resolved from env var or toml).
fn totp_secret(cfg: &config::AgentConfig) -> Option<String> {
    // Check env var first (preferred), then config field
    std::env::var("INNERWARDEN_TOTP_SECRET")
        .ok()
        .or_else(|| cfg.security.as_ref().map(|s| s.totp_secret.clone()))
        .filter(|s| !s.is_empty())
}

/// If 2FA is enabled, intercept the action: store as pending and ask for TOTP code.
/// Returns `true` if the action was intercepted (caller should return without executing).
/// Returns `false` if 2FA is disabled (caller should proceed normally).
pub(crate) fn check_2fa_gate(
    state: &mut AgentState,
    cfg: &config::AgentConfig,
    operator: &str,
    action: two_factor::PendingActionType,
) -> bool {
    if !is_2fa_enabled(cfg) {
        return false;
    }

    // Check lockout before accepting a new action
    if state.two_factor_state.is_locked_out(operator) {
        tg_reply(
            state,
            "\u{1f6ab} Too many failed 2FA attempts. Try again later.",
        );
        return true;
    }

    let now = chrono::Utc::now();
    let pending = two_factor::PendingAction {
        action_type: action,
        operator: operator.to_string(),
        created_at: now,
        expires_at: now + chrono::Duration::minutes(5),
        method: two_factor::TwoFactorMethod::Totp,
    };
    state.two_factor_state.set_pending(operator, pending);

    tg_reply(
        state,
        "\u{1f510} Enter your 6-digit TOTP code (expires in 5 min):",
    );
    info!(operator = %operator, "2FA: pending action stored, waiting for TOTP code");
    true
}

/// Try to handle a Telegram message as a TOTP code response.
/// Returns `true` if it was recognized as a TOTP attempt (code or cancel).
pub(crate) fn handle_totp_response(
    result: &telegram::ApprovalResult,
    data_dir: &Path,
    cfg: &config::AgentConfig,
    state: &mut AgentState,
) -> bool {
    let text = result.incident_id.trim();

    // Cancel pending 2FA
    if text == "/cancel" {
        if state
            .two_factor_state
            .take_pending(&result.operator_name)
            .is_some()
        {
            tg_reply(state, "\u{274c} 2FA verification cancelled.");
            return true;
        }
        return false;
    }

    // Only intercept 6-digit numeric strings when there's a pending action
    let is_6_digits = text.len() == 6 && text.chars().all(|c| c.is_ascii_digit());
    if !is_6_digits {
        return false;
    }

    let pending = match state.two_factor_state.take_pending(&result.operator_name) {
        Some(p) => p,
        None => return false, // No pending action — not a TOTP attempt
    };

    // Check if expired
    if pending.expires_at < chrono::Utc::now() {
        tg_reply(state, "\u{23f0} 2FA code expired. Please retry the action.");
        return true;
    }

    // Verify TOTP code
    let secret = match totp_secret(cfg) {
        Some(s) => s,
        None => {
            warn!("2FA enabled but no TOTP secret configured");
            tg_reply(
                state,
                "\u{26a0}\u{fe0f} 2FA is enabled but no TOTP secret is configured. Run: innerwarden configure 2fa",
            );
            return true;
        }
    };

    let provider = match two_factor::TotpProvider::new(&secret) {
        Some(p) => p,
        None => {
            warn!("2FA: invalid TOTP secret in config");
            tg_reply(
                state,
                "\u{26a0}\u{fe0f} Invalid TOTP secret. Re-run: innerwarden configure 2fa",
            );
            return true;
        }
    };

    if !provider.verify(text) {
        state.two_factor_state.record_failure(&result.operator_name);
        if state.two_factor_state.is_locked_out(&result.operator_name) {
            tg_reply(
                state,
                "\u{274c} Wrong code. You are now locked out for 1 hour.",
            );
        } else {
            // Re-store the pending action so operator can retry
            state
                .two_factor_state
                .set_pending(&result.operator_name, pending);
            tg_reply(state, "\u{274c} Wrong code. Try again or /cancel.");
        }
        return true;
    }

    // Code verified — execute the pending action
    info!(
        operator = %result.operator_name,
        action = ?pending.action_type,
        "2FA: TOTP verified, executing pending action"
    );
    execute_verified_action(pending.action_type, &result.operator_name, data_dir, state);
    true
}

/// Execute a 2FA-verified action.
fn execute_verified_action(
    action: two_factor::PendingActionType,
    operator: &str,
    data_dir: &Path,
    state: &mut AgentState,
) {
    let allowlist_path = Path::new("/etc/innerwarden/allowlist.toml");
    let ts = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ");

    match action {
        two_factor::PendingActionType::AllowlistProcess(ref comm) => {
            let reason = format!("Allowed via Telegram + 2FA ({ts})");
            match telegram::append_to_allowlist(allowlist_path, "processes", comm, &reason) {
                Ok(()) => {
                    telegram::log_allowlist_change(data_dir, comm, "processes", operator, "add");
                    write_telegram_triage_audit(
                        state, "__2fa_verified__", operator, "allowlist_add",
                        None, Some(format!("process:{comm}")),
                        format!("Operator {operator} added process '{comm}' to allowlist (2FA verified)"),
                        format!("allowlist_process_added:{comm}"),
                    );
                    tg_reply(state, format!(
                        "\u{2705} Allowed <code>{comm}</code> (verified by TOTP). Sensor will pick this up in up to 60s."
                    ));
                }
                Err(e) => {
                    tg_reply(
                        state,
                        format!(
                            "\u{274c} Failed to allowlist <code>{comm}</code>: {}",
                            e.to_string().chars().take(180).collect::<String>()
                        ),
                    );
                }
            }
        }
        two_factor::PendingActionType::AllowlistIp(ref ip) => {
            let reason = format!("Allowed via Telegram + 2FA ({ts})");
            match telegram::append_to_allowlist(allowlist_path, "ips", ip, &reason) {
                Ok(()) => {
                    telegram::log_allowlist_change(data_dir, ip, "ips", operator, "add");
                    write_telegram_triage_audit(
                        state,
                        "__2fa_verified__",
                        operator,
                        "allowlist_add",
                        Some(ip.clone()),
                        None,
                        format!("Operator {operator} added IP '{ip}' to allowlist (2FA verified)"),
                        format!("allowlist_ip_added:{ip}"),
                    );
                    tg_reply(state, format!(
                        "\u{2705} Allowed <code>{ip}</code> (verified by TOTP). Sensor will pick this up in up to 60s."
                    ));
                }
                Err(e) => {
                    tg_reply(
                        state,
                        format!(
                            "\u{274c} Failed to allowlist <code>{ip}</code>: {}",
                            e.to_string().chars().take(180).collect::<String>()
                        ),
                    );
                }
            }
        }
        two_factor::PendingActionType::UndoAllowlist {
            ref section,
            ref key,
        } => match telegram::remove_from_allowlist(allowlist_path, section, key) {
            Ok(()) => {
                telegram::log_allowlist_change(data_dir, key, section, operator, "remove");
                write_telegram_triage_audit(
                        state, "__2fa_verified__", operator, "allowlist_remove",
                        None, None,
                        format!("Operator {operator} removed '{key}' from {section} allowlist (2FA verified)"),
                        format!("allowlist_removed:{key}"),
                    );
                tg_reply(
                    state,
                    format!(
                        "\u{2705} Removed <code>{}</code> from allowlist (verified by TOTP).",
                        telegram::escape_html_pub(key)
                    ),
                );
            }
            Err(e) => {
                tg_reply(
                    state,
                    format!(
                        "\u{274c} Failed to remove <code>{}</code>: {}",
                        telegram::escape_html_pub(key),
                        e.to_string().chars().take(180).collect::<String>()
                    ),
                );
            }
        },
        two_factor::PendingActionType::AutoFpAllowlist {
            ref section,
            ref entity,
        } => {
            let reason = format!("Auto-FP allowlist via Telegram + 2FA ({ts})");
            match telegram::append_to_allowlist(allowlist_path, section, entity, &reason) {
                Ok(()) => {
                    telegram::log_allowlist_change(data_dir, entity, section, operator, "add");
                    tg_reply(state, format!(
                        "\u{2705} Added <code>{}</code> to {} allowlist permanently (verified by TOTP).",
                        telegram::escape_html_pub(entity), section
                    ));
                }
                Err(e) => {
                    tg_reply(
                        state,
                        format!(
                            "\u{274c} Failed to add to allowlist: {}",
                            e.to_string().chars().take(180).collect::<String>()
                        ),
                    );
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Format an RFC3339 timestamp as a human-readable "X ago" string.
pub(crate) fn format_time_ago(ts_str: &str) -> String {
    let ts = match chrono::DateTime::parse_from_rfc3339(ts_str) {
        Ok(t) => t.with_timezone(&chrono::Utc),
        Err(_) => return "recently".to_string(),
    };
    let diff = chrono::Utc::now() - ts;
    if diff.num_days() > 0 {
        format!("{}d ago", diff.num_days())
    } else if diff.num_hours() > 0 {
        format!("{}h ago", diff.num_hours())
    } else {
        format!("{}m ago", diff.num_minutes().max(1))
    }
}

pub(crate) fn local_hostname_for_audit() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::fs::read_to_string("/etc/hostname").map(|s| s.trim().to_string()))
        .unwrap_or_else(|_| "unknown".to_string())
}

fn tg_reply(state: &AgentState, text: impl Into<String>) {
    if let Some(ref tg) = state.telegram_client {
        let tg = tg.clone();
        let text = text.into();
        tokio::spawn(async move {
            let _ = tg.send_text_message(&text).await;
        });
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn write_telegram_triage_audit(
    state: &mut AgentState,
    incident_id: &str,
    operator: &str,
    action_type: &str,
    target_ip: Option<String>,
    target_user: Option<String>,
    reason: String,
    execution_result: String,
) {
    if let Some(writer) = &mut state.decision_writer {
        let entry = decisions::DecisionEntry {
            ts: chrono::Utc::now(),
            incident_id: incident_id.to_string(),
            host: local_hostname_for_audit(),
            ai_provider: format!("operator:telegram:{operator}"),
            action_type: action_type.to_string(),
            target_ip,
            target_user,
            skill_id: None,
            confidence: 1.0,
            auto_executed: true,
            dry_run: false,
            reason,
            estimated_threat: "manual".to_string(),
            execution_result,
            prev_hash: None,
        };
        if let Err(e) = writer.write(&entry) {
            warn!(
                error = %e,
                action_type,
                incident_id,
                operator,
                "failed to write Telegram triage audit entry"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::knowledge_graph::types::{Edge, Node, Relation};
    use crate::knowledge_graph::KnowledgeGraph;
    use tempfile::TempDir;

    fn seeded_graph() -> std::sync::Arc<std::sync::RwLock<KnowledgeGraph>> {
        let mut graph = KnowledgeGraph::new();
        let now = chrono::Utc::now();
        let ip_a = graph.ensure_ip("203.0.113.10", now);
        let ip_b = graph.ensure_ip("198.51.100.7", now);

        let inc_a = graph.add_node(Node::Incident {
            incident_id: "ssh_bruteforce:203.0.113.10:1".to_string(),
            detector: "ssh_bruteforce".to_string(),
            severity: "high".to_string(),
            title: "SSH brute-force".to_string(),
            summary: "many failed logins".to_string(),
            ts: now,
            mitre_ids: vec![],
            decision: Some("block_ip".to_string()),
            confidence: Some(0.93),
            decision_reason: Some("clear abuse".to_string()),
            decision_target: Some("203.0.113.10".to_string()),
            auto_executed: true,
            is_allowlisted: false,
            false_positive: false,
            fp_reporter: None,
            fp_reported_at: None,
            research_only: false,
        });
        graph.add_edge(Edge::new(inc_a, ip_a, Relation::TriggeredBy, now));

        let inc_b = graph.add_node(Node::Incident {
            incident_id: "port_scan:198.51.100.7:2".to_string(),
            detector: "port_scan".to_string(),
            severity: "medium".to_string(),
            title: "Port scan".to_string(),
            summary: "sequential probes".to_string(),
            ts: now - chrono::Duration::minutes(5),
            mitre_ids: vec![],
            decision: Some("monitor".to_string()),
            confidence: Some(0.55),
            decision_reason: Some("observe".to_string()),
            decision_target: Some("198.51.100.7".to_string()),
            auto_executed: false,
            is_allowlisted: false,
            false_positive: false,
            fp_reporter: None,
            fp_reported_at: None,
            research_only: false,
        });
        graph.add_edge(Edge::new(
            inc_b,
            ip_b,
            Relation::TriggeredBy,
            now - chrono::Duration::minutes(5),
        ));

        std::sync::Arc::new(std::sync::RwLock::new(graph))
    }

    // --- parse_telegram_triage_action ---

    #[test]
    fn parse_allow_proc_action() {
        let action = parse_telegram_triage_action("__allow_proc__:sshd");
        assert_eq!(action, Some(TelegramTriageAction::AllowProc("sshd")));
    }

    #[test]
    fn parse_allow_ip_action() {
        let action = parse_telegram_triage_action("__allow_ip__:1.2.3.4");
        assert_eq!(action, Some(TelegramTriageAction::AllowIp("1.2.3.4")));
    }

    #[test]
    fn parse_fp_action() {
        let action = parse_telegram_triage_action("__fp__:ssh_bruteforce:1.2.3.4:abc");
        assert_eq!(
            action,
            Some(TelegramTriageAction::ReportFp("ssh_bruteforce:1.2.3.4:abc"))
        );
    }

    #[test]
    fn parse_unknown_returns_none() {
        assert_eq!(parse_telegram_triage_action("some:normal:incident"), None);
        assert_eq!(parse_telegram_triage_action(""), None);
        assert_eq!(parse_telegram_triage_action("__unknown__:xyz"), None);
    }

    // --- sanitize_allowlist_process_name ---

    #[test]
    fn sanitize_normal_name() {
        assert_eq!(
            sanitize_allowlist_process_name("sshd"),
            Some("sshd".to_string())
        );
    }

    #[test]
    fn sanitize_strips_quotes_and_trims() {
        assert_eq!(
            sanitize_allowlist_process_name("  \"my_proc\"  "),
            Some("my_proc".to_string())
        );
    }

    #[test]
    fn sanitize_replaces_newlines() {
        assert_eq!(
            sanitize_allowlist_process_name("proc\nwith\nnewlines"),
            Some("proc with newlines".to_string())
        );
    }

    #[test]
    fn sanitize_empty_returns_none() {
        assert_eq!(sanitize_allowlist_process_name(""), None);
        assert_eq!(sanitize_allowlist_process_name("  "), None);
        assert_eq!(sanitize_allowlist_process_name("\"\""), None);
    }

    // --- is_2fa_enabled ---

    #[test]
    fn is_2fa_disabled_when_no_security_section() {
        let cfg = config::AgentConfig {
            security: None,
            ..Default::default()
        };
        assert!(!is_2fa_enabled(&cfg));
    }

    #[test]
    fn is_2fa_enabled_when_totp() {
        let cfg = config::AgentConfig {
            security: Some(config::SecurityConfig {
                two_factor_method: "totp".to_string(),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert!(is_2fa_enabled(&cfg));
    }

    #[test]
    fn is_2fa_disabled_when_method_is_none() {
        let cfg = config::AgentConfig {
            security: Some(config::SecurityConfig {
                two_factor_method: "none".to_string(),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert!(!is_2fa_enabled(&cfg));
    }

    #[test]
    fn graph_helpers_summarize_incidents_and_decisions() {
        let kg = seeded_graph();
        assert_eq!(graph_count(&kg, "incidents"), 2);
        assert_eq!(graph_count(&kg, "decisions"), 2);
        assert_eq!(graph_count(&kg, "unknown"), 0);

        let threats = graph_last_incidents(&kg, 5);
        assert!(threats.contains("Recent threats"));
        assert!(threats.contains("SSH brute-force"));
        assert!(threats.contains("<code>203.0.113.10</code>"));

        let decisions = graph_last_decisions(&kg, 5);
        assert!(decisions.contains("Recent decisions"));
        assert!(decisions.contains("block_ip"));
        assert!(decisions.contains("monitor"));
    }

    #[test]
    fn graph_helpers_handle_empty_graph() {
        let kg = std::sync::Arc::new(std::sync::RwLock::new(KnowledgeGraph::new()));
        assert_eq!(
            graph_last_incidents(&kg, 3),
            "🔇 Clean slate - no intrusion attempts today."
        );
        assert_eq!(
            graph_last_decisions(&kg, 3),
            "⚖️ No decisions yet today - standing by."
        );
    }

    #[test]
    fn triage_action_handles_invalid_and_fp_paths() {
        let dir = TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let cfg = config::AgentConfig::default();

        let invalid_proc = crate::tests::triage_approval("__allow_proc__:   \"\"   ", "operator");
        assert!(handle_telegram_triage_action(
            &invalid_proc,
            dir.path(),
            &cfg,
            &mut state
        ));

        let invalid_ip = crate::tests::triage_approval("__allow_ip__:not-an-ip", "operator");
        assert!(handle_telegram_triage_action(
            &invalid_ip,
            dir.path(),
            &cfg,
            &mut state
        ));

        let empty_fp = crate::tests::triage_approval("__fp__:", "operator");
        assert!(handle_telegram_triage_action(
            &empty_fp,
            dir.path(),
            &cfg,
            &mut state
        ));

        // Valid FP path updates graph incident metadata.
        {
            let mut graph = state.knowledge_graph.write().expect("graph write");
            graph.add_node(Node::Incident {
                incident_id: "ssh_bruteforce:203.0.113.44:test".to_string(),
                detector: "ssh_bruteforce".to_string(),
                severity: "high".to_string(),
                title: "SSH brute-force".to_string(),
                summary: "many attempts".to_string(),
                ts: chrono::Utc::now(),
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
        }

        let fp = crate::tests::triage_approval("__fp__:ssh_bruteforce:203.0.113.44:test", "alice");
        assert!(handle_telegram_triage_action(
            &fp,
            dir.path(),
            &cfg,
            &mut state
        ));

        let graph = state.knowledge_graph.read().expect("graph read");
        let node_id = graph
            .find_by_incident("ssh_bruteforce:203.0.113.44:test")
            .expect("incident node exists");
        match graph.get_node(node_id) {
            Some(Node::Incident {
                false_positive,
                fp_reporter,
                ..
            }) => {
                assert!(*false_positive);
                assert_eq!(fp_reporter.as_deref(), Some("alice"));
            }
            other => panic!("expected incident node, got {other:?}"),
        }
    }

    #[test]
    fn check_2fa_gate_and_totp_cancel_flow() {
        let dir = TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let mut cfg = config::AgentConfig::default();
        cfg.security = Some(config::SecurityConfig {
            two_factor_method: "totp".to_string(),
            totp_secret: "JBSWY3DPEHPK3PXP".to_string(),
            ..Default::default()
        });

        let intercepted = check_2fa_gate(
            &mut state,
            &cfg,
            "operator",
            two_factor::PendingActionType::AllowlistIp("1.2.3.4".to_string()),
        );
        assert!(intercepted);
        assert!(state.two_factor_state.pending.contains_key("operator"));

        let cancel = crate::tests::triage_approval("/cancel", "operator");
        assert!(handle_totp_response(&cancel, dir.path(), &cfg, &mut state));
        assert!(!state.two_factor_state.pending.contains_key("operator"));
    }

    #[test]
    fn handle_totp_response_ignores_non_totp_or_missing_pending() {
        let dir = TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let cfg = config::AgentConfig::default();

        let plain_text = crate::tests::triage_approval("hello", "operator");
        assert!(!handle_totp_response(
            &plain_text,
            dir.path(),
            &cfg,
            &mut state
        ));

        let six_digits_no_pending = crate::tests::triage_approval("123456", "operator");
        assert!(!handle_totp_response(
            &six_digits_no_pending,
            dir.path(),
            &cfg,
            &mut state
        ));
    }

    #[test]
    fn handle_totp_response_wrong_code_keeps_pending_for_retry() {
        let dir = TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let mut cfg = config::AgentConfig::default();
        cfg.security = Some(config::SecurityConfig {
            two_factor_method: "totp".to_string(),
            totp_secret: "JBSWY3DPEHPK3PXP".to_string(),
            ..Default::default()
        });

        check_2fa_gate(
            &mut state,
            &cfg,
            "operator",
            two_factor::PendingActionType::AllowlistProcess("sshd".to_string()),
        );
        assert!(state.two_factor_state.pending.contains_key("operator"));

        let wrong = crate::tests::triage_approval("000000", "operator");
        assert!(handle_totp_response(&wrong, dir.path(), &cfg, &mut state));
        assert!(
            state.two_factor_state.pending.contains_key("operator"),
            "pending action should be re-stored after wrong code"
        );
    }

    // ── Spec 043 Phase 2 anchors (AUDIT-SPEC043-PHASE2) ──────────────────
    //
    // Pre-Phase-2 the Telegram /ask prompt only carried last-3 incident
    // titles + last-5 decision targets, which produced operator-reported
    // "muito basico" answers. ask_context_deep enriches the prompt with
    // KG-derived data already ingested but unused: IP risk_score, threat
    // intel datasets, high-risk entity snapshot, and a depth-1 subgraph
    // for any IP the question text mentions. Hard char-budget cap protects
    // LLM cost / latency.
    //
    // These four anchors pin: enrichment correctness, subgraph trigger
    // by question text, budget-cap enforcement, and the most-expendable-
    // first truncation order.

    fn make_ip_node(addr: &str, risk: u8, datasets: Vec<String>) -> knowledge_graph::types::Node {
        knowledge_graph::types::Node::Ip {
            addr: addr.to_string(),
            is_internal: false,
            datasets,
            risk_score: risk,
            is_tor: false,
            first_seen: chrono::Utc::now() - chrono::Duration::days(7),
            last_seen: chrono::Utc::now(),
            attempted_usernames: vec![],
        }
    }

    fn make_inc_node(
        id: &str,
        sev: &str,
        title: &str,
        summary: &str,
    ) -> knowledge_graph::types::Node {
        knowledge_graph::types::Node::Incident {
            incident_id: id.to_string(),
            detector: "test".to_string(),
            severity: sev.to_string(),
            title: title.to_string(),
            summary: summary.to_string(),
            ts: chrono::Utc::now(),
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
        }
    }

    /// Spec 043 Phase 2 anchor: ask_context_deep must surface the
    /// IP risk_score and threat-intel datasets in the RECENT INCIDENTS
    /// section so the LLM has real ground truth instead of just titles.
    /// Pre-Phase-2 these fields were write-only in the KG.
    #[test]
    fn ask_context_deep_includes_ip_risk_and_datasets() {
        use knowledge_graph::types::{Edge, Relation};
        let kg = std::sync::Arc::new(std::sync::RwLock::new(
            knowledge_graph::KnowledgeGraph::new(),
        ));
        {
            let mut g = kg.write().unwrap();
            let ip_id = g.add_node(make_ip_node(
                "203.0.113.99",
                85,
                vec!["AbuseIPDB".to_string(), "ThreatFox".to_string()],
            ));
            let inc_id = g.add_node(make_inc_node(
                "ssh_bf:1",
                "high",
                "SSH brute-force",
                "many failed logins",
            ));
            g.add_edge(Edge::new(
                inc_id,
                ip_id,
                Relation::TriggeredBy,
                chrono::Utc::now(),
            ));
        }

        let out = ask_context_deep(&kg, "what's going on?", 8000);

        assert!(
            out.contains("RECENT INCIDENTS:"),
            "expected RECENT INCIDENTS header; got:\n{out}"
        );
        assert!(
            out.contains("SSH brute-force"),
            "expected incident title; got:\n{out}"
        );
        assert!(
            out.contains("ip_risk=85"),
            "expected IP risk_score enrichment; got:\n{out}"
        );
        assert!(
            out.contains("AbuseIPDB"),
            "expected threat-intel dataset; got:\n{out}"
        );
        assert!(
            out.contains("ThreatFox"),
            "expected threat-intel dataset; got:\n{out}"
        );
    }

    /// Spec 043 Phase 2 anchor: when the operator's question text
    /// mentions an IP that exists in the KG, ask_context_deep MUST
    /// pull the IP's depth-1 neighborhood and attach it as the
    /// SUBGRAPH FOR QUESTION section. Pre-Phase-2 the LLM had no
    /// way to ground "why is X.X.X.X blocked?" questions.
    #[test]
    fn ask_context_deep_pulls_subgraph_when_question_mentions_ip() {
        use knowledge_graph::types::{Edge, Relation};
        let kg = std::sync::Arc::new(std::sync::RwLock::new(
            knowledge_graph::KnowledgeGraph::new(),
        ));
        {
            let mut g = kg.write().unwrap();
            let ip_id = g.add_node(make_ip_node("198.51.100.42", 60, vec![]));
            let port_id = g.add_node(knowledge_graph::types::Node::Port {
                number: 22,
                protocol: "tcp".to_string(),
            });
            g.add_edge(Edge::new(
                ip_id,
                port_id,
                Relation::ConnectedTo,
                chrono::Utc::now(),
            ));
        }

        let out = ask_context_deep(&kg, "why is 198.51.100.42 blocked?", 8000);

        assert!(
            out.contains("SUBGRAPH FOR QUESTION:"),
            "expected subgraph header; got:\n{out}"
        );
        assert!(
            out.contains("198.51.100.42"),
            "expected subgraph to mention the queried IP; got:\n{out}"
        );
        assert!(
            out.contains("Port(22/tcp)"),
            "expected subgraph to render the connected Port node; got:\n{out}"
        );
    }

    /// Spec 043 Phase 2 anchor: with a tight char budget, ask_context_deep
    /// MUST drop the most-expendable section first (subgraph), keeping
    /// the highest-signal context (recent incidents) intact. Anti-
    /// regression for accidentally dropping incidents to fit subgraph,
    /// which would degrade /ask quality on memory-constrained runs.
    #[test]
    fn ask_context_deep_respects_budget_cap_drops_subgraph_first() {
        use knowledge_graph::types::{Edge, Relation};
        let kg = std::sync::Arc::new(std::sync::RwLock::new(
            knowledge_graph::KnowledgeGraph::new(),
        ));
        {
            let mut g = kg.write().unwrap();
            let ip_id = g.add_node(make_ip_node("203.0.113.5", 75, vec![]));
            let inc_id = g.add_node(make_inc_node(
                "i1",
                "high",
                "very long incident title that takes up significant prompt budget",
                "and the summary is also long enough to crowd out anything optional from the prompt",
            ));
            g.add_edge(Edge::new(
                inc_id,
                ip_id,
                Relation::TriggeredBy,
                chrono::Utc::now(),
            ));
            // Add a port the question would want in the subgraph.
            let port_id = g.add_node(knowledge_graph::types::Node::Port {
                number: 22,
                protocol: "tcp".to_string(),
            });
            g.add_edge(Edge::new(
                ip_id,
                port_id,
                Relation::ConnectedTo,
                chrono::Utc::now(),
            ));
        }

        // Budget tight enough that subgraph + high-risk + decisions
        // sections cannot all fit alongside the long incident.
        let out = ask_context_deep(&kg, "why is 203.0.113.5 blocked?", 200);

        assert!(
            out.len() <= 200 + 32,
            "output exceeded budget; got {} chars",
            out.len()
        );
        // Recent incidents survives (highest signal).
        assert!(
            out.contains("RECENT INCIDENTS:") || out.is_empty(),
            "RECENT INCIDENTS must survive truncation; got:\n{out}"
        );
        // Subgraph dropped first (most expendable).
        assert!(
            !out.contains("SUBGRAPH FOR QUESTION:"),
            "SUBGRAPH must be dropped first under tight budget; got:\n{out}"
        );
    }

    /// Spec 043 Phase 2 anchor: empty KG produces empty output (no
    /// dangling section headers). Pins the same defensive behaviour
    /// as the legacy graph_last_incidents_raw helper had — the
    /// integration site only adds the "RECENT INCIDENTS:" header
    /// when there's content to label.
    #[test]
    fn ask_context_deep_empty_graph_returns_empty_string() {
        let kg = std::sync::Arc::new(std::sync::RwLock::new(
            knowledge_graph::KnowledgeGraph::new(),
        ));
        let out = ask_context_deep(&kg, "anything", 8000);
        assert!(
            out.is_empty(),
            "empty graph should produce empty context; got:\n{out}"
        );
    }
}
