// Auto-extracted from mod.rs — dashboard agent_api handlers

use super::*;

// ---------------------------------------------------------------------------
// Agent API - security context for AI agents (OpenClaw, n8n, etc.)
// ---------------------------------------------------------------------------

/// GET /api/agent/security-context - threat overview for AI agents
pub(super) async fn api_agent_security_context(
    State(state): State<DashboardState>,
) -> Json<serde_json::Value> {
    let date = resolve_date(None);
    let incidents = read_jsonl::<innerwarden_core::incident::Incident>(&dated_path(
        &state.data_dir,
        "incidents",
        &date,
    ));
    let decisions = read_jsonl::<DecisionEntry>(&dated_path(&state.data_dir, "decisions", &date));

    let total_incidents = incidents.len();
    let high_or_critical = incidents
        .iter()
        .filter(|i| {
            matches!(
                i.severity,
                innerwarden_core::event::Severity::High
                    | innerwarden_core::event::Severity::Critical
            )
        })
        .count();
    let blocks_today = decisions
        .iter()
        .filter(|d| d.action_type == "block_ip" && !d.dry_run)
        .count();

    // Collect top detectors from incident IDs (prefix before first ':')
    let mut detector_counts = std::collections::HashMap::<String, usize>::new();
    for inc in &incidents {
        let detector = inc
            .incident_id
            .split(':')
            .next()
            .unwrap_or("unknown")
            .to_string();
        *detector_counts.entry(detector).or_default() += 1;
    }
    let mut top: Vec<_> = detector_counts.into_iter().collect();
    top.sort_by(|a, b| b.1.cmp(&a.1));
    let top_threats: Vec<String> = top.iter().take(5).map(|(k, _)| k.clone()).collect();

    // Threat level based on AI-confirmed actions, not raw incident count.
    // Raw incidents include noise. Only AI decisions that resulted in action matter.
    let ai_actions = decisions
        .iter()
        .filter(|d| d.action_type != "ignore" && d.action_type != "request_confirmation")
        .count();
    let threat_level = if ai_actions >= 10 {
        "critical"
    } else if ai_actions >= 5 {
        "high"
    } else if ai_actions >= 1 {
        "medium"
    } else {
        "low"
    };

    let recommendation = match threat_level {
        "critical" => "server under active attack - avoid risky operations",
        "high" => "elevated threat level - proceed with caution",
        _ => "safe to proceed",
    };

    Json(serde_json::json!({
        "threat_level": threat_level,
        "active_incidents_today": total_incidents,
        "high_or_critical_today": high_or_critical,
        "recent_blocks_today": blocks_today,
        "top_threats": top_threats,
        "recommendation": recommendation,
        "date": date,
    }))
}

/// Query params for check-ip
#[derive(serde::Deserialize)]
pub(super) struct CheckIpQuery {
    ip: String,
}

/// GET /api/agent/check-ip?ip=X - check if an IP is known threat
pub(super) async fn api_agent_check_ip(
    State(state): State<DashboardState>,
    Query(query): Query<CheckIpQuery>,
) -> Json<serde_json::Value> {
    let ip = query.ip.trim();
    let date = resolve_date(None);
    let incidents = read_jsonl::<innerwarden_core::incident::Incident>(&dated_path(
        &state.data_dir,
        "incidents",
        &date,
    ));
    let decisions = read_jsonl::<DecisionEntry>(&dated_path(&state.data_dir, "decisions", &date));

    // Count incidents involving this IP
    let matching_incidents: Vec<_> = incidents
        .iter()
        .filter(|inc| {
            inc.entities
                .iter()
                .any(|e| e.r#type == innerwarden_core::entities::EntityType::Ip && e.value == ip)
        })
        .collect();

    let incident_count = matching_incidents.len();
    let blocked = decisions
        .iter()
        .any(|d| d.action_type == "block_ip" && d.target_ip.as_deref() == Some(ip));
    let last_seen = matching_incidents
        .iter()
        .map(|i| i.ts)
        .max()
        .map(|ts| ts.to_rfc3339());

    let mut detectors = std::collections::HashSet::new();
    for inc in &matching_incidents {
        if let Some(d) = inc.incident_id.split(':').next() {
            detectors.insert(d.to_string());
        }
    }

    let recommendation = if blocked {
        "avoid"
    } else if incident_count > 0 {
        "caution"
    } else {
        "no threat data"
    };

    Json(serde_json::json!({
        "ip": ip,
        "known_threat": incident_count > 0 || blocked,
        "incident_count": incident_count,
        "blocked": blocked,
        "last_seen": last_seen,
        "detectors": detectors.into_iter().collect::<Vec<_>>(),
        "recommendation": recommendation,
    }))
}

/// Request body for check-command
#[derive(serde::Deserialize)]
pub(super) struct CheckCommandRequest {
    command: String,
    #[serde(default)]
    agent_name: Option<String>,
}

/// Analyze a command for dangerous patterns (pure function, no state).
/// Returns a JSON object with risk_score, severity, signals, recommendation, explanation.
/// Run agent-guard unified command analysis and optionally emit a snitch alert.
pub(super) fn run_analysis(
    state: &DashboardState,
    command: &str,
    agent_name: Option<&str>,
) -> serde_json::Value {
    let analysis = innerwarden_agent_guard::mcp::analyze_command(command, Some(&state.rule_engine));

    // Emit snitch alert if deny or review.
    if analysis.recommendation == "deny" || analysis.recommendation == "review" {
        let alert = AgentGuardAlert {
            ts: Utc::now(),
            agent_name: agent_name.unwrap_or("unknown").to_string(),
            command: if command.len() > 200 {
                format!("{}...", &command[..200])
            } else {
                command.to_string()
            },
            risk_score: analysis.risk_score,
            severity: analysis.severity.clone(),
            recommendation: analysis.recommendation.clone(),
            signals: analysis.signals.iter().map(|s| s.signal.clone()).collect(),
            atr_rule_ids: analysis
                .atr_matches
                .iter()
                .map(|m| m.rule_id.clone())
                .collect(),
            explanation: analysis.explanation.clone(),
        };
        let _ = state.agent_alert_tx.try_send(alert);
    }

    // Serialize to the same JSON shape as the old analyze_command for backward compat.
    serde_json::json!({
        "command": analysis.command,
        "risk_score": analysis.risk_score,
        "severity": analysis.severity,
        "signals": analysis.signals,
        "recommendation": analysis.recommendation,
        "explanation": analysis.explanation,
    })
}

/// POST /api/agent/check-command - analyze a command for dangerous patterns
pub(super) async fn api_agent_check_command(
    State(state): State<DashboardState>,
    Json(body): Json<CheckCommandRequest>,
) -> Json<serde_json::Value> {
    Json(run_analysis(
        &state,
        &body.command,
        body.agent_name.as_deref(),
    ))
}

/// POST /api/advisor/check-command - analyze + cache advisory for deny/review results
pub(super) async fn api_advisor_check_command(
    State(state): State<DashboardState>,
    Json(body): Json<CheckCommandRequest>,
) -> Json<serde_json::Value> {
    let mut result = run_analysis(&state, &body.command, body.agent_name.as_deref());

    // If deny or review, cache the advisory for correlation with real incidents
    let recommendation = result
        .get("recommendation")
        .and_then(|v| v.as_str())
        .unwrap_or("allow");
    let risk_score = result
        .get("risk_score")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u32;

    if recommendation == "deny" || recommendation == "review" {
        let advisory_id = generate_session_token();
        // Trim to 16 chars for advisory IDs
        let advisory_id = advisory_id[..16].to_string();

        let signals: Vec<String> = result
            .get("signals")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|s| s.get("signal").and_then(|v| v.as_str()).map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        let command_lower = body.command.to_lowercase();
        let command_hash = innerwarden_core::audit::sha256_hex(command_lower.trim());
        let command_preview = if body.command.len() > 120 {
            format!("{}...", &body.command[..120])
        } else {
            body.command.clone()
        };

        let entry = AdvisoryEntry {
            advisory_id: advisory_id.clone(),
            command_hash,
            command_preview,
            risk_score,
            recommendation: recommendation.to_string(),
            signals,
            ts: Utc::now(),
        };

        if let Ok(mut cache) = state.advisory_cache.write() {
            if cache.len() >= 256 {
                cache.pop_front();
            }
            cache.push_back(entry);
        }

        result["advisory_id"] = serde_json::Value::String(advisory_id);
    }

    Json(result)
}

// ---------------------------------------------------------------------------
// Prometheus metrics endpoint
// ---------------------------------------------------------------------------
// Agent Guard API
// ---------------------------------------------------------------------------

/// POST /api/agent-guard/connect — an AI agent registers itself with InnerWarden.
///
/// Request: { "name": "openclaw", "pid": 1234, "label": "work-agent" }
/// Response: { "connected": true, "agent_id": "ag-0001", "check_command": "...", "policy": {...} }
pub(super) async fn api_agent_guard_connect(
    State(state): State<DashboardState>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let name = body["name"].as_str().unwrap_or("unknown");
    let pid = body["pid"].as_u64().unwrap_or(0) as u32;
    let label = body["label"].as_str();

    let mut registry = state.agent_registry.lock().await;
    match registry.connect(name, pid, label) {
        Ok(agent_id) => {
            tracing::info!(agent_id = %agent_id, name, pid, "agent-guard: agent connected via API");
            Json(serde_json::json!({
                "connected": true,
                "agent_id": agent_id,
                "check_command": "http://localhost:8787/api/agent/check-command",
                "security_context": "http://localhost:8787/api/agent/security-context",
                "policy": {
                    "mode": "warn",
                    "sensitive_paths_blocked": true,
                    "max_calls_per_minute": 30,
                }
            }))
        }
        Err(e) => Json(serde_json::json!({
            "connected": false,
            "error": e,
        })),
    }
}

/// POST /api/agent-guard/disconnect — remove an agent from monitoring.
///
/// Request: { "agent_id": "ag-0001" }
pub(super) async fn api_agent_guard_disconnect(
    State(state): State<DashboardState>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let agent_id = body["agent_id"].as_str().unwrap_or("");
    let mut registry = state.agent_registry.lock().await;
    let ok = registry.disconnect(agent_id);
    Json(serde_json::json!({ "disconnected": ok }))
}

/// GET /api/agent-guard/agents — list all connected agents and detected tools.
pub(super) async fn api_agent_guard_list(State(state): State<DashboardState>) -> Json<serde_json::Value> {
    let registry = state.agent_registry.lock().await;
    let agents = registry.list();
    Json(serde_json::json!({
        "agents": agents,
        "total": registry.count_total(),
        "agents_count": registry.count_agents(),
        "tools_count": registry.count_tools(),
    }))
}

// ---------------------------------------------------------------------------

pub(super) async fn api_prometheus_metrics(State(state): State<DashboardState>) -> axum::response::Response {
    let date = resolve_date(None);

    // Read latest telemetry snapshot (small file, already cached)
    let telem = crate::telemetry::read_latest_snapshot(&state.data_dir, &date);

    let mut out = String::with_capacity(2048);

    // Help + type headers for Prometheus scraper
    out.push_str("# HELP innerwarden_events_total Total events collected today by collector\n");
    out.push_str("# TYPE innerwarden_events_total counter\n");
    if let Some(ref t) = telem {
        for (collector, count) in &t.events_by_collector {
            out.push_str(&format!(
                "innerwarden_events_total{{collector=\"{collector}\"}} {count}\n"
            ));
        }
    }

    out.push_str("# HELP innerwarden_incidents_total Total incidents detected today by detector\n");
    out.push_str("# TYPE innerwarden_incidents_total counter\n");
    if let Some(ref t) = telem {
        for (detector, count) in &t.incidents_by_detector {
            out.push_str(&format!(
                "innerwarden_incidents_total{{detector=\"{detector}\"}} {count}\n"
            ));
        }
    }

    out.push_str("# HELP innerwarden_decisions_total Total AI/auto decisions today by action\n");
    out.push_str("# TYPE innerwarden_decisions_total counter\n");
    if let Some(ref t) = telem {
        for (action, count) in &t.decisions_by_action {
            out.push_str(&format!(
                "innerwarden_decisions_total{{action=\"{action}\"}} {count}\n"
            ));
        }
    }

    out.push_str("# HELP innerwarden_ai_calls_total Total AI provider calls today\n");
    out.push_str("# TYPE innerwarden_ai_calls_total counter\n");
    if let Some(ref t) = telem {
        out.push_str(&format!("innerwarden_ai_calls_total {}\n", t.ai_sent_count));
    }

    out.push_str("# HELP innerwarden_ai_latency_avg_ms Average AI decision latency in ms\n");
    out.push_str("# TYPE innerwarden_ai_latency_avg_ms gauge\n");
    if let Some(ref t) = telem {
        out.push_str(&format!(
            "innerwarden_ai_latency_avg_ms {:.1}\n",
            t.avg_decision_latency_ms
        ));
    }

    out.push_str("# HELP innerwarden_errors_total Errors by component\n");
    out.push_str("# TYPE innerwarden_errors_total counter\n");
    if let Some(ref t) = telem {
        for (component, count) in &t.errors_by_component {
            out.push_str(&format!(
                "innerwarden_errors_total{{component=\"{component}\"}} {count}\n"
            ));
        }
    }

    out.push_str("# HELP innerwarden_executions_total Skill executions today (dry_run vs live)\n");
    out.push_str("# TYPE innerwarden_executions_total counter\n");
    if let Some(ref t) = telem {
        out.push_str(&format!(
            "innerwarden_executions_total{{mode=\"dry_run\"}} {}\n",
            t.dry_run_execution_count
        ));
        out.push_str(&format!(
            "innerwarden_executions_total{{mode=\"live\"}} {}\n",
            t.real_execution_count
        ));
    }

    // Response lifecycle metrics (from responses.json snapshot).
    let responses_path = state.data_dir.join("responses.json");
    if let Ok(data) = std::fs::read_to_string(&responses_path) {
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&data) {
            out.push_str("# HELP innerwarden_responses_active Currently active response actions\n");
            out.push_str("# TYPE innerwarden_responses_active gauge\n");
            if let Some(count) = json["active_count"].as_u64() {
                out.push_str(&format!("innerwarden_responses_active {count}\n"));
            }
            out.push_str("# HELP innerwarden_responses_total Total response actions registered\n");
            out.push_str("# TYPE innerwarden_responses_total counter\n");
            if let Some(count) = json["totals"]["registered"].as_u64() {
                out.push_str(&format!("innerwarden_responses_total {count}\n"));
            }
            out.push_str("# HELP innerwarden_responses_expired_total Responses expired by TTL\n");
            out.push_str("# TYPE innerwarden_responses_expired_total counter\n");
            if let Some(count) = json["totals"]["expired"].as_u64() {
                out.push_str(&format!("innerwarden_responses_expired_total {count}\n"));
            }
            out.push_str(
                "# HELP innerwarden_responses_reverted_total Responses manually reverted\n",
            );
            out.push_str("# TYPE innerwarden_responses_reverted_total counter\n");
            if let Some(count) = json["totals"]["reverted"].as_u64() {
                out.push_str(&format!("innerwarden_responses_reverted_total {count}\n"));
            }
        }
    }

    axum::response::Response::builder()
        .header("content-type", "text/plain; version=0.0.4; charset=utf-8")
        .body(Body::from(out))
        .unwrap()
        .into_response()
}

/// GET /api/responses — active and historical response actions with TTL.
pub(super) async fn api_responses(State(state): State<DashboardState>) -> axum::response::Response {
    let responses_path = state.data_dir.join("responses.json");
    match std::fs::read_to_string(&responses_path) {
        Ok(data) => axum::response::Response::builder()
            .header("content-type", "application/json")
            .body(Body::from(data))
            .unwrap()
            .into_response(),
        Err(_) => {
            let empty = serde_json::json!({"active": [], "active_count": 0, "history": [], "totals": {"registered": 0, "expired": 0, "reverted": 0}});
            axum::response::Response::builder()
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&empty).unwrap()))
                .unwrap()
                .into_response()
        }
    }
}

/// GET /api/mitre/navigator — ATT&CK Navigator layer JSON.
/// Download and load at https://mitre-attack.github.io/attack-navigator/
pub(super) async fn api_mitre_navigator() -> axum::response::Response {
    let layer = crate::mitre::generate_navigator_layer();
    axum::response::Response::builder()
        .header("content-type", "application/json")
        .header(
            "content-disposition",
            "attachment; filename=\"innerwarden-coverage.json\"",
        )
        .body(Body::from(
            serde_json::to_string_pretty(&layer).unwrap_or_default(),
        ))
        .unwrap()
        .into_response()
}

/// GET /api/mitre/coverage — summary of MITRE ATT&CK coverage.
pub(super) async fn api_mitre_coverage() -> axum::response::Response {
    let ids = crate::mitre::all_technique_ids();
    let layer = crate::mitre::generate_navigator_layer();
    let techniques = layer["techniques"].as_array().map(|a| a.len()).unwrap_or(0);

    let summary = serde_json::json!({
        "total_techniques": techniques,
        "technique_ids": ids,
        "navigator_url": "/api/mitre/navigator",
    });

    axum::response::Response::builder()
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_string(&summary).unwrap_or_default(),
        ))
        .unwrap()
        .into_response()
}
