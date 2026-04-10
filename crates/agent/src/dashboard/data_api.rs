// Auto-extracted from mod.rs — dashboard data_api handlers

use super::*;
use std::io::BufRead;

/// Dashboard auto-sleep timeout: 15 minutes of no requests.
pub(super) const DASHBOARD_SLEEP_SECS: u64 = 15 * 60;

pub(super) fn is_dashboard_sleeping(last_activity: &std::sync::atomic::AtomicU64) -> bool {
    let last = last_activity.load(std::sync::atomic::Ordering::Relaxed);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    now.saturating_sub(last) > DASHBOARD_SLEEP_SECS
}
pub(super) async fn api_overview(
    State(state): State<DashboardState>,
    Query(query): Query<ListQuery>,
) -> Json<OverviewResponse> {
    let date = resolve_date(query.date.as_deref());
    // When sleeping, return minimal data from telemetry only
    if is_dashboard_sleeping(&state.last_activity) {
        return Json(OverviewResponse {
            date: date.clone(),
            events_count: 0,
            incidents_count: 0,
            decisions_count: 0,
            ai_confirmed: 0,
            ai_responded: 0,
            ai_ignored: 0,
            top_detectors: vec![],
            latest_telemetry: crate::telemetry::read_latest_snapshot(&state.data_dir, &date),
        });
    }

    // Read from knowledge graph (live) instead of JSONL
    let graph = state.knowledge_graph.read().unwrap();
    let metrics = graph.metrics();

    // Count decisions from Incident nodes
    use crate::knowledge_graph::types::{Node, NodeType};
    let incident_nodes = graph.nodes_of_type(NodeType::Incident);
    let mut by_detector: BTreeMap<String, usize> = BTreeMap::new();
    let mut decisions_count = 0usize;
    let mut ai_confirmed = 0usize;
    let mut ai_responded = 0usize;
    let mut ai_ignored = 0usize;

    for &id in &incident_nodes {
        if let Some(Node::Incident {
            detector, decision, ..
        }) = graph.get_node(id)
        {
            *by_detector.entry(detector.clone()).or_insert(0) += 1;
            if let Some(dec) = decision {
                decisions_count += 1;
                match dec.as_str() {
                    "ignore" => ai_ignored += 1,
                    "monitor" => ai_confirmed += 1,
                    _ => {
                        ai_confirmed += 1;
                        ai_responded += 1;
                    }
                }
            }
        }
    }

    let mut top_detectors: Vec<DetectorCount> = by_detector
        .into_iter()
        .map(|(detector, count)| DetectorCount { detector, count })
        .collect();
    top_detectors.sort_by(|a, b| b.count.cmp(&a.count).then(a.detector.cmp(&b.detector)));
    top_detectors.truncate(6);

    let telemetry = crate::telemetry::read_latest_snapshot(&state.data_dir, &date);
    Json(OverviewResponse {
        date,
        events_count: metrics.edge_count, // edges ≈ events (each event creates edges)
        incidents_count: incident_nodes.len(),
        decisions_count,
        ai_confirmed,
        ai_responded,
        ai_ignored,
        top_detectors,
        latest_telemetry: telemetry,
    })
}

pub(super) async fn api_incidents(
    State(state): State<DashboardState>,
    Query(query): Query<ListQuery>,
) -> Json<IncidentListResponse> {
    let date = resolve_date(query.date.as_deref());
    let limit = normalize_limit(query.limit);

    // Read from knowledge graph (live)
    use crate::knowledge_graph::types::{Node, NodeType};
    let graph = state.knowledge_graph.read().unwrap();

    let mut incident_views: Vec<IncidentView> = graph
        .nodes_of_type(NodeType::Incident)
        .iter()
        .filter_map(|&id| {
            if let Some(Node::Incident {
                incident_id,
                detector: _,
                severity,
                title,
                summary,
                ts,
                mitre_ids,
                decision,
                confidence: _,
                decision_reason: _,
                decision_target: _,
                auto_executed: _,
            }) = graph.get_node(id)
            {
                // Collect entities from TriggeredBy edges
                let entities: Vec<String> = graph
                    .outgoing_edges(id)
                    .iter()
                    .filter(|e| e.relation == crate::knowledge_graph::types::Relation::TriggeredBy)
                    .filter_map(|e| {
                        graph.get_node(e.to).map(|n| {
                            let ntype = format!("{:?}", n.node_type()).to_lowercase();
                            format!("{}:{}", ntype, n.label())
                        })
                    })
                    .collect();

                let outcome = match decision.as_deref() {
                    Some("block_ip") => "blocked",
                    Some("suspend_user_sudo") => "suspended",
                    Some("kill_process") => "killed",
                    Some("block_container") => "contained",
                    Some("monitor") => "monitored",
                    Some("honeypot") => "honeypot",
                    Some("ignore") => "ignored",
                    Some(_) => "resolved",
                    None => "open",
                };

                Some(IncidentView {
                    ts: *ts,
                    incident_id: incident_id.clone(),
                    severity: severity.to_lowercase(),
                    title: title.clone(),
                    summary: summary.clone(),
                    entities,
                    tags: mitre_ids.clone(),
                    outcome: outcome.to_string(),
                    action_taken: decision.clone(),
                })
            } else {
                None
            }
        })
        .collect();

    incident_views.sort_by(|a, b| b.ts.cmp(&a.ts));
    let total = incident_views.len();
    let items: Vec<IncidentView> = incident_views.into_iter().take(limit).collect();

    Json(IncidentListResponse { date, total, items })
}
pub(super) async fn api_decisions(
    State(state): State<DashboardState>,
    Query(query): Query<ListQuery>,
) -> Json<DecisionListResponse> {
    let date = resolve_date(query.date.as_deref());
    let limit = normalize_limit(query.limit);

    use crate::knowledge_graph::types::{Node, NodeType};
    let graph = state.knowledge_graph.read().unwrap();

    let mut views: Vec<DecisionView> = graph
        .nodes_of_type(NodeType::Incident)
        .iter()
        .filter_map(|&id| {
            if let Some(Node::Incident {
                incident_id,
                ts,
                decision: Some(action_type),
                confidence,
                decision_reason,
                decision_target,
                auto_executed,
                ..
            }) = graph.get_node(id)
            {
                Some(DecisionView {
                    ts: *ts,
                    incident_id: incident_id.clone(),
                    action_type: action_type.clone(),
                    target_ip: decision_target.clone(),
                    skill_id: None, // not stored in graph (audit trail detail)
                    confidence: confidence.unwrap_or(0.0),
                    auto_executed: *auto_executed,
                    dry_run: false,
                    reason: decision_reason.clone().unwrap_or_default(),
                    execution_result: if *auto_executed {
                        "ok".to_string()
                    } else {
                        "skipped".to_string()
                    },
                })
            } else {
                None
            }
        })
        .collect();

    views.sort_by(|a, b| b.ts.cmp(&a.ts));
    let total = views.len();
    let items: Vec<DecisionView> = views.into_iter().take(limit).collect();

    Json(DecisionListResponse { date, total, items })
}
/// GET /api/report[?date=YYYY-MM-DD]
/// Returns a TrialReport JSON computed on-demand.
/// `date` defaults to the most recent date with data.
pub(super) async fn api_report(
    State(state): State<DashboardState>,
    Query(query): Query<ReportQuery>,
) -> Response {
    let graph = state.knowledge_graph.read().unwrap();
    let report: TrialReport =
        report_mod::compute_for_date_from_graph(&state.data_dir, query.date.as_deref(), &graph);

    match serde_json::to_string_pretty(&report) {
        Ok(body) => (
            [(header::CONTENT_TYPE, "application/json; charset=utf-8")],
            body,
        )
            .into_response(),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to serialize report",
        )
            .into_response(),
    }
}

/// GET /api/report/dates
/// Returns a JSON array of date strings (YYYY-MM-DD) for which data exists,
/// most recent first. Used by the dashboard report date picker.
pub(super) async fn api_report_dates(State(state): State<DashboardState>) -> Json<Vec<String>> {
    let data_dir = state.data_dir.clone();
    let dates = tokio::task::spawn_blocking(move || report_mod::list_available_dates(&data_dir))
        .await
        .unwrap_or_default();
    Json(dates)
}
// ---------------------------------------------------------------------------
// Business logic - overview
// ---------------------------------------------------------------------------

pub(super) fn compute_overview(data_dir: &Path, date: &str) -> OverviewResponse {
    // Count events by line count (fast) instead of parsing 100MB+ of JSON
    let events_count = count_file_lines(&dated_path(data_dir, "events", date));
    let incidents = read_jsonl::<innerwarden_core::incident::Incident>(&dated_path(
        data_dir,
        "incidents",
        date,
    ));
    let decisions = read_jsonl::<DecisionEntry>(&dated_path(data_dir, "decisions", date));

    let mut by_detector: BTreeMap<String, usize> = BTreeMap::new();
    for inc in &incidents {
        let detector = inc
            .incident_id
            .split(':')
            .next()
            .unwrap_or("unknown")
            .to_string();
        *by_detector.entry(detector).or_insert(0) += 1;
    }
    let mut top_detectors: Vec<DetectorCount> = by_detector
        .into_iter()
        .map(|(detector, count)| DetectorCount { detector, count })
        .collect();
    top_detectors.sort_by(|a, b| b.count.cmp(&a.count).then(a.detector.cmp(&b.detector)));
    top_detectors.truncate(6);

    // Classify AI decisions: confirmed (action taken) vs ignored
    let ai_confirmed = decisions
        .iter()
        .filter(|d| d.action_type != "ignore" && d.action_type != "request_confirmation")
        .count();
    let ai_responded = decisions
        .iter()
        .filter(|d| d.auto_executed && d.action_type != "ignore" && d.action_type != "monitor")
        .count();
    let ai_ignored = decisions
        .iter()
        .filter(|d| d.action_type == "ignore")
        .count();

    OverviewResponse {
        date: date.to_string(),
        events_count,
        incidents_count: incidents.len(),
        decisions_count: decisions.len(),
        ai_confirmed,
        ai_responded,
        ai_ignored,
        top_detectors,
        latest_telemetry: crate::telemetry::read_latest_snapshot(data_dir, date),
    }
}

/// Count non-empty lines in a file without parsing JSON (fast for large files).
pub(super) fn count_file_lines(path: &Path) -> usize {
    let Ok(file) = std::fs::File::open(path) else {
        return 0;
    };
    std::io::BufReader::new(file)
        .lines()
        .filter(|l| l.as_ref().map(|s| !s.trim().is_empty()).unwrap_or(false))
        .count()
}
