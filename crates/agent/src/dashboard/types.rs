use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::telemetry::TelemetrySnapshot;

pub struct AdvisoryEntry {
    pub advisory_id: String,
    pub command_hash: String,
    pub command_preview: String,
    pub risk_score: u32,
    pub recommendation: String,
    pub signals: Vec<String>,
    pub ts: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// D3 - action request / response structs
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub(crate) struct BlockIpRequest {
    /// Target IP address to block.
    ip: String,
    /// Operator-supplied reason (mandatory - becomes the audit trail entry).
    reason: String,
    /// Optional incident ID to associate this action with.
    incident_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct SuspendUserRequest {
    /// Linux username to suspend from sudo.
    user: String,
    /// Operator-supplied reason (mandatory).
    reason: String,
    /// How long to suspend (seconds). Defaults to 3600 (1 hour).
    duration_secs: Option<u64>,
    /// Optional incident ID to associate this action with.
    incident_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct HoneypotTestRequest {
    /// Operator-supplied reason (mandatory).
    reason: String,
    /// Duration in seconds for the honeypot session (default: 120).
    duration_secs: Option<u64>,
}

#[derive(Debug, Serialize)]
pub(crate) struct ActionResponse {
    success: bool,
    dry_run: bool,
    message: String,
    /// Echoes back the skill ID that was invoked (or would have been).
    skill_id: String,
}

// ---------------------------------------------------------------------------
// Query structs
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub(crate) struct ListQuery {
    limit: Option<usize>,
    date: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct EntitiesQuery {
    limit: Option<usize>,
    date: Option<String>,
    severity_min: Option<String>,
    detector: Option<String>,
    group_by: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct JourneyQuery {
    subject_type: Option<String>,
    subject: Option<String>,
    // Backward compatibility with D2.1 clients
    ip: Option<String>,
    date: Option<String>,
    severity_min: Option<String>,
    detector: Option<String>,
    window_seconds: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct ClusterQuery {
    limit: Option<usize>,
    date: Option<String>,
    severity_min: Option<String>,
    detector: Option<String>,
    window_seconds: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct ExportQuery {
    date: Option<String>,
    format: Option<String>,
    subject_type: Option<String>,
    subject: Option<String>,
    // Backward compatibility with D2.1 clients
    ip: Option<String>,
    severity_min: Option<String>,
    detector: Option<String>,
    group_by: Option<String>,
    limit: Option<usize>,
    window_seconds: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct ReportQuery {
    /// Optional specific date (YYYY-MM-DD). Defaults to latest available.
    date: Option<String>,
}

// ---------------------------------------------------------------------------
// Response structs - existing
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub(crate) struct OverviewResponse {
    date: String,
    events_count: usize,
    incidents_count: usize,
    decisions_count: usize,
    /// Incidents where AI decided to act (block, kill, honeypot, monitor).
    /// This is the "real threat" count. incidents_count - confirmed = noise/ignored.
    ai_confirmed: usize,
    /// Incidents where AI executed a response action (block_ip, kill_process, etc).
    ai_responded: usize,
    /// Incidents where AI decided to ignore (false positive or low risk).
    ai_ignored: usize,
    top_detectors: Vec<DetectorCount>,
    latest_telemetry: Option<TelemetrySnapshot>,
}

#[derive(Debug, Serialize)]
pub(crate) struct DetectorCount {
    detector: String,
    count: usize,
}

#[derive(Debug, Serialize)]
pub(crate) struct IncidentListResponse {
    date: String,
    total: usize,
    items: Vec<IncidentView>,
}

#[derive(Debug, Serialize)]
pub(crate) struct DecisionListResponse {
    date: String,
    total: usize,
    items: Vec<DecisionView>,
}

#[derive(Debug, Serialize)]
pub(crate) struct IncidentView {
    ts: chrono::DateTime<Utc>,
    incident_id: String,
    severity: String,
    title: String,
    summary: String,
    entities: Vec<String>,
    tags: Vec<String>,
    /// Resolution status: "blocked", "suspended", "monitored", "ignored", or "open"
    outcome: String,
    /// What action was taken (e.g. "block-ip-ufw", "fail2ban:sshd")
    #[serde(skip_serializing_if = "Option::is_none")]
    action_taken: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct DecisionView {
    ts: chrono::DateTime<Utc>,
    incident_id: String,
    action_type: String,
    target_ip: Option<String>,
    skill_id: Option<String>,
    confidence: f32,
    auto_executed: bool,
    dry_run: bool,
    reason: String,
    execution_result: String,
}

// ---------------------------------------------------------------------------
// Response structs - D2 journey
// ---------------------------------------------------------------------------

/// Summarizes an attacker (IP with at least one incident) for the left panel.
#[derive(Debug, Serialize)]
pub(crate) struct AttackerSummary {
    ip: String,
    first_seen: chrono::DateTime<Utc>,
    last_seen: chrono::DateTime<Utc>,
    max_severity: String,
    detectors: Vec<String>,
    /// "blocked" | "monitoring" | "honeypot" | "active" | "unknown"
    outcome: String,
    incident_count: usize,
    event_count: usize,
}

#[derive(Debug, Serialize)]
pub(crate) struct EntitiesResponse {
    date: String,
    attackers: Vec<AttackerSummary>,
}

/// One timestamped entry in an attacker's journey timeline.
#[derive(Debug, Serialize)]
pub(crate) struct JourneyEntry {
    ts: chrono::DateTime<Utc>,
    /// "event" | "incident" | "decision" | "honeypot_ssh" | "honeypot_http" | "honeypot_banner"
    kind: String,
    data: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub(crate) struct JourneySummary {
    total_entries: usize,
    events_count: usize,
    incidents_count: usize,
    decisions_count: usize,
    honeypot_count: usize,
    first_event: Option<chrono::DateTime<Utc>>,
    first_incident: Option<chrono::DateTime<Utc>>,
    first_decision: Option<chrono::DateTime<Utc>>,
    first_honeypot: Option<chrono::DateTime<Utc>>,
    pivot_shortcuts: Vec<String>,
    hints: Vec<String>,
}

/// D5 - High-level attack assessment derived from the journey entries.
#[derive(Debug, Serialize)]
pub(crate) struct JourneyVerdict {
    /// Detected attack vector: "ssh_bruteforce" | "credential_stuffing" |
    /// "port_scan" | "sudo_abuse" | "unknown"
    entry_vector: String,
    /// "no_evidence_of_success" | "likely_success" | "confirmed_success" | "inconclusive"
    access_status: String,
    /// "no_evidence" | "attempted" | "confirmed" | "inconclusive"
    privilege_status: String,
    /// "blocked" | "monitored" | "honeypot" | "active" | "unknown"
    containment_status: String,
    /// "engaged" | "diverted" | "not_engaged"
    honeypot_status: String,
    /// "high" | "medium" | "low"
    confidence: String,
}

/// D5 - A logical phase of the attack story derived from consecutive entries.
#[derive(Debug, Serialize)]
pub(crate) struct JourneyChapter {
    /// Stage label: "reconnaissance" | "initial_access_attempt" | "access_success" |
    /// "privilege_abuse" | "response" | "containment" | "honeypot_interaction" | "unknown"
    stage: String,
    title: String,
    summary: String,
    start_ts: chrono::DateTime<Utc>,
    end_ts: chrono::DateTime<Utc>,
    entry_count: usize,
    /// Key facts / evidence highlights (usernames, ports, credentials, etc.)
    evidence_highlights: Vec<String>,
    /// Indices into the parent `entries` array for drill-down
    entry_indices: Vec<usize>,
}

#[derive(Debug, Serialize)]
pub(crate) struct JourneyResponse {
    subject_type: String,
    subject: String,
    date: String,
    first_seen: Option<chrono::DateTime<Utc>>,
    last_seen: Option<chrono::DateTime<Utc>>,
    outcome: String,
    summary: JourneySummary,
    /// D5 - high-level attack assessment
    verdict: JourneyVerdict,
    /// D5 - logical attack chapters derived from entries
    chapters: Vec<JourneyChapter>,
    entries: Vec<JourneyEntry>,
}

#[derive(Debug, Serialize)]
pub(crate) struct PivotItem {
    group_by: String,
    value: String,
    first_seen: chrono::DateTime<Utc>,
    last_seen: chrono::DateTime<Utc>,
    max_severity: String,
    incident_count: usize,
    event_count: usize,
    outcome: String,
    detectors: Vec<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct PivotResponse {
    date: String,
    group_by: String,
    total: usize,
    items: Vec<PivotItem>,
}

#[derive(Debug, Serialize)]
pub(crate) struct ClusterItem {
    cluster_id: String,
    pivot: String,
    pivot_type: String,
    pivot_value: String,
    start_ts: DateTime<Utc>,
    end_ts: DateTime<Utc>,
    incident_count: usize,
    detector_kinds: Vec<String>,
    incident_ids: Vec<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct ClusterResponse {
    date: String,
    total: usize,
    items: Vec<ClusterItem>,
}

#[derive(Debug, Serialize)]
pub(crate) struct InvestigationExport {
    generated_at: DateTime<Utc>,
    date: String,
    filters: serde_json::Value,
    group_by: String,
    subject_type: Option<String>,
    subject: Option<String>,
    overview: OverviewResponse,
    pivots: Vec<PivotItem>,
    clusters: Vec<ClusterItem>,
    journey: Option<JourneyResponse>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PivotKind {
    Ip,
    User,
    Detector,
}

impl PivotKind {
    pub(crate) fn parse(raw: Option<&str>) -> Self {
        match raw.unwrap_or("ip").trim().to_ascii_lowercase().as_str() {
            "user" => Self::User,
            "detector" => Self::Detector,
            _ => Self::Ip,
        }
    }

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Ip => "ip",
            Self::User => "user",
            Self::Detector => "detector",
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct InvestigationFilters {
    severity_min: Option<u8>,
    detector: Option<String>,
}

impl InvestigationFilters {
    pub(crate) fn from_query(severity_min: Option<&str>, detector: Option<&str>) -> Self {
        let severity_min = severity_min
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(|v| severity_order(v.to_ascii_lowercase().as_str()));
        let severity_min = match severity_min {
            Some(0) | None => None,
            other => other,
        };

        let detector = detector
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(|v| v.to_ascii_lowercase());

        Self {
            severity_min,
            detector,
        }
    }
}

// ---------------------------------------------------------------------------
// Internal accumulator for grouping events/incidents by IP
// ---------------------------------------------------------------------------

#[derive(Default)]
pub(crate) struct IpAccumulator {
    first_seen: Option<chrono::DateTime<Utc>>,
    last_seen: Option<chrono::DateTime<Utc>>,
    max_severity: u8,
    max_severity_str: String,
    detectors: BTreeSet<String>,
    ips: BTreeSet<String>,
    incident_count: usize,
    event_count: usize,
}

impl IpAccumulator {
    pub(crate) fn update_time(&mut self, ts: chrono::DateTime<Utc>) {
        if self.first_seen.is_none_or(|existing| ts < existing) {
            self.first_seen = Some(ts);
        }
        if self.last_seen.is_none_or(|existing| ts > existing) {
            self.last_seen = Some(ts);
        }
    }
}

pub(crate) fn severity_order(s: &str) -> u8 {
    match s {
        "critical" => 5,
        "high" => 4,
        "medium" => 3,
        "low" => 2,
        "info" => 1,
        _ => 0,
    }
}
