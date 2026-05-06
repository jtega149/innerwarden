//! Spec 043 Phase 1 — KG-derived features for the Decide path (shadow-first).
//!
//! Reads the knowledge graph for an incident's primary IP and produces
//! a numeric `confidence_modifier` (-0.30 .. +0.20) that the decision
//! pipeline uses to nudge AI-proposed confidence based on the entity's
//! history. Long-term replaces the indirect `attacker_profiles` sidecar
//! lookup currently in `incident_decision_eval.rs` (Spec 043 Phase 8);
//! during Phase 1 the existing path stays intact and this runs after it.
//!
//! Three modes via `[kg.decide_modifier_mode]`:
//! - `"off"`     — code path skips entirely (rollback without redeploy).
//! - `"shadow"`  — computes modifier, writes a JSONL log, does NOT apply.
//! - `"enforce"` — applies the modifier to `decision.confidence`.
//!
//! Critical floor (defensive layering with Phase 7): on `Severity::Critical`
//! incidents, negative modifiers are clamped to 0.0. Real Critical alerts
//! never get suppressed via this path even when an entity looks benign on
//! paper. Anti-regression anchor pins the rule.
//!
//! Operator promotion gate (per Spec 043): minimum 7 days of `shadow`
//! data with non-zero `would_change_action` count and operator-sampled
//! correctness check before flipping config to `enforce`.

use std::path::Path;

use chrono::{DateTime, Duration, Utc};
use innerwarden_core::entities::EntityType;
use innerwarden_core::event::Severity;
use innerwarden_core::incident::Incident;
use serde::Serialize;
use tracing::warn;

use crate::knowledge_graph::types::{Node, Relation};
use crate::knowledge_graph::KnowledgeGraph;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecideModifierMode {
    Off,
    Shadow,
    Enforce,
}

pub fn parse_mode(s: &str) -> DecideModifierMode {
    match s.trim().to_ascii_lowercase().as_str() {
        "enforce" => DecideModifierMode::Enforce,
        "shadow" => DecideModifierMode::Shadow,
        _ => DecideModifierMode::Off,
    }
}

/// Six numeric features derived from the entity's neighborhood + history.
/// All bounded so the consumer (`compute_modifier`) can stay branch-only.
#[derive(Debug, Clone, Copy, Serialize, PartialEq)]
pub struct KgDecideFeatures {
    /// Count of incidents triggered by this entity in the last 24h.
    pub prior_incidents_24h: u32,
    /// Ratio of (low-sev + false-positive) incidents to total incidents in
    /// the last 7d. `0.0` = all malicious, `1.0` = all benign. When the
    /// entity has no 7d history, defaults to `0.5` (neutral) rather than
    /// `0.0` or `1.0` to avoid biasing an unknown attacker either way.
    pub benign_history_score: f32,
    /// Number of campaigns this IP is a member of (outgoing `MemberOf`
    /// edges to Campaign nodes).
    pub related_campaigns: u32,
    /// Distinct neighbor count at depth=1 (in + out edges, dedup'd by
    /// other-end node id).
    pub cluster_size: u32,
    /// AbuseIPDB risk score (0..100) cached on the IP node.
    pub risk_score: u8,
    /// How long the agent has known this IP, in whole days.
    pub first_seen_age_days: u32,
}

/// Extract features for `incident`'s primary IP. Returns `None` when:
/// - the incident has no `EntityType::Ip` entity, or
/// - the IP is not yet a node in the graph (first observation).
///
/// `now` is injected so the caller controls the clock (tests set it to
/// a fixed instant; production passes `Utc::now()`).
pub fn extract_features(
    kg: &KnowledgeGraph,
    incident: &Incident,
    now: DateTime<Utc>,
) -> Option<KgDecideFeatures> {
    let ip = incident
        .entities
        .iter()
        .find(|e| e.r#type == EntityType::Ip)
        .map(|e| e.value.as_str())?;

    let ip_id = kg.find_by_ip(ip)?;
    let ip_node = kg.get_node(ip_id)?;

    let (risk_score, first_seen) = match ip_node {
        Node::Ip {
            risk_score,
            first_seen,
            ..
        } => (*risk_score, *first_seen),
        _ => return None,
    };

    let cutoff_24h = now - Duration::hours(24);
    let cutoff_7d = now - Duration::days(7);

    let mut prior_incidents_24h: u32 = 0;
    let mut benign_count: u32 = 0;
    let mut malicious_count: u32 = 0;

    // TriggeredBy edges point Incident -> Entity; from the IP's
    // perspective they are incoming.
    for edge in kg.incoming_edges(ip_id) {
        if edge.relation != Relation::TriggeredBy {
            continue;
        }
        if let Some(Node::Incident {
            ts,
            severity,
            false_positive,
            ..
        }) = kg.get_node(edge.from)
        {
            if *ts >= cutoff_24h {
                prior_incidents_24h = prior_incidents_24h.saturating_add(1);
            }
            if *ts >= cutoff_7d {
                let sev = severity.to_ascii_lowercase();
                let benign_class = *false_positive || sev == "low" || sev == "info";
                if benign_class {
                    benign_count = benign_count.saturating_add(1);
                } else {
                    malicious_count = malicious_count.saturating_add(1);
                }
            }
        }
    }

    let total_7d = benign_count.saturating_add(malicious_count);
    let benign_history_score = if total_7d == 0 {
        // Neutral when no history — don't bias unknown attackers either way.
        0.5
    } else {
        benign_count as f32 / total_7d as f32
    };

    let related_campaigns = kg
        .outgoing_edges(ip_id)
        .iter()
        .filter(|e| e.relation == Relation::MemberOf)
        .count() as u32;

    let mut neighbors: std::collections::HashSet<crate::knowledge_graph::types::NodeId> =
        std::collections::HashSet::new();
    for edge in kg.outgoing_edges(ip_id) {
        neighbors.insert(edge.to);
    }
    for edge in kg.incoming_edges(ip_id) {
        neighbors.insert(edge.from);
    }
    let cluster_size = neighbors.len() as u32;

    let first_seen_age_days = (now - first_seen).num_days().max(0) as u32;

    Some(KgDecideFeatures {
        prior_incidents_24h,
        benign_history_score,
        related_campaigns,
        cluster_size,
        risk_score,
        first_seen_age_days,
    })
}

/// Translate features into a confidence modifier in `[-0.30, +0.20]`.
/// The branch order matters: we check the strongest benign signal first
/// so an entity that qualifies for `-0.30` does not also qualify for the
/// weaker `-0.10` band. Every band carries a reason string surfaced in
/// the shadow log so an operator can audit why a decision was nudged.
pub fn compute_modifier(f: &KgDecideFeatures) -> (f32, &'static str) {
    if f.benign_history_score >= 0.90
        && f.risk_score < 20
        && f.first_seen_age_days >= 30
        && f.prior_incidents_24h == 0
    {
        return (
            -0.30,
            "long-tenure benign entity (history>=0.90, risk<20, age>=30d, no recent activity)",
        );
    }
    if f.benign_history_score >= 0.75 && f.risk_score < 40 && f.first_seen_age_days >= 7 {
        return (-0.10, "moderately benign (history>=0.75, risk<40, age>=7d)");
    }
    if f.benign_history_score < 0.30 && f.related_campaigns > 0 {
        return (0.20, "campaign-cluster member with low benign history");
    }
    if f.risk_score > 80 && f.prior_incidents_24h > 5 {
        return (
            0.15,
            "high-reputation-risk repeat offender (risk>80, prior_24h>5)",
        );
    }
    (0.0, "no actionable signal")
}

/// Defensive layering with Spec 043 Phase 7: Critical incidents NEVER
/// receive a negative modifier through this path. Even an entity with
/// pristine 90-day history cannot suppress a real Critical compromise
/// alert. Positive modifiers on Critical are still allowed (they just
/// confirm a high-confidence threat further).
pub fn apply_critical_floor(modifier: f32, severity: &Severity) -> f32 {
    if matches!(severity, Severity::Critical) {
        modifier.max(0.0)
    } else {
        modifier
    }
}

/// Single record appended to `kg_shadow_decide_modifier_<YYYY-MM-DD>.jsonl`
/// when running in `mode = "shadow"`. Operator inspects this log for at
/// least 7 days before promoting to `enforce`. The `would_change_action`
/// boolean is the operator's primary scrutiny target — it counts how
/// many real-world decisions WOULD have flipped.
#[derive(Debug, Serialize)]
pub struct ShadowLogRecord {
    pub ts: String,
    pub incident_id: String,
    pub real_action: String,
    pub real_confidence: f32,
    pub modifier_raw: f32,
    pub modifier_after_floor: f32,
    pub new_confidence: f32,
    pub would_change_action: bool,
    pub features: KgDecideFeatures,
    pub reason: &'static str,
}

/// Best-effort append to today's shadow log. Failures (disk full, perm
/// denied) emit a `WARN` and DO NOT propagate — the agent must keep
/// running even when the audit log path is broken.
pub fn write_shadow_log(data_dir: &Path, record: &ShadowLogRecord) {
    let date = chrono::Utc::now().format("%Y-%m-%d").to_string();
    let path = data_dir.join(format!("kg_shadow_decide_modifier_{}.jsonl", date));
    let line = match serde_json::to_string(record) {
        Ok(s) => s,
        Err(e) => {
            warn!("kg_decide_features: failed to serialize shadow log: {e}");
            return;
        }
    };
    let result = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .and_then(|mut f| {
            use std::io::Write;
            writeln!(f, "{}", line)
        });
    if let Err(e) = result {
        warn!(
            "kg_decide_features: failed to append shadow log {}: {e}",
            path.display()
        );
    }
}

/// Helper used by the integration site to detect a would-be action
/// flip. The current AI router treats `confidence >= 0.85` as
/// auto-execute boundary (per `auto_exec_threshold` in the local
/// classifier; LLM providers use the same in practice). A modifier
/// that pushes confidence across this boundary is operationally
/// significant; one that nudges within the same band is cosmetic.
pub fn would_change_action(real_conf: f32, new_conf: f32) -> bool {
    const AUTO_EXEC_THRESHOLD: f32 = 0.85;
    (real_conf >= AUTO_EXEC_THRESHOLD) != (new_conf >= AUTO_EXEC_THRESHOLD)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::knowledge_graph::types::{Edge, Node};
    use chrono::TimeZone;
    use innerwarden_core::entities::EntityRef;
    use innerwarden_core::event::Severity;
    use innerwarden_core::incident::Incident;

    fn fixed_now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 5, 6, 12, 0, 0).unwrap()
    }

    fn make_ip_node(addr: &str, risk: u8, age_days: i64) -> Node {
        let now = fixed_now();
        Node::Ip {
            addr: addr.to_string(),
            is_internal: false,
            datasets: vec![],
            risk_score: risk,
            is_tor: false,
            first_seen: now - Duration::days(age_days),
            last_seen: now,
            attempted_usernames: vec![],
        }
    }

    fn make_incident_node(id: &str, sev: &str, ago_secs: i64, false_positive: bool) -> Node {
        Node::Incident {
            incident_id: id.to_string(),
            detector: "test_detector".to_string(),
            severity: sev.to_string(),
            title: format!("test {sev} incident"),
            summary: "test".to_string(),
            ts: fixed_now() - Duration::seconds(ago_secs),
            mitre_ids: vec![],
            decision: None,
            confidence: None,
            decision_reason: None,
            decision_target: None,
            auto_executed: false,
            is_allowlisted: false,
            false_positive,
            fp_reporter: None,
            fp_reported_at: None,
            research_only: false,
        }
    }

    fn make_incident(ip: &str) -> Incident {
        Incident {
            ts: fixed_now(),
            host: String::new(),
            incident_id: format!("trigger:test:{ip}"),
            severity: Severity::High,
            title: "trigger incident".to_string(),
            summary: String::new(),
            evidence: serde_json::Value::Null,
            recommended_checks: vec![],
            tags: vec![],
            entities: vec![EntityRef::ip(ip)],
        }
    }

    /// Spec 043 Phase 1 anchor: feature extraction over a fixture KG with
    /// known benign + malicious history yields the expected ratio.
    #[test]
    fn extract_features_from_fixture_graph() {
        let mut kg = KnowledgeGraph::new();
        let ip_id = kg.add_node(make_ip_node("203.0.113.10", 12, 45));
        // 5 benign (low) + 2 malicious (high) within 7d → ratio ≈ 0.714
        for i in 0..5 {
            let inc = kg.add_node(make_incident_node(
                &format!("benign:{i}"),
                "low",
                3600 * 12,
                false,
            ));
            kg.add_edge(Edge::new(
                inc,
                ip_id,
                Relation::TriggeredBy,
                fixed_now() - Duration::hours(12),
            ));
        }
        for i in 0..2 {
            let inc = kg.add_node(make_incident_node(
                &format!("malicious:{i}"),
                "high",
                3600 * 6,
                false,
            ));
            kg.add_edge(Edge::new(
                inc,
                ip_id,
                Relation::TriggeredBy,
                fixed_now() - Duration::hours(6),
            ));
        }

        let inc = make_incident("203.0.113.10");
        let f = extract_features(&kg, &inc, fixed_now()).expect("features extracted");

        assert_eq!(f.risk_score, 12);
        assert_eq!(f.first_seen_age_days, 45);
        assert_eq!(
            f.prior_incidents_24h, 7,
            "all 7 fixture incidents in 24h window"
        );
        // 5 benign / 7 total ≈ 0.714
        assert!(
            (f.benign_history_score - 5.0 / 7.0).abs() < 0.01,
            "got benign_history_score = {}",
            f.benign_history_score
        );
    }

    /// Anchor: the strongest benign signal (`-0.30` band) requires all
    /// four sub-conditions; missing any one falls through.
    #[test]
    fn compute_modifier_benign_history_yields_negative() {
        let f = KgDecideFeatures {
            prior_incidents_24h: 0,
            benign_history_score: 0.95,
            related_campaigns: 0,
            cluster_size: 12,
            risk_score: 10,
            first_seen_age_days: 45,
        };
        let (m, reason) = compute_modifier(&f);
        assert!((m - (-0.30)).abs() < f32::EPSILON, "got {m}");
        assert!(reason.contains("long-tenure benign"));
    }

    /// Anchor: the strongest malicious signal (`+0.20` band) requires
    /// both campaign membership AND low benign history.
    #[test]
    fn compute_modifier_aggressive_attacker_yields_positive() {
        let f = KgDecideFeatures {
            prior_incidents_24h: 3,
            benign_history_score: 0.10,
            related_campaigns: 2,
            cluster_size: 8,
            risk_score: 60,
            first_seen_age_days: 5,
        };
        let (m, reason) = compute_modifier(&f);
        assert!((m - 0.20).abs() < f32::EPSILON, "got {m}");
        assert!(reason.contains("campaign-cluster"));
    }

    /// Anchor: Critical incidents never receive a negative modifier.
    /// Defensive layering with Phase 7 — even when the entity looks
    /// benign on paper, a Critical compromise alert MUST go through.
    #[test]
    fn critical_severity_floor_holds() {
        // Strongly benign signal on a Critical incident.
        let benign_modifier = -0.30;
        assert_eq!(
            apply_critical_floor(benign_modifier, &Severity::Critical),
            0.0,
            "Critical must clamp negative modifier to 0"
        );
        // Positive modifier on Critical passes through.
        assert_eq!(
            apply_critical_floor(0.20, &Severity::Critical),
            0.20,
            "Critical must allow positive modifier (additional confirmation)"
        );
        // Non-Critical incidents pass any modifier through.
        assert_eq!(
            apply_critical_floor(-0.30, &Severity::High),
            -0.30,
            "High severity does not clamp"
        );
    }

    /// Anchor: the would_change_action heuristic flags only the
    /// auto-execute boundary crossing (the operationally significant
    /// flip), not within-band wiggle.
    #[test]
    fn would_change_action_detects_threshold_crossings_only() {
        // Crossing 0.85 boundary (auto-execute flipped off).
        assert!(would_change_action(0.90, 0.80));
        // Crossing 0.85 boundary (auto-execute flipped on).
        assert!(would_change_action(0.80, 0.90));
        // Same band (both above 0.85).
        assert!(!would_change_action(0.95, 0.90));
        // Same band (both below 0.85).
        assert!(!would_change_action(0.50, 0.40));
        // Edge: exactly at threshold counts as "above".
        assert!(would_change_action(0.84, 0.85));
    }

    /// Anchor: `parse_mode` collapses unknown / malformed strings to
    /// `Off` rather than panicking. The agent must boot even when the
    /// operator typoed the config.
    #[test]
    fn parse_mode_unknown_string_falls_back_to_off() {
        assert_eq!(parse_mode("enforce"), DecideModifierMode::Enforce);
        assert_eq!(parse_mode("ENFORCE"), DecideModifierMode::Enforce);
        assert_eq!(parse_mode("shadow"), DecideModifierMode::Shadow);
        assert_eq!(parse_mode("off"), DecideModifierMode::Off);
        assert_eq!(parse_mode(""), DecideModifierMode::Off);
        assert_eq!(parse_mode("typo"), DecideModifierMode::Off);
    }

    /// Anchor: shadow_log writes the JSONL line and the integration
    /// site can later flip mode to `enforce` without code changes.
    /// Pins file naming + JSON schema so a future "rotate format" PR
    /// must update both code and operator's downstream parsers.
    #[test]
    fn write_shadow_log_writes_jsonl_with_expected_schema() {
        let dir = tempfile::tempdir().expect("tempdir");
        let record = ShadowLogRecord {
            ts: "2026-05-06T12:00:00Z".to_string(),
            incident_id: "test:1".to_string(),
            real_action: "block_ip".to_string(),
            real_confidence: 0.90,
            modifier_raw: -0.30,
            modifier_after_floor: -0.30,
            new_confidence: 0.60,
            would_change_action: true,
            features: KgDecideFeatures {
                prior_incidents_24h: 0,
                benign_history_score: 0.95,
                related_campaigns: 0,
                cluster_size: 5,
                risk_score: 10,
                first_seen_age_days: 60,
            },
            reason: "test reason",
        };
        write_shadow_log(dir.path(), &record);

        // File name is date-stamped; pick the only one in the dir.
        let entries: Vec<_> = std::fs::read_dir(dir.path())
            .expect("readdir")
            .filter_map(Result::ok)
            .collect();
        assert_eq!(entries.len(), 1, "exactly one shadow log file");
        let body = std::fs::read_to_string(entries[0].path()).expect("read");
        assert!(body.contains("\"incident_id\":\"test:1\""));
        assert!(body.contains("\"modifier_after_floor\":-0.3"));
        assert!(body.contains("\"would_change_action\":true"));
    }
}
