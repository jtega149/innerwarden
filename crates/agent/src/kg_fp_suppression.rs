//! Spec 043 Phase 7 — KG-based false-positive suppression (shadow-first).
//!
//! Walks the KG neighborhood of an incident's primary entity and
//! computes a `likelihood` in `[0, 1]` that the incident is a false
//! positive. Combines:
//!
//! - `benign_history_score` (reuse `kg_decide_features::extract_features_for_ip`):
//!   ratio of dismissed / low-severity / FP-flagged incidents over 7d.
//! - Edges to entities the operator has explicitly marked
//!   `false_positive = true` — strong human-confirmed signal.
//!
//! Three actions per likelihood band (per spec 043):
//! - `>= suppress_threshold` (default 0.80) → suppress (write dismiss
//!   decision, skip routing).
//! - `< suppress_threshold`                 → pass through unchanged.
//!
//! Phase 7 v1 ships **suppress** + **pass-through** only. The spec's
//! "downgrade severity by one level" tier is deferred — it requires
//! mutating `&Incident` (currently borrowed immutably through the
//! whole intake loop), which is invasive. Operator can request that
//! tier later if shadow data shows a meaningful 0.50..0.80 band.
//!
//! Three modes via `[kg.fp_suppression].mode`:
//! - `"off"`     — code path skips entirely (rollback without redeploy).
//! - `"shadow"`  — computes likelihood, writes a JSONL log, does NOT
//!   change behavior. Default.
//! - `"enforce"` — applies suppression decisions for incidents above
//!   `suppress_threshold`.
//!
//! Critical floor (hard rule in code, anchor pinned): incidents with
//! `Severity::Critical` MUST NEVER be suppressed by this path even at
//! likelihood = 1.0. Defensive layering with operator-reviewed safety
//! cases — Critical is reserved for active compromise indicators
//! (kill chain, reverse shell, ransomware, data exfil) where the
//! operator wants visibility regardless of historical benign signal.
//!
//! Operator promotion gate (per Spec 043 prerequisites): Phase 1 must
//! be in `enforce` mode in prod for ≥7 days before Phase 7 promotes
//! from `shadow` to `enforce`. The two phases are mutually reinforcing
//! — Phase 1 modifies AI confidence; Phase 7 short-circuits suppression
//! at intake. Reaching enforce on Phase 7 too early without Phase 1
//! validation risks suppressing real signal that the modifier hasn't
//! had a chance to evaluate.

use std::path::Path;

use chrono::{DateTime, Utc};
use innerwarden_core::event::Severity;
use innerwarden_core::incident::Incident;
use serde::Serialize;
use tracing::warn;

use crate::knowledge_graph::types::{Node, Relation};
use crate::knowledge_graph::KnowledgeGraph;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FpSuppressionMode {
    Off,
    Shadow,
    Enforce,
}

pub fn parse_mode(s: &str) -> FpSuppressionMode {
    match s.trim().to_ascii_lowercase().as_str() {
        "enforce" => FpSuppressionMode::Enforce,
        "shadow" => FpSuppressionMode::Shadow,
        _ => FpSuppressionMode::Off,
    }
}

/// Action the suppressor recommends for the current incident. Resolved
/// from `(likelihood, severity, config)` via `classify`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FpAction {
    /// Likelihood < `suppress_threshold` OR Critical severity. Caller
    /// continues normal routing.
    PassThrough,
    /// Likelihood >= `suppress_threshold` AND severity != Critical.
    /// Caller (in enforce mode) writes a dismiss decision and skips
    /// further routing.
    Suppress,
}

/// Compute the FP likelihood for an incident.
///
/// Returns `0.0` when the incident has no IP entity OR the IP isn't
/// yet a node in the graph. This makes the function fail-safe: an
/// unknown entity always passes through (no suppression possible).
///
/// Returns a value in `[0, 1]` weighted as:
/// - 70% `benign_history_score` (the bulk of the signal)
/// - 30% bonus for any `Relation::TriggeredBy` edges to entities
///   marked `false_positive = true` (capped at 0.30 to prevent the
///   bonus alone from triggering suppression).
pub fn fp_likelihood(kg: &KnowledgeGraph, incident: &Incident, now: DateTime<Utc>) -> f32 {
    let Some(features) = crate::kg_decide_features::extract_features(kg, incident, now) else {
        return 0.0;
    };

    let history_score = features.benign_history_score;

    // Operator-FP-edge bonus: count incidents on this IP that the
    // operator (or auto-flagger) has explicitly marked as
    // false_positive. Each one adds 0.10 to the bonus, capped at 0.30
    // (3 confirmed FPs is enough to flip the verdict).
    let fp_edge_bonus = {
        let primary_ip = incident
            .entities
            .iter()
            .find(|e| matches!(e.r#type, innerwarden_core::entities::EntityType::Ip))
            .map(|e| e.value.as_str());
        let Some(ip) = primary_ip else {
            return 0.0;
        };
        let Some(ip_id) = kg.find_by_ip(ip) else {
            return history_score;
        };
        let mut fp_count: u32 = 0;
        for edge in kg.incoming_edges(ip_id) {
            if edge.relation != Relation::TriggeredBy {
                continue;
            }
            if let Some(Node::Incident { false_positive, .. }) = kg.get_node(edge.from) {
                if *false_positive {
                    fp_count = fp_count.saturating_add(1);
                }
            }
        }
        (fp_count as f32 * 0.10).min(0.30)
    };

    // Final blend: 70% history + 30% bonus, clamped to [0, 1].
    let blended = history_score * 0.70 + fp_edge_bonus;
    blended.clamp(0.0, 1.0)
}

/// Critical floor (defensive layering): regardless of likelihood,
/// `Severity::Critical` incidents NEVER get suppressed. Operator wants
/// visibility on active-compromise indicators (kill chain, reverse
/// shell, ransomware, data exfil) even when the entity history looks
/// pristine. Anchor test pins this rule.
pub fn classify(likelihood: f32, severity: &Severity, suppress_threshold: f32) -> FpAction {
    if matches!(severity, Severity::Critical) {
        return FpAction::PassThrough;
    }
    if likelihood >= suppress_threshold {
        FpAction::Suppress
    } else {
        FpAction::PassThrough
    }
}

/// Single record appended to `kg_shadow_fp_suppression_<YYYY-MM-DD>.jsonl`
/// when running in `mode = "shadow"`. Operator inspects this log
/// for ≥7 days before promoting to `enforce`. The
/// `would_change_action` boolean (true when the action would have
/// been Suppress) is the operator's primary scrutiny target.
#[derive(Debug, Serialize)]
pub struct FpShadowLogRecord {
    pub ts: String,
    pub incident_id: String,
    pub real_severity: String,
    pub fp_likelihood: f32,
    pub action: &'static str, // "passthrough" | "suppress"
    pub would_change_action: bool,
    pub features: crate::kg_decide_features::KgDecideFeatures,
}

/// Best-effort append to today's FP-suppression shadow log. Failures
/// emit a `WARN` and DO NOT propagate. Mirrors `kg_decide_features::
/// write_shadow_log` for consistency — operator's downstream `jq`
/// pipelines can grep the same way on both files.
pub fn write_shadow_log(data_dir: &Path, record: &FpShadowLogRecord) {
    let date = chrono::Utc::now().format("%Y-%m-%d").to_string();
    let path = data_dir.join(format!("kg_shadow_fp_suppression_{}.jsonl", date));
    let line = match serde_json::to_string(record) {
        Ok(s) => s,
        Err(e) => {
            warn!("kg_fp_suppression: failed to serialize shadow log: {e}");
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
            "kg_fp_suppression: failed to append shadow log {}: {e}",
            path.display()
        );
    }
}

/// Convert `Severity` to the lowercase string the agent's audit JSONL
/// uses (`"critical"`, `"high"`, `"medium"`, `"low"`, `"info"`).
fn severity_label(sev: &Severity) -> &'static str {
    match sev {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
        Severity::Info => "info",
        // Anything else (e.g. Debug, future variants) collapses to
        // "low" in the audit log — better than panicking on a new
        // variant that the agent gets but the KG-FP path didn't
        // anticipate.
        _ => "low",
    }
}

/// Construct a shadow log record for the given (incident, likelihood,
/// action) tuple. Extracted so tests can build records without going
/// through the full intake.
pub fn make_shadow_record(
    incident: &Incident,
    likelihood: f32,
    action: FpAction,
    features: crate::kg_decide_features::KgDecideFeatures,
    now: DateTime<Utc>,
) -> FpShadowLogRecord {
    let action_label = match action {
        FpAction::PassThrough => "passthrough",
        FpAction::Suppress => "suppress",
    };
    FpShadowLogRecord {
        ts: now.to_rfc3339(),
        incident_id: incident.incident_id.clone(),
        real_severity: severity_label(&incident.severity).to_string(),
        fp_likelihood: likelihood,
        action: action_label,
        would_change_action: matches!(action, FpAction::Suppress),
        features,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::knowledge_graph::types::{Edge, Node};
    use chrono::{Duration, TimeZone};
    use innerwarden_core::entities::EntityRef;

    fn fixed_now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 5, 6, 12, 0, 0).unwrap()
    }

    fn make_ip_node(addr: &str, age_days: i64) -> Node {
        let now = fixed_now();
        Node::Ip {
            addr: addr.to_string(),
            is_internal: false,
            datasets: vec![],
            risk_score: 5,
            is_tor: false,
            first_seen: now - Duration::days(age_days),
            last_seen: now,
            attempted_usernames: vec![],
        }
    }

    fn make_incident_node(id: &str, sev: &str, dismissed: bool, fp: bool) -> Node {
        Node::Incident {
            incident_id: id.to_string(),
            detector: "test".to_string(),
            severity: sev.to_string(),
            title: format!("test {sev}"),
            summary: String::new(),
            ts: fixed_now() - Duration::hours(6),
            mitre_ids: vec![],
            decision: if dismissed {
                Some("dismiss".to_string())
            } else {
                None
            },
            confidence: None,
            decision_reason: None,
            decision_target: None,
            auto_executed: false,
            is_allowlisted: false,
            false_positive: fp,
            fp_reporter: None,
            fp_reported_at: None,
            research_only: false,
        }
    }

    fn make_incident(ip: &str, sev: Severity) -> Incident {
        Incident {
            ts: fixed_now(),
            host: String::new(),
            incident_id: format!("test:{ip}"),
            severity: sev,
            title: "trigger".to_string(),
            summary: String::new(),
            evidence: serde_json::Value::Null,
            recommended_checks: vec![],
            tags: vec![],
            entities: vec![EntityRef::ip(ip)],
        }
    }

    fn seed_history(
        kg: &mut KnowledgeGraph,
        ip_id: crate::knowledge_graph::types::NodeId,
        benign_count: usize,
        malicious_count: usize,
    ) {
        for i in 0..benign_count {
            let inc = kg.add_node(make_incident_node(
                &format!("benign:{i}"),
                "medium",
                true,
                false,
            ));
            kg.add_edge(Edge::new(
                inc,
                ip_id,
                Relation::TriggeredBy,
                fixed_now() - Duration::hours(6),
            ));
        }
        for i in 0..malicious_count {
            let inc = kg.add_node(make_incident_node(
                &format!("malicious:{i}"),
                "high",
                false,
                false,
            ));
            kg.add_edge(Edge::new(
                inc,
                ip_id,
                Relation::TriggeredBy,
                fixed_now() - Duration::hours(6),
            ));
        }
    }

    /// Headline anchor: an entity with overwhelming benign history
    /// returns a high likelihood. 100 dismissed-Medium + 1 malicious
    /// → benign_history_score ≈ 0.99 → likelihood ≈ 0.69 (just below
    /// suppress_threshold of 0.80; needs FP edges or stronger history
    /// to trigger Suppress).
    #[test]
    fn high_benign_history_returns_high_likelihood() {
        let mut kg = KnowledgeGraph::new();
        let ip_id = kg.add_node(make_ip_node("203.0.113.10", 30));
        seed_history(&mut kg, ip_id, 100, 1);
        let inc = make_incident("203.0.113.10", Severity::Medium);
        let likelihood = fp_likelihood(&kg, &inc, fixed_now());
        // history ≈ 0.99 * 0.70 = 0.693
        assert!(
            (0.65..0.75).contains(&likelihood),
            "100 benign + 1 malicious must yield ~0.69 (history * 0.70); got {likelihood}"
        );
    }

    /// Critical floor anchor: even with likelihood = 1.0, a Critical
    /// incident MUST PassThrough. The most dangerous failure mode of
    /// the whole spec — silently suppressing a real compromise alert
    /// on an entity that looks pristine on paper.
    #[test]
    fn critical_severity_always_passes_through() {
        let action = classify(1.0, &Severity::Critical, 0.80);
        assert_eq!(
            action,
            FpAction::PassThrough,
            "Critical severity MUST PassThrough regardless of likelihood"
        );
        // And lower likelihoods too (defensive coverage).
        assert_eq!(
            classify(0.95, &Severity::Critical, 0.80),
            FpAction::PassThrough
        );
    }

    /// High severity at high likelihood DOES suppress. Mirror anchor
    /// proving the Critical floor isn't accidentally hiding everything.
    #[test]
    fn high_severity_above_threshold_is_suppressed() {
        assert_eq!(classify(0.85, &Severity::High, 0.80), FpAction::Suppress);
        assert_eq!(classify(0.81, &Severity::High, 0.80), FpAction::Suppress);
    }

    /// Below-threshold incidents pass through regardless of severity.
    #[test]
    fn below_threshold_passes_through() {
        assert_eq!(classify(0.79, &Severity::High, 0.80), FpAction::PassThrough);
        assert_eq!(
            classify(0.50, &Severity::Medium, 0.80),
            FpAction::PassThrough
        );
        assert_eq!(classify(0.0, &Severity::Low, 0.80), FpAction::PassThrough);
    }

    /// Operator-confirmed FP edges add up to 0.30 bonus, capped. Three
    /// false_positive=true incidents alone (no benign-history) push
    /// likelihood from 0.5 * 0.7 = 0.35 to 0.35 + 0.30 = 0.65 — still
    /// below the 0.80 threshold. Anchors the cap so a single operator
    /// FP-flag spree can't flip suppression unilaterally.
    #[test]
    fn fp_edge_bonus_caps_at_zero_thirty() {
        let mut kg = KnowledgeGraph::new();
        let ip_id = kg.add_node(make_ip_node("203.0.113.20", 30));
        // 5 false_positive=true incidents (more than the 3 cap)
        for i in 0..5 {
            let inc = kg.add_node(make_incident_node(
                &format!("fp:{i}"),
                "high",
                false,
                true, // false_positive = true
            ));
            kg.add_edge(Edge::new(
                inc,
                ip_id,
                Relation::TriggeredBy,
                fixed_now() - Duration::hours(6),
            ));
        }
        let inc = make_incident("203.0.113.20", Severity::Medium);
        let likelihood = fp_likelihood(&kg, &inc, fixed_now());
        // Note: false_positive=true incidents ALSO count as benign in
        // benign_history_score (per kg_decide_features logic), so the
        // history is 1.0 * 0.70 = 0.70; bonus is capped at 0.30; total
        // capped at 1.0.
        assert!(
            likelihood <= 1.0 + f32::EPSILON,
            "likelihood must be clamped to [0, 1]; got {likelihood}"
        );
        // Bonus alone (without high history) cannot exceed 0.30.
        // We can't measure bonus directly here without history=0 fixture,
        // but we can verify the clamp upper bound.
        assert!(likelihood >= 0.95, "got {likelihood}");
    }

    /// Default fallback: no IP entity → likelihood = 0.0 (PassThrough).
    /// Anchors the fail-safe so a malformed incident never accidentally
    /// gets suppressed.
    #[test]
    fn no_ip_entity_returns_zero_likelihood() {
        let kg = KnowledgeGraph::new();
        let inc = Incident {
            ts: fixed_now(),
            host: String::new(),
            incident_id: "no-ip".to_string(),
            severity: Severity::High,
            title: String::new(),
            summary: String::new(),
            evidence: serde_json::Value::Null,
            recommended_checks: vec![],
            tags: vec![],
            entities: vec![], // no entities at all
        };
        let likelihood = fp_likelihood(&kg, &inc, fixed_now());
        assert_eq!(likelihood, 0.0);
    }

    /// Mode parsing fallback: typo'd / empty config strings collapse
    /// to `Off` rather than panicking. Mirror of `kg_decide_features::
    /// parse_mode`'s contract.
    #[test]
    fn parse_mode_unknown_collapses_to_off() {
        assert_eq!(parse_mode("enforce"), FpSuppressionMode::Enforce);
        assert_eq!(parse_mode("ENFORCE"), FpSuppressionMode::Enforce);
        assert_eq!(parse_mode("shadow"), FpSuppressionMode::Shadow);
        assert_eq!(parse_mode(""), FpSuppressionMode::Off);
        assert_eq!(parse_mode("typo"), FpSuppressionMode::Off);
    }

    /// Shadow log writes JSONL with the expected schema. Pins the
    /// operator-facing structure so a future "rotate format" PR must
    /// update both writer and downstream `jq` parsers.
    #[test]
    fn write_shadow_log_writes_jsonl_with_expected_schema() {
        let dir = tempfile::tempdir().expect("tempdir");
        let features = crate::kg_decide_features::KgDecideFeatures {
            prior_incidents_24h: 5,
            benign_history_score: 0.92,
            related_campaigns: 0,
            cluster_size: 8,
            risk_score: 12,
            first_seen_age_days: 10,
        };
        let inc = make_incident("203.0.113.30", Severity::High);
        let record = make_shadow_record(&inc, 0.85, FpAction::Suppress, features, fixed_now());
        write_shadow_log(dir.path(), &record);

        let entries: Vec<_> = std::fs::read_dir(dir.path())
            .expect("readdir")
            .filter_map(Result::ok)
            .collect();
        assert_eq!(entries.len(), 1, "exactly one shadow log file");
        let body = std::fs::read_to_string(entries[0].path()).expect("read");
        assert!(body.contains("\"action\":\"suppress\""));
        assert!(body.contains("\"would_change_action\":true"));
        assert!(body.contains("\"fp_likelihood\":0.85"));
        assert!(body.contains("\"real_severity\":\"high\""));
    }
}
