//! Spec 049 PR20 — Cases tab reads from SQLite, not the in-memory KG.
//!
//! ## Why this exists
//!
//! Pre-PR20 the dashboard's `compute_incidents_blocking` read from
//! the in-memory `KnowledgeGraph`. The KG carries a 50 MB memory cap
//! with LRU eviction (`crate::knowledge_graph::graph::enforce_memory_limit`).
//! On a real day with ~480 sensor incidents the cap held; on a day
//! with hundreds of sensor false positives plus restarts, eviction
//! drops older Incident nodes from the KG. Result: the Cases tab
//! shrinks vs the canonical SQLite `incidents` table.
//!
//! Operator-reported on 2026-05-13 with `incidents_count: 480`
//! in `/api/overview` (SQLite) but only `68` items in `/api/incidents`
//! (KG). PR18 added a boot-time replay that closes the gap immediately
//! after restart; PR20 closes it permanently by making the Cases tab
//! read SQLite directly.
//!
//! ## What it covers
//!
//! 1. **Sensor incidents:** every row in the `incidents` table for the
//!    requested date, attached to its decision (if any) via the
//!    `incident_id` join. Output matches the legacy `IncidentView`
//!    shape so the frontend code is untouched.
//!
//! 2. **Non-incident-pipeline decisions** (Wave-10b documented):
//!    six `incident_id` prefixes emit decisions WITHOUT writing a
//!    matching incident row (`honeypot:always-on:abuseipdb:`,
//!    `honeypot:abuseipdb:`, `repeat-offender:`, `proto_anomaly:`,
//!    `suspicious_archive:`, `logging_config_change:`). PR20
//!    synthesises an `IncidentView` for each so the operator-visible
//!    audit trail mirrors the site's `/api/live-feed` count.
//!
//! ## Trade-off
//!
//! The KG continues to power `/api/journey` and drill-down queries
//! where relationship-walking is the point; the legacy `still_active_now`
//! decoration also stays in place. Cases listing is the only surface
//! that flips to SQLite.

use std::collections::{HashMap, HashSet};

use chrono::{DateTime, NaiveDate, Utc};
use innerwarden_core::incident::Incident;
use serde_json::Value;

use crate::dashboard::types::IncidentView;

/// Maximum incidents + decisions to walk per Cases-tab request. Loose
/// enough that no honest workload truncates and tight enough that a
/// pathological day cannot pin the response thread.
pub(super) const MAX_CASES_PER_REQUEST: usize = 100_000;

/// Build the full list of `IncidentView` rows for `date_str`.
///
/// Returns rows sorted ts-descending (newest first), trimmed to
/// `limit`. The total count returned in `IncidentListResponse.total`
/// is the unbounded total (pre-`take(limit)`) so the operator-visible
/// "N attackers · M cases" subtitle stays honest.
pub(super) fn build_cases_for_date(
    store: &innerwarden_store::Store,
    date_str: &str,
    now: DateTime<Utc>,
) -> (usize, Vec<IncidentView>) {
    // 1. Read incidents for the date (sensor-emitted rows).
    let start_ts = start_of_day_ts(date_str, now);
    let incidents = match store.incidents_since_ts(&start_ts, MAX_CASES_PER_REQUEST) {
        Ok(rows) => rows
            .into_iter()
            .filter(|i| ts_is_on_date(i.ts, date_str))
            .collect::<Vec<_>>(),
        Err(e) => {
            tracing::warn!(error = %e, "cases_from_sqlite: incidents query failed");
            Vec::new()
        }
    };

    // 2. Read decisions for the same date.
    let raw_decisions = match store.decisions_for_date(date_str, MAX_CASES_PER_REQUEST) {
        Ok(rows) => rows,
        Err(e) => {
            tracing::warn!(error = %e, "cases_from_sqlite: decisions query failed");
            Vec::new()
        }
    };
    let decisions_by_incident_id = group_decisions_by_incident_id(&raw_decisions);

    // 3. Build IncidentViews for the sensor incidents. Skip rows whose
    //    only external IP is self-traffic / Cloudflare so the listing
    //    agrees with `/api/overview.flagged_by_system_count` (PR20 fix
    //    for the "1 currently observing but no row to click" gap
    //    operator-reported on 2026-05-13 — `172.70.80.132` was a
    //    Cloudflare edge IP the strip counted but the panel hid).
    let mut views: Vec<IncidentView> = incidents
        .iter()
        .filter_map(|inc| build_view_for_sensor_incident(inc, &decisions_by_incident_id))
        .filter(|v| !view_only_touches_self_traffic(v))
        .collect();

    // 4. Synthesise IncidentViews for orphan decisions (Wave-10b).
    let seen: HashSet<String> = views.iter().map(|v| v.incident_id.clone()).collect();
    for (inc_id, decisions) in &decisions_by_incident_id {
        if seen.contains(inc_id) {
            continue;
        }
        if !is_non_incident_pipeline_prefix(inc_id) {
            // Unknown orphan — out of an abundance of caution, don't
            // synthesise. The PR20 promise is to surface the six
            // documented non-incident-pipeline prefixes; arbitrary
            // unknown orphans stay invisible until investigated.
            continue;
        }
        if let Some(view) = synthesise_view_from_orphan_decision(inc_id, decisions) {
            if view_only_touches_self_traffic(&view) {
                continue;
            }
            views.push(view);
        }
    }

    // 5. Sort newest-first.
    views.sort_by(|a, b| b.ts.cmp(&a.ts));

    let total = views.len();
    (total, views)
}

/// Returns the start-of-day RFC-3339 string for `date_str`. Falls back
/// to `now`'s date if `date_str` is malformed so the handler does not
/// crash on a typo.
pub(super) fn start_of_day_ts(date_str: &str, now: DateTime<Utc>) -> String {
    let day = NaiveDate::parse_from_str(date_str, "%Y-%m-%d").unwrap_or_else(|_| now.date_naive());
    day.and_hms_opt(0, 0, 0)
        .expect("00:00:00 is a valid time")
        .and_utc()
        .to_rfc3339()
}

/// `true` when `ts` falls on the same calendar day as `date_str` (UTC).
fn ts_is_on_date(ts: DateTime<Utc>, date_str: &str) -> bool {
    let Ok(day) = NaiveDate::parse_from_str(date_str, "%Y-%m-%d") else {
        return true; // garbage in → don't filter
    };
    ts.naive_utc().date() == day
}

/// Group raw decisions by `incident_id`. Each entry is the parsed JSON
/// `serde_json::Value` so callers can read whichever fields they need
/// (action_type, reason, confidence, decision_layer).
fn group_decisions_by_incident_id(
    raw_decisions: &[(String, String, String)],
) -> HashMap<String, Vec<Value>> {
    let mut map: HashMap<String, Vec<Value>> = HashMap::new();
    for (_ts, incident_id, data_json) in raw_decisions {
        if let Ok(v) = serde_json::from_str::<Value>(data_json) {
            map.entry(incident_id.clone()).or_default().push(v);
        }
    }
    map
}

/// Returns `true` when `incident_id` matches one of the six Wave-10b
/// non-incident-pipeline prefixes. Hand-curated allow-list (not a
/// regex) so adding a new auto-block path is a deliberate, reviewed
/// change.
fn is_non_incident_pipeline_prefix(incident_id: &str) -> bool {
    const PREFIXES: &[&str] = &[
        "honeypot:always-on:abuseipdb:",
        "honeypot:abuseipdb:",
        "repeat-offender:",
        "proto_anomaly:",
        "suspicious_archive:",
        "logging_config_change:",
    ];
    PREFIXES.iter().any(|p| incident_id.starts_with(p))
}

/// Build an `IncidentView` for a sensor-emitted incident, attaching
/// its first decision (chronologically — the canonical one for the
/// audit trail).
fn build_view_for_sensor_incident(
    inc: &Incident,
    decisions_by_incident_id: &HashMap<String, Vec<Value>>,
) -> Option<IncidentView> {
    // 2026-04-29 contract: outcome string normalised via
    // `threat_contract::classify_decision` so this view agrees with
    // `/api/overview.blocked_count`, `/api/pivots`, and the journey
    // verdict.
    let decision = decisions_by_incident_id
        .get(&inc.incident_id)
        .and_then(|decs| decs.first());
    let action = decision
        .and_then(|d| d.get("action_type"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let outcome = crate::dashboard::threat_contract::classify_decision(action.as_deref(), None);
    let sev_lower = format!("{:?}", inc.severity).to_lowercase();
    let effective = super::data_api::effective_severity(outcome, &sev_lower);

    let confidence = decision
        .and_then(|d| d.get("confidence"))
        .and_then(|v| v.as_f64())
        .map(|c| c as f32);

    let entities = entity_strings_for_incident(inc);
    let tags = mitre_tags(&inc.tags);

    Some(IncidentView {
        ts: inc.ts,
        incident_id: inc.incident_id.clone(),
        severity: sev_lower,
        effective_severity: effective,
        title: inc.title.clone(),
        summary: inc.summary.clone(),
        entities,
        tags,
        outcome: outcome.to_string(),
        action_taken: action,
        confidence,
        is_allowlisted: false,
        still_active_now: None,
    })
}

/// Synthesise an `IncidentView` for a decision whose `incident_id` has
/// no matching row in the `incidents` table — the Wave-10b case.
///
/// The synthetic row exposes:
/// * `incident_id` as written by the decision emitter,
/// * `title` derived from the prefix family (honeypot / repeat-offender /
///   proto_anomaly direct / suspicious_archive / logging_config_change),
/// * `severity` from the decision's `estimated_threat` field or a
///   prefix-family default,
/// * `outcome` from the decision's `action_type` via the canonical
///   `classify_decision` helper,
/// * `entities` extracted from the decision's `target_ip` field
///   (and, when absent, parsed from the IP segment of the
///   `incident_id`).
fn synthesise_view_from_orphan_decision(
    incident_id: &str,
    decisions: &[Value],
) -> Option<IncidentView> {
    let first = decisions.first()?;
    let action = first
        .get("action_type")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let ts_str = first.get("ts").and_then(|v| v.as_str())?;
    let ts: DateTime<Utc> = ts_str.parse().ok()?;
    let reason = first
        .get("reason")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let estimated_threat = first
        .get("estimated_threat")
        .and_then(|v| v.as_str())
        .unwrap_or("medium")
        .to_string();
    let target_ip = first.get("target_ip").and_then(|v| v.as_str());
    let confidence = first
        .get("confidence")
        .and_then(|v| v.as_f64())
        .map(|c| c as f32);

    let outcome = crate::dashboard::threat_contract::classify_decision(action.as_deref(), None);
    let severity = synth_severity(&estimated_threat, &action);
    let effective = super::data_api::effective_severity(outcome, severity.as_str());
    let title = synth_title(incident_id);
    let entities = synth_entities(incident_id, target_ip);

    Some(IncidentView {
        ts,
        incident_id: incident_id.to_string(),
        severity,
        effective_severity: effective,
        title,
        summary: reason,
        entities,
        tags: Vec::new(),
        outcome: outcome.to_string(),
        action_taken: action,
        confidence,
        is_allowlisted: false,
        still_active_now: None,
    })
}

/// Operator-readable title for a synthetic row, keyed off the prefix.
/// Hand-written copy — operator should be able to read the title and
/// know "this came from the AbuseIPDB honeypot path" without source
/// archaeology.
fn synth_title(incident_id: &str) -> String {
    if incident_id.starts_with("honeypot:always-on:abuseipdb:") {
        return "Honeypot AbuseIPDB auto-block".to_string();
    }
    if incident_id.starts_with("honeypot:abuseipdb:") {
        return "Honeypot AbuseIPDB block".to_string();
    }
    if incident_id.starts_with("repeat-offender:") {
        return "Repeat offender escalation".to_string();
    }
    if incident_id.starts_with("proto_anomaly:") {
        return "Protocol anomaly (direct decision)".to_string();
    }
    if incident_id.starts_with("suspicious_archive:") {
        return "Suspicious archive activity".to_string();
    }
    if incident_id.starts_with("logging_config_change:") {
        return "Logging config change".to_string();
    }
    "Auto-block".to_string()
}

/// Maps `estimated_threat` strings to the operator-visible severity
/// vocabulary. Block-class decisions default to `high` when no
/// `estimated_threat` is present (auto-blocks are not "low").
fn synth_severity(estimated_threat: &str, action: &Option<String>) -> String {
    match estimated_threat.to_lowercase().as_str() {
        "high" | "known-malicious" | "confirmed-attacker" => "high".to_string(),
        "medium" => "medium".to_string(),
        "low" | "none" => "low".to_string(),
        _ => {
            if action.as_deref() == Some("block_ip") {
                "high".to_string()
            } else {
                "medium".to_string()
            }
        }
    }
}

/// Extract entities for the synthetic row from the decision's
/// `target_ip` (preferred — written by the emitter) and the
/// `incident_id` suffix (fallback — works for the honeypot and
/// repeat-offender prefixes that bake the IP into the id).
fn synth_entities(incident_id: &str, target_ip: Option<&str>) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(ip) = target_ip {
        if !ip.is_empty() {
            out.push(format!("ip:{ip}"));
        }
    }
    if out.is_empty() {
        if let Some(ip) = ip_from_incident_id(incident_id) {
            out.push(format!("ip:{ip}"));
        }
    }
    out
}

/// Parse the IP segment out of a Wave-10b incident_id. The id is
/// colon-separated, the IP is typically the third segment (after the
/// prefix family + sub-kind), e.g.
/// `honeypot:always-on:abuseipdb:31.14.254.81`.
fn ip_from_incident_id(incident_id: &str) -> Option<&str> {
    let parts: Vec<&str> = incident_id.split(':').collect();
    parts.into_iter().rev().find(|p| looks_like_ip(p))
}

fn looks_like_ip(s: &str) -> bool {
    s.parse::<std::net::IpAddr>().is_ok()
}

/// Build the entity strings for a sensor incident. Pre-PR20 this was
/// done via the KG TriggeredBy edges; PR20 reads the entities directly
/// off the incident struct since the KG path is no longer the source
/// of truth for the listing.
fn entity_strings_for_incident(inc: &Incident) -> Vec<String> {
    inc.entities
        .iter()
        .map(|e| {
            let kind = format!("{:?}", e.r#type).to_lowercase();
            format!("{kind}:{}", e.value)
        })
        .collect()
}

/// Extract MITRE tag IDs from the incident's tag list.
fn mitre_tags(tags: &[String]) -> Vec<String> {
    tags.iter()
        .filter(|t| t.starts_with('T') && t.len() >= 5)
        .cloned()
        .collect()
}

/// PR20 — `true` when EVERY IP entity on the view points at the
/// agent's own infrastructure (Cloudflare edge, host's bound IPs,
/// RFC1918, loopback). Used to suppress Cases rows that the operator
/// has no agency over and that the strip currently inflates the
/// observing count with.
///
/// A row with no IP entities at all returns `false` (don't silently
/// drop), and a row that mixes self-traffic + real attacker IPs
/// also returns `false` (keep — the real attacker side matters).
fn view_only_touches_self_traffic(view: &IncidentView) -> bool {
    let mut had_any_ip = false;
    for ent in &view.entities {
        let Some(ip) = ent.strip_prefix("ip:") else {
            continue;
        };
        had_any_ip = true;
        if !is_self_traffic_or_internal(ip) {
            return false;
        }
    }
    had_any_ip
}

/// PR20 — equivalent to the JS-side `isIpTrusted || isPrivateIp` check
/// in the Cases panel's `buildGroupedList`. Backend authority so the
/// strip / Current state / Cases listing all agree on what counts as
/// "noise we hide from the operator's view".
fn is_self_traffic_or_internal(ip: &str) -> bool {
    crate::incident_auto_rules::is_internal_ip_pub(ip)
        || crate::cloud_safelist::is_self_traffic_ip(ip)
}

#[cfg(test)]
mod tests {
    use super::*;
    use innerwarden_core::event::Severity;
    use innerwarden_core::incident::Incident;

    fn day() -> NaiveDate {
        NaiveDate::from_ymd_opt(2026, 5, 13).unwrap()
    }

    fn day_ts(hour: u32) -> DateTime<Utc> {
        day().and_hms_opt(hour, 0, 0).unwrap().and_utc()
    }

    fn incident_row(id: &str, ts: DateTime<Utc>, severity: Severity) -> Incident {
        Incident {
            ts,
            host: "h".into(),
            incident_id: id.into(),
            severity,
            title: format!("title for {id}"),
            summary: "summary".into(),
            evidence: serde_json::json!({}),
            recommended_checks: vec![],
            tags: vec![],
            entities: vec![],
        }
    }

    fn decision_json(
        incident_id: &str,
        action: &str,
        ts: DateTime<Utc>,
        ip: Option<&str>,
    ) -> String {
        let mut obj = serde_json::Map::new();
        obj.insert("ts".into(), Value::String(ts.to_rfc3339()));
        obj.insert("incident_id".into(), Value::String(incident_id.into()));
        obj.insert("action_type".into(), Value::String(action.into()));
        obj.insert(
            "target_ip".into(),
            match ip {
                Some(s) => Value::String(s.into()),
                None => Value::Null,
            },
        );
        obj.insert("confidence".into(), serde_json::json!(1.0));
        obj.insert("estimated_threat".into(), Value::String("high".into()));
        obj.insert("reason".into(), Value::String("test".into()));
        Value::Object(obj).to_string()
    }

    #[test]
    fn cases_returns_every_sensor_incident_for_the_date() {
        // Hot-path operator promise: the Cases tab must show every
        // incident the sensor wrote for the day, no eviction. Mirrors
        // the 480-vs-68 prod regression from 2026-05-13.
        let store = innerwarden_store::Store::open_memory().unwrap();
        for n in 0..10 {
            store
                .insert_incident(&incident_row(
                    &format!("inc-{n}"),
                    day_ts(8 + n),
                    Severity::High,
                ))
                .unwrap();
        }
        let (total, items) = build_cases_for_date(&store, "2026-05-13", day_ts(20));
        assert_eq!(total, 10, "every today-row must surface");
        assert_eq!(items.len(), 10);
    }

    #[test]
    fn cases_synthesises_view_for_honeypot_abuseipdb_orphan_decision() {
        // Wave-10b regression anchor: a decision with
        // `incident_id = "honeypot:always-on:abuseipdb:<ip>"` and NO
        // matching `incidents` row must still surface in Cases. Pre-PR20
        // these were invisible to the operator dashboard while the site
        // counted them (Wave-10b documented).
        let store = innerwarden_store::Store::open_memory().unwrap();
        let ts = day_ts(12);
        // Insert a decision without a backing incident.
        let dec_json = decision_json(
            "honeypot:always-on:abuseipdb:31.14.254.81",
            "block_ip",
            ts,
            Some("31.14.254.81"),
        );
        let row = innerwarden_store::decisions::DecisionRow {
            ts: ts.to_rfc3339(),
            incident_id: "honeypot:always-on:abuseipdb:31.14.254.81".into(),
            action_type: "block_ip".into(),
            target_ip: Some("31.14.254.81".into()),
            target_user: None,
            confidence: 1.0,
            auto_executed: true,
            reason: Some("test".into()),
            data: dec_json,
        };
        store.insert_decision(&row).unwrap();

        let (total, items) = build_cases_for_date(&store, "2026-05-13", day_ts(20));
        assert_eq!(total, 1, "the synthetic row must be counted");
        let v = &items[0];
        assert_eq!(v.incident_id, "honeypot:always-on:abuseipdb:31.14.254.81");
        assert!(v.title.contains("Honeypot AbuseIPDB"));
        assert_eq!(v.severity, "high");
        assert!(v.entities.contains(&"ip:31.14.254.81".to_string()));
        assert_eq!(v.outcome, "blocked");
    }

    #[test]
    fn cases_does_not_synthesise_for_unknown_orphan_prefix() {
        // Defensive: if a future writer ships a new non-incident
        // path with an unrecognised prefix, we do NOT synthesise an
        // implausible row. The operator can then file an issue and a
        // new prefix gets added to the allow-list deliberately.
        let store = innerwarden_store::Store::open_memory().unwrap();
        let ts = day_ts(12);
        let row = innerwarden_store::decisions::DecisionRow {
            ts: ts.to_rfc3339(),
            incident_id: "future-thing:foo:bar".into(),
            action_type: "block_ip".into(),
            target_ip: Some("1.2.3.4".into()),
            target_user: None,
            confidence: 1.0,
            auto_executed: true,
            reason: Some("test".into()),
            data: decision_json("future-thing:foo:bar", "block_ip", ts, Some("1.2.3.4")),
        };
        store.insert_decision(&row).unwrap();

        let (total, items) = build_cases_for_date(&store, "2026-05-13", day_ts(20));
        assert_eq!(total, 0);
        assert!(items.is_empty());
    }

    #[test]
    fn cases_attaches_decision_to_sensor_incident_when_both_exist() {
        // Standard prod path: sensor wrote the incident, AI router
        // wrote a decision pointing at the same `incident_id`. The
        // Cases row must reflect the action — operator should not see
        // an "Awaiting analysis" row when a decision exists.
        let store = innerwarden_store::Store::open_memory().unwrap();
        let ts = day_ts(10);
        store
            .insert_incident(&incident_row(
                "proto_anomaly:ProtocolMismatch:1.2.3.4:2026-05-13T10:00Z",
                ts,
                Severity::High,
            ))
            .unwrap();
        let row = innerwarden_store::decisions::DecisionRow {
            ts: ts.to_rfc3339(),
            incident_id: "proto_anomaly:ProtocolMismatch:1.2.3.4:2026-05-13T10:00Z".into(),
            action_type: "block_ip".into(),
            target_ip: Some("1.2.3.4".into()),
            target_user: None,
            confidence: 0.95,
            auto_executed: true,
            reason: Some("intel".into()),
            data: decision_json(
                "proto_anomaly:ProtocolMismatch:1.2.3.4:2026-05-13T10:00Z",
                "block_ip",
                ts,
                Some("1.2.3.4"),
            ),
        };
        store.insert_decision(&row).unwrap();

        let (total, items) = build_cases_for_date(&store, "2026-05-13", day_ts(20));
        assert_eq!(total, 1, "incident + decision must collapse to one row");
        assert_eq!(items[0].action_taken.as_deref(), Some("block_ip"));
        assert_eq!(items[0].outcome, "blocked");
    }

    #[test]
    fn cases_excludes_prior_day_incidents() {
        // Boundary anchor: scope is a single calendar day (UTC).
        // Yesterday's 23:59 must not bleed into today.
        let store = innerwarden_store::Store::open_memory().unwrap();
        let yesterday = day() - chrono::Duration::days(1);
        let yesterday_ts = yesterday.and_hms_opt(23, 30, 0).unwrap().and_utc();
        store
            .insert_incident(&incident_row("yesterday-row", yesterday_ts, Severity::High))
            .unwrap();
        store
            .insert_incident(&incident_row("today-row", day_ts(8), Severity::High))
            .unwrap();

        let (total, items) = build_cases_for_date(&store, "2026-05-13", day_ts(20));
        assert_eq!(total, 1, "yesterday's row must NOT bleed in");
        assert_eq!(items[0].incident_id, "today-row");
    }

    #[test]
    fn cases_returns_empty_for_clean_store() {
        let store = innerwarden_store::Store::open_memory().unwrap();
        let (total, items) = build_cases_for_date(&store, "2026-05-13", day_ts(20));
        assert_eq!(total, 0);
        assert!(items.is_empty());
    }

    #[test]
    fn ip_from_incident_id_handles_all_prefix_families() {
        assert_eq!(
            ip_from_incident_id("honeypot:always-on:abuseipdb:31.14.254.81"),
            Some("31.14.254.81")
        );
        assert_eq!(
            ip_from_incident_id("repeat-offender:1.2.3.4:1234567890"),
            Some("1.2.3.4")
        );
        assert_eq!(
            ip_from_incident_id("proto_anomaly:SshVersionAnomaly:5.6.7.8:2026-05-13T10:00Z"),
            Some("5.6.7.8")
        );
        assert_eq!(ip_from_incident_id("logging_config_change:unknown"), None);
    }

    #[test]
    fn is_non_incident_pipeline_prefix_covers_wave_10b_set() {
        // Allow-list anchor. Adding a new prefix means adding it
        // here AND in the function — in lockstep — so a future
        // writer cannot land an orphan-emitting path without
        // touching this list.
        assert!(is_non_incident_pipeline_prefix(
            "honeypot:always-on:abuseipdb:1.2.3.4"
        ));
        assert!(is_non_incident_pipeline_prefix(
            "honeypot:abuseipdb:1.2.3.4"
        ));
        assert!(is_non_incident_pipeline_prefix(
            "repeat-offender:1.2.3.4:123"
        ));
        assert!(is_non_incident_pipeline_prefix(
            "proto_anomaly:SshVersionAnomaly:1.2.3.4:2026-05-13T10:00Z"
        ));
        assert!(is_non_incident_pipeline_prefix("suspicious_archive:foo"));
        assert!(is_non_incident_pipeline_prefix("logging_config_change:foo"));
        assert!(!is_non_incident_pipeline_prefix("ssh_bruteforce:1.2.3.4"));
        assert!(!is_non_incident_pipeline_prefix("kill_chain:DATA_EXFIL:1"));
    }

    #[test]
    fn synth_severity_defaults_to_high_for_block_actions() {
        // A block_ip auto-decision without `estimated_threat` is
        // never "low" — the blocked IP is by definition something
        // the system felt strongly enough about to enforce a kernel
        // rule. Pin this so a future refactor that defaults to
        // "medium"/"low" cannot regress the operator-visible
        // severity column.
        assert_eq!(synth_severity("", &Some("block_ip".to_string())), "high");
        assert_eq!(synth_severity("", &Some("dismiss".to_string())), "medium");
        assert_eq!(synth_severity("low", &None), "low");
        assert_eq!(
            synth_severity("known-malicious", &Some("block_ip".to_string())),
            "high"
        );
    }
}
