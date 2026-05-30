//! Spec 062 Phase 4 — learned suppression (weight-aware, LLM-optional).
//!
//! Operator model: **"besta nem pergunta; com peso confirma."** When the
//! same incident shape `(detector | target_ip)` has been dismissed by
//! GENUINE signals N times and never once led to a weighty action, future
//! matches are auto-suppressed silently. Anything weighty (would lead to a
//! block, or touches High/Critical) is never auto-acted — it flows through
//! normal routing so a human still sees it.
//!
//! Why this exists: prod measurement (2026-05-30) showed 88% of all
//! dismissals are repeated `(detector|ip)` shapes seen >=3x — e.g.
//! `imds_ssrf | 169.254.169.254` dismissed 1105 times (the host's own
//! cloud metadata IP). Each repetition currently re-runs the full intake
//! and (pre-spec-062) leaked to the orphan-recovery silent dismiss. This
//! gate removes that noise deterministically — **with no LLM required**,
//! the hard invariant of spec 062.
//!
//! ## Anti-laundering (critical correctness rule)
//!
//! The dismissal count must reflect *genuine* repeated dismissals, not the
//! bug we are fixing. Two providers are EXCLUDED from the count:
//! - `orphan-recovery` — the silent-leak class spec 062 exists to kill.
//!   Counting it would launder the bug into "learning": the agent would
//!   teach itself that the very incidents it failed to decide are safe.
//! - `learned-suppression` — our own output (anti-loop; otherwise the
//!   count would compound on itself once enforcing).
//!
//! ## Weight gate (safety)
//!
//! - Only `Low` / `Medium` severity are ever eligible. `High` / `Critical`
//!   (and any unknown severity) NEVER auto-suppress — fail safe. Mirrors
//!   [`crate::needs_review_timeout::may_auto_resolve`] and the Critical
//!   floor in [`crate::kg_fp_suppression`].
//! - Any prior weighty action on the shape (`block_ip`, `monitor`,
//!   `kill_process`, `suspend_user_sudo`, `block_container`, honeypot)
//!   disqualifies it. If the shape ever mattered enough to act on, it is
//!   not "besta".
//!
//! ## Modes (mirror [`crate::kg_fp_suppression`])
//!
//! - `"off"`     — code path skips entirely (rollback without redeploy).
//! - `"shadow"`  — computes the verdict, writes a JSONL log of what it
//!   WOULD suppress, changes nothing. **Default** (validate on the lab,
//!   read the numbers, then promote to enforce via config — no code
//!   change). Honours spec 062's "validate on test001 before prod" rule.
//! - `"enforce"` — writes the `learned-suppression` dismiss decision and
//!   skips routing for eligible shapes.

use std::path::Path;

use chrono::{DateTime, Utc};
use innerwarden_core::event::Severity;
use innerwarden_core::incident::Incident;
use serde::Serialize;
use tracing::warn;

/// `ai_provider` written on the dismiss decisions this module emits, and
/// the anti-loop exclusion token (see module docs).
pub(crate) const SUPPRESSION_AI_PROVIDER: &str = "learned-suppression";

/// Dismiss `ai_provider`s that must NOT count toward "genuine repeated
/// dismissal". See the anti-laundering section in the module docs.
pub(crate) const EXCLUDED_DISMISS_PROVIDERS: &[&str] =
    &["orphan-recovery", SUPPRESSION_AI_PROVIDER];

/// Action types that mean a real, weighty action was once taken on this
/// shape. Any of these in the shape's history → "com peso confirma" →
/// never auto-suppress. `honeypot` covers the redirect skill family.
pub(crate) const ACTIONED_TYPES: &[&str] = &[
    "block_ip",
    "monitor",
    "kill_process",
    "suspend_user_sudo",
    "block_container",
    "honeypot",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SuppressionMode {
    Off,
    Shadow,
    Enforce,
}

/// Parse the `[learning] suppression_mode` string. Unknown / empty values
/// collapse to `Shadow` (the safe default), NOT `Off` — an operator who
/// typo'd the mode still gets the no-op shadow behaviour rather than
/// silently disabling learning. Mirrors the spec's "absent section behaves
/// correctly" rule.
pub(crate) fn parse_mode(s: &str) -> SuppressionMode {
    match s.trim().to_ascii_lowercase().as_str() {
        "off" => SuppressionMode::Off,
        "enforce" => SuppressionMode::Enforce,
        _ => SuppressionMode::Shadow,
    }
}

/// Only `Low` / `Medium` may ever be auto-suppressed. Everything else —
/// `High`, `Critical`, and any future/unknown variant — fails safe to
/// `false`. Shares the exact contract of
/// [`crate::needs_review_timeout::may_auto_resolve`].
pub(crate) fn may_learn_suppress(severity: &Severity) -> bool {
    matches!(severity, Severity::Low | Severity::Medium)
}

/// The detector half of a shape: the `incident_id` prefix before the first
/// `:`. `imds_ssrf:169.254.169.254:2026-...` → `imds_ssrf`.
pub(crate) fn detector_of(incident_id: &str) -> &str {
    incident_id.split(':').next().unwrap_or("")
}

/// The primary IP entity of an incident, if any. Suppression keys on
/// `(detector | ip)`; an incident with no IP entity is never eligible.
pub(crate) fn primary_ip(incident: &Incident) -> Option<String> {
    incident
        .entities
        .iter()
        .find(|e| e.r#type == innerwarden_core::entities::EntityType::Ip)
        .map(|e| e.value.clone())
}

/// Stats for a shape, as returned by the store. Re-exported shape so the
/// pure [`decide`] can be unit-tested without a live store.
pub(crate) use innerwarden_store::decisions::ShapeDismissalStats;

/// Verdict of the learned-suppression policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LearnedVerdict {
    /// Not eligible: severity too high, the shape has weighty history, the
    /// incident has no IP, or it is below the repetition threshold. The
    /// caller routes the incident normally (it is NOT lost).
    PassThrough,
    /// Eligible: Low/Medium, zero weighty history, `dismissals >= N`. In
    /// enforce mode the caller writes a `learned-suppression` dismiss; in
    /// shadow mode it only logs.
    Suppress { dismissals: u64 },
}

/// Pure policy step. Free of I/O so every branch (severity gate, weighty
/// history, threshold) is unit-testable.
///
/// Order matters: the weight gate (`actioned > 0`) is checked BEFORE the
/// count so a shape that was ever blocked never auto-suppresses, no matter
/// how many times it was also dismissed.
pub(crate) fn decide(
    severity: &Severity,
    stats: ShapeDismissalStats,
    min_dismissals: u64,
    mesh_corroboration: u64,
) -> LearnedVerdict {
    if !may_learn_suppress(severity) {
        return LearnedVerdict::PassThrough;
    }
    if stats.actioned > 0 {
        // "Com peso confirma" — the shape mattered enough to act on at
        // least once; never silently suppress it.
        return LearnedVerdict::PassThrough;
    }
    // min_dismissals == 0 would suppress on the first sight, defeating the
    // "repeated" premise; treat <1 as 1 (defensive — config validates too).
    let n = min_dismissals.max(1);

    // Spec 062 Phase 6b — mesh fleet corroboration. A high-trust peer's
    // advisory can only HELP a shape this host has ALREADY dismissed at least
    // once (never originate a suppression from peers alone), and is capped at
    // n/2 so peers can shave the threshold but the host still needs real local
    // repetition (e.g. n=5 → cap 2 → ≥3 local dismissals required even with
    // full corroboration). The reported count stays the honest LOCAL count.
    let corroboration = if stats.genuine_dismissals >= 1 {
        mesh_corroboration.min(n / 2)
    } else {
        0
    };
    let effective = stats.genuine_dismissals + corroboration;

    if effective >= n {
        LearnedVerdict::Suppress {
            dismissals: stats.genuine_dismissals,
        }
    } else {
        LearnedVerdict::PassThrough
    }
}

/// Store-backed evaluation: resolve the shape, query its dismissal stats,
/// and apply [`decide`]. Returns `PassThrough` for any incident that is
/// not eligible by construction (no IP, severity too high) WITHOUT hitting
/// the store. Pure of side effects (read-only on the store), so it is
/// safe to call before deciding whether to mutate agent state.
pub(crate) fn evaluate(
    store: &innerwarden_store::Store,
    incident: &Incident,
    min_dismissals: u64,
    mesh_corroboration: u64,
) -> LearnedVerdict {
    if !may_learn_suppress(&incident.severity) {
        return LearnedVerdict::PassThrough;
    }
    let Some(ip) = primary_ip(incident) else {
        return LearnedVerdict::PassThrough;
    };
    let detector = detector_of(&incident.incident_id);
    if detector.is_empty() {
        return LearnedVerdict::PassThrough;
    }
    let stats = match store.shape_dismissal_stats(
        detector,
        &ip,
        EXCLUDED_DISMISS_PROVIDERS,
        ACTIONED_TYPES,
    ) {
        Ok(s) => s,
        Err(e) => {
            warn!(
                detector,
                ip = %ip,
                error = %e,
                "learned-suppression: shape_dismissal_stats query failed; passing through"
            );
            return LearnedVerdict::PassThrough;
        }
    };
    decide(
        &incident.severity,
        stats,
        min_dismissals,
        mesh_corroboration,
    )
}

/// Build the human/audit reason for a learned-suppression dismiss.
pub(crate) fn suppression_reason(detector: &str, ip: &str, dismissals: u64, n: u64) -> String {
    format!(
        "Learned suppression: shape ({detector} | {ip}) was dismissed by genuine \
         signals {dismissals} times (>= threshold {n}) and never once led to a \
         block/monitor/kill or a High/Critical incident. Auto-dismissed without \
         routing. Reversible; the audit trail keeps every occurrence. \
         (orphan-recovery and prior learned-suppression dismissals are excluded \
         from the count.)"
    )
}

/// One record appended to `learned_suppression_shadow_<DATE>.jsonl` in
/// shadow mode. The operator inspects this for a few days before promoting
/// to `enforce`. `would_suppress` is always true here (only Suppress
/// verdicts are logged) — it is kept explicit so the schema matches the
/// kg_fp_suppression shadow log convention and downstream `jq` filters
/// read the same way on both files.
#[derive(Debug, Serialize)]
pub(crate) struct ShadowLogRecord {
    pub ts: String,
    pub incident_id: String,
    pub detector: String,
    pub target_ip: String,
    pub severity: String,
    pub genuine_dismissals: u64,
    pub threshold: u64,
    pub would_suppress: bool,
}

/// Best-effort append to today's shadow log. Failures `warn!` and do NOT
/// propagate (mirrors [`crate::kg_fp_suppression::write_shadow_log`]).
pub(crate) fn write_shadow_log(data_dir: &Path, record: &ShadowLogRecord, now: DateTime<Utc>) {
    let date = now.format("%Y-%m-%d").to_string();
    let path = data_dir.join(format!("learned_suppression_shadow_{date}.jsonl"));
    let line = match serde_json::to_string(record) {
        Ok(s) => s,
        Err(e) => {
            warn!("learned-suppression: failed to serialize shadow log: {e}");
            return;
        }
    };
    let result = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .and_then(|mut f| {
            use std::io::Write;
            writeln!(f, "{line}")
        });
    if let Err(e) = result {
        warn!(
            "learned-suppression: failed to append shadow log {}: {e}",
            path.display()
        );
    }
}

/// Lowercase severity label for the audit/shadow records (matches the
/// agent's JSONL convention).
pub(crate) fn severity_label(sev: &Severity) -> &'static str {
    match sev {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
        Severity::Info => "info",
        _ => "low",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use innerwarden_core::entities::EntityRef;

    fn stats(genuine: u64, actioned: u64) -> ShapeDismissalStats {
        ShapeDismissalStats {
            genuine_dismissals: genuine,
            actioned,
        }
    }

    #[test]
    fn parse_mode_defaults_to_shadow_not_off() {
        assert_eq!(parse_mode("off"), SuppressionMode::Off);
        assert_eq!(parse_mode("OFF"), SuppressionMode::Off);
        assert_eq!(parse_mode("enforce"), SuppressionMode::Enforce);
        assert_eq!(parse_mode("Enforce"), SuppressionMode::Enforce);
        assert_eq!(parse_mode("shadow"), SuppressionMode::Shadow);
        // Unknown / empty → Shadow (safe), NOT Off.
        assert_eq!(parse_mode(""), SuppressionMode::Shadow);
        assert_eq!(parse_mode("typo"), SuppressionMode::Shadow);
    }

    #[test]
    fn may_learn_suppress_only_low_and_medium() {
        assert!(may_learn_suppress(&Severity::Low));
        assert!(may_learn_suppress(&Severity::Medium));
        // Safety-critical half: never these.
        assert!(!may_learn_suppress(&Severity::High));
        assert!(!may_learn_suppress(&Severity::Critical));
        assert!(!may_learn_suppress(&Severity::Info));
    }

    #[test]
    fn detector_of_extracts_prefix() {
        assert_eq!(detector_of("imds_ssrf:169.254.169.254:2026"), "imds_ssrf");
        assert_eq!(detector_of("single"), "single");
        assert_eq!(detector_of(""), "");
    }

    #[test]
    fn primary_ip_finds_first_ip_entity() {
        let inc = Incident {
            ts: Utc::now(),
            host: String::new(),
            incident_id: "x:1".into(),
            severity: Severity::Low,
            title: String::new(),
            summary: String::new(),
            evidence: serde_json::Value::Null,
            recommended_checks: vec![],
            tags: vec![],
            entities: vec![EntityRef::ip("203.0.113.7")],
        };
        assert_eq!(primary_ip(&inc).as_deref(), Some("203.0.113.7"));
    }

    #[test]
    fn decide_suppresses_low_at_threshold_with_no_actioned() {
        let v = decide(&Severity::Low, stats(5, 0), 5, 0);
        assert_eq!(v, LearnedVerdict::Suppress { dismissals: 5 });
        // and above
        assert_eq!(
            decide(&Severity::Medium, stats(1105, 0), 5, 0),
            LearnedVerdict::Suppress { dismissals: 1105 }
        );
    }

    #[test]
    fn decide_passes_through_below_threshold() {
        assert_eq!(
            decide(&Severity::Low, stats(4, 0), 5, 0),
            LearnedVerdict::PassThrough
        );
    }

    #[test]
    fn decide_never_suppresses_high_or_critical() {
        // Even with overwhelming dismissal history.
        assert_eq!(
            decide(&Severity::High, stats(9999, 0), 5, 0),
            LearnedVerdict::PassThrough
        );
        assert_eq!(
            decide(&Severity::Critical, stats(9999, 0), 5, 0),
            LearnedVerdict::PassThrough
        );
    }

    #[test]
    fn decide_never_suppresses_when_shape_was_ever_actioned() {
        // "Com peso confirma": a single block in the shape's history
        // disqualifies it forever, regardless of dismissal count.
        assert_eq!(
            decide(&Severity::Low, stats(1000, 1), 5, 0),
            LearnedVerdict::PassThrough
        );
    }

    #[test]
    fn decide_treats_zero_threshold_as_one() {
        // Defensive: N=0 must not suppress on first sight.
        assert_eq!(
            decide(&Severity::Low, stats(0, 0), 0, 0),
            LearnedVerdict::PassThrough
        );
        assert_eq!(
            decide(&Severity::Low, stats(1, 0), 0, 0),
            LearnedVerdict::Suppress { dismissals: 1 }
        );
    }

    // ── Spec 062 Phase 6b: mesh corroboration ──

    #[test]
    fn mesh_corroboration_helps_locally_dismissed_shape_reach_threshold() {
        // n=5, cap n/2=2. 3 local + 2 corroboration = 5 → suppress.
        assert_eq!(
            decide(&Severity::Low, stats(3, 0), 5, 2),
            LearnedVerdict::Suppress { dismissals: 3 } // honest LOCAL count
        );
    }

    #[test]
    fn mesh_corroboration_is_capped_at_half_n() {
        // 1 local + unlimited peers is still capped at n/2=2 → effective 3 < 5.
        assert_eq!(
            decide(&Severity::Low, stats(1, 0), 5, 9999),
            LearnedVerdict::PassThrough
        );
    }

    #[test]
    fn mesh_corroboration_never_originates_from_peers_alone() {
        // 0 local dismissals → corroboration contributes nothing, ever.
        assert_eq!(
            decide(&Severity::Low, stats(0, 0), 5, 9999),
            LearnedVerdict::PassThrough
        );
    }

    #[test]
    fn mesh_corroboration_cannot_revive_an_actioned_shape() {
        // Weighty history disqualifies regardless of corroboration.
        assert_eq!(
            decide(&Severity::Low, stats(1000, 1), 5, 9999),
            LearnedVerdict::PassThrough
        );
    }

    #[test]
    fn severity_label_covers_all_arms() {
        assert_eq!(severity_label(&Severity::Critical), "critical");
        assert_eq!(severity_label(&Severity::High), "high");
        assert_eq!(severity_label(&Severity::Medium), "medium");
        assert_eq!(severity_label(&Severity::Low), "low");
        assert_eq!(severity_label(&Severity::Info), "info");
    }

    #[test]
    fn excluded_providers_include_the_leak_and_self() {
        assert!(EXCLUDED_DISMISS_PROVIDERS.contains(&"orphan-recovery"));
        assert!(EXCLUDED_DISMISS_PROVIDERS.contains(&SUPPRESSION_AI_PROVIDER));
    }

    #[test]
    fn suppression_reason_mentions_shape_and_counts() {
        let r = suppression_reason("imds_ssrf", "169.254.169.254", 1105, 5);
        assert!(r.contains("imds_ssrf"));
        assert!(r.contains("169.254.169.254"));
        assert!(r.contains("1105"));
        assert!(r.contains("orphan-recovery"));
    }

    #[test]
    fn write_shadow_log_writes_jsonl() {
        let dir = tempfile::tempdir().unwrap();
        let now = Utc::now();
        let rec = ShadowLogRecord {
            ts: now.to_rfc3339(),
            incident_id: "imds_ssrf:169.254.169.254:x".into(),
            detector: "imds_ssrf".into(),
            target_ip: "169.254.169.254".into(),
            severity: "low".into(),
            genuine_dismissals: 1105,
            threshold: 5,
            would_suppress: true,
        };
        write_shadow_log(dir.path(), &rec, now);
        let entries: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .collect();
        assert_eq!(entries.len(), 1);
        let body = std::fs::read_to_string(entries[0].path()).unwrap();
        assert!(body.contains("\"would_suppress\":true"));
        assert!(body.contains("\"genuine_dismissals\":1105"));
        assert!(body.contains("imds_ssrf"));
    }

    // ── Store-backed evaluate() e2e (real on-disk store) ────────────────

    fn open_store(tmp: &tempfile::TempDir) -> innerwarden_store::Store {
        innerwarden_store::Store::open(tmp.path()).expect("open store")
    }

    fn seed_dismiss(store: &innerwarden_store::Store, incident_id: &str, ip: &str, provider: &str) {
        let data = serde_json::json!({ "ai_provider": provider }).to_string();
        store
            .insert_decision(&innerwarden_store::decisions::DecisionRow {
                ts: Utc::now().to_rfc3339(),
                incident_id: incident_id.into(),
                action_type: "dismiss".into(),
                target_ip: Some(ip.into()),
                target_user: None,
                confidence: 1.0,
                auto_executed: true,
                reason: Some("test".into()),
                data,
            })
            .unwrap();
    }

    fn seed_action(
        store: &innerwarden_store::Store,
        incident_id: &str,
        ip: &str,
        action_type: &str,
    ) {
        let data = serde_json::json!({ "ai_provider": "manual" }).to_string();
        store
            .insert_decision(&innerwarden_store::decisions::DecisionRow {
                ts: Utc::now().to_rfc3339(),
                incident_id: incident_id.into(),
                action_type: action_type.into(),
                target_ip: Some(ip.into()),
                target_user: None,
                confidence: 1.0,
                auto_executed: true,
                reason: Some("test".into()),
                data,
            })
            .unwrap();
    }

    fn low_incident(detector: &str, ip: &str) -> Incident {
        Incident {
            ts: Utc::now(),
            host: "h".into(),
            incident_id: format!("{detector}:{ip}:now"),
            severity: Severity::Low,
            title: "t".into(),
            summary: "s".into(),
            evidence: serde_json::Value::Null,
            recommended_checks: vec![],
            tags: vec![],
            entities: vec![EntityRef::ip(ip)],
        }
    }

    #[test]
    fn evaluate_suppresses_repeated_genuine_dismissals() {
        let tmp = tempfile::tempdir().unwrap();
        let store = open_store(&tmp);
        let ip = "169.254.169.254";
        for i in 0..6 {
            seed_dismiss(&store, &format!("imds_ssrf:{ip}:{i}"), ip, "noise-gate");
        }
        let inc = low_incident("imds_ssrf", ip);
        assert_eq!(
            evaluate(&store, &inc, 5, 0),
            LearnedVerdict::Suppress { dismissals: 6 }
        );
    }

    #[test]
    fn evaluate_mesh_corroboration_threads_through_store_path() {
        let tmp = tempfile::tempdir().unwrap();
        let store = open_store(&tmp);
        let ip = "169.254.169.254";
        // 3 genuine local dismissals — below N=5 on its own.
        for i in 0..3 {
            seed_dismiss(&store, &format!("imds_ssrf:{ip}:{i}"), ip, "noise-gate");
        }
        let inc = low_incident("imds_ssrf", ip);
        // No corroboration → passes through.
        assert_eq!(evaluate(&store, &inc, 5, 0), LearnedVerdict::PassThrough);
        // 2 corroborating peers (cap n/2=2) → 3+2=5 → suppress, honest local 3.
        assert_eq!(
            evaluate(&store, &inc, 5, 2),
            LearnedVerdict::Suppress { dismissals: 3 }
        );
    }

    #[test]
    fn evaluate_excludes_orphan_recovery_from_count() {
        let tmp = tempfile::tempdir().unwrap();
        let store = open_store(&tmp);
        let ip = "169.254.169.254";
        // All dismissals are the LEAK — must not count → below threshold.
        for i in 0..20 {
            seed_dismiss(
                &store,
                &format!("imds_ssrf:{ip}:{i}"),
                ip,
                "orphan-recovery",
            );
        }
        let inc = low_incident("imds_ssrf", ip);
        assert_eq!(
            evaluate(&store, &inc, 5, 0),
            LearnedVerdict::PassThrough,
            "orphan-recovery dismissals must NOT be laundered into learning"
        );
    }

    #[test]
    fn evaluate_excludes_own_output_anti_loop() {
        let tmp = tempfile::tempdir().unwrap();
        let store = open_store(&tmp);
        let ip = "169.254.169.254";
        for i in 0..20 {
            seed_dismiss(
                &store,
                &format!("imds_ssrf:{ip}:{i}"),
                ip,
                SUPPRESSION_AI_PROVIDER,
            );
        }
        let inc = low_incident("imds_ssrf", ip);
        assert_eq!(evaluate(&store, &inc, 5, 0), LearnedVerdict::PassThrough);
    }

    #[test]
    fn evaluate_passthrough_when_shape_was_blocked() {
        let tmp = tempfile::tempdir().unwrap();
        let store = open_store(&tmp);
        let ip = "203.0.113.9";
        for i in 0..10 {
            seed_dismiss(&store, &format!("port_scan:{ip}:{i}"), ip, "noise-gate");
        }
        // One block in history → weighty → never auto-suppress.
        seed_action(&store, &format!("port_scan:{ip}:blk"), ip, "block_ip");
        let inc = low_incident("port_scan", ip);
        assert_eq!(evaluate(&store, &inc, 5, 0), LearnedVerdict::PassThrough);
    }

    #[test]
    fn evaluate_passthrough_for_different_detector_same_ip() {
        // The shape is (detector|ip): dismissals of detector A must not
        // suppress detector B on the same IP.
        let tmp = tempfile::tempdir().unwrap();
        let store = open_store(&tmp);
        let ip = "169.254.169.254";
        for i in 0..10 {
            seed_dismiss(&store, &format!("imds_ssrf:{ip}:{i}"), ip, "noise-gate");
        }
        let inc = low_incident("reverse_shell", ip);
        assert_eq!(evaluate(&store, &inc, 5, 0), LearnedVerdict::PassThrough);
    }

    #[test]
    fn evaluate_passthrough_high_severity_without_touching_store() {
        let tmp = tempfile::tempdir().unwrap();
        let store = open_store(&tmp);
        let ip = "169.254.169.254";
        for i in 0..10 {
            seed_dismiss(&store, &format!("imds_ssrf:{ip}:{i}"), ip, "noise-gate");
        }
        let mut inc = low_incident("imds_ssrf", ip);
        inc.severity = Severity::High;
        assert_eq!(evaluate(&store, &inc, 5, 0), LearnedVerdict::PassThrough);
    }

    #[test]
    fn evaluate_passthrough_when_no_ip_entity() {
        let tmp = tempfile::tempdir().unwrap();
        let store = open_store(&tmp);
        let inc = Incident {
            ts: Utc::now(),
            host: "h".into(),
            incident_id: "imds_ssrf:none:now".into(),
            severity: Severity::Low,
            title: "t".into(),
            summary: "s".into(),
            evidence: serde_json::Value::Null,
            recommended_checks: vec![],
            tags: vec![],
            entities: vec![],
        };
        assert_eq!(evaluate(&store, &inc, 5, 0), LearnedVerdict::PassThrough);
    }
}
