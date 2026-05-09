//! Severity downgrade engine — Phase 3 of spec 044.
//!
//! Reads the host posture snapshot and demotes incidents that hit
//! already-hardened controls. The principle, in the operator's words
//! (2026-05-09): "what can't fail is alerting on a real compromise; SSH
//! login com [password] usuário tá até desabilitado no server, então
//! isso não vai nem fazer cócegas".
//!
//! **Hard invariant**: never demote when the incident carries a "real
//! landing" signal — `session_established`, `process_executed`,
//! `file_written`, `key_match`. Posture tells us what defenses are in
//! place; landing tells us those defenses were bypassed. Once an
//! attacker is past auth and observable on the host, posture-awareness
//! is moot.
//!
//! **What this replaces**: a hardcoded `effective_severity` in
//! `narrative_daily_summary.rs` that assumed `PasswordAuthentication=no`
//! globally and demoted every `ssh_bruteforce` incident regardless of
//! the host's actual sshd config. That assumption was right on this
//! prod host but wrong as a generic policy — a fleet member with
//! password auth enabled would have lost real bruteforce alerts.
//!
//! **What this does NOT do**: emit incidents, mutate state, persist
//! anything. Pure function. The caller (briefing aggregator) decides
//! whether to apply the demoted severity to its counters or to log
//! the reason. Phase 4 will surface `DowngradeReason` on the dashboard
//! so the operator sees WHY a candidate was demoted.

use innerwarden_core::event::Severity;
use innerwarden_core::incident::Incident;

use super::HostPosture;

/// Reason a downgrade was applied — exported so the briefing aggregator
/// can log it and Phase 4 dashboard can surface a "why was this demoted"
/// hint to the operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // some variants only used by Phase 4 telemetry, not yet wired.
pub enum DowngradeReason {
    /// No demote applied — incident keeps its original severity.
    None,
    /// Real-landing signal present (`session_established`,
    /// `process_executed`, `file_written`, `key_match` tag). Posture
    /// is bypassed; never demote.
    LandingSignalPresent,
    /// `ssh_bruteforce` on a host where both `PasswordAuthentication`
    /// and `KbdInteractiveAuthentication` are explicitly `no`. Failed
    /// password attempts cannot land, regardless of target user, so
    /// the alert is informational at most.
    SshPasswordSurfaceDisabled,
    /// `proto_anomaly` from external scanners — already at protocol
    /// level. Pre-spec-044 demote retained because it is independent
    /// of posture (no posture facts could change the verdict).
    ProtoAnomalyExternalScan,
    /// `killchain` incident with `pattern == "unknown"` — incomplete
    /// sequence, not a confirmed chain. Pre-spec-044 demote retained.
    KillchainPatternUnknown,
    /// `threat_intel` hit that was already auto-blocked. The block
    /// was the success, not a residual threat. Pre-spec-044 demote
    /// retained.
    ThreatIntelAutoBlocked,
}

/// Compute effective severity for the briefing aggregator.
///
/// `detector` comes from the caller's `extract_detector_pub(&incident_id)`
/// since the incident itself does not carry a structured detector field.
/// `posture` is the snapshot taken by the slow-loop refresh — the
/// caller is responsible for honouring the staleness contract (Phase 4
/// will surface `posture.last_refresh_age_seconds` on the dashboard).
///
/// Returns the effective severity and the reason. When no rule applies
/// the function returns the original severity with `DowngradeReason::None`.
pub fn effective_severity(
    incident: &Incident,
    detector: &str,
    posture: &HostPosture,
) -> (Severity, DowngradeReason) {
    let raw = incident.severity.clone();

    // Hard invariant: any landing signal short-circuits posture
    // demotes. A "successful SSH brute force" tag, a `process_executed`
    // tag (eBPF saw the attacker spawn something), a `file_written`
    // tag (auth_keys / sudoers / cron tampering): all bypass posture
    // and surface at original severity.
    if has_real_landing_signal(incident) {
        return (raw, DowngradeReason::LandingSignalPresent);
    }

    // Rule table — flat if-else chain so each detector + posture
    // condition is one obvious row. Adding a rule = adding one block.
    // Order is independence: each rule only fires for its detector
    // string, so the chain order does not affect behaviour.

    // Phase 3 first rule: ssh_bruteforce demotes IFF posture confirms
    // the password surface is closed. Critical incidents (which the
    // detector emits when count >= 5x threshold) keep their severity
    // even on hardened hosts — that volume of failures is itself
    // worth surfacing.
    if detector == "ssh_bruteforce"
        && posture.sshd.password_login_effectively_disabled()
        && !matches!(raw, Severity::Critical)
    {
        return (Severity::Low, DowngradeReason::SshPasswordSurfaceDisabled);
    }

    if detector == "proto_anomaly" && matches!(raw, Severity::High) {
        return (Severity::Medium, DowngradeReason::ProtoAnomalyExternalScan);
    }

    if detector == "killchain"
        && killchain_pattern_is_unknown(incident)
        && matches!(raw, Severity::High | Severity::Medium)
    {
        return (Severity::Low, DowngradeReason::KillchainPatternUnknown);
    }

    if detector == "correlated_anomaly" && matches!(raw, Severity::High) {
        return (Severity::Medium, DowngradeReason::None);
    }

    if detector == "threat_intel" && incident.tags.iter().any(|t| t == "auto_blocked") {
        return (Severity::Low, DowngradeReason::ThreatIntelAutoBlocked);
    }

    (raw, DowngradeReason::None)
}

/// Real-landing tags. Each represents a fact the agent's other paths
/// emit when an attacker actually got past defenses (or the operator
/// has not yet investigated). Adding to this list is a one-way ratchet
/// toward "more conservative" — never remove without operator review.
fn has_real_landing_signal(incident: &Incident) -> bool {
    incident.tags.iter().any(|t| {
        t == "session_established"
            || t == "process_executed"
            || t == "file_written"
            || t == "key_match"
    })
}

/// Killchain incidents store the pattern in `evidence[0].pattern` (when
/// emitted by the inline killchain pipeline) or `evidence.pattern`
/// (when emitted by the legacy code path). Returning false on parse
/// failure is conservative — keep the alert at original severity.
fn killchain_pattern_is_unknown(incident: &Incident) -> bool {
    let pattern = incident
        .evidence
        .get("pattern")
        .or_else(|| incident.evidence.get(0).and_then(|e| e.get("pattern")))
        .and_then(|p| p.as_str());
    matches!(pattern, Some("unknown"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::posture::sshd::{ProbeState, SshdPosture, SshdToggle};

    fn make_incident(
        detector: &str,
        severity: Severity,
        tags: Vec<&str>,
        evidence: serde_json::Value,
    ) -> Incident {
        Incident {
            ts: chrono::Utc::now(),
            host: "test".into(),
            incident_id: format!("{}:1.2.3.4:test", detector),
            severity,
            title: "Test".into(),
            summary: "".into(),
            evidence,
            recommended_checks: vec![],
            tags: tags.into_iter().map(|s| s.to_string()).collect(),
            entities: vec![],
        }
    }

    fn hardened_posture() -> HostPosture {
        HostPosture {
            sshd: SshdPosture {
                probe_state: ProbeState::Ok,
                password_authentication: SshdToggle::No,
                kbd_interactive_authentication: SshdToggle::No,
                permit_root_login: SshdToggle::No,
                pubkey_authentication: SshdToggle::Yes,
                max_auth_tries: Some(3),
                ports: vec![22],
                error: None,
            },
            ..Default::default()
        }
    }

    fn permissive_posture() -> HostPosture {
        HostPosture {
            sshd: SshdPosture {
                probe_state: ProbeState::Ok,
                password_authentication: SshdToggle::Yes,
                kbd_interactive_authentication: SshdToggle::Yes,
                permit_root_login: SshdToggle::Yes,
                pubkey_authentication: SshdToggle::Yes,
                max_auth_tries: Some(6),
                ports: vec![22],
                error: None,
            },
            ..Default::default()
        }
    }

    fn unknown_posture() -> HostPosture {
        // Posture probe never ran (Pending) — bias permissive. The
        // operator should never see a demote based on a snapshot that
        // does not exist.
        HostPosture::default()
    }

    // ─── ssh_bruteforce ────────────────────────────────────────────────────

    #[test]
    fn ssh_bruteforce_high_demotes_on_hardened_host() {
        let inc = make_incident(
            "ssh_bruteforce",
            Severity::High,
            vec![],
            serde_json::json!([{}]),
        );
        let (sev, reason) = effective_severity(&inc, "ssh_bruteforce", &hardened_posture());
        assert_eq!(sev, Severity::Low);
        assert_eq!(reason, DowngradeReason::SshPasswordSurfaceDisabled);
    }

    #[test]
    fn ssh_bruteforce_high_keeps_severity_on_permissive_host() {
        let inc = make_incident(
            "ssh_bruteforce",
            Severity::High,
            vec![],
            serde_json::json!([{}]),
        );
        let (sev, reason) = effective_severity(&inc, "ssh_bruteforce", &permissive_posture());
        assert_eq!(sev, Severity::High);
        assert_eq!(reason, DowngradeReason::None);
    }

    /// Posture probe never ran → biases permissive (no demote). The
    /// downgrade engine MUST NOT silently swallow alerts based on a
    /// snapshot that does not exist.
    #[test]
    fn ssh_bruteforce_keeps_severity_when_posture_unknown() {
        let inc = make_incident(
            "ssh_bruteforce",
            Severity::High,
            vec![],
            serde_json::json!([{}]),
        );
        let (sev, reason) = effective_severity(&inc, "ssh_bruteforce", &unknown_posture());
        assert_eq!(sev, Severity::High);
        assert_eq!(reason, DowngradeReason::None);
    }

    /// Critical ssh_bruteforce never demotes — that volume of failed
    /// attempts is itself worth surfacing even on a hardened host.
    #[test]
    fn ssh_bruteforce_critical_keeps_severity_on_hardened_host() {
        let inc = make_incident(
            "ssh_bruteforce",
            Severity::Critical,
            vec![],
            serde_json::json!([{}]),
        );
        let (sev, reason) = effective_severity(&inc, "ssh_bruteforce", &hardened_posture());
        assert_eq!(sev, Severity::Critical);
        assert_eq!(reason, DowngradeReason::None);
    }

    /// Spec 044 invariant anchor: only `PasswordAuthentication=no` is
    /// not enough — `KbdInteractiveAuthentication=yes` still routes
    /// to PAM/shadow. The downgrade engine demands BOTH No.
    #[test]
    fn ssh_bruteforce_does_not_demote_when_kbd_interactive_yes() {
        let inc = make_incident(
            "ssh_bruteforce",
            Severity::High,
            vec![],
            serde_json::json!([{}]),
        );
        let mut posture = hardened_posture();
        posture.sshd.kbd_interactive_authentication = SshdToggle::Yes;
        let (sev, reason) = effective_severity(&inc, "ssh_bruteforce", &posture);
        assert_eq!(sev, Severity::High);
        assert_eq!(reason, DowngradeReason::None);
    }

    // ─── Real-landing guards ───────────────────────────────────────────────

    /// Hard invariant 1: `session_established` tag means the attacker
    /// actually got in. Posture-aware demote is bypassed regardless
    /// of how hardened the host is — by definition something got past
    /// the hardening.
    #[test]
    fn session_established_tag_bypasses_demote_on_hardened_host() {
        let inc = make_incident(
            "ssh_bruteforce",
            Severity::High,
            vec!["session_established"],
            serde_json::json!([{}]),
        );
        let (sev, reason) = effective_severity(&inc, "ssh_bruteforce", &hardened_posture());
        assert_eq!(sev, Severity::High);
        assert_eq!(reason, DowngradeReason::LandingSignalPresent);
    }

    #[test]
    fn process_executed_tag_bypasses_demote() {
        let inc = make_incident(
            "ssh_bruteforce",
            Severity::High,
            vec!["process_executed"],
            serde_json::json!([{}]),
        );
        let (sev, reason) = effective_severity(&inc, "ssh_bruteforce", &hardened_posture());
        assert_eq!(sev, Severity::High);
        assert_eq!(reason, DowngradeReason::LandingSignalPresent);
    }

    #[test]
    fn file_written_tag_bypasses_demote() {
        let inc = make_incident(
            "ssh_bruteforce",
            Severity::High,
            vec!["file_written"],
            serde_json::json!([{}]),
        );
        let (sev, reason) = effective_severity(&inc, "ssh_bruteforce", &hardened_posture());
        assert_eq!(sev, Severity::High);
        assert_eq!(reason, DowngradeReason::LandingSignalPresent);
    }

    #[test]
    fn key_match_tag_bypasses_demote() {
        // ssh_key_injection where the agent confirmed an authorized_keys
        // entry — that is a real landing, not a posture-shielded probe.
        let inc = make_incident(
            "ssh_key_injection",
            Severity::High,
            vec!["key_match"],
            serde_json::json!([{}]),
        );
        let (sev, reason) = effective_severity(&inc, "ssh_key_injection", &hardened_posture());
        assert_eq!(sev, Severity::High);
        assert_eq!(reason, DowngradeReason::LandingSignalPresent);
    }

    // ─── Existing rules retained (no posture dependency) ───────────────────

    #[test]
    fn proto_anomaly_high_to_medium() {
        let inc = make_incident(
            "proto_anomaly",
            Severity::High,
            vec![],
            serde_json::json!([{}]),
        );
        let (sev, reason) = effective_severity(&inc, "proto_anomaly", &permissive_posture());
        assert_eq!(sev, Severity::Medium);
        assert_eq!(reason, DowngradeReason::ProtoAnomalyExternalScan);
    }

    #[test]
    fn killchain_unknown_pattern_demotes() {
        let inc = make_incident(
            "killchain",
            Severity::High,
            vec![],
            serde_json::json!([{ "pattern": "unknown" }]),
        );
        let (sev, reason) = effective_severity(&inc, "killchain", &permissive_posture());
        assert_eq!(sev, Severity::Low);
        assert_eq!(reason, DowngradeReason::KillchainPatternUnknown);
    }

    #[test]
    fn killchain_known_pattern_keeps_severity() {
        let inc = make_incident(
            "killchain",
            Severity::High,
            vec![],
            serde_json::json!([{ "pattern": "DATA_EXFIL" }]),
        );
        let (sev, reason) = effective_severity(&inc, "killchain", &permissive_posture());
        assert_eq!(sev, Severity::High);
        assert_eq!(reason, DowngradeReason::None);
    }

    #[test]
    fn threat_intel_auto_blocked_demotes() {
        let inc = make_incident(
            "threat_intel",
            Severity::High,
            vec!["auto_blocked"],
            serde_json::json!([{}]),
        );
        let (sev, reason) = effective_severity(&inc, "threat_intel", &permissive_posture());
        assert_eq!(sev, Severity::Low);
        assert_eq!(reason, DowngradeReason::ThreatIntelAutoBlocked);
    }

    #[test]
    fn threat_intel_not_auto_blocked_keeps_severity() {
        let inc = make_incident(
            "threat_intel",
            Severity::High,
            vec![],
            serde_json::json!([{}]),
        );
        let (sev, reason) = effective_severity(&inc, "threat_intel", &permissive_posture());
        assert_eq!(sev, Severity::High);
        assert_eq!(reason, DowngradeReason::None);
    }

    /// Catch-all: detectors not in the table return original severity
    /// regardless of posture. Adding a new detector to the demote
    /// table must be deliberate.
    #[test]
    fn unrecognised_detector_keeps_severity() {
        let inc = make_incident(
            "exotic_new_detector",
            Severity::High,
            vec![],
            serde_json::json!([{}]),
        );
        let (sev, reason) = effective_severity(&inc, "exotic_new_detector", &hardened_posture());
        assert_eq!(sev, Severity::High);
        assert_eq!(reason, DowngradeReason::None);
    }
}
