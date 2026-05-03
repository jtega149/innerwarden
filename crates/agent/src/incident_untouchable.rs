//! Untouchable detector classifier.
//!
//! Identifies incidents whose evidence is so strong (kernel-level
//! signal, multi-stage cross-layer chain, specific high-confidence
//! detector classes) that an AI proposing `Dismiss` or `Ignore` at
//! Critical severity must be overridden by the agent rather than
//! trusted. Origin: 2026-05-01 dashboard QA audit finding 1.3 — AI
//! auto-dismissed a `kill_chain DATA_EXFIL + reverse_shell` at 100%
//! confidence with rationale "ssh is a known operator/system tool".
//! The detector evidence was eBPF kernel-level fd-redirect-to-socket;
//! dismissing that is exactly the failure mode a security tool must
//! never have.
//!
//! Three policy choices are deliberate:
//!
//! 1. **Detection over enforcement**: classifier returns the class
//!    name + a short evidence pointer; the override decision (whether
//!    to actually flip the action) lives in `incident_post_decision`
//!    so the same classifier can later feed a UI badge ("this
//!    detector class is untouchable") without coupling.
//!
//! 2. **Conservative class set**: only five classes today. We do NOT
//!    want a runaway list that turns every incident into "operator
//!    must review", which is the failure mode that erodes trust in
//!    the opposite direction. Each class is justified inline.
//!
//! 3. **Severity is part of the override, not the class**: a
//!    `kill_chain` at Medium is still a kill chain but it is
//!    legitimately triagable by AI; the override only kicks in at
//!    Critical (see post_decision wiring). The classifier itself is
//!    severity-agnostic so it can be reused elsewhere.

use innerwarden_core::incident::Incident;

use crate::ai;

/// A class of detector / evidence the AI is not allowed to silently
/// dismiss at Critical severity. Variants are ordered by how strong
/// the evidence is (eBPF kernel signals first).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UntouchableClass {
    /// Kill chain detection (any chain rule fired). Multi-stage
    /// pattern detected by the LSM/kernel layer; by definition
    /// already required multiple stages of evidence to fire.
    KillChain,

    /// Reverse shell with kernel/eBPF evidence. Specifically the
    /// fd-redirect-to-socket pattern caught by the eBPF reverse-shell
    /// detector — process redirected stdin/stdout to a network
    /// socket, which is mechanically reverse-shell behaviour and
    /// not a binary-name heuristic the AI can wave away.
    ReverseShellKernel,

    /// Ransomware detector — fanotify burst-write + entropy
    /// signature. Cost of a missed ransomware detection is total
    /// data loss; the AI dismissing this is the highest-impact
    /// possible false negative.
    Ransomware,

    /// Data exfiltration via eBPF (`data_exfil_ebpf` detector).
    /// Kernel-level egress volume detection; not a heuristic on log
    /// text. The detector itself already filters known-benign
    /// destinations before firing, so an AI second-guess is rarely
    /// adding signal.
    DataExfilEbpf,

    /// Cross-layer correlation chain with `stages >= 2` AND
    /// `layers >= 2`. By construction this means the same entity
    /// crossed at least two of {firmware, hypervisor, kernel,
    /// userspace, network, honeypot} in the correlation window —
    /// not a single noisy detector firing in isolation.
    MultiStageCrossLayer,
}

impl UntouchableClass {
    /// Stable string identifier used in audit logs, telemetry, and
    /// the override reason annotation. Stable across releases — do
    /// not change without bumping a schema note.
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            UntouchableClass::KillChain => "kill_chain",
            UntouchableClass::ReverseShellKernel => "reverse_shell_kernel",
            UntouchableClass::Ransomware => "ransomware",
            UntouchableClass::DataExfilEbpf => "data_exfil_ebpf",
            UntouchableClass::MultiStageCrossLayer => "multi_stage_cross_layer",
        }
    }
}

/// Classify an incident. Returns `Some(class)` when the incident
/// belongs to one of the untouchable categories, `None` otherwise.
///
/// Identification is primarily prefix-matched on `incident_id`
/// because that is the field every existing persistence path
/// (`decisions.jsonl`, SQLite `decisions` table) already serialises
/// consistently, and changing the agent's
/// incident-id convention is out of scope for an audit-completeness
/// fix. Evidence-field probing supplements this for the
/// reverse-shell case where we must distinguish kernel-level
/// (eBPF) from heuristic detection.
pub(crate) fn classify(incident: &Incident) -> Option<UntouchableClass> {
    let id = incident.incident_id.as_str();

    // Kill chain. The detector emits ids like `kill_chain_detected_<TYPE>_<PID>_<TS>`
    // (underscore-separated; see eBPF detector layer) and also ids
    // prefixed `kill_chain:` from the inline correlation path. Both
    // shapes count.
    if id.starts_with("kill_chain") {
        return Some(UntouchableClass::KillChain);
    }

    if id.starts_with("ransomware:") {
        return Some(UntouchableClass::Ransomware);
    }

    if id.starts_with("data_exfil_ebpf:") {
        return Some(UntouchableClass::DataExfilEbpf);
    }

    // Reverse shell only counts as untouchable when the evidence
    // names the kernel/eBPF layer. Userland heuristics (e.g. a log
    // line that looks shell-y) can still be triaged by AI without
    // the override; only the fd-redirect-to-socket / syscall
    // sequence path goes here.
    if id.starts_with("reverse_shell:") || id.starts_with("reverse_shell_") {
        if let Some(source) = incident.evidence.get("source").and_then(|v| v.as_str()) {
            let s = source.to_ascii_lowercase();
            if s == "ebpf" || s == "syscall_sequence" || s == "kernel" {
                return Some(UntouchableClass::ReverseShellKernel);
            }
        }
        if incident
            .tags
            .iter()
            .any(|t| t.eq_ignore_ascii_case("ebpf") || t.eq_ignore_ascii_case("kernel"))
        {
            return Some(UntouchableClass::ReverseShellKernel);
        }
    }

    // Multi-stage cross-layer chain. The correlation engine writes
    // `stages` and `layers` into the incident evidence object;
    // require both >= 2. A single-layer chain (e.g. all eBPF) is
    // legitimately triagable; a chain that crossed firmware →
    // network is qualitatively different.
    let stages = incident.evidence.get("stages").and_then(|v| v.as_u64());
    let layers = incident.evidence.get("layers").and_then(|v| v.as_u64());
    if matches!((stages, layers), (Some(s), Some(l)) if s >= 2 && l >= 2) {
        return Some(UntouchableClass::MultiStageCrossLayer);
    }

    None
}

/// Returns true when the AI's proposed action is one we are
/// willing to override (Dismiss or Ignore). Other actions
/// (BlockIp, Monitor, RequestConfirmation already, ...) are not
/// the failure mode the audit caught and are left as-is.
pub(crate) fn is_dismiss_like(action: &ai::AiAction) -> bool {
    matches!(
        action,
        ai::AiAction::Dismiss { .. } | ai::AiAction::Ignore { .. }
    )
}

/// Replace `decision` in place with the override form: action
/// becomes `RequestConfirmation` so the operator sees it, the
/// original AI rationale is preserved in the `reason` suffix so the
/// audit trail keeps the dismiss-attempt as evidence, and
/// `auto_execute` is forced false. Used by the enforce-mode branch
/// of `incident_post_decision::apply_post_decision_safeguards`.
pub(crate) fn override_to_confirmation(
    decision: &mut ai::AiDecision,
    class: UntouchableClass,
    incident_id: &str,
) {
    let proposed_action = decision.action.name();
    let original_reason = decision.reason.clone();
    let summary = format!(
        "Operator override required: AI proposed {proposed_action} on a Critical {class_str} \
         incident ({incident_id}). Kernel-level evidence cannot be auto-dismissed.",
        class_str = class.as_str(),
    );
    *decision = ai::AiDecision {
        action: ai::AiAction::RequestConfirmation { summary },
        confidence: decision.confidence,
        auto_execute: false,
        reason: format!(
            "{original_reason} [overridden: untouchable={}, severity=Critical, AI auto-dismiss not permitted]",
            class.as_str(),
        ),
        alternatives: decision.alternatives.clone(),
        estimated_threat: "critical".into(),
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use innerwarden_core::event::Severity;

    fn incident(id: &str, evidence: serde_json::Value, tags: Vec<&str>) -> Incident {
        Incident {
            ts: Utc::now(),
            host: "h".into(),
            incident_id: id.into(),
            severity: Severity::Critical,
            title: "t".into(),
            summary: "s".into(),
            evidence,
            recommended_checks: vec![],
            tags: tags.into_iter().map(String::from).collect(),
            entities: vec![],
        }
    }

    #[test]
    fn kill_chain_detected_id_classifies() {
        let inc = incident(
            "kill_chain_detected_DATA_EXFIL_3742008_2026-04-30T15_24Z",
            serde_json::json!({}),
            vec![],
        );
        assert_eq!(classify(&inc), Some(UntouchableClass::KillChain));
    }

    #[test]
    fn kill_chain_colon_id_also_classifies() {
        let inc = incident(
            "kill_chain:CHAIN-0040:CL-008",
            serde_json::json!({}),
            vec![],
        );
        assert_eq!(classify(&inc), Some(UntouchableClass::KillChain));
    }

    #[test]
    fn ransomware_classifies() {
        let inc = incident(
            "ransomware:as:mass_write:2026-04-15T20:32Z",
            serde_json::json!({}),
            vec![],
        );
        assert_eq!(classify(&inc), Some(UntouchableClass::Ransomware));
    }

    #[test]
    fn data_exfil_ebpf_classifies() {
        let inc = incident(
            "data_exfil_ebpf:3742008:2026-04-30T15:24Z",
            serde_json::json!({}),
            vec![],
        );
        assert_eq!(classify(&inc), Some(UntouchableClass::DataExfilEbpf));
    }

    #[test]
    fn reverse_shell_with_ebpf_source_classifies() {
        let inc = incident(
            "reverse_shell:3815134:2026-05-01T01:53Z",
            serde_json::json!({"source": "ebpf"}),
            vec![],
        );
        assert_eq!(classify(&inc), Some(UntouchableClass::ReverseShellKernel));
    }

    #[test]
    fn reverse_shell_with_kernel_tag_classifies() {
        let inc = incident(
            "reverse_shell:3815134:2026-05-01T01:53Z",
            serde_json::json!({}),
            vec!["kernel"],
        );
        assert_eq!(classify(&inc), Some(UntouchableClass::ReverseShellKernel));
    }

    #[test]
    fn reverse_shell_without_kernel_evidence_does_not_classify() {
        // Heuristic / log-based reverse_shell — AI can still triage.
        let inc = incident(
            "reverse_shell:3815134:2026-05-01T01:53Z",
            serde_json::json!({"source": "auth_log"}),
            vec!["heuristic"],
        );
        assert_eq!(classify(&inc), None);
    }

    #[test]
    fn multi_stage_multi_layer_chain_classifies() {
        let inc = incident(
            "correlated_anomaly:CHAIN-0040",
            serde_json::json!({"stages": 3, "layers": 2}),
            vec![],
        );
        assert_eq!(classify(&inc), Some(UntouchableClass::MultiStageCrossLayer));
    }

    #[test]
    fn single_layer_chain_does_not_classify() {
        // Same number of stages but only one layer — AI is allowed
        // to triage these because the entire chain stayed in one
        // layer (e.g. all userspace heuristics) and might be a
        // single noisy detector firing repeatedly.
        let inc = incident(
            "correlated_anomaly:CHAIN-0040",
            serde_json::json!({"stages": 3, "layers": 1}),
            vec![],
        );
        assert_eq!(classify(&inc), None);
    }

    #[test]
    fn unrelated_detector_does_not_classify() {
        let inc = incident(
            "ssh_bruteforce:1.2.3.4:2026-05-01T03:00Z",
            serde_json::json!({}),
            vec![],
        );
        assert_eq!(classify(&inc), None);
    }

    fn dismiss_decision() -> ai::AiDecision {
        ai::AiDecision {
            action: ai::AiAction::Dismiss {
                reason: "ssh is a known operator/system tool".into(),
            },
            confidence: 1.0,
            auto_execute: true,
            reason: "looks benign".into(),
            alternatives: vec!["block_ip".into()],
            estimated_threat: "low".into(),
        }
    }

    #[test]
    fn is_dismiss_like_matches_dismiss_and_ignore() {
        let dismiss = dismiss_decision();
        assert!(is_dismiss_like(&dismiss.action));

        let ignore_decision = ai::AiDecision {
            action: ai::AiAction::Ignore {
                reason: "duplicate".into(),
            },
            ..dismiss.clone()
        };
        assert!(is_dismiss_like(&ignore_decision.action));
    }

    #[test]
    fn is_dismiss_like_rejects_other_actions() {
        let block = ai::AiDecision {
            action: ai::AiAction::BlockIp {
                ip: "1.2.3.4".into(),
                skill_id: "block-ip-ufw".into(),
            },
            ..dismiss_decision()
        };
        assert!(!is_dismiss_like(&block.action));

        let monitor = ai::AiDecision {
            action: ai::AiAction::Monitor {
                ip: "1.2.3.4".into(),
            },
            ..dismiss_decision()
        };
        assert!(!is_dismiss_like(&monitor.action));

        let confirm = ai::AiDecision {
            action: ai::AiAction::RequestConfirmation {
                summary: "needs review".into(),
            },
            ..dismiss_decision()
        };
        assert!(!is_dismiss_like(&confirm.action));
    }

    #[test]
    fn override_to_confirmation_preserves_original_rationale_in_suffix() {
        // Audit invariant: the AI's original dismiss rationale must
        // survive in the audit trail so an operator reviewing later
        // can see WHY the AI got it wrong, not just that the agent
        // overrode. This is the data the dashboard's "Why I might
        // be wrong" panel will eventually surface (tracked-spec-ai-override).
        let mut decision = dismiss_decision();
        override_to_confirmation(
            &mut decision,
            UntouchableClass::KillChain,
            "kill_chain_detected_DATA_EXFIL_3742008_2026-04-30T15_24Z",
        );
        assert!(matches!(
            decision.action,
            ai::AiAction::RequestConfirmation { .. }
        ));
        assert!(!decision.auto_execute);
        assert_eq!(decision.estimated_threat, "critical");
        assert!(
            decision.reason.contains("looks benign"),
            "original reason must survive: {}",
            decision.reason
        );
        assert!(
            decision.reason.contains("untouchable=kill_chain"),
            "override annotation missing: {}",
            decision.reason
        );
        assert!(
            decision.reason.contains("AI auto-dismiss not permitted"),
            "override label missing: {}",
            decision.reason
        );
    }

    #[test]
    fn override_to_confirmation_keeps_confidence_and_alternatives() {
        // The confidence number is the AI's input — keeping it lets
        // the dashboard display "AI proposed dismiss at 100%
        // confidence; agent overrode" instead of zeroing the data.
        // Alternatives the AI considered also stay, in case the
        // operator wants to take one of them after review.
        let mut decision = dismiss_decision();
        let original_conf = decision.confidence;
        let original_alts = decision.alternatives.clone();
        override_to_confirmation(
            &mut decision,
            UntouchableClass::ReverseShellKernel,
            "reverse_shell:3815134:2026-05-01T01:53Z",
        );
        assert!((decision.confidence - original_conf).abs() < f32::EPSILON);
        assert_eq!(decision.alternatives, original_alts);
    }

    #[test]
    fn class_string_identifiers_are_stable() {
        assert_eq!(UntouchableClass::KillChain.as_str(), "kill_chain");
        assert_eq!(
            UntouchableClass::ReverseShellKernel.as_str(),
            "reverse_shell_kernel"
        );
        assert_eq!(UntouchableClass::Ransomware.as_str(), "ransomware");
        assert_eq!(UntouchableClass::DataExfilEbpf.as_str(), "data_exfil_ebpf");
        assert_eq!(
            UntouchableClass::MultiStageCrossLayer.as_str(),
            "multi_stage_cross_layer"
        );
    }
}
