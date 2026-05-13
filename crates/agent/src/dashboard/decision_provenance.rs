//! Spec 049 PR9 — decision provenance labelling for the Cases drill-down.
//!
//! Derives a stable, operator-facing `DecisionLayer` label at READ
//! time from the fields already persisted on a `DecisionEntry`
//! (`ai_provider`, `reason`, `confidence`). NO write-path changes —
//! every historical decision JSONL entry classifies correctly by
//! construction.
//!
//! The classifier is intentionally CONSERVATIVE: it only assigns a
//! specific layer when the signature is unambiguous. Anything else
//! falls through to `Unknown` with the raw `ai_provider` echoed in
//! `detail`. An honest unknown beats a wrong classification in the
//! drill-down — the operator sees "unknown (auto-rule:foo)" instead
//! of being told the wrong layer decided.
//!
//! If a future PR pins `decision_layer` at write time (a follow-up
//! to PR9), this classifier becomes the validation oracle for the
//! pinned value rather than the live derivation.

use serde::Serialize;

/// Operator-facing decision layer label.
///
/// Wire format is the snake-case string from `as_str()` — surfaced
/// in the `/api/journey` decision entries' `data.decision_layer`
/// field. The frontend keys on these strings, so changing them is
/// a breaking change for the drill-down UI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum DecisionLayer {
    /// Pre-AI suppression: allowlist match, cloud_safelist match,
    /// repeat-offender ladder, skill_gate refusal.
    AlgorithmGate,
    /// PR #507 deterministic strong-pattern fast-path (killchain
    /// inline) — bypasses the AI router entirely.
    KillchainFastPath,
    /// Cross-layer correlation rule (CL-NNN) decided.
    CorrelationRule,
    /// Local Warden Model (ONNX classifier) decided. Spec 049's
    /// canonical AI Decide layer.
    AiLocalWarden,
    /// LLM provider decided (openai / anthropic / ollama).
    AiLlm,
    /// `incident_auto_rules` pipeline emitted the decision.
    AutoRule,
    /// `honeypot_post_session` or `honeypot_always_on` auto-block.
    HoneypotPostSession,
    /// `narrative_observation_verify` escalation/suppression.
    ObservationVerifier,
    /// Operator click via dashboard, Telegram, or CLI.
    ManualOperator,
    /// Heuristic could not classify — surface honestly so the
    /// operator can investigate rather than read a wrong label.
    Unknown,
}

impl DecisionLayer {
    /// String form of the layer label. Identical to the JSON wire
    /// format the frontend keys on. Currently used only in tests
    /// to assert the wire contract; production goes through serde
    /// directly. Kept on the production type (not gated on
    /// `cfg(test)`) so a future call site does not have to relax
    /// the gate.
    #[allow(dead_code)]
    pub(super) fn as_str(&self) -> &'static str {
        match self {
            Self::AlgorithmGate => "algorithm_gate",
            Self::KillchainFastPath => "killchain_fast_path",
            Self::CorrelationRule => "correlation_rule",
            Self::AiLocalWarden => "ai_local_warden",
            Self::AiLlm => "ai_llm",
            Self::AutoRule => "auto_rule",
            Self::HoneypotPostSession => "honeypot_post_session",
            Self::ObservationVerifier => "observation_verifier",
            Self::ManualOperator => "manual_operator",
            Self::Unknown => "unknown",
        }
    }
}

/// A `DecisionLayer` plus an operator-facing `detail` line. The
/// detail is what the drill-down renders next to the badge — never
/// empty; always at minimum a copy of the layer name.
#[derive(Debug, Clone, Serialize)]
pub(super) struct DecisionProvenance {
    pub(super) layer: DecisionLayer,
    pub(super) detail: String,
}

/// Classify a decision into its provenance layer using ONLY the
/// fields surfaced on a `DecisionEntry`. Pure function — same
/// input always yields the same output, no I/O, no state.
///
/// Ordering matters: more specific signatures (provider-prefixed
/// strings) are checked first, then provider-name matches, then
/// reason-string heuristics. Anything that does not match any
/// rule falls through to `Unknown`.
pub(super) fn classify_decision_layer_from_fields(
    ai_provider: &str,
    reason: &str,
    confidence: Option<f32>,
) -> DecisionProvenance {
    let provider = ai_provider.trim();
    let provider_lower = provider.to_ascii_lowercase();
    let reason_lower = reason.to_ascii_lowercase();

    // 1. Provider-prefixed paths (most specific first). These are
    //    string conventions production writers use (grep'd from the
    //    actual call sites: honeypot:*, observation-verify, auto-rule:*).
    if provider.starts_with("honeypot:") {
        return DecisionProvenance {
            layer: DecisionLayer::HoneypotPostSession,
            detail: provider.to_string(),
        };
    }
    if provider == "observation-verify" {
        return DecisionProvenance {
            layer: DecisionLayer::ObservationVerifier,
            detail: provider.to_string(),
        };
    }
    if let Some(detector) = provider.strip_prefix("auto-rule:") {
        return DecisionProvenance {
            layer: DecisionLayer::AutoRule,
            detail: format!("auto-rule · detector: {detector}"),
        };
    }

    // 2. Local Warden vs LLM. The provider name is set by the AI
    //    router; `local_classifier` / `local_warden` are the two
    //    canonical names for the ONNX classifier (spec 032 +
    //    spec 049 rename). LLMs use their canonical provider name.
    if provider_lower == "local_classifier" || provider_lower == "local_warden" {
        let detail = match confidence {
            Some(c) => format!("Local Warden Model · confidence {c:.2}"),
            None => "Local Warden Model".to_string(),
        };
        return DecisionProvenance {
            layer: DecisionLayer::AiLocalWarden,
            detail,
        };
    }
    if matches!(
        provider_lower.as_str(),
        "openai" | "anthropic" | "ollama" | "llm"
    ) {
        let detail = match confidence {
            Some(c) => format!("LLM ({provider}) · confidence {c:.2}"),
            None => format!("LLM ({provider})"),
        };
        return DecisionProvenance {
            layer: DecisionLayer::AiLlm,
            detail,
        };
    }

    // 3. Reason-based inference. Used only when the provider name
    //    is generic / test-like and the reason gives a stronger
    //    signal. The operator-readable label MUST agree with how
    //    spec 049 §8.2.E talks about the layers — same words.
    if reason_lower.contains("operator action") || reason_lower.contains("manual operator") {
        return DecisionProvenance {
            layer: DecisionLayer::ManualOperator,
            detail: format!("operator action · {}", short_reason(reason)),
        };
    }
    if reason_lower.contains("killchain fast")
        || reason_lower.contains("kill_chain fast")
        || reason_lower.contains("fast-path block")
    {
        return DecisionProvenance {
            layer: DecisionLayer::KillchainFastPath,
            detail: format!("killchain fast-path · {}", short_reason(reason)),
        };
    }
    if reason_lower.contains("correlation rule cl-") || reason_lower.contains("cl-0") {
        return DecisionProvenance {
            layer: DecisionLayer::CorrelationRule,
            detail: short_reason(reason),
        };
    }
    if reason_lower.contains("allowlist")
        || reason_lower.contains("cloud_safelist")
        || reason_lower.contains("cloud safelist")
        || reason_lower.contains("repeat-offender")
        || reason_lower.contains("skill_gate")
        || reason_lower.contains("safelist")
    {
        return DecisionProvenance {
            layer: DecisionLayer::AlgorithmGate,
            detail: short_reason(reason),
        };
    }

    // 4. Fallback — honest unknown. Echo the raw provider so the
    //    operator has a starting point for investigation.
    DecisionProvenance {
        layer: DecisionLayer::Unknown,
        detail: if provider.is_empty() {
            "unknown (no provider recorded)".to_string()
        } else {
            format!("unknown (provider: {provider})")
        },
    }
}

/// Trim a reason to a readable single-line snippet for the
/// drill-down `detail` field. Long stack-trace-like reasons make
/// the row visually noisy.
fn short_reason(reason: &str) -> String {
    let trimmed = reason.trim();
    if trimmed.len() <= 80 {
        return trimmed.to_string();
    }
    // Char-safe truncate: take up to 77 chars, append ellipsis.
    let mut out: String = trimmed.chars().take(77).collect();
    out.push_str("...");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Provider-prefixed paths ────────────────────────────────────

    #[test]
    fn honeypot_provider_prefix_classifies_as_honeypot_post_session() {
        let p =
            classify_decision_layer_from_fields("honeypot:always-on", "block on session end", None);
        assert_eq!(p.layer, DecisionLayer::HoneypotPostSession);
        assert!(p.detail.contains("honeypot:always-on"));
    }

    #[test]
    fn honeypot_abuseipdb_gate_also_classifies_as_honeypot() {
        let p = classify_decision_layer_from_fields(
            "honeypot:abuseipdb_gate",
            "AbuseIPDB score 95",
            None,
        );
        assert_eq!(p.layer, DecisionLayer::HoneypotPostSession);
    }

    #[test]
    fn observation_verify_provider_classifies_as_observation_verifier() {
        let p =
            classify_decision_layer_from_fields("observation-verify", "promotion confirmed", None);
        assert_eq!(p.layer, DecisionLayer::ObservationVerifier);
        assert_eq!(p.detail, "observation-verify");
    }

    #[test]
    fn auto_rule_provider_prefix_classifies_as_auto_rule_with_detector_in_detail() {
        let p =
            classify_decision_layer_from_fields("auto-rule:ssh_bruteforce", "lockout rule", None);
        assert_eq!(p.layer, DecisionLayer::AutoRule);
        assert!(
            p.detail.contains("ssh_bruteforce"),
            "detail must surface the detector name from the provider prefix"
        );
    }

    // ── AI providers ───────────────────────────────────────────────

    #[test]
    fn local_classifier_classifies_as_ai_local_warden() {
        let p = classify_decision_layer_from_fields(
            "local_classifier",
            "score > 0.95 block",
            Some(0.97),
        );
        assert_eq!(p.layer, DecisionLayer::AiLocalWarden);
        assert!(p.detail.contains("Local Warden Model"));
        assert!(
            p.detail.contains("0.97"),
            "detail must include confidence when present"
        );
    }

    #[test]
    fn local_warden_alias_classifies_as_ai_local_warden() {
        // Spec 049 rename: `local_warden` is the operator-facing
        // brand name; legacy `local_classifier` still parses
        // (decisions.rs serde alias). Both must classify identically.
        let p = classify_decision_layer_from_fields("local_warden", "block", None);
        assert_eq!(p.layer, DecisionLayer::AiLocalWarden);
        assert!(p.detail.contains("Local Warden Model"));
    }

    #[test]
    fn local_warden_without_confidence_omits_confidence_from_detail() {
        let p = classify_decision_layer_from_fields("local_classifier", "block", None);
        assert!(!p.detail.contains("confidence"));
    }

    #[test]
    fn openai_classifies_as_ai_llm() {
        let p = classify_decision_layer_from_fields("openai", "decision", Some(0.88));
        assert_eq!(p.layer, DecisionLayer::AiLlm);
        assert!(p.detail.contains("LLM"));
        assert!(p.detail.contains("openai"));
        assert!(p.detail.contains("0.88"));
    }

    #[test]
    fn anthropic_and_ollama_also_classify_as_ai_llm() {
        for provider in ["anthropic", "ollama"] {
            let p = classify_decision_layer_from_fields(provider, "", None);
            assert_eq!(p.layer, DecisionLayer::AiLlm, "provider {provider}");
        }
    }

    // ── Reason-based heuristics ────────────────────────────────────

    #[test]
    fn reason_with_killchain_fast_path_phrase_classifies_as_killchain() {
        let p = classify_decision_layer_from_fields(
            "killchain",
            "killchain fast-path strong pattern detected",
            None,
        );
        assert_eq!(p.layer, DecisionLayer::KillchainFastPath);
        assert!(p.detail.contains("killchain fast-path"));
    }

    #[test]
    fn reason_with_cl_id_classifies_as_correlation_rule() {
        let p = classify_decision_layer_from_fields(
            "rule-engine",
            "correlation rule CL-002 matched: packet_flood + port_scan",
            None,
        );
        assert_eq!(p.layer, DecisionLayer::CorrelationRule);
    }

    #[test]
    fn reason_with_allowlist_classifies_as_algorithm_gate() {
        let p = classify_decision_layer_from_fields(
            "skill-gate",
            "skipped: ip is on operator allowlist",
            None,
        );
        assert_eq!(p.layer, DecisionLayer::AlgorithmGate);
    }

    #[test]
    fn reason_with_cloud_safelist_classifies_as_algorithm_gate() {
        let p = classify_decision_layer_from_fields(
            "skill-gate",
            "skipped: ip in cloud_safelist (Cloudflare)",
            None,
        );
        assert_eq!(p.layer, DecisionLayer::AlgorithmGate);
    }

    #[test]
    fn reason_with_operator_action_classifies_as_manual() {
        let p = classify_decision_layer_from_fields(
            "manual",
            "operator action via dashboard Block button",
            None,
        );
        assert_eq!(p.layer, DecisionLayer::ManualOperator);
        assert!(p.detail.contains("operator action"));
    }

    // ── Unknown fallback ───────────────────────────────────────────

    #[test]
    fn unknown_provider_with_no_reason_signal_falls_back_to_unknown() {
        let p = classify_decision_layer_from_fields("test", "decision", None);
        assert_eq!(p.layer, DecisionLayer::Unknown);
        assert!(p.detail.contains("test"));
    }

    #[test]
    fn empty_provider_falls_back_to_unknown_with_no_provider_recorded_note() {
        let p = classify_decision_layer_from_fields("", "", None);
        assert_eq!(p.layer, DecisionLayer::Unknown);
        assert_eq!(p.detail, "unknown (no provider recorded)");
    }

    #[test]
    fn provider_takes_precedence_over_reason_heuristic() {
        // If both the provider matches a specific path AND the reason
        // contains a heuristic keyword, the provider wins. Otherwise
        // a honeypot-provider decision with reason "allowlist" would
        // be classified as algorithm_gate, which is wrong.
        let p = classify_decision_layer_from_fields(
            "honeypot:always-on",
            "blocked despite allowlist consideration",
            None,
        );
        assert_eq!(p.layer, DecisionLayer::HoneypotPostSession);
    }

    // ── Serialization contract ─────────────────────────────────────

    #[test]
    fn decision_layer_serializes_as_snake_case_strings() {
        // Frontend keys on these wire strings — changing them is a
        // breaking change for the drill-down UI. Pin them.
        for (layer, wire) in [
            (DecisionLayer::AlgorithmGate, "algorithm_gate"),
            (DecisionLayer::KillchainFastPath, "killchain_fast_path"),
            (DecisionLayer::CorrelationRule, "correlation_rule"),
            (DecisionLayer::AiLocalWarden, "ai_local_warden"),
            (DecisionLayer::AiLlm, "ai_llm"),
            (DecisionLayer::AutoRule, "auto_rule"),
            (DecisionLayer::HoneypotPostSession, "honeypot_post_session"),
            (DecisionLayer::ObservationVerifier, "observation_verifier"),
            (DecisionLayer::ManualOperator, "manual_operator"),
            (DecisionLayer::Unknown, "unknown"),
        ] {
            let json = serde_json::to_string(&layer).unwrap();
            assert_eq!(json, format!("\"{wire}\""), "layer {layer:?}");
            assert_eq!(layer.as_str(), wire, "as_str() must agree with serde");
        }
    }

    #[test]
    fn provenance_struct_serializes_with_layer_and_detail_fields() {
        let p = DecisionProvenance {
            layer: DecisionLayer::AiLocalWarden,
            detail: "Local Warden Model · confidence 0.97".to_string(),
        };
        let json = serde_json::to_value(&p).unwrap();
        assert_eq!(json["layer"], "ai_local_warden");
        assert_eq!(json["detail"], "Local Warden Model · confidence 0.97");
    }

    // ── Detail truncation ──────────────────────────────────────────

    #[test]
    fn short_reason_passes_through_short_input() {
        assert_eq!(short_reason("short reason"), "short reason");
    }

    #[test]
    fn short_reason_truncates_long_input_with_ellipsis() {
        let long = "x".repeat(200);
        let out = short_reason(&long);
        assert!(out.len() <= 80);
        assert!(out.ends_with("..."));
    }

    #[test]
    fn short_reason_handles_multibyte_chars_without_panicking() {
        // chars().take() — not bytes — so emoji / accents survive
        // truncation without slicing in the middle of a code point.
        let s = "área de trabalho ".repeat(10);
        let out = short_reason(&s);
        // Just must not panic; length bounds are checked above.
        assert!(!out.is_empty());
    }
}
