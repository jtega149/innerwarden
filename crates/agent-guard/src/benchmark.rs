//! Agent-attack proof benchmark (spec 079 P1).
//!
//! An honest, reproducible catch/miss/false-positive measurement of the
//! command-analysis engine ([`crate::mcp::analyze_command`], the exact path
//! `/api/agent/check-command` uses) against a curated corpus of agent-native
//! attacks plus a benign control set.
//!
//! This module is the *scoring* logic (testable + covered). The corpus YAML and
//! the runnable harness that prints / writes a `SCOREBOARD.md` live in
//! `examples/agent_attack_benchmark.rs`.
//!
//! The measured number is deliberately honest: the current engine is a
//! command-string analyzer, so it scores well on execution-style attacks
//! (reverse shell, download-exec, destructive, obfuscation) and is expected to
//! MISS agent-native attacks it was not built for (pure prompt injection,
//! indirect injection via poisoned tool results, tool poisoning). Those misses
//! are recorded, not hidden — they are the measured justification for spec 079
//! P2/P3 (deep MCP / behavioral inspection).

use serde::Deserialize;

use crate::mcp::analyze_command;
use crate::rules::RuleEngine;

/// Ground-truth label for a corpus case.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Label {
    /// Should be caught (deny or review). An `allow` is a MISS.
    Malicious,
    /// Should pass (allow). A deny/review is a FALSE POSITIVE.
    Benign,
}

/// One corpus entry.
#[derive(Debug, Clone, Deserialize)]
pub struct Case {
    pub id: String,
    pub category: String,
    pub label: Label,
    pub input: String,
}

/// The parsed corpus file.
#[derive(Debug, Clone, Deserialize)]
pub struct Corpus {
    pub cases: Vec<Case>,
}

impl Corpus {
    /// Parse a YAML corpus. Fails loudly on malformed input so a broken corpus
    /// can never silently report a perfect score.
    pub fn from_yaml(yaml: &str) -> Result<Self, serde_yaml::Error> {
        serde_yaml::from_str(yaml)
    }
}

/// Outcome of scoring one case against the engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Malicious input surfaced (deny or review).
    Caught,
    /// Malicious input slipped through (allow).
    Missed,
    /// Benign input wrongly surfaced (deny or review).
    FalsePositive,
    /// Benign input correctly allowed.
    Ok,
}

/// Map `(label, engine recommendation)` to a benchmark [`Outcome`].
///
/// `recommendation` is `"deny" | "review" | "allow"`. A malicious case is
/// CAUGHT if it is denied OR surfaced for review (review = not silently
/// allowed); only `allow` on a malicious case is a MISS. A benign case that is
/// denied or reviewed is a FALSE POSITIVE.
pub fn classify(label: Label, recommendation: &str) -> Outcome {
    let surfaced = recommendation == "deny" || recommendation == "review";
    match (label, surfaced) {
        (Label::Malicious, true) => Outcome::Caught,
        (Label::Malicious, false) => Outcome::Missed,
        (Label::Benign, true) => Outcome::FalsePositive,
        (Label::Benign, false) => Outcome::Ok,
    }
}

/// Per-case scored result.
#[derive(Debug, Clone)]
pub struct CaseResult {
    pub id: String,
    pub category: String,
    pub label: Label,
    pub input: String,
    /// `"deny" | "review" | "allow"`.
    pub recommendation: String,
    pub risk_score: u32,
    pub outcome: Outcome,
}

impl CaseResult {
    /// A hard block (deny), as opposed to merely surfaced-for-review.
    pub fn is_denied(&self) -> bool {
        self.recommendation == "deny"
    }
}

/// Run every case in `corpus` through the engine and return scored results in
/// corpus order.
pub fn run(corpus: &Corpus, engine: &RuleEngine) -> Vec<CaseResult> {
    corpus
        .cases
        .iter()
        .map(|c| {
            let a = analyze_command(&c.input, Some(engine));
            CaseResult {
                id: c.id.clone(),
                category: c.category.clone(),
                label: c.label,
                input: c.input.clone(),
                recommendation: a.recommendation.clone(),
                risk_score: a.risk_score,
                outcome: classify(c.label, &a.recommendation),
            }
        })
        .collect()
}

/// Aggregate metrics over a set of [`CaseResult`]s.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Scoreboard {
    pub malicious_total: usize,
    pub caught: usize,
    pub missed: usize,
    pub denied: usize,
    pub benign_total: usize,
    pub false_positives: usize,
    pub benign_ok: usize,
}

impl Scoreboard {
    pub fn from_results(results: &[CaseResult]) -> Self {
        let mut s = Scoreboard::default();
        for r in results {
            match r.label {
                Label::Malicious => {
                    s.malicious_total += 1;
                    match r.outcome {
                        Outcome::Caught => s.caught += 1,
                        Outcome::Missed => s.missed += 1,
                        _ => {}
                    }
                    if r.is_denied() {
                        s.denied += 1;
                    }
                }
                Label::Benign => {
                    s.benign_total += 1;
                    match r.outcome {
                        Outcome::FalsePositive => s.false_positives += 1,
                        Outcome::Ok => s.benign_ok += 1,
                        _ => {}
                    }
                }
            }
        }
        s
    }

    /// Caught (deny OR review) / malicious total.
    pub fn catch_rate(&self) -> f64 {
        pct(self.caught, self.malicious_total)
    }

    /// Hard-denied / malicious total (a stricter view than catch_rate).
    pub fn deny_rate(&self) -> f64 {
        pct(self.denied, self.malicious_total)
    }

    /// False positives / benign total.
    pub fn false_positive_rate(&self) -> f64 {
        pct(self.false_positives, self.benign_total)
    }
}

fn pct(n: usize, d: usize) -> f64 {
    if d == 0 {
        0.0
    } else {
        100.0 * n as f64 / d as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_covers_all_four_quadrants() {
        assert_eq!(classify(Label::Malicious, "deny"), Outcome::Caught);
        assert_eq!(classify(Label::Malicious, "review"), Outcome::Caught);
        assert_eq!(classify(Label::Malicious, "allow"), Outcome::Missed);
        assert_eq!(classify(Label::Benign, "allow"), Outcome::Ok);
        assert_eq!(classify(Label::Benign, "deny"), Outcome::FalsePositive);
        assert_eq!(classify(Label::Benign, "review"), Outcome::FalsePositive);
    }

    #[test]
    fn scoreboard_rates_are_computed_honestly() {
        let results = vec![
            CaseResult {
                id: "m1".into(),
                category: "rs".into(),
                label: Label::Malicious,
                input: "x".into(),
                recommendation: "deny".into(),
                risk_score: 60,
                outcome: Outcome::Caught,
            },
            CaseResult {
                id: "m2".into(),
                category: "pi".into(),
                label: Label::Malicious,
                input: "y".into(),
                recommendation: "allow".into(),
                risk_score: 0,
                outcome: Outcome::Missed,
            },
            CaseResult {
                id: "b1".into(),
                category: "dev".into(),
                label: Label::Benign,
                input: "git status".into(),
                recommendation: "allow".into(),
                risk_score: 0,
                outcome: Outcome::Ok,
            },
            CaseResult {
                id: "b2".into(),
                category: "dev".into(),
                label: Label::Benign,
                input: "rm -rf ./build".into(),
                recommendation: "review".into(),
                risk_score: 20,
                outcome: Outcome::FalsePositive,
            },
        ];
        let s = Scoreboard::from_results(&results);
        assert_eq!(s.malicious_total, 2);
        assert_eq!(s.caught, 1);
        assert_eq!(s.missed, 1);
        assert_eq!(s.denied, 1);
        assert_eq!(s.benign_total, 2);
        assert_eq!(s.false_positives, 1);
        assert_eq!(s.catch_rate(), 50.0);
        assert_eq!(s.deny_rate(), 50.0);
        assert_eq!(s.false_positive_rate(), 50.0);
    }

    #[test]
    fn embedded_corpus_parses_and_runs_against_the_real_engine() {
        // Smoke test: the shipped corpus parses, and the real embedded ATR
        // engine scores every case without panicking. Asserts only structural
        // sanity (not a fixed rate — the rate is a measured artifact, not a
        // gate here).
        let yaml = include_str!("../benchmarks/agent_attack_corpus.yml");
        let corpus = Corpus::from_yaml(yaml).expect("corpus must parse");
        assert!(corpus.cases.len() >= 40, "corpus should be substantial");
        let engine = RuleEngine::load_embedded();
        let results = run(&corpus, &engine);
        assert_eq!(results.len(), corpus.cases.len());
        let s = Scoreboard::from_results(&results);
        assert_eq!(s.malicious_total + s.benign_total, corpus.cases.len());
        // Sanity floor: blatant execution attacks (reverse shell, rm -rf /)
        // MUST be caught, or something is badly broken.
        let rs = results.iter().find(|r| r.id == "rs-001").unwrap();
        assert_eq!(rs.outcome, Outcome::Caught, "reverse shell must be caught");
    }
}
