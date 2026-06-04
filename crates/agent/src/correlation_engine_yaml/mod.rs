//! YAML loader for correlation rules.
//!
//! Spec 055 Phase 1: load `Vec<CorrelationRule>` from YAML files instead of
//! hardcoded Rust literals. Produces byte-for-byte identical rule sets.
//!
//! Phase 1 establishes the anchor: YAML output matches hardcoded byte-for-byte.
//! Phase 2 wires this into runtime via `CorrelationEngine::from_yaml_dir()`
//! and hot-reload via mtime tracking. Phases 3-5 add CLI integration, named
//! lists, and finally remove the hardcoded literals.

use std::collections::HashMap;

use serde::Deserialize;

use crate::correlation_engine::{CorrelationRule, Layer, RuleStage};
use innerwarden_core::event::Severity;

pub const BUILTIN_YAML: &str = include_str!("builtin/00-builtin.yml");

#[derive(Debug, Deserialize)]
struct RuleFile {
    #[allow(dead_code)]
    version: u32,
    #[serde(default)]
    lists: HashMap<String, Vec<String>>,
    #[serde(default)]
    rules: Vec<RawRule>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRule {
    id: String,
    name: String,
    severity: String,
    window_secs: u64,
    min_confidence: f32,
    stages: Vec<RawStage>,
    #[serde(default)]
    disabled: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawStage {
    #[serde(default)]
    layer: Option<String>,
    kind_patterns: Vec<String>,
    entity_must_match: bool,
}

// Production callers (via `correlation_engine::builtin_rules`, the post-Spec-055-Phase-5
// thin wrapper used by `Engine::new` and the `from_yaml_dir` fallback path) +
// tests + the byte-anchor on rule count all flow through here. The YAML file
// 00-builtin.yml is the single source of truth for the 68 CL-rules.
pub fn load_builtin() -> Result<Vec<CorrelationRule>, String> {
    parse_rules(BUILTIN_YAML, "00-builtin.yml")
}

/// Load all correlation rules from a directory + the embedded built-in.
/// Built-in rules are always loaded first. On-disk rules with the same
/// `id` override the built-in; new ids are added. Files are read in
/// lexicographic order.
///
/// Named lists (`lists:` section in any file) accumulate across files with
/// first-defined-wins semantics — built-in lists from 00-builtin.yml take
/// precedence over operator-supplied files. References (`$list_name`) in
/// `kind_patterns` are expanded against the accumulated list set per file.
pub fn load_rules_dir(dir: &std::path::Path) -> Result<Vec<CorrelationRule>, String> {
    let mut by_id: HashMap<String, CorrelationRule> = HashMap::new();
    let mut global_lists: HashMap<String, Vec<String>> = HashMap::new();

    // Always load built-in first. Its lists become the baseline for any
    // on-disk file that references $exfil_kinds / $recon_kinds / etc.
    let builtin = parse_file(BUILTIN_YAML, "00-builtin.yml", &global_lists)?;
    for (k, v) in builtin.lists {
        global_lists.entry(k).or_insert(v);
    }
    for rule in builtin.rules {
        by_id.insert(rule.id.clone(), rule);
    }

    if dir.is_dir() {
        let mut entries: Vec<_> = std::fs::read_dir(dir)
            .map_err(|e| format!("read_dir {}: {e}", dir.display()))?
            .filter_map(|e| e.ok())
            .filter(|e| {
                let name = e.file_name();
                let s = name.to_string_lossy();
                (s.ends_with(".yml") || s.ends_with(".yaml"))
                    && e.file_type().is_ok_and(|t| t.is_file())
            })
            .collect();
        entries.sort_by_key(|e| e.file_name());

        for entry in entries {
            let path = entry.path();
            let name = path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string();
            match std::fs::read_to_string(&path) {
                Ok(yaml) => match parse_file(&yaml, &name, &global_lists) {
                    Ok(parsed) => {
                        for (k, v) in parsed.lists {
                            global_lists.entry(k).or_insert(v);
                        }
                        for rule in parsed.rules {
                            by_id.insert(rule.id.clone(), rule);
                        }
                    }
                    Err(e) => tracing::warn!("correlation_engine_yaml: {e}"),
                },
                Err(e) => {
                    tracing::warn!(file = %name, "correlation_engine_yaml: read error: {e}")
                }
            }
        }
    }

    let mut rules: Vec<CorrelationRule> = by_id.into_values().collect();
    // Sort by id for deterministic order
    rules.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(rules)
}

/// Compute the max mtime of YAML files in the rules directory. Used by
/// hot-reload to detect changes without re-parsing. Reserved for Phase 3
/// when mtime-based reload replaces always-reload.
#[allow(dead_code)]
pub fn dir_max_mtime(dir: &std::path::Path) -> Option<std::time::SystemTime> {
    let entries = std::fs::read_dir(dir).ok()?;
    let mut max = None;
    for entry in entries.flatten() {
        if let Ok(meta) = entry.metadata() {
            if let Ok(mtime) = meta.modified() {
                max = Some(match max {
                    Some(m) if mtime > m => mtime,
                    Some(m) => m,
                    None => mtime,
                });
            }
        }
    }
    max
}

/// Simple API: parse a single YAML string. Lists declared inline in the file
/// expand within the rules in that file; external lists are not visible
/// (use `parse_file` / `load_rules_dir` for cross-file expansion).
#[allow(dead_code)]
pub fn parse_rules(yaml: &str, source: &str) -> Result<Vec<CorrelationRule>, String> {
    parse_file(yaml, source, &HashMap::new()).map(|p| p.rules)
}

/// Output of parsing one YAML file: compiled rules + lists declared in this file.
/// The loader (`load_rules_dir`) accumulates lists across files for cross-file
/// references; individual callers (tests, the simple `parse_rules` wrapper) can
/// discard the lists.
struct ParsedFile {
    rules: Vec<CorrelationRule>,
    lists: HashMap<String, Vec<String>>,
}

fn parse_file(
    yaml: &str,
    source: &str,
    external_lists: &HashMap<String, Vec<String>>,
) -> Result<ParsedFile, String> {
    let rf: RuleFile =
        serde_yaml::from_str(yaml).map_err(|e| format!("{source}: YAML parse error: {e}"))?;

    // Merge external lists with this file's lists. First-defined-wins:
    // the external set wins ties (callers pass earlier-file lists in as
    // external; the loader puts 00-builtin.yml's lists in external first).
    let mut effective_lists = external_lists.clone();
    for (k, v) in &rf.lists {
        effective_lists
            .entry(k.clone())
            .or_insert_with(|| v.clone());
    }

    let mut compiled = Vec::new();
    for raw in rf.rules {
        if raw.disabled {
            continue;
        }
        let severity = parse_severity(&raw.severity).ok_or_else(|| {
            format!(
                "{source}: rule {} unknown severity {:?}",
                raw.id, raw.severity
            )
        })?;
        let mut stages = Vec::new();
        for s in raw.stages {
            let layer =
                match s.layer.as_deref() {
                    Some(l) => Some(parse_layer(l).ok_or_else(|| {
                        format!("{source}: rule {} unknown layer {:?}", raw.id, l)
                    })?),
                    None => None,
                };
            let kind_patterns = expand_list_refs(s.kind_patterns, &effective_lists, &raw.id);
            stages.push(RuleStage {
                layer,
                kind_patterns,
                entity_must_match: s.entity_must_match,
            });
        }
        compiled.push(CorrelationRule {
            id: raw.id,
            name: raw.name,
            stages,
            window_secs: raw.window_secs,
            min_confidence: raw.min_confidence,
            severity,
        });
    }
    Ok(ParsedFile {
        rules: compiled,
        lists: rf.lists,
    })
}

// Expands `$name` references in a kind_patterns vec. Unknown lists are kept
// as literal `$name` strings and a WARN is logged so the rule still loads
// (consistent with event_pipeline's behaviour from PR #842).
fn expand_list_refs(
    patterns: Vec<String>,
    lists: &HashMap<String, Vec<String>>,
    rule_id: &str,
) -> Vec<String> {
    let mut out = Vec::with_capacity(patterns.len());
    for p in patterns {
        if let Some(name) = p.strip_prefix('$') {
            match lists.get(name) {
                Some(expanded) => out.extend(expanded.iter().cloned()),
                None => {
                    tracing::warn!(
                        rule = %rule_id,
                        list = %name,
                        "correlation_engine_yaml: unknown list reference ${name} kept as literal"
                    );
                    out.push(p);
                }
            }
        } else {
            out.push(p);
        }
    }
    out
}

fn parse_severity(s: &str) -> Option<Severity> {
    match s.to_ascii_lowercase().as_str() {
        "critical" => Some(Severity::Critical),
        "high" => Some(Severity::High),
        "medium" => Some(Severity::Medium),
        "low" => Some(Severity::Low),
        "info" => Some(Severity::Info),
        "debug" => Some(Severity::Debug),
        _ => None,
    }
}

fn parse_layer(s: &str) -> Option<Layer> {
    match s.to_ascii_lowercase().as_str() {
        "firmware" => Some(Layer::Firmware),
        "hypervisor" => Some(Layer::Hypervisor),
        "kernel" => Some(Layer::Kernel),
        "userspace" => Some(Layer::Userspace),
        "network" => Some(Layer::Network),
        "honeypot" => Some(Layer::Honeypot),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_yaml_parses_to_69_rules() {
        let rules = load_builtin().unwrap();
        assert_eq!(rules.len(), 69, "expected 69 rules, got {}", rules.len());
    }

    #[test]
    fn builtin_yaml_covers_expected_cl_id_set() {
        // After Spec 055 Phase 5 removed the hardcoded `builtin_rules()` literal,
        // the YAML is the single source of truth. This anchor catches accidental
        // rule deletions / renames that the rule-count test alone wouldn't.
        let rules = load_builtin().unwrap();
        let ids: std::collections::HashSet<String> = rules.iter().map(|r| r.id.clone()).collect();
        // Spot-check a handful from each CL-NNN range (CL-001..CL-047 + CL-051..CL-071,
        // gaps at CL-048/49/50). If the YAML drops one of these, the test fails.
        for required in &[
            "CL-001", "CL-008", "CL-010", "CL-024", "CL-041", "CL-043", "CL-047", "CL-051",
            "CL-060", "CL-071",
        ] {
            assert!(
                ids.contains(*required),
                "00-builtin.yml lost CL-rule {required}; this is a YAML edit regression"
            );
        }
    }

    #[test]
    fn rejects_unknown_severity() {
        let yaml = r#"
version: 1
rules:
  - id: "TEST-1"
    name: "test"
    severity: explosion
    window_secs: 300
    min_confidence: 0.7
    stages:
      - kind_patterns: ["foo"]
        entity_must_match: false
"#;
        assert!(parse_rules(yaml, "test").is_err());
    }

    #[test]
    fn disabled_rule_is_skipped() {
        let yaml = r#"
version: 1
rules:
  - id: "TEST-1"
    name: "test"
    severity: high
    window_secs: 300
    min_confidence: 0.7
    disabled: true
    stages:
      - kind_patterns: ["foo"]
        entity_must_match: false
"#;
        let rules = parse_rules(yaml, "test").unwrap();
        assert_eq!(rules.len(), 0);
    }

    // ===== Spec 055 Phase 4: named lists in kind_patterns =====

    #[test]
    fn inline_list_reference_expands_within_file() {
        let yaml = r#"
version: 1
lists:
  recon:
    - port_scan
    - nmap_scan
    - wordlist_scan
rules:
  - id: "TEST-RECON"
    name: "recon test"
    severity: high
    window_secs: 300
    min_confidence: 0.7
    stages:
      - kind_patterns: ["$recon"]
        entity_must_match: false
"#;
        let rules = parse_rules(yaml, "test").unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(
            rules[0].stages[0].kind_patterns,
            vec![
                "port_scan".to_string(),
                "nmap_scan".to_string(),
                "wordlist_scan".to_string(),
            ]
        );
    }

    #[test]
    fn list_reference_and_literal_can_coexist() {
        let yaml = r#"
version: 1
lists:
  exfil:
    - data_exfiltration
    - outbound_anomaly
rules:
  - id: "TEST-MIXED"
    name: "mixed"
    severity: high
    window_secs: 300
    min_confidence: 0.7
    stages:
      - kind_patterns: ["$exfil", "dns_tunneling"]
        entity_must_match: false
"#;
        let rules = parse_rules(yaml, "test").unwrap();
        let kp = &rules[0].stages[0].kind_patterns;
        assert_eq!(
            kp,
            &vec![
                "data_exfiltration".to_string(),
                "outbound_anomaly".to_string(),
                "dns_tunneling".to_string(),
            ],
            "list reference should expand inline preserving order; literal stays put"
        );
    }

    #[test]
    fn unknown_list_reference_kept_as_literal() {
        let yaml = r#"
version: 1
rules:
  - id: "TEST-UNKNOWN"
    name: "unknown list"
    severity: high
    window_secs: 300
    min_confidence: 0.7
    stages:
      - kind_patterns: ["$does_not_exist", "fallback_kind"]
        entity_must_match: false
"#;
        let rules = parse_rules(yaml, "test").unwrap();
        // Unknown $does_not_exist stays as a literal "$does_not_exist" — the
        // agent's matcher will simply never match an event with that literal
        // kind. We log a warn but never crash the load.
        assert_eq!(
            rules[0].stages[0].kind_patterns,
            vec!["$does_not_exist".to_string(), "fallback_kind".to_string()]
        );
    }

    #[test]
    fn builtin_lists_define_the_four_spec_names() {
        // Anchor that spec 055 Phase 4's four named lists exist in 00-builtin.yml
        // so operator-supplied YAML files can reference them without redefining.
        let rf: RuleFile = serde_yaml::from_str(BUILTIN_YAML).unwrap();
        for name in &[
            "exfil_kinds",
            "recon_kinds",
            "persistence_kinds",
            "c2_kinds",
        ] {
            assert!(
                rf.lists.contains_key(*name),
                "00-builtin.yml must define `{name}` for operator-authored rules to reference",
            );
            assert!(
                !rf.lists.get(*name).unwrap().is_empty(),
                "list `{name}` in 00-builtin.yml must not be empty",
            );
        }
    }

    #[test]
    fn external_list_expands_in_operator_file() {
        // Simulates a load_rules_dir flow: operator file references a list
        // defined in 00-builtin.yml (passed in as external_lists), with no
        // local `lists:` section.
        let mut external = HashMap::new();
        external.insert(
            "exfil".to_string(),
            vec!["data_exfiltration".to_string(), "dns_tunneling".to_string()],
        );

        let yaml = r#"
version: 1
rules:
  - id: "OP-1"
    name: "operator rule"
    severity: high
    window_secs: 300
    min_confidence: 0.7
    stages:
      - kind_patterns: ["$exfil"]
        entity_must_match: false
"#;
        let parsed = parse_file(yaml, "10-operator.yml", &external).unwrap();
        assert_eq!(
            parsed.rules[0].stages[0].kind_patterns,
            vec!["data_exfiltration".to_string(), "dns_tunneling".to_string()]
        );
    }

    #[test]
    fn cross_file_list_first_defined_wins() {
        // External (acts as the earlier file's lists) defines `exfil` with 2 items.
        // The current file redefines `exfil` with 99 items. First definition wins,
        // so the rule expands to the external set.
        let mut external = HashMap::new();
        external.insert(
            "exfil".to_string(),
            vec!["original_a".to_string(), "original_b".to_string()],
        );
        let yaml = r#"
version: 1
lists:
  exfil:
    - override_x
    - override_y
    - override_z
rules:
  - id: "OP-2"
    name: "redef"
    severity: high
    window_secs: 300
    min_confidence: 0.7
    stages:
      - kind_patterns: ["$exfil"]
        entity_must_match: false
"#;
        let parsed = parse_file(yaml, "20-operator.yml", &external).unwrap();
        assert_eq!(
            parsed.rules[0].stages[0].kind_patterns,
            vec!["original_a".to_string(), "original_b".to_string()],
            "earlier file's list definition must win"
        );
    }

    #[test]
    fn load_rules_dir_makes_builtin_lists_available_to_disk_files() {
        // End-to-end: operator drops a file that references $exfil_kinds; the
        // 00-builtin.yml lists must be in scope.
        let dir = tempfile::tempdir().unwrap();
        let yaml = r#"
version: 1
rules:
  - id: "CL-OP-001"
    name: "operator exfil chain"
    severity: high
    window_secs: 300
    min_confidence: 0.7
    stages:
      - kind_patterns: ["$exfil_kinds"]
        entity_must_match: false
"#;
        std::fs::write(dir.path().join("50-operator.yml"), yaml).unwrap();
        let rules = load_rules_dir(dir.path()).unwrap();
        let op_rule = rules.iter().find(|r| r.id == "CL-OP-001").unwrap();
        assert!(
            op_rule.stages[0]
                .kind_patterns
                .contains(&"data_exfiltration".to_string()),
            "operator file should see exfil_kinds expanded; got: {:?}",
            op_rule.stages[0].kind_patterns
        );
        assert!(op_rule.stages[0].kind_patterns.len() >= 5);
    }
}
