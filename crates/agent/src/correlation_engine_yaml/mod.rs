//! YAML loader for correlation rules.
//!
//! Spec 055 Phase 1: load `Vec<CorrelationRule>` from YAML files instead of
//! hardcoded Rust literals. Produces byte-for-byte identical rule sets.
//!
//! Phase 1 establishes the anchor: YAML output matches hardcoded byte-for-byte.
//! Phase 2 wires this into runtime via `CorrelationEngine::from_yaml_dir()`
//! and hot-reload via mtime tracking. Phases 3-5 add CLI integration, named
//! lists, and finally remove the hardcoded literals.

use serde::Deserialize;

use crate::correlation_engine::{CorrelationRule, Layer, RuleStage};
use innerwarden_core::event::Severity;

pub const BUILTIN_YAML: &str = include_str!("builtin/00-builtin.yml");

#[derive(Debug, Deserialize)]
struct RuleFile {
    #[allow(dead_code)]
    version: u32,
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

pub fn load_builtin() -> Result<Vec<CorrelationRule>, String> {
    parse_rules(BUILTIN_YAML, "00-builtin.yml")
}

/// Load all correlation rules from a directory + the embedded built-in.
/// Built-in rules are always loaded first. On-disk rules with the same
/// `id` override the built-in; new ids are added. Files are read in
/// lexicographic order.
pub fn load_rules_dir(dir: &std::path::Path) -> Result<Vec<CorrelationRule>, String> {
    use std::collections::HashMap;

    let mut by_id: HashMap<String, CorrelationRule> = HashMap::new();

    // Always load built-in first
    for rule in load_builtin()? {
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
                Ok(yaml) => match parse_rules(&yaml, &name) {
                    Ok(rules) => {
                        for rule in rules {
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

pub fn parse_rules(yaml: &str, source: &str) -> Result<Vec<CorrelationRule>, String> {
    let rf: RuleFile =
        serde_yaml::from_str(yaml).map_err(|e| format!("{source}: YAML parse error: {e}"))?;

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
            stages.push(RuleStage {
                layer,
                kind_patterns: s.kind_patterns,
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
    Ok(compiled)
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
    use crate::correlation_engine::builtin_rules_for_test;

    #[test]
    fn builtin_yaml_parses_to_68_rules() {
        let rules = load_builtin().unwrap();
        assert_eq!(rules.len(), 68, "expected 68 rules, got {}", rules.len());
    }

    #[test]
    fn yaml_rules_match_hardcoded_byte_for_byte() {
        let yaml_rules = load_builtin().unwrap();
        let hardcoded = builtin_rules_for_test();

        assert_eq!(
            yaml_rules.len(),
            hardcoded.len(),
            "rule count mismatch: yaml={} hardcoded={}",
            yaml_rules.len(),
            hardcoded.len()
        );

        for (y, h) in yaml_rules.iter().zip(hardcoded.iter()) {
            assert_eq!(y.id, h.id, "id mismatch at {}", y.id);
            assert_eq!(y.name, h.name, "name mismatch at {}", y.id);
            assert_eq!(y.window_secs, h.window_secs, "window_secs at {}", y.id);
            assert!(
                (y.min_confidence - h.min_confidence).abs() < f32::EPSILON,
                "min_confidence at {}: yaml={} hardcoded={}",
                y.id,
                y.min_confidence,
                h.min_confidence
            );
            assert_eq!(
                format!("{:?}", y.severity),
                format!("{:?}", h.severity),
                "severity at {}",
                y.id
            );
            assert_eq!(y.stages.len(), h.stages.len(), "stage count at {}", y.id);
            for (i, (ys, hs)) in y.stages.iter().zip(h.stages.iter()).enumerate() {
                assert_eq!(
                    format!("{:?}", ys.layer),
                    format!("{:?}", hs.layer),
                    "layer at {} stage {}",
                    y.id,
                    i
                );
                assert_eq!(
                    ys.kind_patterns, hs.kind_patterns,
                    "kind_patterns at {} stage {}",
                    y.id, i
                );
                assert_eq!(
                    ys.entity_must_match, hs.entity_must_match,
                    "entity_must_match at {} stage {}",
                    y.id, i
                );
            }
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
}
