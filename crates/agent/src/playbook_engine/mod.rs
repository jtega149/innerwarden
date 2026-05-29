//! Spec 056 Phase 1: SOC playbook loader + schema.
//!
//! Operators encode deterministic incident response in YAML files under
//! `/etc/innerwarden/rules/playbooks/`. Each playbook ties triggers (chain
//! id, rule id, kind glob) + optional conditions (asset tag, ip allowlist,
//! sample rate) to an ordered or parallel list of skill calls.
//!
//! Phase 1 ships ONLY the loader + schema + 2 embedded built-ins. The
//! executor (sequential/parallel + retry + on_error + skill_gate
//! integration) lands in Phase 2 — this module deliberately does NOT
//! execute anything yet so the schema can be reviewed against real
//! operator-facing YAML before the runtime contract is locked in.
//!
//! ## Design choices that are not negotiable
//!
//! - `#[serde(deny_unknown_fields)]` on every struct. Operators who typo
//!   `severity_grade` instead of `severity_gte` get a load-time error that
//!   names the bad field; silent skip is the worst UX in YAML config.
//! - All identifiers are newtyped (`PlaybookId`, `StepId`). String confusion
//!   between a playbook id and a step id is a class of bug we avoid by
//!   construction.
//! - Schema validation runs in TWO passes: serde (structural) + a
//!   semantic pass that checks template strings (`{trigger.X}` keys must
//!   be in the allowlist) and id uniqueness. Errors carry the YAML file
//!   name and a 1-line hint.
//! - Lists accumulate across files first-defined-wins (matches
//!   `correlation_engine_yaml` + event_pipeline). Embedded built-ins go
//!   first; operator files in lexicographic order; same `metadata.id`
//!   replaces the previous entry. This is the contract operators already
//!   know from the other four rule types.
//!
//! ## dead_code for the whole module
//!
//! Phase 2 wires `load_dir` into the agent boot path and the executor
//! consumes every type below. Until that lands the module surface is
//! reachable only from the in-file test suite, so the workspace clippy
//! gate would reject the public API. The blanket `allow(dead_code)` at
//! the module level keeps the API discoverable while Phase 2 catches up.
#![allow(dead_code)]

pub mod executor;
mod virtual_skills;

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::time::SystemTime;

use serde::Deserialize;

pub const BUILTIN_DATA_EXFIL: &str = include_str!("builtin/00-data-exfil-default.yml");
pub const BUILTIN_CREDENTIAL_STUFFING: &str =
    include_str!("builtin/00-credential-stuffing-default.yml");

/// All two-tuple `(name, yaml)` pairs of embedded playbooks. CTL reads
/// these directly via `include_str!` across the crate boundary (same
/// pattern as `correlation_engine_yaml` + `event_pipeline`).
pub const BUILTIN_PLAYBOOKS: &[(&str, &str)] = &[
    ("00-data-exfil-default.yml", BUILTIN_DATA_EXFIL),
    (
        "00-credential-stuffing-default.yml",
        BUILTIN_CREDENTIAL_STUFFING,
    ),
];

/// Type-stable wrapper around a playbook id. Catches the class of bug
/// where a step id ends up where a playbook id was expected.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize)]
#[serde(transparent)]
pub struct PlaybookId(pub String);

impl PlaybookId {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize)]
#[serde(transparent)]
pub struct StepId(pub String);

impl StepId {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PlaybookFile {
    #[allow(dead_code)]
    version: u32,
    metadata: PlaybookMetadata,
    triggers: Vec<RawTrigger>,
    #[serde(default)]
    conditions: Option<RawConditions>,
    steps: Vec<RawStep>,
    #[serde(default)]
    disabled: bool,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct PlaybookMetadata {
    pub id: PlaybookId,
    pub name: String,
    #[serde(default)]
    pub description: String,
}

/// Trigger predicate. Operators write exactly ONE of the optional fields
/// per list entry (`- chain_id: "CL-002"`). compile_trigger validates this
/// invariant and surfaces a useful error if the operator forgets or sets
/// two.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTrigger {
    #[serde(default)]
    chain_id: Option<String>,
    #[serde(default)]
    rule_id: Option<String>,
    #[serde(default)]
    kind_glob: Option<String>,
    #[serde(default)]
    severity_gte: Option<String>,
    #[serde(default)]
    entity_type: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConditions {
    #[serde(default)]
    asset_tags: Vec<String>,
    #[serde(default)]
    ip_in: Vec<String>,
    #[serde(default)]
    ip_not_in: Vec<String>,
    #[serde(default)]
    user_in: Vec<String>,
    #[serde(default)]
    user_not_in: Vec<String>,
    #[serde(default = "default_time_window")]
    time_window: String,
    #[serde(default = "default_sample_rate")]
    sample_rate: f32,
}

fn default_time_window() -> String {
    "any".to_string()
}
fn default_sample_rate() -> f32 {
    1.0
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, untagged)]
enum RawStep {
    // Boxed because LeafStep is ~264 bytes (multiple Strings + serde_yaml::Value)
    // and ParallelGroup is ~32 bytes — clippy's large_enum_variant lint would
    // otherwise reserve 264 bytes for every Vec<RawStep> entry, including the
    // overwhelmingly common parallel-group case.
    Leaf(Box<LeafStep>),
    Parallel(ParallelGroup),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeafStep {
    id: StepId,
    skill: String,
    #[serde(default)]
    args: serde_yaml::Value,
    #[serde(default)]
    retry: Option<RawRetry>,
    #[serde(default = "default_on_error")]
    on_error: String,
    #[serde(default = "default_step_timeout")]
    timeout_secs: u64,
    #[serde(default)]
    condition: Option<serde_yaml::Value>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ParallelGroup {
    parallel: bool,
    steps: Vec<RawStep>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
struct RawRetry {
    #[serde(default = "default_retry_count")]
    count: u32,
    #[serde(default = "default_retry_backoff")]
    backoff: String,
    #[serde(default = "default_retry_base_ms")]
    base_ms: u64,
}

fn default_on_error() -> String {
    "abort".to_string()
}
fn default_step_timeout() -> u64 {
    30
}
fn default_retry_count() -> u32 {
    0
}
fn default_retry_backoff() -> String {
    "linear".to_string()
}
fn default_retry_base_ms() -> u64 {
    100
}

// ---------------------------------------------------------------------------
// Compiled (validated) form. Public API surface for Phase 2's executor.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct Playbook {
    pub metadata: PlaybookMetadata,
    pub triggers: Vec<Trigger>,
    pub conditions: Conditions,
    pub steps: Vec<Step>,
    pub disabled: bool,
    pub source_file: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Trigger {
    ChainId(String),
    RuleId(String),
    KindGlob(String),
    SeverityGte(Severity),
    EntityType(EntityType),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntityType {
    Ip,
    User,
    Container,
    Pid,
    File,
}

#[derive(Debug, Clone, Default)]
pub struct Conditions {
    pub asset_tags: Vec<String>,
    pub ip_in: Vec<String>,
    pub ip_not_in: Vec<String>,
    pub user_in: Vec<String>,
    pub user_not_in: Vec<String>,
    pub time_window: TimeWindow,
    pub sample_rate: f32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TimeWindow {
    #[default]
    Any,
    BusinessHours,
    AfterHours,
}

#[derive(Debug, Clone)]
pub enum Step {
    Leaf(LeafStepCompiled),
    Parallel(Vec<Step>),
}

#[derive(Debug, Clone)]
pub struct LeafStepCompiled {
    pub id: StepId,
    pub skill: String,
    pub args: serde_yaml::Value,
    pub retry: Retry,
    pub on_error: OnError,
    pub timeout_secs: u64,
    pub condition: Option<serde_yaml::Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnError {
    Continue,
    Abort,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Retry {
    pub count: u32,
    pub backoff: Backoff,
    pub base_ms: u64,
}

impl Default for Retry {
    fn default() -> Self {
        Self {
            count: 0,
            backoff: Backoff::Linear,
            base_ms: 100,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backoff {
    Linear,
    Exponential,
}

// ---------------------------------------------------------------------------
// Loader
// ---------------------------------------------------------------------------

/// Errors carry the source file name + a 1-line operator-friendly hint.
/// This is the only error type the caller sees; internal serde errors are
/// wrapped with file context before reaching here.
#[derive(Debug, Clone)]
pub struct LoadError {
    pub file: String,
    pub message: String,
}

impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.file, self.message)
    }
}

impl std::error::Error for LoadError {}

/// Load every embedded built-in. Production callers invoke this at boot
/// and then layer operator files via `load_dir`.
pub fn load_builtins() -> Result<Vec<Playbook>, LoadError> {
    let mut out = Vec::with_capacity(BUILTIN_PLAYBOOKS.len());
    for (name, yaml) in BUILTIN_PLAYBOOKS {
        let pb = parse_one(yaml, name)?;
        out.push(pb);
    }
    Ok(out)
}

/// Load embedded built-ins + every `.yml` / `.yaml` file in `dir`. Files
/// are merged in lexicographic order; same `metadata.id` replaces the
/// previous entry. Embedded built-ins are loaded first so operator files
/// with the same id win.
pub fn load_dir(dir: &Path) -> Result<Vec<Playbook>, LoadError> {
    let mut by_id: HashMap<PlaybookId, Playbook> = HashMap::new();
    let mut order: Vec<PlaybookId> = Vec::new();

    for pb in load_builtins()? {
        let id = pb.metadata.id.clone();
        if !by_id.contains_key(&id) {
            order.push(id.clone());
        }
        by_id.insert(id, pb);
    }

    if dir.is_dir() {
        let mut entries: Vec<_> = std::fs::read_dir(dir)
            .map_err(|e| LoadError {
                file: dir.display().to_string(),
                message: format!("read_dir failed: {e}"),
            })?
            .filter_map(|e| e.ok())
            .filter(|e| {
                let n = e.file_name();
                let s = n.to_string_lossy();
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
            let yaml = std::fs::read_to_string(&path).map_err(|e| LoadError {
                file: name.clone(),
                message: format!("read error: {e}"),
            })?;
            let pb = parse_one(&yaml, &name)?;
            let id = pb.metadata.id.clone();
            if !by_id.contains_key(&id) {
                order.push(id.clone());
            }
            by_id.insert(id, pb);
        }
    }

    Ok(order
        .into_iter()
        .filter_map(|id| by_id.remove(&id))
        .collect())
}

/// Compute the max mtime of YAML files in `dir`. Phase 2's reload loop
/// uses this to skip re-parsing when nothing changed.
#[allow(dead_code)]
pub fn dir_max_mtime(dir: &Path) -> Option<SystemTime> {
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

// ---------------------------------------------------------------------------
// Parsing + semantic validation
// ---------------------------------------------------------------------------

fn parse_one(yaml: &str, source: &str) -> Result<Playbook, LoadError> {
    let file: PlaybookFile = serde_yaml::from_str(yaml).map_err(|e| LoadError {
        file: source.to_string(),
        message: format!("YAML parse error: {e}"),
    })?;

    if file.version != 1 {
        return Err(LoadError {
            file: source.to_string(),
            message: format!("unsupported version {} (only 1 is supported)", file.version),
        });
    }

    if file.triggers.is_empty() {
        return Err(LoadError {
            file: source.to_string(),
            message: "playbook must declare at least one trigger".to_string(),
        });
    }

    let triggers = file
        .triggers
        .into_iter()
        .map(|t| compile_trigger(t, source))
        .collect::<Result<Vec<_>, _>>()?;

    let conditions = match file.conditions {
        Some(c) => compile_conditions(c, source)?,
        None => Conditions {
            sample_rate: 1.0,
            ..Default::default()
        },
    };

    let steps = compile_steps(file.steps, source)?;

    enforce_unique_step_ids(&steps, source)?;
    validate_templates(&steps, source)?;

    Ok(Playbook {
        metadata: file.metadata,
        triggers,
        conditions,
        steps,
        disabled: file.disabled,
        source_file: source.to_string(),
    })
}

fn compile_trigger(raw: RawTrigger, source: &str) -> Result<Trigger, LoadError> {
    let set_count = [
        raw.chain_id.is_some(),
        raw.rule_id.is_some(),
        raw.kind_glob.is_some(),
        raw.severity_gte.is_some(),
        raw.entity_type.is_some(),
    ]
    .iter()
    .filter(|b| **b)
    .count();
    if set_count != 1 {
        return Err(LoadError {
            file: source.to_string(),
            message: format!(
                "each trigger entry must set EXACTLY ONE of chain_id, rule_id, kind_glob, \
                 severity_gte, entity_type; got {set_count}"
            ),
        });
    }
    if let Some(s) = raw.chain_id {
        return Ok(Trigger::ChainId(s));
    }
    if let Some(s) = raw.rule_id {
        return Ok(Trigger::RuleId(s));
    }
    if let Some(s) = raw.kind_glob {
        return Ok(Trigger::KindGlob(s));
    }
    if let Some(s) = raw.severity_gte {
        return Ok(Trigger::SeverityGte(parse_severity(&s).ok_or_else(
            || LoadError {
                file: source.to_string(),
                message: format!(
                    "trigger.severity_gte must be one of info/low/medium/high/critical; got {s:?}"
                ),
            },
        )?));
    }
    if let Some(s) = raw.entity_type {
        return Ok(Trigger::EntityType(parse_entity_type(&s).ok_or_else(
            || LoadError {
                file: source.to_string(),
                message: format!(
                    "trigger.entity_type must be one of ip/user/container/pid/file; got {s:?}"
                ),
            },
        )?));
    }
    // set_count == 1 invariant above makes this unreachable.
    unreachable!()
}

fn parse_severity(s: &str) -> Option<Severity> {
    match s.to_ascii_lowercase().as_str() {
        "info" => Some(Severity::Info),
        "low" => Some(Severity::Low),
        "medium" => Some(Severity::Medium),
        "high" => Some(Severity::High),
        "critical" => Some(Severity::Critical),
        _ => None,
    }
}

fn parse_entity_type(s: &str) -> Option<EntityType> {
    match s.to_ascii_lowercase().as_str() {
        "ip" => Some(EntityType::Ip),
        "user" => Some(EntityType::User),
        "container" => Some(EntityType::Container),
        "pid" => Some(EntityType::Pid),
        "file" => Some(EntityType::File),
        _ => None,
    }
}

fn compile_conditions(raw: RawConditions, source: &str) -> Result<Conditions, LoadError> {
    if !(0.0..=1.0).contains(&raw.sample_rate) {
        return Err(LoadError {
            file: source.to_string(),
            message: format!(
                "conditions.sample_rate must be in [0.0, 1.0]; got {}",
                raw.sample_rate
            ),
        });
    }
    let time_window = match raw.time_window.as_str() {
        "any" => TimeWindow::Any,
        "business_hours" => TimeWindow::BusinessHours,
        "after_hours" => TimeWindow::AfterHours,
        other => {
            return Err(LoadError {
                file: source.to_string(),
                message: format!(
                    "conditions.time_window must be any/business_hours/after_hours; got {other:?}"
                ),
            })
        }
    };
    Ok(Conditions {
        asset_tags: raw.asset_tags,
        ip_in: raw.ip_in,
        ip_not_in: raw.ip_not_in,
        user_in: raw.user_in,
        user_not_in: raw.user_not_in,
        time_window,
        sample_rate: raw.sample_rate,
    })
}

fn compile_steps(raw: Vec<RawStep>, source: &str) -> Result<Vec<Step>, LoadError> {
    raw.into_iter()
        .map(|s| compile_step(s, source))
        .collect::<Result<Vec<_>, _>>()
}

fn compile_step(raw: RawStep, source: &str) -> Result<Step, LoadError> {
    match raw {
        RawStep::Leaf(l) => {
            // Box -> LeafStep so we can move fields out below.
            let l = *l;
            let on_error = match l.on_error.as_str() {
                "continue" => OnError::Continue,
                "abort" => OnError::Abort,
                other => {
                    return Err(LoadError {
                        file: source.to_string(),
                        message: format!(
                            "step {}.on_error must be continue/abort; got {other:?}",
                            l.id.as_str()
                        ),
                    })
                }
            };
            let retry = match l.retry {
                None => Retry::default(),
                Some(r) => {
                    if r.count > 10 {
                        return Err(LoadError {
                            file: source.to_string(),
                            message: format!(
                                "step {}.retry.count is hard-capped at 10 to prevent infinite \
                                 loops; got {}",
                                l.id.as_str(),
                                r.count
                            ),
                        });
                    }
                    let backoff = match r.backoff.as_str() {
                        "linear" => Backoff::Linear,
                        "exponential" => Backoff::Exponential,
                        other => {
                            return Err(LoadError {
                                file: source.to_string(),
                                message: format!(
                                    "step {}.retry.backoff must be linear/exponential; got \
                                     {other:?}",
                                    l.id.as_str()
                                ),
                            })
                        }
                    };
                    Retry {
                        count: r.count,
                        backoff,
                        base_ms: r.base_ms,
                    }
                }
            };
            Ok(Step::Leaf(LeafStepCompiled {
                id: l.id,
                skill: l.skill,
                args: l.args,
                retry,
                on_error,
                timeout_secs: l.timeout_secs,
                condition: l.condition,
            }))
        }
        RawStep::Parallel(g) => {
            if !g.parallel {
                return Err(LoadError {
                    file: source.to_string(),
                    message: "parallel group must set `parallel: true` explicitly".to_string(),
                });
            }
            if g.steps.is_empty() {
                return Err(LoadError {
                    file: source.to_string(),
                    message: "parallel group must contain at least one step".to_string(),
                });
            }
            Ok(Step::Parallel(compile_steps(g.steps, source)?))
        }
    }
}

fn enforce_unique_step_ids(steps: &[Step], source: &str) -> Result<(), LoadError> {
    let mut seen = HashSet::new();
    walk_step_ids(steps, &mut |id| {
        if !seen.insert(id.clone()) {
            Some(LoadError {
                file: source.to_string(),
                message: format!("step id {} is declared more than once", id.as_str()),
            })
        } else {
            None
        }
    })
}

fn walk_step_ids(
    steps: &[Step],
    visit: &mut dyn FnMut(&StepId) -> Option<LoadError>,
) -> Result<(), LoadError> {
    for s in steps {
        match s {
            Step::Leaf(l) => {
                if let Some(e) = visit(&l.id) {
                    return Err(e);
                }
            }
            Step::Parallel(inner) => walk_step_ids(inner, visit)?,
        }
    }
    Ok(())
}

/// Validates that every `{trigger.X}` / `{prev.<id>.X}` template in step
/// args references a known key. Catches `{trigger.ipp}` typos at load
/// time instead of at first incident.
fn validate_templates(steps: &[Step], source: &str) -> Result<(), LoadError> {
    let allowed_trigger_keys: HashSet<&'static str> = [
        "rule_id",
        "chain_id",
        "chain_name",
        "primary_ip",
        "primary_user",
        "target_user",
        "severity",
        "ts",
        "geo_country",
        "evidence_count",
    ]
    .into_iter()
    .collect();

    let mut step_ids: HashSet<String> = HashSet::new();
    walk_step_ids(steps, &mut |id| {
        step_ids.insert(id.as_str().to_string());
        None
    })?;

    walk_leaves(steps, &mut |leaf| {
        let yaml_text = serde_yaml::to_string(&leaf.args).unwrap_or_default();
        for token in extract_template_tokens(&yaml_text) {
            if let Some(rest) = token.strip_prefix("trigger.") {
                if !allowed_trigger_keys.contains(rest) {
                    return Some(LoadError {
                        file: source.to_string(),
                        message: format!(
                            "step {} references unknown trigger key {{trigger.{}}}; allowed: {}",
                            leaf.id.as_str(),
                            rest,
                            allowed_trigger_keys
                                .iter()
                                .copied()
                                .collect::<Vec<_>>()
                                .join(", ")
                        ),
                    });
                }
            } else if let Some(rest) = token.strip_prefix("prev.") {
                let step_part = rest.split('.').next().unwrap_or("");
                if !step_ids.contains(step_part) {
                    return Some(LoadError {
                        file: source.to_string(),
                        message: format!(
                            "step {} references unknown prev step {{prev.{}.*}}; declared step \
                             ids: {}",
                            leaf.id.as_str(),
                            step_part,
                            step_ids.iter().cloned().collect::<Vec<_>>().join(", ")
                        ),
                    });
                }
            } else if token.starts_with("env:") {
                // ${env:VAR} is resolved at execution time; nothing to validate at load.
            } else {
                return Some(LoadError {
                    file: source.to_string(),
                    message: format!(
                        "step {} references unknown template namespace {{{}}}; allowed \
                         namespaces: trigger, prev, env",
                        leaf.id.as_str(),
                        token
                    ),
                });
            }
        }
        None
    })
}

fn walk_leaves(
    steps: &[Step],
    visit: &mut dyn FnMut(&LeafStepCompiled) -> Option<LoadError>,
) -> Result<(), LoadError> {
    for s in steps {
        match s {
            Step::Leaf(l) => {
                if let Some(e) = visit(l) {
                    return Err(e);
                }
            }
            Step::Parallel(inner) => walk_leaves(inner, visit)?,
        }
    }
    Ok(())
}

/// Pulls out tokens that look like `{namespace.path}`. Tolerates other `{`
/// uses in args (e.g., shell templates the operator wrote intentionally —
/// we'd false-positive on `{foo}` if we expanded the namespace list later;
/// for now anything inside `{...}` must be a known namespace).
fn extract_template_tokens(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut chars = text.char_indices().peekable();
    while let Some((i, c)) = chars.next() {
        if c == '{' {
            // Skip "${env:..." which uses a different delimiter form.
            if i > 0 && text.as_bytes()[i - 1] == b'$' {
                let mut depth = 1;
                let mut end = i + 1;
                for (j, cc) in chars.by_ref() {
                    if cc == '}' {
                        depth -= 1;
                        if depth == 0 {
                            end = j;
                            break;
                        }
                    } else if cc == '{' {
                        depth += 1;
                    }
                }
                out.push(text[i + 1..end].to_string());
                continue;
            }
            let mut end = i + 1;
            for (j, cc) in chars.by_ref() {
                if cc == '}' {
                    end = j;
                    break;
                }
            }
            if end > i + 1 {
                let token = &text[i + 1..end];
                // Skip bare numbers (YAML may have flow `{0, 1}` somewhere) and
                // tokens lacking a dot (which can't be a namespace ref).
                if token.contains('.') {
                    out.push(token.to_string());
                }
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(yaml: &str) -> Result<Playbook, LoadError> {
        parse_one(yaml, "test.yml")
    }

    // ===== Built-ins ship and validate =====

    #[test]
    fn builtin_data_exfil_parses_cleanly() {
        let pb = parse(BUILTIN_DATA_EXFIL).expect("data-exfil built-in must parse");
        assert_eq!(pb.metadata.id.as_str(), "pb-data-exfil-default");
        // 4 steps: tarpit, page_oncall, snapshot_pcap, open_jira_ticket
        assert_eq!(pb.steps.len(), 4);
        // Triggers cover both CL-IDs + the kind glob.
        assert!(matches!(pb.triggers[0], Trigger::ChainId(ref s) if s == "CL-002"));
        assert!(matches!(pb.triggers[1], Trigger::ChainId(ref s) if s == "CL-008"));
        assert!(matches!(pb.triggers[2], Trigger::KindGlob(_)));
    }

    #[test]
    fn builtin_credential_stuffing_parses_cleanly() {
        let pb = parse(BUILTIN_CREDENTIAL_STUFFING).expect("credential stuffing built-in");
        assert_eq!(pb.metadata.id.as_str(), "pb-credential-stuffing-default");
        assert_eq!(pb.steps.len(), 3);
    }

    #[test]
    fn load_builtins_returns_two() {
        let pbs = load_builtins().expect("load_builtins");
        assert_eq!(pbs.len(), 2);
        assert!(pbs
            .iter()
            .any(|p| p.metadata.id.as_str() == "pb-data-exfil-default"));
        assert!(pbs
            .iter()
            .any(|p| p.metadata.id.as_str() == "pb-credential-stuffing-default"));
    }

    #[test]
    fn trigger_with_no_fields_set_is_rejected() {
        // Operator forgot to write the trigger field; we surface that
        // immediately instead of skipping the entry silently.
        let yaml = r#"
version: 1
metadata: {id: pb-empty-trig, name: x}
triggers:
  - {}
steps:
  - id: a
    skill: wait
    args: {ms: 1}
"#;
        let err = parse(yaml).unwrap_err();
        assert!(err.message.contains("EXACTLY ONE"), "got: {}", err.message);
    }

    #[test]
    fn trigger_with_two_fields_set_is_rejected() {
        // The serde model accepts both; compile_trigger catches the
        // contradiction. This matches Sigma single-discriminant
        // semantics and keeps the matcher fast.
        let yaml = r#"
version: 1
metadata: {id: pb-double-trig, name: x}
triggers:
  - chain_id: "CL-002"
    rule_id: ssh_bruteforce
steps:
  - id: a
    skill: wait
    args: {ms: 1}
"#;
        let err = parse(yaml).unwrap_err();
        assert!(err.message.contains("EXACTLY ONE"), "got: {}", err.message);
    }

    // ===== Schema errors are operator-friendly =====

    #[test]
    fn missing_triggers_is_a_named_error() {
        let yaml = r#"
version: 1
metadata: {id: pb-empty, name: empty}
triggers: []
steps:
  - id: noop
    skill: wait
    args: {ms: 1}
"#;
        let err = parse(yaml).unwrap_err();
        assert!(
            err.message.contains("at least one trigger"),
            "got: {}",
            err.message
        );
    }

    #[test]
    fn unknown_field_in_metadata_is_rejected_at_parse_time() {
        // Operator typed `descriptionn` instead of `description`. The whole
        // playbook gets rejected with the field name — far better than the
        // typo being silently ignored.
        let yaml = r#"
version: 1
metadata:
  id: pb-typo
  name: oops
  descriptionn: "typo"
triggers:
  - chain_id: "CL-002"
steps:
  - id: a
    skill: wait
    args: {ms: 1}
"#;
        let err = parse(yaml).unwrap_err();
        assert!(
            err.message.contains("descriptionn") || err.message.contains("unknown field"),
            "got: {}",
            err.message
        );
    }

    #[test]
    fn unknown_severity_in_trigger_names_the_bad_value() {
        let yaml = r#"
version: 1
metadata: {id: pb-bad-sev, name: x}
triggers:
  - severity_gte: nuclear
steps:
  - id: a
    skill: wait
    args: {ms: 1}
"#;
        let err = parse(yaml).unwrap_err();
        assert!(err.message.contains("nuclear"), "got: {}", err.message);
    }

    #[test]
    fn sample_rate_out_of_range_is_rejected() {
        let yaml = r#"
version: 1
metadata: {id: pb-bad-rate, name: x}
triggers:
  - chain_id: "CL-002"
conditions:
  sample_rate: 1.5
steps:
  - id: a
    skill: wait
    args: {ms: 1}
"#;
        let err = parse(yaml).unwrap_err();
        assert!(err.message.contains("sample_rate"), "got: {}", err.message);
    }

    #[test]
    fn retry_count_over_ten_is_capped() {
        let yaml = r#"
version: 1
metadata: {id: pb-loop, name: x}
triggers:
  - chain_id: "CL-002"
steps:
  - id: a
    skill: wait
    args: {ms: 1}
    retry:
      count: 100
      backoff: linear
"#;
        let err = parse(yaml).unwrap_err();
        assert!(err.message.contains("hard-capped"), "got: {}", err.message);
    }

    // ===== Template validator catches typos at load time =====

    #[test]
    fn unknown_trigger_key_in_template_is_rejected() {
        let yaml = r#"
version: 1
metadata: {id: pb-bad-tpl, name: x}
triggers:
  - chain_id: "CL-002"
steps:
  - id: a
    skill: route_alert
    args:
      target: "{trigger.ipp}"
"#;
        let err = parse(yaml).unwrap_err();
        assert!(err.message.contains("ipp"), "got: {}", err.message);
        assert!(
            err.message.contains("primary_ip"),
            "should name allowed keys"
        );
    }

    #[test]
    fn unknown_prev_step_reference_is_rejected() {
        let yaml = r#"
version: 1
metadata: {id: pb-bad-prev, name: x}
triggers:
  - chain_id: "CL-002"
steps:
  - id: a
    skill: wait
    args: {ms: 1}
  - id: b
    skill: route_alert
    args:
      target: "{prev.aa.result}"
"#;
        let err = parse(yaml).unwrap_err();
        assert!(err.message.contains("aa"), "got: {}", err.message);
    }

    #[test]
    fn env_template_is_accepted() {
        let yaml = r#"
version: 1
metadata: {id: pb-env, name: x}
triggers:
  - chain_id: "CL-002"
steps:
  - id: a
    skill: open_ticket
    args:
      auth: "${env:JIRA_TOKEN}"
      title: "{trigger.chain_name} via {trigger.primary_ip}"
"#;
        let pb = parse(yaml).expect("env templates are valid");
        assert_eq!(pb.steps.len(), 1);
    }

    // ===== Parallel groups =====

    #[test]
    fn parallel_group_compiles() {
        let yaml = r#"
version: 1
metadata: {id: pb-par, name: x}
triggers:
  - chain_id: "CL-002"
steps:
  - parallel: true
    steps:
      - id: a
        skill: wait
        args: {ms: 1}
      - id: b
        skill: wait
        args: {ms: 2}
"#;
        let pb = parse(yaml).expect("parallel valid");
        assert_eq!(pb.steps.len(), 1);
        match &pb.steps[0] {
            Step::Parallel(inner) => assert_eq!(inner.len(), 2),
            _ => panic!("expected parallel group"),
        }
    }

    #[test]
    fn empty_parallel_group_is_rejected() {
        let yaml = r#"
version: 1
metadata: {id: pb-empty-par, name: x}
triggers:
  - chain_id: "CL-002"
steps:
  - parallel: true
    steps: []
"#;
        let err = parse(yaml).unwrap_err();
        assert!(
            err.message.contains("at least one step"),
            "got: {}",
            err.message
        );
    }

    // ===== Duplicate step ids =====

    #[test]
    fn duplicate_step_ids_across_top_level_are_rejected() {
        let yaml = r#"
version: 1
metadata: {id: pb-dup, name: x}
triggers:
  - chain_id: "CL-002"
steps:
  - id: a
    skill: wait
    args: {ms: 1}
  - id: a
    skill: wait
    args: {ms: 2}
"#;
        let err = parse(yaml).unwrap_err();
        assert!(
            err.message.contains("declared more than once"),
            "got: {}",
            err.message
        );
    }

    #[test]
    fn duplicate_step_ids_inside_parallel_are_rejected() {
        let yaml = r#"
version: 1
metadata: {id: pb-dup-par, name: x}
triggers:
  - chain_id: "CL-002"
steps:
  - id: outer
    skill: wait
    args: {ms: 1}
  - parallel: true
    steps:
      - id: outer
        skill: wait
        args: {ms: 1}
      - id: inner
        skill: wait
        args: {ms: 1}
"#;
        let err = parse(yaml).unwrap_err();
        assert!(
            err.message.contains("declared more than once"),
            "got: {}",
            err.message
        );
    }

    // ===== Cross-file: override-by-id + builtin precedence =====

    #[test]
    fn load_dir_with_no_dir_returns_only_builtins() {
        let bogus = std::path::PathBuf::from("/tmp/iw-playbook-no-such-dir-xyz-12345");
        let pbs = load_dir(&bogus).expect("missing dir is not an error");
        assert_eq!(pbs.len(), 2);
    }

    #[test]
    fn load_dir_override_by_id_keeps_builtin_count_stable() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let yaml = r#"
version: 1
metadata:
  id: pb-data-exfil-default
  name: "Operator override"
triggers:
  - chain_id: "CL-002"
steps:
  - id: noop
    skill: wait
    args: {ms: 1}
"#;
        std::fs::write(tmp.path().join("10-override.yml"), yaml).expect("write");
        let pbs = load_dir(tmp.path()).expect("load");
        assert_eq!(pbs.len(), 2, "override must not change the playbook count");
        let exfil = pbs
            .iter()
            .find(|p| p.metadata.id.as_str() == "pb-data-exfil-default")
            .expect("override present");
        assert_eq!(exfil.metadata.name, "Operator override");
        assert_eq!(
            exfil.steps.len(),
            1,
            "operator override carries the operator's steps"
        );
    }

    #[test]
    fn load_dir_new_id_is_appended() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let yaml = r#"
version: 1
metadata:
  id: pb-operator-custom
  name: "Operator custom"
triggers:
  - chain_id: "CL-003"
steps:
  - id: noop
    skill: wait
    args: {ms: 1}
"#;
        std::fs::write(tmp.path().join("20-custom.yml"), yaml).expect("write");
        let pbs = load_dir(tmp.path()).expect("load");
        assert_eq!(pbs.len(), 3);
        assert!(pbs
            .iter()
            .any(|p| p.metadata.id.as_str() == "pb-operator-custom"));
    }
}
