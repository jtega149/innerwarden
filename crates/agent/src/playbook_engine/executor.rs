//! Spec 056 Phase 2: playbook executor + skill_gate integration + audit trail.
//!
//! Phase 1 ([`super`]) shipped the loader + schema. This module turns a
//! validated [`Playbook`] into actions when an incident matches its
//! triggers + conditions.
//!
//! ## Execution contract
//!
//! - **Sequential by default**, with `parallel: true` groups run
//!   concurrently via [`futures::future::join_all`]. A group is a barrier:
//!   the playbook does not advance past it until every child has reached a
//!   terminal state (success / failure / refusal / skip).
//! - **Retry + backoff** is owned by the executor core, not the skill. Only
//!   a hard [`StepStatus::Failed`] is retried — a gate [`StepStatus::Refused`]
//!   or a Phase-3 [`StepStatus::Deferred`] never retries (retrying a refused
//!   block-ip would just re-log the refusal).
//! - **`on_error`**: `abort` stops the playbook after the failing step;
//!   `continue` records the failure and moves on.
//! - **skill_gate floor**: every `block_ip_*` skill mints a
//!   [`crate::skill_gate::GatedBlockIp`] token before the firewall backend
//!   is touched. A declarative playbook cannot bypass the cloud-safelist +
//!   operator-trusted-IP safety floor any more than the AI decision path can
//!   (spec §6 "Hard rule").
//! - **Audit**: every step result lands in BOTH `decisions.jsonl` (via the
//!   hash-chained [`crate::decisions::append_chained`]) AND a dedicated
//!   `playbook_steps-<date>.jsonl`.
//!
//! Virtual skills wrap existing agent capabilities behind a uniform skill
//! surface (see [`super::virtual_skills`]). Phase 3a implements the four
//! that need nothing beyond what [`RegistryStepExecutor`] already carries
//! (`wait`, `emit_metric`, `block_subnet`, `open_ticket`). The three that
//! need `&mut AgentState` subsystems (`route_alert`, `capture_pcap`,
//! `set_tag`) still return [`StepStatus::Deferred`] until Phase 3b.

use std::collections::HashMap;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;
use sha2::{Digest, Sha256};
use tracing::{info, warn};

use innerwarden_core::entities::EntityType as CoreEntityType;
use innerwarden_core::event::Severity as CoreSeverity;
use innerwarden_core::incident::Incident;

use super::{
    Conditions, EntityType, LeafStepCompiled, OnError, Playbook, Severity, Step, TimeWindow,
    Trigger,
};
use crate::{ai, allowlist, cloud_safelist, decisions, skill_gate, skills};

// ---------------------------------------------------------------------------
// Outcome types (consumed by the AI router in Phase 4 as context)
// ---------------------------------------------------------------------------

/// Terminal state of a single playbook step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StepStatus {
    /// Skill ran and reported success.
    Success,
    /// Skill ran and reported failure (the only retriable status).
    Failed,
    /// `block_ip_*` skill_gate refused the target (trusted IP / cloud
    /// safelist / invalid). The firewall backend was never touched.
    Refused,
    /// The step's post-trigger `condition` evaluated false.
    Skipped,
    /// Virtual skill not implemented until Phase 3.
    Deferred,
}

impl StepStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            StepStatus::Success => "success",
            StepStatus::Failed => "failed",
            StepStatus::Refused => "refused",
            StepStatus::Skipped => "skipped",
            StepStatus::Deferred => "deferred",
        }
    }

    fn is_retriable(self) -> bool {
        matches!(self, StepStatus::Failed)
    }

    fn is_terminal_failure(self) -> bool {
        matches!(self, StepStatus::Failed)
    }
}

/// Outcome of one step (after retries are exhausted).
#[derive(Debug, Clone, Serialize)]
pub struct StepOutcome {
    pub step_id: String,
    pub skill: String,
    pub status: StepStatus,
    /// Number of dispatch attempts. `0` means the step was skipped before
    /// any dispatch (condition not met).
    pub attempts: u32,
    pub message: String,
}

/// Outcome of a whole playbook run.
#[derive(Debug, Clone, Serialize)]
pub struct PlaybookOutcome {
    pub playbook_id: String,
    pub steps: Vec<StepOutcome>,
    /// `true` if an `on_error: abort` step failed and halted the run.
    pub aborted: bool,
}

impl PlaybookOutcome {
    /// One-line summary the AI router consumes as context in Phase 4.
    pub fn summary(&self) -> String {
        let count = |st: StepStatus| self.steps.iter().filter(|s| s.status == st).count();
        let parts: Vec<String> = [
            ("success", StepStatus::Success),
            ("failed", StepStatus::Failed),
            ("refused", StepStatus::Refused),
            ("skipped", StepStatus::Skipped),
            ("deferred", StepStatus::Deferred),
        ]
        .iter()
        .filter_map(|(label, st)| {
            let n = count(*st);
            (n > 0).then(|| format!("{n} {label}"))
        })
        .collect();
        format!(
            "playbook {}{}: {}",
            self.playbook_id,
            if self.aborted { " (aborted)" } else { "" },
            parts.join(", ")
        )
    }
}

// ---------------------------------------------------------------------------
// Step dispatch abstraction (so tests can mock skills)
// ---------------------------------------------------------------------------

/// Raw result of dispatching a single skill invocation. The executor core
/// wraps this with retry / on_error / audit.
#[derive(Debug, Clone)]
pub struct StepRunResult {
    pub status: StepStatus,
    pub message: String,
}

/// A single resolved skill invocation handed to a [`StepExecutor`].
pub struct DispatchCall<'a> {
    pub skill: &'a str,
    /// Args after `{trigger.X}` / `{prev.id.field}` interpolation.
    pub args: &'a serde_yaml::Value,
    pub primary_ip: Option<&'a str>,
    pub primary_user: Option<&'a str>,
}

/// Dispatches one leaf skill. Implementors do NOT own retry/backoff — the
/// executor core does. The production impl is [`RegistryStepExecutor`];
/// tests use a mock.
pub trait StepExecutor: Send + Sync {
    fn dispatch<'a>(
        &'a self,
        call: DispatchCall<'a>,
    ) -> Pin<Box<dyn Future<Output = StepRunResult> + Send + 'a>>;
}

/// Virtual skills wrap existing agent capabilities behind a uniform skill
/// surface. Phase 3 implements them; Phase 2 recognises + defers them so a
/// playbook that uses them still loads and the real skills around them run.
fn is_virtual_skill(skill: &str) -> bool {
    matches!(
        skill,
        "route_alert"
            | "capture_pcap"
            | "open_ticket"
            | "wait"
            | "emit_metric"
            | "set_tag"
            | "block_subnet"
    )
}

/// Production dispatcher: resolves a playbook skill name against the real
/// [`skills::SkillRegistry`] and enforces the skill_gate floor on every
/// `block_ip_*` call.
pub struct RegistryStepExecutor<'a> {
    pub registry: &'a skills::SkillRegistry,
    pub trusted_ips: &'a [String],
    pub dry_run: bool,
    pub host: String,
    pub data_dir: PathBuf,
    /// Base incident cloned into each [`skills::SkillContext`].
    pub base_incident: Incident,
    pub honeypot: skills::HoneypotRuntimeConfig,
    pub ai_provider: Option<Arc<dyn ai::AiProvider>>,
}

impl StepExecutor for RegistryStepExecutor<'_> {
    fn dispatch<'a>(
        &'a self,
        call: DispatchCall<'a>,
    ) -> Pin<Box<dyn Future<Output = StepRunResult> + Send + 'a>> {
        Box::pin(async move {
            let skill = call.skill;

            if is_virtual_skill(skill) {
                return self
                    .dispatch_virtual(skill, call.args, call.primary_ip)
                    .await;
            }

            // Playbook YAML uses snake_case skill names (`block_ip_xdp`);
            // the registry keys are kebab-case (`block-ip-xdp`).
            let registry_id = skill.replace('_', "-");
            let Some(resp) = self.registry.get(&registry_id) else {
                return StepRunResult {
                    status: StepStatus::Failed,
                    message: format!("unknown skill '{skill}'"),
                };
            };

            let arg_ip = call.args.get("target_ip").and_then(|v| v.as_str());
            let target_ip = arg_ip.or(call.primary_ip).map(str::to_string);
            let arg_user = call.args.get("user").and_then(|v| v.as_str());
            let target_user = arg_user.or(call.primary_user).map(str::to_string);
            let duration_secs = call
                .args
                .get("ttl_secs")
                .and_then(serde_yaml::Value::as_u64)
                .or_else(|| {
                    call.args
                        .get("duration_secs")
                        .and_then(serde_yaml::Value::as_u64)
                });
            let target_container = call
                .args
                .get("container")
                .and_then(|v| v.as_str())
                .map(str::to_string);

            let ctx = skills::SkillContext {
                incident: self.base_incident.clone(),
                target_ip: target_ip.clone(),
                target_user,
                target_container,
                duration_secs,
                host: self.host.clone(),
                data_dir: self.data_dir.clone(),
                honeypot: self.honeypot.clone(),
                ai_provider: self.ai_provider.clone(),
            };

            // Block-ip skills MUST clear the stateless safety floor first.
            if skill.starts_with("block_ip_") {
                let Some(ip) = target_ip.as_deref() else {
                    return StepRunResult {
                        status: StepStatus::Failed,
                        message: "block-ip step has no target IP".to_string(),
                    };
                };
                return match skill_gate::gate_block_ip(ip, self.trusted_ips) {
                    Ok(gate) => {
                        let r =
                            skill_gate::execute_block_skill_gated(resp, &ctx, self.dry_run, &gate)
                                .await;
                        StepRunResult {
                            status: if r.success {
                                StepStatus::Success
                            } else {
                                StepStatus::Failed
                            },
                            message: r.message,
                        }
                    }
                    Err(refusal) => StepRunResult {
                        status: StepStatus::Refused,
                        message: refusal.to_string(),
                    },
                };
            }

            let r = resp.execute(&ctx, self.dry_run).await;
            StepRunResult {
                status: if r.success {
                    StepStatus::Success
                } else {
                    StepStatus::Failed
                },
                message: r.message,
            }
        })
    }
}

// ---------------------------------------------------------------------------
// Trigger / interpolation context
// ---------------------------------------------------------------------------

/// Interpolation + matching context derived once per incident.
pub struct TriggerCtx {
    /// `{trigger.X}` lookup table.
    vars: HashMap<String, String>,
    primary_ip: Option<String>,
    primary_user: Option<String>,
    target_user: Option<String>,
}

impl TriggerCtx {
    pub fn from_incident(incident: &Incident) -> Self {
        let rule_id = incident
            .incident_id
            .split(':')
            .next()
            .unwrap_or("")
            .to_string();

        let primary_ip = incident
            .entities
            .iter()
            .find(|e| e.r#type == CoreEntityType::Ip)
            .map(|e| e.value.clone());
        let user = incident
            .entities
            .iter()
            .find(|e| e.r#type == CoreEntityType::User)
            .map(|e| e.value.clone());

        let chain_id = incident
            .tags
            .iter()
            .find(|t| t.starts_with("CL-"))
            .cloned()
            .or_else(|| {
                incident
                    .evidence
                    .get("chain_id")
                    .and_then(|v| v.as_str())
                    .map(str::to_string)
            })
            .unwrap_or_default();
        let chain_name = incident
            .evidence
            .get("chain_name")
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .unwrap_or_else(|| incident.title.clone());
        let geo_country = incident
            .evidence
            .get("geo_country")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        let evidence_count = match &incident.evidence {
            serde_json::Value::Array(a) => a.len(),
            serde_json::Value::Object(o) => o.len(),
            _ => incident.entities.len(),
        };

        let mut vars: HashMap<String, String> = HashMap::new();
        vars.insert("rule_id".to_string(), rule_id);
        vars.insert("chain_id".to_string(), chain_id);
        vars.insert("chain_name".to_string(), chain_name);
        vars.insert(
            "primary_ip".to_string(),
            primary_ip.clone().unwrap_or_default(),
        );
        vars.insert("primary_user".to_string(), user.clone().unwrap_or_default());
        vars.insert("target_user".to_string(), user.clone().unwrap_or_default());
        vars.insert(
            "severity".to_string(),
            severity_str(&incident.severity).to_string(),
        );
        vars.insert("ts".to_string(), incident.ts.to_rfc3339());
        vars.insert("geo_country".to_string(), geo_country);
        vars.insert("evidence_count".to_string(), evidence_count.to_string());

        Self {
            vars,
            primary_ip,
            primary_user: user.clone(),
            target_user: user,
        }
    }
}

fn severity_str(s: &CoreSeverity) -> &'static str {
    match s {
        CoreSeverity::Debug => "debug",
        CoreSeverity::Info => "info",
        CoreSeverity::Low => "low",
        CoreSeverity::Medium => "medium",
        CoreSeverity::High => "high",
        CoreSeverity::Critical => "critical",
    }
}

fn core_severity_rank(s: &CoreSeverity) -> u8 {
    match s {
        CoreSeverity::Debug => 0,
        CoreSeverity::Info => 1,
        CoreSeverity::Low => 2,
        CoreSeverity::Medium => 3,
        CoreSeverity::High => 4,
        CoreSeverity::Critical => 5,
    }
}

fn pb_severity_rank(s: Severity) -> u8 {
    match s {
        Severity::Info => 1,
        Severity::Low => 2,
        Severity::Medium => 3,
        Severity::High => 4,
        Severity::Critical => 5,
    }
}

fn entity_type_eq(pb: EntityType, core: &CoreEntityType) -> bool {
    matches!(
        (pb, core),
        (EntityType::Ip, CoreEntityType::Ip)
            | (EntityType::User, CoreEntityType::User)
            | (EntityType::Container, CoreEntityType::Container)
            | (EntityType::File, CoreEntityType::Path)
            // Core has no Pid entity; map playbook Pid to Service (closest
            // process-scoped entity) so an `entity_type: pid` trigger still
            // arms on process-scoped incidents rather than never matching.
            | (EntityType::Pid, CoreEntityType::Service)
    )
}

/// Recursively interpolate `{trigger.X}`, `{prev.id.field}`, `{bare}`, and
/// `${env:NAME}` tokens inside string values of an args tree.
fn interpolate_value(
    v: &serde_yaml::Value,
    tctx: &TriggerCtx,
    prev: &PrevOutputs,
) -> serde_yaml::Value {
    match v {
        serde_yaml::Value::String(s) => serde_yaml::Value::String(interpolate_str(s, tctx, prev)),
        serde_yaml::Value::Sequence(seq) => serde_yaml::Value::Sequence(
            seq.iter()
                .map(|x| interpolate_value(x, tctx, prev))
                .collect(),
        ),
        serde_yaml::Value::Mapping(map) => {
            let mut out = serde_yaml::Mapping::new();
            for (k, val) in map {
                out.insert(k.clone(), interpolate_value(val, tctx, prev));
            }
            serde_yaml::Value::Mapping(out)
        }
        other => other.clone(),
    }
}

fn interpolate_str(s: &str, tctx: &TriggerCtx, prev: &PrevOutputs) -> String {
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        let rest = &s[i..];
        if let Some(stripped) = rest.strip_prefix("${env:") {
            if let Some(end) = stripped.find('}') {
                let name = &stripped[..end];
                out.push_str(&std::env::var(name).unwrap_or_default());
                i += "${env:".len() + end + 1;
                continue;
            }
        }
        if rest.starts_with('{') {
            if let Some(end) = rest.find('}') {
                let tok = &rest[1..end];
                out.push_str(&resolve_token(tok, tctx, prev));
                i += end + 1;
                continue;
            }
        }
        let ch = rest.chars().next().unwrap();
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

fn resolve_token(tok: &str, tctx: &TriggerCtx, prev: &PrevOutputs) -> String {
    if let Some(key) = tok.strip_prefix("trigger.") {
        return tctx.vars.get(key).cloned().unwrap_or_default();
    }
    if let Some(rest) = tok.strip_prefix("prev.") {
        let mut parts = rest.splitn(2, '.');
        let id = parts.next().unwrap_or("");
        let field = parts.next().unwrap_or("");
        return prev
            .get(id)
            .and_then(|m| m.get(field))
            .cloned()
            .unwrap_or_default();
    }
    // Bare `{rule_id}` style — resolve against trigger vars if known,
    // otherwise leave the braces untouched so operator literals survive.
    if !tok.contains('.') {
        if let Some(v) = tctx.vars.get(tok) {
            return v.clone();
        }
    }
    format!("{{{tok}}}")
}

type PrevOutputs = HashMap<String, HashMap<String, String>>;

fn output_map(outcome: &StepOutcome) -> HashMap<String, String> {
    let mut m = HashMap::new();
    m.insert("message".to_string(), outcome.message.clone());
    m.insert("status".to_string(), outcome.status.as_str().to_string());
    // `result` is an alias for `message` — playbooks often reference
    // `{prev.<id>.result}` colloquially.
    m.insert("result".to_string(), outcome.message.clone());
    m
}

// ---------------------------------------------------------------------------
// Audit sink
// ---------------------------------------------------------------------------

/// Sink for per-step audit records. The production impl ([`FileAudit`])
/// writes both `decisions.jsonl` and `playbook_steps-<date>.jsonl`; tests
/// use an in-memory collector.
pub trait PlaybookAudit: Send + Sync {
    fn record(&self, rec: PlaybookStepRecord<'_>);
}

pub struct PlaybookStepRecord<'a> {
    pub incident: &'a Incident,
    pub playbook_id: &'a str,
    pub outcome: &'a StepOutcome,
}

/// One line in `playbook_steps-<date>.jsonl`.
#[derive(Debug, Serialize)]
struct PlaybookStepLine<'a> {
    ts: chrono::DateTime<chrono::Utc>,
    incident_id: &'a str,
    host: &'a str,
    playbook_id: &'a str,
    step_id: &'a str,
    skill: &'a str,
    status: StepStatus,
    attempts: u32,
    dry_run: bool,
    message: &'a str,
}

/// Production audit: dual-write to `decisions.jsonl` (hash-chained) and
/// `playbook_steps-<date>.jsonl`.
pub struct FileAudit {
    pub data_dir: PathBuf,
    pub store: Option<Arc<innerwarden_store::Store>>,
    pub dry_run: bool,
}

impl PlaybookAudit for FileAudit {
    fn record(&self, rec: PlaybookStepRecord<'_>) {
        let now = chrono::Utc::now();
        let target_ip = rec
            .incident
            .entities
            .iter()
            .find(|e| e.r#type == CoreEntityType::Ip)
            .map(|e| e.value.clone());

        // 1. decisions.jsonl (canonical audit + dashboard).
        let entry = decisions::DecisionEntry {
            ts: now,
            incident_id: rec.incident.incident_id.clone(),
            host: rec.incident.host.clone(),
            ai_provider: "playbook".to_string(),
            action_type: format!("playbook:{}", rec.outcome.skill),
            target_ip,
            target_user: None,
            skill_id: Some(rec.outcome.skill.clone()),
            confidence: 1.0,
            auto_executed: !self.dry_run && rec.outcome.status == StepStatus::Success,
            dry_run: self.dry_run,
            reason: format!(
                "playbook {} step {} ({})",
                rec.playbook_id, rec.outcome.step_id, rec.outcome.message
            ),
            estimated_threat: severity_str(&rec.incident.severity).to_string(),
            execution_result: format!("{}: {}", rec.outcome.status.as_str(), rec.outcome.message),
            prev_hash: None,
            decision_layer: Some("playbook".to_string()),
        };
        if let Err(e) = decisions::append_chained(&self.data_dir, &entry, self.store.as_ref()) {
            warn!(error = %e, "playbook: failed to append decision entry");
        }

        // 2. playbook_steps-<date>.jsonl (dedicated step log).
        let line = PlaybookStepLine {
            ts: now,
            incident_id: &rec.incident.incident_id,
            host: &rec.incident.host,
            playbook_id: rec.playbook_id,
            step_id: &rec.outcome.step_id,
            skill: &rec.outcome.skill,
            status: rec.outcome.status,
            attempts: rec.outcome.attempts,
            dry_run: self.dry_run,
            message: &rec.outcome.message,
        };
        if let Err(e) = append_step_line(&self.data_dir, &line) {
            warn!(error = %e, "playbook: failed to append step line");
        }
    }
}

fn append_step_line(data_dir: &Path, line: &PlaybookStepLine<'_>) -> std::io::Result<()> {
    use std::io::Write;
    let date = chrono::Local::now()
        .date_naive()
        .format("%Y-%m-%d")
        .to_string();
    let path = data_dir.join(format!("playbook_steps-{date}.jsonl"));
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)?;
    let json = serde_json::to_string(line).unwrap_or_default();
    writeln!(f, "{json}")
}

// ---------------------------------------------------------------------------
// Executor core
// ---------------------------------------------------------------------------

/// Execute a playbook against an incident. Trigger/condition matching is the
/// caller's responsibility (see [`matches_incident`]); this assumes the
/// playbook has already been selected.
pub async fn execute(
    playbook: &Playbook,
    incident: &Incident,
    exec: &dyn StepExecutor,
    audit: &dyn PlaybookAudit,
) -> PlaybookOutcome {
    let tctx = TriggerCtx::from_incident(incident);
    let mut prev: PrevOutputs = HashMap::new();
    let mut outcomes: Vec<StepOutcome> = Vec::new();
    let mut aborted = false;
    let pb_id = playbook.metadata.id.as_str();

    for step in &playbook.steps {
        match step {
            Step::Leaf(leaf) => {
                let outcome = run_leaf(leaf, &tctx, &prev, exec).await;
                audit.record(PlaybookStepRecord {
                    incident,
                    playbook_id: pb_id,
                    outcome: &outcome,
                });
                prev.insert(outcome.step_id.clone(), output_map(&outcome));
                let abort = outcome.status.is_terminal_failure() && leaf.on_error == OnError::Abort;
                outcomes.push(outcome);
                if abort {
                    aborted = true;
                    break;
                }
            }
            Step::Parallel(children) => {
                let leaves = collect_leaves(children);
                let results = futures_util::future::join_all(
                    leaves
                        .iter()
                        .copied()
                        .map(|l| run_leaf(l, &tctx, &prev, exec)),
                )
                .await;
                let mut group_abort = false;
                for outcome in results {
                    audit.record(PlaybookStepRecord {
                        incident,
                        playbook_id: pb_id,
                        outcome: &outcome,
                    });
                    let on_err = leaves
                        .iter()
                        .find(|l| l.id.as_str() == outcome.step_id.as_str())
                        .map(|l| l.on_error)
                        .unwrap_or(OnError::Abort);
                    if outcome.status.is_terminal_failure() && on_err == OnError::Abort {
                        group_abort = true;
                    }
                    prev.insert(outcome.step_id.clone(), output_map(&outcome));
                    outcomes.push(outcome);
                }
                if group_abort {
                    aborted = true;
                    break;
                }
            }
        }
    }

    PlaybookOutcome {
        playbook_id: pb_id.to_string(),
        steps: outcomes,
        aborted,
    }
}

/// Flatten nested parallel groups into their leaf steps. A parallel group
/// containing another parallel group runs all leaves concurrently (Phase 2
/// does not support staged sub-groups inside a parallel block).
fn collect_leaves(steps: &[Step]) -> Vec<&LeafStepCompiled> {
    let mut out = Vec::new();
    for s in steps {
        match s {
            Step::Leaf(l) => out.push(l),
            Step::Parallel(inner) => out.extend(collect_leaves(inner)),
        }
    }
    out
}

async fn run_leaf(
    leaf: &LeafStepCompiled,
    tctx: &TriggerCtx,
    prev: &PrevOutputs,
    exec: &dyn StepExecutor,
) -> StepOutcome {
    // Post-trigger step condition (e.g. `target_user_present: true`).
    if let Some(cond) = &leaf.condition {
        if !eval_step_condition(cond, tctx) {
            return StepOutcome {
                step_id: leaf.id.as_str().to_string(),
                skill: leaf.skill.clone(),
                status: StepStatus::Skipped,
                attempts: 0,
                message: "step condition not met".to_string(),
            };
        }
    }

    let args = interpolate_value(&leaf.args, tctx, prev);
    let max_attempts = leaf.retry.count.saturating_add(1);
    let mut attempt = 0u32;
    loop {
        attempt += 1;
        let call = DispatchCall {
            skill: &leaf.skill,
            args: &args,
            primary_ip: tctx.primary_ip.as_deref(),
            primary_user: tctx.primary_user.as_deref(),
        };
        let dispatched = tokio::time::timeout(
            Duration::from_secs(leaf.timeout_secs.max(1)),
            exec.dispatch(call),
        )
        .await;
        let result = match dispatched {
            Ok(r) => r,
            Err(_) => StepRunResult {
                status: StepStatus::Failed,
                message: format!("step timed out after {}s", leaf.timeout_secs),
            },
        };

        if !result.status.is_retriable() || attempt >= max_attempts {
            return StepOutcome {
                step_id: leaf.id.as_str().to_string(),
                skill: leaf.skill.clone(),
                status: result.status,
                attempts: attempt,
                message: result.message,
            };
        }

        let delay = backoff_delay(leaf.retry.backoff, leaf.retry.base_ms, attempt);
        tokio::time::sleep(Duration::from_millis(delay)).await;
    }
}

fn backoff_delay(backoff: super::Backoff, base_ms: u64, attempt: u32) -> u64 {
    match backoff {
        super::Backoff::Linear => base_ms.saturating_mul(attempt as u64),
        super::Backoff::Exponential => {
            let factor = 1u64
                .checked_shl(attempt.saturating_sub(1))
                .unwrap_or(u64::MAX);
            base_ms.saturating_mul(factor)
        }
    }
}

/// Evaluate a step's optional post-trigger `condition`. Phase 2 supports
/// `target_user_present: <bool>`; any other condition key is treated as
/// unmet (the step is skipped) so a playbook never acts on a predicate the
/// engine cannot yet evaluate (e.g. `same_subnet_chains_24h`, which needs
/// state that Phase 2 does not carry).
fn eval_step_condition(cond: &serde_yaml::Value, tctx: &TriggerCtx) -> bool {
    let serde_yaml::Value::Mapping(map) = cond else {
        return false;
    };
    for (k, v) in map {
        let Some(key) = k.as_str() else { return false };
        match key {
            "target_user_present" => {
                let want = v.as_bool().unwrap_or(true);
                let present = tctx.target_user.as_deref().is_some_and(|u| !u.is_empty());
                if present != want {
                    return false;
                }
            }
            _ => return false,
        }
    }
    true
}

// ---------------------------------------------------------------------------
// Trigger + condition matching
// ---------------------------------------------------------------------------

/// `true` if any trigger fires AND all conditions pass.
pub fn matches_incident(
    pb: &Playbook,
    incident: &Incident,
    tctx: &TriggerCtx,
    trusted_ips: &[String],
    asset_tags: &[String],
) -> bool {
    if pb.disabled {
        return false;
    }
    let armed = pb
        .triggers
        .iter()
        .any(|t| trigger_matches(t, incident, tctx));
    if !armed {
        return false;
    }
    conditions_pass(&pb.conditions, tctx, trusted_ips, asset_tags, incident)
}

fn trigger_matches(t: &Trigger, incident: &Incident, tctx: &TriggerCtx) -> bool {
    match t {
        Trigger::ChainId(s) => tctx.vars.get("chain_id").is_some_and(|c| c == s),
        Trigger::RuleId(s) => tctx.vars.get("rule_id").is_some_and(|r| r == s),
        Trigger::KindGlob(g) => {
            let rule_id = tctx.vars.get("rule_id").map(String::as_str).unwrap_or("");
            let mut candidates: Vec<&str> = vec![rule_id, incident.incident_id.as_str()];
            candidates.extend(incident.tags.iter().map(String::as_str));
            candidates.iter().any(|c| glob_match(g, c))
        }
        Trigger::SeverityGte(min) => {
            core_severity_rank(&incident.severity) >= pb_severity_rank(*min)
        }
        Trigger::EntityType(et) => incident
            .entities
            .iter()
            .any(|e| entity_type_eq(*et, &e.r#type)),
    }
}

fn conditions_pass(
    c: &Conditions,
    tctx: &TriggerCtx,
    trusted_ips: &[String],
    asset_tags: &[String],
    incident: &Incident,
) -> bool {
    // asset_tags: host must carry at least one of the listed tags.
    if !c.asset_tags.is_empty() && !c.asset_tags.iter().any(|t| asset_tags.contains(t)) {
        return false;
    }

    let ip = tctx.primary_ip.as_deref();
    if !c.ip_in.is_empty() {
        match ip {
            Some(ip) if ip_in_any(ip, &c.ip_in, trusted_ips) => {}
            _ => return false,
        }
    }
    if !c.ip_not_in.is_empty() {
        if let Some(ip) = ip {
            if ip_in_any(ip, &c.ip_not_in, trusted_ips) {
                return false;
            }
        }
    }

    let user = tctx.target_user.as_deref();
    if !c.user_in.is_empty() {
        match user {
            Some(u) if c.user_in.iter().any(|x| x == u) => {}
            _ => return false,
        }
    }
    if !c.user_not_in.is_empty() {
        if let Some(u) = user {
            if c.user_not_in.iter().any(|x| x == u) {
                return false;
            }
        }
    }

    if !time_window_ok(c.time_window, incident.ts) {
        return false;
    }

    if c.sample_rate < 1.0 && sample_fraction(&incident.incident_id) >= c.sample_rate {
        return false;
    }

    true
}

/// Returns `true` if `ip` is in any of the (possibly named) lists.
/// `$cloud_safelist` / `$trusted_ips` expand to the static cloud ranges and
/// the operator allowlist; everything else is treated as a literal IP/CIDR.
fn ip_in_any(ip: &str, list: &[String], trusted_ips: &[String]) -> bool {
    for entry in list {
        match entry.as_str() {
            "$cloud_safelist" => {
                if cloud_safelist::safelist_label(ip).is_some() {
                    return true;
                }
            }
            "$trusted_ips" => {
                if allowlist::is_ip_allowlisted(ip, trusted_ips) {
                    return true;
                }
            }
            _ => {
                if allowlist::is_ip_allowlisted(ip, std::slice::from_ref(entry)) {
                    return true;
                }
            }
        }
    }
    false
}

fn time_window_ok(tw: TimeWindow, ts: chrono::DateTime<chrono::Utc>) -> bool {
    use chrono::{Datelike, Timelike, Weekday};
    match tw {
        TimeWindow::Any => true,
        TimeWindow::BusinessHours => {
            let weekday = !matches!(ts.weekday(), Weekday::Sat | Weekday::Sun);
            let hour = ts.hour();
            weekday && (9..17).contains(&hour)
        }
        TimeWindow::AfterHours => !time_window_ok(TimeWindow::BusinessHours, ts),
    }
}

/// Deterministic per-incident sample fraction in `[0.0, 1.0)`. The same
/// incident id always yields the same fraction, so `sample_rate` is stable
/// across reloads / restarts (spec §4).
fn sample_fraction(seed: &str) -> f32 {
    let digest = Sha256::digest(seed.as_bytes());
    let bytes: [u8; 8] = digest[..8].try_into().unwrap_or([0; 8]);
    let v = u64::from_be_bytes(bytes);
    (v as f64 / u64::MAX as f64) as f32
}

/// Minimal glob matcher supporting `*` only (matches the event-kind globs
/// the correlation engine emits, e.g. `kill_chain_detected_DATA_EXFIL*`).
fn glob_match(pattern: &str, text: &str) -> bool {
    if !pattern.contains('*') {
        return pattern == text;
    }
    let parts: Vec<&str> = pattern.split('*').collect();
    let mut pos = 0;
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }
        if i == 0 {
            if !text[pos..].starts_with(part) {
                return false;
            }
            pos += part.len();
        } else if i == parts.len() - 1 {
            // last non-empty part must match the tail
            if !text[pos..].ends_with(part) {
                return false;
            }
        } else if let Some(found) = text[pos..].find(part) {
            pos += found + part.len();
        } else {
            return false;
        }
    }
    true
}

// ---------------------------------------------------------------------------
// Wiring helper: run all matching playbooks for an incident
// ---------------------------------------------------------------------------

/// Load playbooks (built-ins + operator dir) and run every one that matches
/// `incident`. Returns the outcomes (consumed as AI-router context in
/// Phase 4). Best-effort: a load error logs + returns no outcomes rather
/// than crashing the incident tick.
/// Convenience wrapper for the incident loop: runs all matching playbooks
/// only when `[playbooks] enabled = true`, sourcing every input (rules dir,
/// trusted IPs, dry-run, honeypot runtime) from `cfg`. Keeping the
/// enable-gate + arg assembly here (instead of inline in `process_incidents`)
/// makes it unit-testable without an `AgentState`, and makes the call site a
/// cheap no-op until an operator opts in.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_for_incident_if_enabled(
    incident: &Incident,
    cfg: &crate::config::AgentConfig,
    data_dir: &Path,
    registry: &skills::SkillRegistry,
    honeypot: skills::HoneypotRuntimeConfig,
    ai_provider: Option<Arc<dyn ai::AiProvider>>,
    store: Option<Arc<innerwarden_store::Store>>,
) -> Vec<PlaybookOutcome> {
    if !cfg.playbooks.enabled {
        return Vec::new();
    }
    run_for_incident(
        incident,
        Path::new(&cfg.playbooks.rules_dir),
        data_dir,
        registry,
        &cfg.allowlist.trusted_ips,
        &[], // asset_tags: spec 058 server-profiles will populate this
        cfg.responder.dry_run,
        honeypot,
        ai_provider,
        store,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_for_incident(
    incident: &Incident,
    rules_dir: &Path,
    data_dir: &Path,
    registry: &skills::SkillRegistry,
    trusted_ips: &[String],
    asset_tags: &[String],
    dry_run: bool,
    honeypot: skills::HoneypotRuntimeConfig,
    ai_provider: Option<Arc<dyn ai::AiProvider>>,
    store: Option<Arc<innerwarden_store::Store>>,
) -> Vec<PlaybookOutcome> {
    let playbooks = match super::load_dir(rules_dir) {
        Ok(p) => p,
        Err(e) => {
            warn!(error = %e, "playbook: load_dir failed, skipping playbook execution");
            return Vec::new();
        }
    };

    let tctx = TriggerCtx::from_incident(incident);
    let mut outcomes = Vec::new();
    for pb in &playbooks {
        if !matches_incident(pb, incident, &tctx, trusted_ips, asset_tags) {
            continue;
        }
        let exec = RegistryStepExecutor {
            registry,
            trusted_ips,
            dry_run,
            host: incident.host.clone(),
            data_dir: data_dir.to_path_buf(),
            base_incident: incident.clone(),
            honeypot: honeypot.clone(),
            ai_provider: ai_provider.clone(),
        };
        let audit = FileAudit {
            data_dir: data_dir.to_path_buf(),
            store: store.clone(),
            dry_run,
        };
        let outcome = execute(pb, incident, &exec, &audit).await;
        info!(
            playbook = pb.metadata.id.as_str(),
            steps = outcome.steps.len(),
            aborted = outcome.aborted,
            "playbook executed for incident"
        );
        outcomes.push(outcome);
    }
    outcomes
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::playbook_engine::{Backoff, OnError, PlaybookId, Retry, StepId};
    use std::collections::VecDeque;
    use std::sync::Mutex;

    // ---- builders -------------------------------------------------------

    fn meta(id: &str) -> super::super::PlaybookMetadata {
        super::super::PlaybookMetadata {
            id: PlaybookId(id.to_string()),
            name: id.to_string(),
            description: String::new(),
        }
    }

    fn leaf(id: &str, skill: &str) -> LeafStepCompiled {
        LeafStepCompiled {
            id: StepId(id.to_string()),
            skill: skill.to_string(),
            args: serde_yaml::Value::Null,
            retry: Retry::default(),
            on_error: OnError::Abort,
            timeout_secs: 30,
            condition: None,
        }
    }

    fn playbook(id: &str, steps: Vec<Step>) -> Playbook {
        Playbook {
            metadata: meta(id),
            triggers: vec![Trigger::ChainId("CL-002".to_string())],
            conditions: Conditions {
                sample_rate: 1.0,
                ..Default::default()
            },
            steps,
            disabled: false,
            source_file: "test.yml".to_string(),
        }
    }

    // ---- mock executor --------------------------------------------------

    struct MockExec {
        plan: Mutex<HashMap<String, VecDeque<StepRunResult>>>,
        seen_args: Mutex<Vec<(String, serde_yaml::Value)>>,
    }

    impl MockExec {
        fn new() -> Self {
            Self {
                plan: Mutex::new(HashMap::new()),
                seen_args: Mutex::new(Vec::new()),
            }
        }

        fn program(&self, skill: &str, results: Vec<StepRunResult>) {
            self.plan
                .lock()
                .unwrap()
                .insert(skill.to_string(), results.into());
        }
    }

    impl StepExecutor for MockExec {
        fn dispatch<'a>(
            &'a self,
            call: DispatchCall<'a>,
        ) -> Pin<Box<dyn Future<Output = StepRunResult> + Send + 'a>> {
            let skill = call.skill.to_string();
            let args = call.args.clone();
            Box::pin(async move {
                self.seen_args.lock().unwrap().push((skill.clone(), args));
                let next = self
                    .plan
                    .lock()
                    .unwrap()
                    .get_mut(&skill)
                    .and_then(VecDeque::pop_front);
                next.unwrap_or(StepRunResult {
                    status: StepStatus::Success,
                    message: "ok".to_string(),
                })
            })
        }
    }

    fn ok(msg: &str) -> StepRunResult {
        StepRunResult {
            status: StepStatus::Success,
            message: msg.to_string(),
        }
    }
    fn fail(msg: &str) -> StepRunResult {
        StepRunResult {
            status: StepStatus::Failed,
            message: msg.to_string(),
        }
    }

    // ---- audit collector ------------------------------------------------

    #[derive(Default)]
    struct CollectAudit {
        records: Mutex<Vec<(String, String, StepStatus)>>,
    }
    impl PlaybookAudit for CollectAudit {
        fn record(&self, rec: PlaybookStepRecord<'_>) {
            self.records.lock().unwrap().push((
                rec.playbook_id.to_string(),
                rec.outcome.step_id.clone(),
                rec.outcome.status,
            ));
        }
    }

    fn fast_retry(count: u32) -> Retry {
        Retry {
            count,
            backoff: Backoff::Linear,
            base_ms: 1,
        }
    }

    // ---- core execution -------------------------------------------------

    #[tokio::test]
    async fn happy_path_runs_all_steps() {
        let pb = playbook(
            "pb",
            vec![
                Step::Leaf(leaf("a", "kill_process")),
                Step::Leaf(leaf("b", "kill_process")),
            ],
        );
        let exec = MockExec::new();
        exec.program("kill_process", vec![ok("1"), ok("2")]);
        let audit = CollectAudit::default();
        let out = execute(&pb, &crate::tests::test_incident("9.9.9.9"), &exec, &audit).await;
        assert!(!out.aborted);
        assert_eq!(out.steps.len(), 2);
        assert!(out.steps.iter().all(|s| s.status == StepStatus::Success));
        assert_eq!(audit.records.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn retry_then_success() {
        let mut l = leaf("a", "kill_process");
        l.retry = fast_retry(3);
        let pb = playbook("pb", vec![Step::Leaf(l)]);
        let exec = MockExec::new();
        exec.program("kill_process", vec![fail("e1"), fail("e2"), ok("done")]);
        let audit = CollectAudit::default();
        let out = execute(&pb, &crate::tests::test_incident("9.9.9.9"), &exec, &audit).await;
        assert_eq!(out.steps[0].status, StepStatus::Success);
        assert_eq!(out.steps[0].attempts, 3);
        assert!(!out.aborted);
    }

    #[tokio::test]
    async fn retry_exhausted_then_abort_halts_playbook() {
        let mut l = leaf("a", "kill_process");
        l.retry = fast_retry(2); // 3 attempts total
        l.on_error = OnError::Abort;
        let pb = playbook(
            "pb",
            vec![Step::Leaf(l), Step::Leaf(leaf("b", "kill_process"))],
        );
        let exec = MockExec::new();
        exec.program("kill_process", vec![fail("e1"), fail("e2"), fail("e3")]);
        let audit = CollectAudit::default();
        let out = execute(&pb, &crate::tests::test_incident("9.9.9.9"), &exec, &audit).await;
        assert!(out.aborted);
        assert_eq!(out.steps.len(), 1, "second step must not run after abort");
        assert_eq!(out.steps[0].status, StepStatus::Failed);
        assert_eq!(out.steps[0].attempts, 3);
    }

    #[tokio::test]
    async fn on_error_continue_runs_next_step() {
        let mut l = leaf("a", "kill_process");
        l.on_error = OnError::Continue;
        let pb = playbook(
            "pb",
            vec![Step::Leaf(l), Step::Leaf(leaf("b", "kill_process"))],
        );
        let exec = MockExec::new();
        exec.program("kill_process", vec![fail("boom"), ok("second")]);
        let audit = CollectAudit::default();
        let out = execute(&pb, &crate::tests::test_incident("9.9.9.9"), &exec, &audit).await;
        assert!(!out.aborted);
        assert_eq!(out.steps.len(), 2);
        assert_eq!(out.steps[0].status, StepStatus::Failed);
        assert_eq!(out.steps[1].status, StepStatus::Success);
    }

    #[tokio::test]
    async fn parallel_all_success() {
        let pb = playbook(
            "pb",
            vec![Step::Parallel(vec![
                Step::Leaf(leaf("a", "kill_process")),
                Step::Leaf(leaf("b", "monitor_ip")),
            ])],
        );
        let exec = MockExec::new();
        exec.program("kill_process", vec![ok("a")]);
        exec.program("monitor_ip", vec![ok("b")]);
        let audit = CollectAudit::default();
        let out = execute(&pb, &crate::tests::test_incident("9.9.9.9"), &exec, &audit).await;
        assert!(!out.aborted);
        assert_eq!(out.steps.len(), 2);
        assert!(out.steps.iter().all(|s| s.status == StepStatus::Success));
    }

    #[tokio::test]
    async fn parallel_partial_failure_preserves_outcome_and_continues() {
        // One child fails with on_error: continue -> the group does not
        // abort the playbook, but the failure is preserved in the outcome.
        let mut bad = leaf("b", "monitor_ip");
        bad.on_error = OnError::Continue;
        let pb = playbook(
            "pb",
            vec![
                Step::Parallel(vec![Step::Leaf(leaf("a", "kill_process")), Step::Leaf(bad)]),
                Step::Leaf(leaf("c", "kill_process")),
            ],
        );
        let exec = MockExec::new();
        exec.program("kill_process", vec![ok("a"), ok("c")]);
        exec.program("monitor_ip", vec![fail("b-failed")]);
        let audit = CollectAudit::default();
        let out = execute(&pb, &crate::tests::test_incident("9.9.9.9"), &exec, &audit).await;
        assert!(!out.aborted);
        assert_eq!(out.steps.len(), 3);
        let b = out.steps.iter().find(|s| s.step_id == "b").unwrap();
        assert_eq!(b.status, StepStatus::Failed);
        assert!(out.steps.iter().any(|s| s.step_id == "c"));
    }

    #[tokio::test]
    async fn parallel_abort_child_halts_playbook() {
        let mut bad = leaf("b", "monitor_ip"); // default on_error = Abort
        bad.on_error = OnError::Abort;
        let pb = playbook(
            "pb",
            vec![
                Step::Parallel(vec![Step::Leaf(leaf("a", "kill_process")), Step::Leaf(bad)]),
                Step::Leaf(leaf("c", "kill_process")),
            ],
        );
        let exec = MockExec::new();
        exec.program("kill_process", vec![ok("a")]);
        exec.program("monitor_ip", vec![fail("b-failed")]);
        let audit = CollectAudit::default();
        let out = execute(&pb, &crate::tests::test_incident("9.9.9.9"), &exec, &audit).await;
        assert!(out.aborted);
        assert!(!out.steps.iter().any(|s| s.step_id == "c"));
    }

    // ---- interpolation --------------------------------------------------

    #[tokio::test]
    async fn interpolation_resolves_trigger_and_prev() {
        let mut a = leaf("a", "kill_process");
        a.on_error = OnError::Continue;
        let mut b = leaf("b", "monitor_ip");
        let mut map = serde_yaml::Mapping::new();
        map.insert(
            serde_yaml::Value::String("target".to_string()),
            serde_yaml::Value::String("{prev.a.message}@{trigger.primary_ip}".to_string()),
        );
        b.args = serde_yaml::Value::Mapping(map);
        let pb = playbook("pb", vec![Step::Leaf(a), Step::Leaf(b)]);
        let exec = MockExec::new();
        exec.program("kill_process", vec![ok("ALPHA")]);
        exec.program("monitor_ip", vec![ok("done")]);
        let audit = CollectAudit::default();
        let _ = execute(&pb, &crate::tests::test_incident("9.9.9.9"), &exec, &audit).await;
        let seen = exec.seen_args.lock().unwrap();
        let (_, args) = seen.iter().find(|(s, _)| s == "monitor_ip").unwrap();
        let target = args.get("target").and_then(|v| v.as_str()).unwrap();
        assert_eq!(target, "ALPHA@9.9.9.9");
    }

    #[test]
    fn interpolate_str_handles_env_and_bare_tokens() {
        let inc = crate::tests::test_incident("1.2.3.4");
        let tctx = TriggerCtx::from_incident(&inc);
        let prev = PrevOutputs::new();
        // bare {rule_id} resolves from trigger vars; unknown {x.y} survives.
        let s = interpolate_str("id={rule_id} ip={trigger.primary_ip}", &tctx, &prev);
        assert_eq!(s, "id=ssh_bruteforce ip=1.2.3.4");
    }

    // ---- step condition -------------------------------------------------

    #[tokio::test]
    async fn step_condition_target_user_present_skips_when_absent() {
        let mut l = leaf("a", "suspend_user_sudo");
        let mut cond = serde_yaml::Mapping::new();
        cond.insert(
            serde_yaml::Value::String("target_user_present".to_string()),
            serde_yaml::Value::Bool(true),
        );
        l.condition = Some(serde_yaml::Value::Mapping(cond));
        let pb = playbook("pb", vec![Step::Leaf(l)]);
        let exec = MockExec::new();
        let audit = CollectAudit::default();
        // test_incident has no User entity -> condition unmet -> Skipped.
        let out = execute(&pb, &crate::tests::test_incident("9.9.9.9"), &exec, &audit).await;
        assert_eq!(out.steps[0].status, StepStatus::Skipped);
        assert_eq!(out.steps[0].attempts, 0);
    }

    // ---- skill_gate integration (real registry) -------------------------

    #[tokio::test]
    async fn skill_gate_refuses_block_on_trusted_ip() {
        let registry = skills::SkillRegistry::default_builtin();
        let trusted = vec!["203.0.113.7".to_string()];
        let exec = RegistryStepExecutor {
            registry: &registry,
            trusted_ips: &trusted,
            dry_run: true,
            host: "h".to_string(),
            data_dir: std::env::temp_dir(),
            base_incident: crate::tests::test_incident("203.0.113.7"),
            honeypot: skills::HoneypotRuntimeConfig::default(),
            ai_provider: None,
        };
        let mut l = leaf("tarpit", "block_ip_xdp");
        let mut args = serde_yaml::Mapping::new();
        args.insert(
            serde_yaml::Value::String("ttl_secs".to_string()),
            serde_yaml::Value::Number(serde_yaml::Number::from(3600_i64)),
        );
        l.args = serde_yaml::Value::Mapping(args);
        let pb = playbook("pb", vec![Step::Leaf(l)]);
        let audit = CollectAudit::default();
        let out = execute(
            &pb,
            &crate::tests::test_incident("203.0.113.7"),
            &exec,
            &audit,
        )
        .await;
        assert_eq!(out.steps[0].status, StepStatus::Refused);
        assert!(
            out.steps[0].message.contains("trusted_ips"),
            "got: {}",
            out.steps[0].message
        );
    }

    #[tokio::test]
    async fn block_on_clean_ip_passes_gate_in_dry_run() {
        let registry = skills::SkillRegistry::default_builtin();
        let exec = RegistryStepExecutor {
            registry: &registry,
            trusted_ips: &[],
            dry_run: true,
            host: "h".to_string(),
            data_dir: std::env::temp_dir(),
            base_incident: crate::tests::test_incident("198.51.100.9"),
            honeypot: skills::HoneypotRuntimeConfig::default(),
            ai_provider: None,
        };
        let l = leaf("tarpit", "block_ip_ufw");
        let pb = playbook("pb", vec![Step::Leaf(l)]);
        let audit = CollectAudit::default();
        let out = execute(
            &pb,
            &crate::tests::test_incident("198.51.100.9"),
            &exec,
            &audit,
        )
        .await;
        // dry-run block reports success without touching the firewall.
        assert_eq!(out.steps[0].status, StepStatus::Success);
    }

    #[tokio::test]
    async fn virtual_skill_is_deferred() {
        let registry = skills::SkillRegistry::default_builtin();
        let exec = RegistryStepExecutor {
            registry: &registry,
            trusted_ips: &[],
            dry_run: true,
            host: "h".to_string(),
            data_dir: std::env::temp_dir(),
            base_incident: crate::tests::test_incident("198.51.100.9"),
            honeypot: skills::HoneypotRuntimeConfig::default(),
            ai_provider: None,
        };
        let pb = playbook("pb", vec![Step::Leaf(leaf("p", "route_alert"))]);
        let audit = CollectAudit::default();
        let out = execute(
            &pb,
            &crate::tests::test_incident("198.51.100.9"),
            &exec,
            &audit,
        )
        .await;
        assert_eq!(out.steps[0].status, StepStatus::Deferred);
    }

    // ---- matching -------------------------------------------------------

    #[test]
    fn trigger_matches_rule_id() {
        let inc = crate::tests::test_incident("9.9.9.9"); // rule_id ssh_bruteforce
        let tctx = TriggerCtx::from_incident(&inc);
        let t = Trigger::RuleId("ssh_bruteforce".to_string());
        assert!(trigger_matches(&t, &inc, &tctx));
        let t2 = Trigger::RuleId("port_scan".to_string());
        assert!(!trigger_matches(&t2, &inc, &tctx));
    }

    #[test]
    fn trigger_matches_chain_id_from_tag() {
        let mut inc = crate::tests::test_incident("9.9.9.9");
        inc.tags.push("CL-005".to_string());
        let tctx = TriggerCtx::from_incident(&inc);
        assert!(trigger_matches(
            &Trigger::ChainId("CL-005".to_string()),
            &inc,
            &tctx
        ));
    }

    #[test]
    fn trigger_matches_kind_glob() {
        let inc = crate::tests::test_incident_with_kind(
            "9.9.9.9",
            "kill_chain_detected_DATA_EXFIL_stage2",
        );
        let tctx = TriggerCtx::from_incident(&inc);
        assert!(trigger_matches(
            &Trigger::KindGlob("kill_chain_detected_DATA_EXFIL*".to_string()),
            &inc,
            &tctx
        ));
        assert!(!trigger_matches(
            &Trigger::KindGlob("kill_chain_detected_CREDENTIAL_*".to_string()),
            &inc,
            &tctx
        ));
    }

    #[test]
    fn condition_ip_not_in_trusted_blocks_match() {
        let inc = crate::tests::test_incident("203.0.113.7");
        let tctx = TriggerCtx::from_incident(&inc);
        let conds = Conditions {
            ip_not_in: vec!["$trusted_ips".to_string()],
            sample_rate: 1.0,
            ..Default::default()
        };
        let trusted = vec!["203.0.113.7".to_string()];
        assert!(!conditions_pass(&conds, &tctx, &trusted, &[], &inc));
        // A different (untrusted) IP passes.
        let inc2 = crate::tests::test_incident("198.51.100.42");
        let tctx2 = TriggerCtx::from_incident(&inc2);
        assert!(conditions_pass(&conds, &tctx2, &trusted, &[], &inc2));
    }

    #[test]
    fn condition_asset_tags_require_membership() {
        let inc = crate::tests::test_incident("198.51.100.42");
        let tctx = TriggerCtx::from_incident(&inc);
        let conds = Conditions {
            asset_tags: vec!["env=prod".to_string()],
            sample_rate: 1.0,
            ..Default::default()
        };
        assert!(!conditions_pass(&conds, &tctx, &[], &[], &inc));
        assert!(conditions_pass(
            &conds,
            &tctx,
            &[],
            &["env=prod".to_string()],
            &inc
        ));
    }

    #[test]
    fn matches_incident_end_to_end_credential_builtin() {
        let pbs = super::super::load_builtins().unwrap();
        let cred = pbs
            .iter()
            .find(|p| p.metadata.id.as_str() == "pb-credential-stuffing-default")
            .unwrap();
        // ssh_bruteforce rule_id arms the credential playbook; clean IP +
        // no asset_tags requirement -> matches.
        let inc = crate::tests::test_incident("198.51.100.42");
        let tctx = TriggerCtx::from_incident(&inc);
        assert!(matches_incident(cred, &inc, &tctx, &[], &[]));
        // Same incident but the IP is operator-trusted -> ip_not_in blocks.
        let trusted = vec!["198.51.100.42".to_string()];
        assert!(!matches_incident(cred, &inc, &tctx, &trusted, &[]));
    }

    #[test]
    fn matches_incident_data_exfil_needs_prod_tag() {
        let pbs = super::super::load_builtins().unwrap();
        let exfil = pbs
            .iter()
            .find(|p| p.metadata.id.as_str() == "pb-data-exfil-default")
            .unwrap();
        let mut inc = crate::tests::test_incident("198.51.100.42");
        inc.tags.push("CL-002".to_string());
        let tctx = TriggerCtx::from_incident(&inc);
        // CL-002 arms it, but env=prod asset tag is required.
        assert!(!matches_incident(exfil, &inc, &tctx, &[], &[]));
        assert!(matches_incident(
            exfil,
            &inc,
            &tctx,
            &[],
            &["env=prod".to_string()]
        ));
    }

    // ---- helpers --------------------------------------------------------

    #[test]
    fn glob_match_basic() {
        assert!(glob_match("abc*", "abcdef"));
        assert!(glob_match("*def", "abcdef"));
        assert!(glob_match("a*f", "abcdef"));
        assert!(glob_match("abc", "abc"));
        assert!(!glob_match("abc", "abcd"));
        assert!(!glob_match("x*y", "abc"));
    }

    #[test]
    fn sample_fraction_is_deterministic_and_in_range() {
        let a = sample_fraction("incident-123");
        let b = sample_fraction("incident-123");
        assert_eq!(a, b);
        assert!((0.0..1.0).contains(&a));
        assert_ne!(
            sample_fraction("incident-123"),
            sample_fraction("incident-999")
        );
    }

    #[test]
    fn backoff_delay_linear_and_exponential() {
        assert_eq!(backoff_delay(Backoff::Linear, 100, 3), 300);
        assert_eq!(backoff_delay(Backoff::Exponential, 100, 1), 100);
        assert_eq!(backoff_delay(Backoff::Exponential, 100, 3), 400);
    }

    // ---- additional branch coverage (spec 056 phase 2) ------------------

    #[test]
    fn outcome_summary_counts_statuses() {
        let mk = |id: &str, st: StepStatus| StepOutcome {
            step_id: id.to_string(),
            skill: "x".to_string(),
            status: st,
            attempts: 1,
            message: String::new(),
        };
        let out = PlaybookOutcome {
            playbook_id: "pb".to_string(),
            steps: vec![
                mk("a", StepStatus::Success),
                mk("b", StepStatus::Failed),
                mk("c", StepStatus::Refused),
            ],
            aborted: true,
        };
        let s = out.summary();
        assert!(s.contains("pb (aborted)"), "got: {s}");
        assert!(s.contains("1 success") && s.contains("1 failed") && s.contains("1 refused"));
    }

    #[test]
    fn step_status_as_str_all_variants() {
        assert_eq!(StepStatus::Success.as_str(), "success");
        assert_eq!(StepStatus::Failed.as_str(), "failed");
        assert_eq!(StepStatus::Refused.as_str(), "refused");
        assert_eq!(StepStatus::Skipped.as_str(), "skipped");
        assert_eq!(StepStatus::Deferred.as_str(), "deferred");
    }

    fn registry_exec<'a>(
        reg: &'a skills::SkillRegistry,
        trusted: &'a [String],
        ip: &str,
    ) -> RegistryStepExecutor<'a> {
        RegistryStepExecutor {
            registry: reg,
            trusted_ips: trusted,
            dry_run: true,
            host: "h".to_string(),
            data_dir: std::env::temp_dir(),
            base_incident: crate::tests::test_incident(ip),
            honeypot: skills::HoneypotRuntimeConfig::default(),
            ai_provider: None,
        }
    }

    #[tokio::test]
    async fn dispatch_unknown_skill_fails() {
        let reg = skills::SkillRegistry::default_builtin();
        let exec = registry_exec(&reg, &[], "198.51.100.9");
        let pb = playbook("pb", vec![Step::Leaf(leaf("a", "does_not_exist"))]);
        let audit = CollectAudit::default();
        let out = execute(
            &pb,
            &crate::tests::test_incident("198.51.100.9"),
            &exec,
            &audit,
        )
        .await;
        assert_eq!(out.steps[0].status, StepStatus::Failed);
        assert!(out.steps[0].message.contains("unknown skill"));
    }

    #[tokio::test]
    async fn dispatch_block_ip_without_target_fails() {
        let reg = skills::SkillRegistry::default_builtin();
        let mut inc = crate::tests::test_incident("198.51.100.9");
        inc.entities.clear(); // no IP entity -> primary_ip None
        let exec = RegistryStepExecutor {
            registry: &reg,
            trusted_ips: &[],
            dry_run: true,
            host: "h".to_string(),
            data_dir: std::env::temp_dir(),
            base_incident: inc.clone(),
            honeypot: skills::HoneypotRuntimeConfig::default(),
            ai_provider: None,
        };
        let pb = playbook("pb", vec![Step::Leaf(leaf("a", "block_ip_xdp"))]);
        let audit = CollectAudit::default();
        let out = execute(&pb, &inc, &exec, &audit).await;
        assert_eq!(out.steps[0].status, StepStatus::Failed);
        assert!(out.steps[0].message.contains("no target IP"));
    }

    #[tokio::test]
    async fn dispatch_non_block_real_skill_runs() {
        let reg = skills::SkillRegistry::default_builtin();
        let exec = registry_exec(&reg, &[], "198.51.100.9");
        let pb = playbook("pb", vec![Step::Leaf(leaf("a", "monitor_ip"))]);
        let audit = CollectAudit::default();
        let out = execute(
            &pb,
            &crate::tests::test_incident("198.51.100.9"),
            &exec,
            &audit,
        )
        .await;
        // The non-block branch ran (not gated, not virtual): success or failed.
        assert!(matches!(
            out.steps[0].status,
            StepStatus::Success | StepStatus::Failed
        ));
    }

    #[test]
    fn interpolate_str_resolves_env_var() {
        // HOME is always set in the test environment. Covers the ${env:...}
        // branch without mutating process env (set_var is unsafe in newer
        // editions, and racy across parallel tests).
        let inc = crate::tests::test_incident("9.9.9.9");
        let tctx = TriggerCtx::from_incident(&inc);
        let prev = PrevOutputs::new();
        let out = interpolate_str("home=${env:HOME}", &tctx, &prev);
        assert!(out.starts_with("home=/"), "got: {out}");
        // an unset env var resolves to empty
        let out2 = interpolate_str("x${env:IW_DEFINITELY_UNSET_VAR_xyz}y", &tctx, &prev);
        assert_eq!(out2, "xy");
    }

    #[test]
    fn interpolate_str_prev_status_and_unknown_tokens() {
        let inc = crate::tests::test_incident("1.2.3.4");
        let tctx = TriggerCtx::from_incident(&inc);
        let mut prev = PrevOutputs::new();
        let mut m = HashMap::new();
        m.insert("status".to_string(), "success".to_string());
        prev.insert("a".to_string(), m);
        assert_eq!(interpolate_str("{prev.a.status}", &tctx, &prev), "success");
        // unknown trigger key resolves to empty
        assert_eq!(interpolate_str("x{trigger.nope}y", &tctx, &prev), "xy");
        // unknown namespace with a dot is left intact
        assert_eq!(interpolate_str("{foo.bar}", &tctx, &prev), "{foo.bar}");
    }

    #[test]
    fn eval_step_condition_branches() {
        let mut inc_user = crate::tests::test_incident("1.2.3.4");
        inc_user
            .entities
            .push(innerwarden_core::entities::EntityRef::user("alice"));
        let tctx_user = TriggerCtx::from_incident(&inc_user);
        let tctx_nouser = TriggerCtx::from_incident(&crate::tests::test_incident("1.2.3.4"));
        let mut cond = serde_yaml::Mapping::new();
        cond.insert(
            serde_yaml::Value::String("target_user_present".to_string()),
            serde_yaml::Value::Bool(true),
        );
        let cond = serde_yaml::Value::Mapping(cond);
        assert!(eval_step_condition(&cond, &tctx_user));
        assert!(!eval_step_condition(&cond, &tctx_nouser));
        // unknown condition key -> unmet (safe default)
        let mut unk = serde_yaml::Mapping::new();
        unk.insert(
            serde_yaml::Value::String("same_subnet_chains_24h".to_string()),
            serde_yaml::Value::String(">= 3".to_string()),
        );
        assert!(!eval_step_condition(
            &serde_yaml::Value::Mapping(unk),
            &tctx_user
        ));
        // non-mapping condition -> unmet
        assert!(!eval_step_condition(
            &serde_yaml::Value::Bool(true),
            &tctx_user
        ));
    }

    #[test]
    fn trigger_matches_severity_and_entity() {
        let inc = crate::tests::test_incident("9.9.9.9"); // High + Ip entity
        let tctx = TriggerCtx::from_incident(&inc);
        assert!(trigger_matches(
            &Trigger::SeverityGte(Severity::Medium),
            &inc,
            &tctx
        ));
        assert!(trigger_matches(
            &Trigger::SeverityGte(Severity::High),
            &inc,
            &tctx
        ));
        assert!(!trigger_matches(
            &Trigger::SeverityGte(Severity::Critical),
            &inc,
            &tctx
        ));
        assert!(trigger_matches(
            &Trigger::EntityType(EntityType::Ip),
            &inc,
            &tctx
        ));
        assert!(!trigger_matches(
            &Trigger::EntityType(EntityType::Container),
            &inc,
            &tctx
        ));
    }

    #[test]
    fn severity_debug_arm_is_lowest_rank() {
        let mut inc = crate::tests::test_incident("9.9.9.9");
        inc.severity = innerwarden_core::event::Severity::Debug;
        let tctx = TriggerCtx::from_incident(&inc);
        assert_eq!(tctx.vars.get("severity").unwrap(), "debug");
        assert!(!trigger_matches(
            &Trigger::SeverityGte(Severity::Info),
            &inc,
            &tctx
        ));
    }

    #[test]
    fn conditions_ip_in_and_sample_rate() {
        let inc = crate::tests::test_incident("198.51.100.42");
        let tctx = TriggerCtx::from_incident(&inc);
        let inrange = Conditions {
            ip_in: vec!["198.51.100.0/24".to_string()],
            sample_rate: 1.0,
            ..Default::default()
        };
        assert!(conditions_pass(&inrange, &tctx, &[], &[], &inc));
        let outrange = Conditions {
            ip_in: vec!["10.0.0.0/8".to_string()],
            sample_rate: 1.0,
            ..Default::default()
        };
        assert!(!conditions_pass(&outrange, &tctx, &[], &[], &inc));
        // sample_rate 0.0 -> deterministic drop
        let zero = Conditions {
            sample_rate: 0.0,
            ..Default::default()
        };
        assert!(!conditions_pass(&zero, &tctx, &[], &[], &inc));
    }

    #[test]
    fn conditions_user_in_and_not_in() {
        let mut inc = crate::tests::test_incident("198.51.100.42");
        inc.entities
            .push(innerwarden_core::entities::EntityRef::user("bob"));
        let tctx = TriggerCtx::from_incident(&inc);
        let user_in = Conditions {
            user_in: vec!["bob".to_string()],
            sample_rate: 1.0,
            ..Default::default()
        };
        assert!(conditions_pass(&user_in, &tctx, &[], &[], &inc));
        let user_in_miss = Conditions {
            user_in: vec!["alice".to_string()],
            sample_rate: 1.0,
            ..Default::default()
        };
        assert!(!conditions_pass(&user_in_miss, &tctx, &[], &[], &inc));
        let user_not_in = Conditions {
            user_not_in: vec!["bob".to_string()],
            sample_rate: 1.0,
            ..Default::default()
        };
        assert!(!conditions_pass(&user_not_in, &tctx, &[], &[], &inc));
    }

    #[test]
    fn ip_in_any_named_and_literal_lists() {
        crate::cloud_safelist::init();
        assert!(ip_in_any(
            "104.16.0.1",
            &["$cloud_safelist".to_string()],
            &[]
        ));
        assert!(ip_in_any(
            "10.0.0.5",
            &["$trusted_ips".to_string()],
            &["10.0.0.0/8".to_string()]
        ));
        assert!(ip_in_any(
            "203.0.113.5",
            &["203.0.113.0/24".to_string()],
            &[]
        ));
        assert!(!ip_in_any("8.8.8.8", &["203.0.113.0/24".to_string()], &[]));
    }

    #[test]
    fn time_window_complement_and_night() {
        use chrono::TimeZone;
        let noon = chrono::Utc.with_ymd_and_hms(2026, 5, 29, 12, 0, 0).unwrap();
        assert!(time_window_ok(TimeWindow::Any, noon));
        // business + after-hours are exact complements
        assert_ne!(
            time_window_ok(TimeWindow::BusinessHours, noon),
            time_window_ok(TimeWindow::AfterHours, noon)
        );
        // 03:00 is never business hours regardless of weekday
        let night = chrono::Utc.with_ymd_and_hms(2026, 5, 29, 3, 0, 0).unwrap();
        assert!(!time_window_ok(TimeWindow::BusinessHours, night));
        assert!(time_window_ok(TimeWindow::AfterHours, night));
    }

    #[tokio::test]
    async fn nested_parallel_flattens_to_all_leaves() {
        let pb = playbook(
            "pb",
            vec![Step::Parallel(vec![
                Step::Leaf(leaf("a", "monitor_ip")),
                Step::Parallel(vec![Step::Leaf(leaf("b", "monitor_ip"))]),
            ])],
        );
        let exec = MockExec::new();
        let audit = CollectAudit::default();
        let out = execute(&pb, &crate::tests::test_incident("9.9.9.9"), &exec, &audit).await;
        assert_eq!(out.steps.len(), 2);
    }

    struct SlowExec;
    impl StepExecutor for SlowExec {
        fn dispatch<'a>(
            &'a self,
            _call: DispatchCall<'a>,
        ) -> Pin<Box<dyn Future<Output = StepRunResult> + Send + 'a>> {
            Box::pin(async move {
                tokio::time::sleep(Duration::from_secs(3)).await;
                StepRunResult {
                    status: StepStatus::Success,
                    message: "late".to_string(),
                }
            })
        }
    }

    #[tokio::test]
    async fn step_timeout_marks_failed() {
        let mut l = leaf("a", "monitor_ip");
        l.timeout_secs = 1;
        l.on_error = OnError::Continue;
        let pb = playbook("pb", vec![Step::Leaf(l)]);
        let audit = CollectAudit::default();
        let out = execute(
            &pb,
            &crate::tests::test_incident("9.9.9.9"),
            &SlowExec,
            &audit,
        )
        .await;
        assert_eq!(out.steps[0].status, StepStatus::Failed);
        assert!(out.steps[0].message.contains("timed out"));
    }

    #[tokio::test]
    async fn run_for_incident_if_enabled_respects_switch() {
        let reg = skills::SkillRegistry::default_builtin();
        let dir = tempfile::tempdir().unwrap();
        let inc = crate::tests::test_incident("198.51.100.42");
        let mut cfg: crate::config::AgentConfig = toml::from_str("").unwrap();
        cfg.responder.dry_run = true;
        cfg.playbooks.rules_dir = dir.path().join("no-such").to_string_lossy().to_string();

        // disabled -> no outcomes, no work
        cfg.playbooks.enabled = false;
        let none = run_for_incident_if_enabled(
            &inc,
            &cfg,
            dir.path(),
            &reg,
            skills::HoneypotRuntimeConfig::default(),
            None,
            None,
        )
        .await;
        assert!(none.is_empty());

        // enabled -> credential built-in matches ssh_bruteforce and runs
        cfg.playbooks.enabled = true;
        let some = run_for_incident_if_enabled(
            &inc,
            &cfg,
            dir.path(),
            &reg,
            skills::HoneypotRuntimeConfig::default(),
            None,
            None,
        )
        .await;
        assert!(
            some.iter()
                .any(|o| o.playbook_id == "pb-credential-stuffing-default"),
            "expected credential builtin to run: {some:?}"
        );
    }

    // ---- FileAudit dual-write ------------------------------------------

    #[tokio::test]
    async fn file_audit_writes_both_logs() {
        let dir = tempfile::tempdir().unwrap();
        let exec = MockExec::new();
        exec.program("kill_process", vec![ok("done")]);
        let audit = FileAudit {
            data_dir: dir.path().to_path_buf(),
            store: None,
            dry_run: true,
        };
        let pb = playbook("pb-audit", vec![Step::Leaf(leaf("a", "kill_process"))]);
        let _ = execute(&pb, &crate::tests::test_incident("9.9.9.9"), &exec, &audit).await;

        let entries: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
        assert!(
            entries.iter().any(|n| n.starts_with("playbook_steps-")),
            "playbook_steps log missing: {entries:?}"
        );
        assert!(
            entries.iter().any(|n| n.starts_with("decisions-")),
            "decisions log missing: {entries:?}"
        );
    }

    #[tokio::test]
    async fn run_for_incident_runs_matching_builtin() {
        let dir = tempfile::tempdir().unwrap();
        let registry = skills::SkillRegistry::default_builtin();
        // ssh_bruteforce incident from a clean IP matches the credential
        // builtin (no operator dir present -> only built-ins load).
        let inc = crate::tests::test_incident("198.51.100.42");
        let no_rules_dir = dir.path().join("no-such-rules-dir");
        let outcomes = run_for_incident(
            &inc,
            &no_rules_dir,
            dir.path(),
            &registry,
            &[],
            &[],
            true,
            skills::HoneypotRuntimeConfig::default(),
            None,
            None,
        )
        .await;
        assert!(
            outcomes
                .iter()
                .any(|o| o.playbook_id == "pb-credential-stuffing-default"),
            "credential builtin should have run: {outcomes:?}"
        );
    }
}
