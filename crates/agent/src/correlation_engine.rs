//! Cross-Layer Correlation Engine.
//!
//! Correlates events across all layers (firmware, kernel/eBPF, userspace,
//! network, honeypot) to detect multi-stage attack chains that no single
//! detector can see. Uses a rule-based pattern matching engine with entity
//! pivoting and configurable time windows.
//!
//! Example chain: CL-004 MSR Write → Process Injection → Log Tampering
//! Each stage produces an event in a different layer; the engine connects
//! them via shared entities (PID, IP, user) within a time window.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::info;

use innerwarden_core::entities::{EntityRef, EntityType};
use innerwarden_core::event::Severity;
use innerwarden_core::incident::Incident;

use crate::knowledge_graph::intern::intern;

// ---------------------------------------------------------------------------
// Core types
// ---------------------------------------------------------------------------

/// Which system layer produced this event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Layer {
    Firmware,
    Hypervisor,
    Kernel,
    Userspace,
    Network,
    Honeypot,
}

/// A normalized event for cross-layer correlation.
///
/// Wave 6 (AUDIT-WAVE6-INTERN, 2026-05-05): `source` and `kind` are
/// `Arc<str>` interned at insert time so the 10 000-entry
/// `event_window` (and any `AttackChain.events` clones it produces)
/// shares one allocation per distinct value. Pre-Wave-6 each entry
/// held an independent `String`, so a window full of
/// `kind = "ssh.login_failed"` paid 10 000 × (24-byte header + heap
/// chars). On the prod jeprof baseline saved 2026-05-05 these two
/// fields drove ~1 MB of duplicated heap inside the correlation
/// engine alone.
///
/// Pinned by
/// `correlation_engine::tests::correlation_event_source_and_kind_share_arc_allocations`.
///
/// `incident_id` stays `String` because it is unique per incident — no
/// dedup possible. `details` stays `serde_json::Value` (Wave 7 target).
#[derive(Debug, Clone, Serialize)]
pub struct CorrelationEvent {
    pub ts: DateTime<Utc>,
    pub layer: Layer,
    pub source: Arc<str>,
    pub kind: Arc<str>,
    pub severity: Severity,
    pub entities: Vec<EntityRef>,
    pub details: serde_json::Value,
    /// Phase 014-C: incident_id when the event originated from an Incident
    /// (set by classify_incident). Empty for raw events.
    #[serde(default)]
    pub incident_id: String,
}

/// A detected multi-stage attack chain.
#[derive(Debug, Clone, Serialize)]
pub struct AttackChain {
    pub chain_id: String,
    pub rule_id: String,
    pub rule_name: String,
    pub start_ts: DateTime<Utc>,
    pub last_ts: DateTime<Utc>,
    pub events: Vec<CorrelationEvent>,
    pub stages_matched: usize,
    pub stages_total: usize,
    pub confidence: f32,
    pub layers_involved: Vec<Layer>,
    pub severity: Severity,
    pub summary: String,
}

// ---------------------------------------------------------------------------
// Rule definitions
// ---------------------------------------------------------------------------

/// A correlation rule defines a multi-stage pattern to detect.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct CorrelationRule {
    pub id: String,
    pub name: String,
    pub stages: Vec<RuleStage>,
    /// Maximum seconds between first and last stage event.
    pub window_secs: u64,
    /// Minimum confidence to emit the chain as an incident.
    pub min_confidence: f32,
    /// Override severity when chain is detected.
    pub severity: Severity,
}

/// One stage in a correlation rule.
#[derive(Debug, Clone)]
pub struct RuleStage {
    /// Required layer (None = any layer).
    pub layer: Option<Layer>,
    /// Event kind patterns to match (glob-style: "firmware.*", "ssh_bruteforce").
    pub kind_patterns: Vec<String>,
    /// If true, this stage must share at least one entity with the previous stage.
    pub entity_must_match: bool,
}

/// Tracks an in-progress chain match.
#[derive(Debug, Clone)]
struct PendingChain {
    rule_id: String,
    matched_events: Vec<CorrelationEvent>,
    matched_entities: HashSet<String>,
    next_stage: usize,
    started_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Engine
// ---------------------------------------------------------------------------

/// The cross-layer correlation engine.
pub struct CorrelationEngine {
    /// Sliding window of recent events (all layers).
    event_window: VecDeque<CorrelationEvent>,
    /// Maximum events to retain in the window.
    max_window_size: usize,
    /// In-progress chain matches.
    pending_chains: Vec<PendingChain>,
    /// Completed chains (drained by the caller).
    completed_chains: Vec<AttackChain>,
    /// Correlation rules.
    rules: Vec<CorrelationRule>,
    /// Cooldown: avoid re-emitting the same chain within N seconds.
    chain_cooldowns: HashMap<String, DateTime<Utc>>,
    /// Chain ID counter.
    next_chain_id: u64,
}

impl CorrelationEngine {
    /// Create a new engine with the built-in rule set. Used by short-lived
    /// engines (firmware_tick, killchain_inline) and tests. Production boot
    /// uses `from_yaml_dir()`.
    #[allow(dead_code)]
    pub fn new() -> Self {
        Self::with_rules(builtin_rules())
    }

    /// Create a new engine with a custom rule set. Used by the YAML loader
    /// path (`from_yaml_dir`) and tests that need specific rules.
    pub fn with_rules(rules: Vec<CorrelationRule>) -> Self {
        Self {
            event_window: VecDeque::with_capacity(10_000),
            max_window_size: 10_000,
            pending_chains: Vec::new(),
            completed_chains: Vec::new(),
            rules,
            chain_cooldowns: HashMap::new(),
            next_chain_id: 1,
        }
    }

    /// Load rules from the YAML directory. Falls back to built-in rules
    /// on any load error so the engine never starts empty in prod.
    pub fn from_yaml_dir(rules_dir: &std::path::Path) -> Self {
        let rules = crate::correlation_engine_yaml::load_rules_dir(rules_dir).unwrap_or_else(|e| {
            tracing::warn!("correlation_engine: YAML load failed ({e}), falling back to built-in");
            builtin_rules()
        });
        Self::with_rules(rules)
    }

    /// Replace the rule set in-place. Used by hot-reload after detecting
    /// an mtime change in the YAML directory. Pending chains and cooldowns
    /// are preserved -- only the rule set itself swaps. Returns the new
    /// rule count.
    pub fn replace_rules(&mut self, rules: Vec<CorrelationRule>) -> usize {
        let count = rules.len();
        self.rules = rules;
        count
    }

    /// Feed a new event into the engine.
    ///
    /// Checks all pending chains and starts new chains if the event matches
    /// the first stage of any rule.
    pub fn observe(&mut self, event: CorrelationEvent) {
        let now = event.ts;

        // Expire old pending chains
        self.pending_chains.retain(|pc| pc.expires_at > now);

        // Expire old cooldowns
        self.chain_cooldowns.retain(|_, expires| *expires > now);

        // Try to advance existing pending chains
        let mut newly_completed = Vec::new();
        for pc in &mut self.pending_chains {
            let rule = match self.rules.iter().find(|r| r.id == pc.rule_id) {
                Some(r) => r,
                None => continue,
            };

            if pc.next_stage >= rule.stages.len() {
                continue;
            }

            let stage = &rule.stages[pc.next_stage];

            if matches_stage(stage, &event, &pc.matched_entities, &pc.rule_id) {
                pc.matched_events.push(event.clone());
                // Add all entity values to the set for next-stage matching
                for entity in &event.entities {
                    pc.matched_entities.insert(format!(
                        "{}:{}",
                        entity_type_str(&entity.r#type),
                        entity.value
                    ));
                }
                pc.next_stage += 1;

                // Check if chain is complete
                if pc.next_stage >= rule.stages.len() {
                    newly_completed.push(pc.clone());
                }
            }
        }

        // Emit completed chains
        for mut pc in newly_completed {
            let rule = match self.rules.iter().find(|r| r.id == pc.rule_id) {
                Some(r) => r,
                None => continue,
            };

            // Cooldown check: same rule + same primary entity
            let cooldown_key = format!(
                "{}:{}",
                pc.rule_id,
                pc.matched_entities.iter().next().unwrap_or(&String::new())
            );
            if self.chain_cooldowns.contains_key(&cooldown_key) {
                continue;
            }

            let chain_id = format!("CHAIN-{:04}", self.next_chain_id);
            self.next_chain_id += 1;

            let layers: Vec<Layer> = pc
                .matched_events
                .iter()
                .map(|e| e.layer)
                .collect::<HashSet<_>>()
                .into_iter()
                .collect();

            let confidence = if layers.len() >= 3 {
                0.95
            } else if layers.len() >= 2 {
                0.85
            } else {
                0.70
            };

            // 2026-05-08 (fix/chains-tab-honesty-bundle): sort by
            // event timestamp before computing start/last so the
            // duration in the chain summary can never go negative.
            // Operator's prod 2026-05-08 dashboard showed multiple
            // chains with summaries like
            // `"...: 2 stages across 1 layers in -2s"` — that
            // happened when the second stage's event arrived in
            // the matched_events vec earlier than the first stage
            // (rule order independence + event-delivery race).
            // `.first()` / `.last()` walked vec order, not time
            // order — sorting here pins the contract that duration
            // is the actual chronological window.
            pc.matched_events.sort_by_key(|e| e.ts);
            let start_ts = pc.matched_events.first().map(|e| e.ts).unwrap_or(now);
            let last_ts = pc.matched_events.last().map(|e| e.ts).unwrap_or(now);

            let summary = format!(
                "{}: {} stages across {} layers in {}s",
                rule.name,
                pc.matched_events.len(),
                layers.len(),
                (last_ts - start_ts).num_seconds()
            );

            info!(
                chain_id = %chain_id,
                rule = %rule.id,
                stages = pc.matched_events.len(),
                layers = layers.len(),
                "attack chain detected: {}",
                rule.name
            );

            self.completed_chains.push(AttackChain {
                chain_id,
                rule_id: rule.id.clone(),
                rule_name: rule.name.clone(),
                start_ts,
                last_ts,
                events: pc.matched_events,
                stages_matched: rule.stages.len(),
                stages_total: rule.stages.len(),
                confidence,
                layers_involved: layers,
                severity: rule.severity.clone(),
                summary,
            });

            // Set cooldown (10 minutes for same rule + entity)
            self.chain_cooldowns
                .insert(cooldown_key, now + chrono::Duration::seconds(600));

            // Remove the completed pending chain
            self.pending_chains
                .retain(|p| p.rule_id != pc.rule_id || p.started_at != pc.started_at);
        }

        // Try to start new chains (event matches first stage of a rule)
        for rule in &self.rules {
            let first_stage = &rule.stages[0];
            if matches_stage(first_stage, &event, &HashSet::new(), &rule.id) {
                let mut entities = HashSet::new();
                for entity in &event.entities {
                    entities.insert(format!(
                        "{}:{}",
                        entity_type_str(&entity.r#type),
                        entity.value
                    ));
                }

                self.pending_chains.push(PendingChain {
                    rule_id: rule.id.clone(),
                    matched_events: vec![event.clone()],
                    matched_entities: entities,
                    next_stage: 1,
                    started_at: now,
                    expires_at: now + chrono::Duration::seconds(rule.window_secs as i64),
                });
            }
        }

        // Add to event window
        self.event_window.push_back(event);
        while self.event_window.len() > self.max_window_size {
            self.event_window.pop_front();
        }
    }

    /// Drain completed attack chains. Caller should convert these to incidents.
    pub fn drain_completed(&mut self) -> Vec<AttackChain> {
        std::mem::take(&mut self.completed_chains)
    }

    /// Number of pending (in-progress) chains.
    #[allow(dead_code)]
    pub fn pending_count(&self) -> usize {
        self.pending_chains.len()
    }

    /// Number of rules loaded.
    #[allow(dead_code)]
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Convert an Event from the sensor into a CorrelationEvent.
    pub fn classify_event(event: &innerwarden_core::event::Event) -> CorrelationEvent {
        let layer = classify_layer(&event.source, &event.kind);
        CorrelationEvent {
            ts: event.ts,
            layer,
            source: intern(&event.source),
            kind: intern(&event.kind),
            severity: event.severity.clone(),
            entities: event.entities.clone(),
            details: event.details.clone(),
            incident_id: String::new(),
        }
    }

    /// Convert an Incident into a CorrelationEvent (using the detector kind).
    pub fn classify_incident(incident: &Incident) -> CorrelationEvent {
        let detector = crate::mitre::detector_from_incident_id(&incident.incident_id);
        let layer = classify_layer("detector", detector);
        CorrelationEvent {
            ts: incident.ts,
            layer,
            source: intern("detector"),
            kind: intern(detector),
            severity: incident.severity.clone(),
            entities: incident.entities.clone(),
            details: incident.evidence.clone(),
            incident_id: incident.incident_id.clone(),
        }
    }

    /// Create a CorrelationEvent from SMM firmware scan results.
    /// Called from `firmware_tick::process_firmware_tick` for each
    /// Critical/Warning check and each correlated threat, so CL-043
    /// (Ring -2 + Ring -1 deep compromise) can match against real
    /// firmware signal alongside hypervisor and kernel events.
    pub fn firmware_event(kind: &str, details: serde_json::Value) -> CorrelationEvent {
        CorrelationEvent {
            ts: Utc::now(),
            layer: Layer::Firmware,
            source: intern("smm"),
            kind: intern(kind),
            severity: Severity::High,
            entities: vec![],
            details,
            incident_id: String::new(),
        }
    }

    /// Create a CorrelationEvent from hypervisor audit results.
    pub fn hypervisor_event(kind: &str, details: serde_json::Value) -> CorrelationEvent {
        CorrelationEvent {
            ts: Utc::now(),
            layer: Layer::Hypervisor,
            source: intern("hypervisor"),
            kind: intern(kind),
            severity: Severity::High,
            entities: vec![],
            details,
            incident_id: String::new(),
        }
    }

    /// Create a CorrelationEvent from kill chain detection.
    pub fn killchain_event(kind: &str, details: serde_json::Value) -> CorrelationEvent {
        CorrelationEvent {
            ts: Utc::now(),
            layer: Layer::Kernel,
            source: intern("killchain"),
            kind: intern(kind),
            severity: Severity::Critical,
            entities: vec![],
            details,
            incident_id: String::new(),
        }
    }

    /// Create a CorrelationEvent from threat DNA analysis.
    pub fn dna_event(kind: &str, details: serde_json::Value) -> CorrelationEvent {
        CorrelationEvent {
            ts: Utc::now(),
            layer: Layer::Userspace,
            source: intern("dna"),
            kind: intern(kind),
            severity: Severity::Medium,
            entities: vec![],
            details,
            incident_id: String::new(),
        }
    }

    /// Create a CorrelationEvent from baseline anomaly detection.
    pub fn baseline_event(
        kind: &str,
        severity: Severity,
        entities: Vec<EntityRef>,
        details: serde_json::Value,
    ) -> CorrelationEvent {
        CorrelationEvent {
            ts: Utc::now(),
            layer: Layer::Userspace,
            source: intern("baseline"),
            kind: intern(kind),
            severity,
            entities,
            details,
            incident_id: String::new(),
        }
    }

    /// Create a CorrelationEvent from autoencoder neural anomaly.
    pub fn neural_event(
        score: f32,
        entities: Vec<EntityRef>,
        details: serde_json::Value,
    ) -> CorrelationEvent {
        let severity = if score > 0.9 {
            Severity::High
        } else if score > 0.7 {
            Severity::Medium
        } else {
            Severity::Low
        };
        CorrelationEvent {
            ts: Utc::now(),
            layer: Layer::Userspace,
            source: intern("autoencoder"),
            kind: intern("neural.anomaly"),
            severity,
            entities,
            details,
            incident_id: String::new(),
        }
    }

    /// Create a CorrelationEvent from shield escalation.
    pub fn shield_event(kind: &str, details: serde_json::Value) -> CorrelationEvent {
        CorrelationEvent {
            ts: Utc::now(),
            layer: Layer::Network,
            source: intern("shield"),
            kind: intern(kind),
            severity: Severity::High,
            entities: vec![],
            details,
            incident_id: String::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Matching logic
// ---------------------------------------------------------------------------

fn matches_stage(
    stage: &RuleStage,
    event: &CorrelationEvent,
    previous_entities: &HashSet<String>,
    rule_id: &str,
) -> bool {
    // Layer check
    if let Some(required_layer) = stage.layer {
        if event.layer != required_layer {
            return false;
        }
    }

    // Kind pattern check (any pattern matching = success)
    let kind_match = stage.kind_patterns.iter().any(|pattern| {
        if pattern.contains('*') {
            // Glob match: "firmware.*" matches "firmware.msr_write"
            let prefix = pattern.trim_end_matches('*');
            event.kind.starts_with(prefix)
        } else if pattern.contains('|') {
            // OR match: "ssh_bruteforce|credential_stuffing"
            // Wave 6: event.kind is `Arc<str>` so we deref via `&*`
            // to get a `&str` PartialEq with the trimmed pattern.
            pattern.split('|').any(|p| &*event.kind == p.trim())
        } else {
            // `*event.kind` derefs `Arc<str>` to `str`; matched against
            // `*pattern` (also `str`). The clippy `op_ref` lint flags
            // `&*event.kind` in this position so we deref directly.
            *event.kind == *pattern
        }
    });

    if !kind_match {
        return false;
    }

    // Entity matching (if required and previous entities exist)
    if stage.entity_must_match && !previous_entities.is_empty() {
        let current_entities: HashSet<String> = event
            .entities
            .iter()
            .map(|e| format!("{}:{}", entity_type_str(&e.r#type), e.value))
            .collect();

        if current_entities.is_disjoint(previous_entities) {
            return false;
        }
    }

    // Wave 8a (2026-05-04): per-rule comm suppression.
    // Suppresses chains where the originating process is a known package
    // manager / system-update tool. Without this CL-008 was blocking
    // Ubuntu mirrors, GitHub Pages, Telegram, etc. during apt upgrades
    // (the agent's own notification infra in Telegram's case).
    if event_comm_is_suppressed(rule_id, event) {
        return false;
    }

    true
}

/// Does `event.details.comm` match a suppression list? Four distinct
/// policies share this gate:
///
/// 1. **InnerWarden binary self-traffic** (Wave 8a + PR ε; rule-agnostic,
///    every rule). The originating process is one of our binaries
///    (`innerwarden-age` truncated, `innerwarden-sen`, `innerwarden-ctl`,
///    `innerwarden-watc`). These names are unambiguous - no third-party
///    process produces them - so we suppress regardless of which chain
///    wants to claim the event.
///
/// 2. **CL-008-only Tokio worker carve-out** (PR ε; CL-008 only).
///    `tokio-rt-worker` is the thread name Tokio gives every runtime
///    worker on every Tokio-based process, which means a malicious
///    Tokio app could legitimately execute under that comm. We do NOT
///    suppress it rule-agnostically, but for CL-008 specifically (the
///    "file.read + outbound connect" data-exfil chain) the false-
///    positive rate from the agent's own outbound traffic is high
///    enough to warrant suppression there. Other chains
///    (`lateral_movement`, `credential_theft`, etc.) still fire on
///    `tokio-rt-worker` if their own kind patterns match.
///
/// 3. **CL-008-only long-running service daemons** (2026-05-26;
///    CL-008 only). Web servers / PHP-FPM / databases / CrowdSec
///    legitimately read sensitive files and make outbound calls as
///    part of their normal job description. On a vanilla LAMP/LEMP
///    host this chain fired 80x in 2 min in prod before the fix.
///    See [`CL008_SERVICE_DAEMON_COMMS`].
///
/// 4. **Per-rule package manager** (Wave 8a; opt-in by `rule_id`,
///    currently only CL-008). Apt/dpkg/dnf/etc. running upgrades
///    naturally trigger CL-008's two stages. Operators may want
///    package-manager suppression for some chains and not others, so
///    this stays per-rule via [`rule_comm_suppressions`].
///
/// Returns false when the event has no `comm` field or when no list
/// matches.
pub(crate) fn event_comm_is_suppressed(rule_id: &str, event: &CorrelationEvent) -> bool {
    let Some(comm) = event.details.get("comm").and_then(|v| v.as_str()) else {
        return false;
    };
    // PR ε: rule-agnostic InnerWarden binary suppression. Pinned by
    // `innerwarden_binary_self_traffic_suppression_is_rule_agnostic`.
    if INNERWARDEN_SELF_COMMS.contains(&comm) {
        return true;
    }
    // PR ε: CL-008-only `tokio-rt-worker` carve-out. The thread name
    // is generic (every Tokio app uses it), so we deliberately do NOT
    // promote it to the rule-agnostic list - that would create a
    // blind spot for a malicious Tokio-based attacker tool. We only
    // suppress it for the rule whose FP rate makes it operationally
    // necessary. Pinned by both `cl008_suppressed_..._tokio_rt_worker`
    // and `tokio_rt_worker_only_suppressed_on_cl008_not_other_rules`.
    if rule_id == "CL-008" && comm == "tokio-rt-worker" {
        return true;
    }
    // 2026-05-26 (CL-008 saturation fix): CL-008-only long-running
    // service-daemon carve-out. Web servers / PHP-FPM / databases /
    // CrowdSec all legitimately read sensitive files and make outbound
    // connections as part of their normal work; on a typical LAMP/LEMP
    // host that produces an apache2 → php-fpm → mysqld pipeline that
    // fires CL-008 every request. Same trade-off as the package-manager
    // list: rule-specific, not rule-agnostic, so other chains
    // (lateral_movement, credential_theft, …) still see these comms.
    // Pinned by `cl008_suppressed_when_comm_is_service_daemon_*` and
    // `service_daemon_suppression_does_not_leak_to_other_rules`.
    if rule_id == "CL-008" && CL008_SERVICE_DAEMON_COMMS.contains(&comm) {
        return true;
    }
    // Wave 8a: per-rule package-manager suppression.
    rule_comm_suppressions(rule_id).contains(&comm)
}

/// Wave 8a (2026-05-04): per-rule list of `comm` values whose events
/// should NOT participate in chain matching. Returning `&[]` (the
/// default) means no suppression — events match by kind/layer/entity
/// only, as before.
///
/// Currently only CL-008 (Data Exfiltration via eBPF Sequence) opts in,
/// because that rule's two stages (sensitive file read + outbound
/// connect) trigger every package-manager run on every distro. Other
/// rules can opt in by adding a match arm here.
fn rule_comm_suppressions(rule_id: &str) -> &'static [&'static str] {
    match rule_id {
        "CL-008" => PACKAGE_MANAGER_COMMS,
        _ => &[],
    }
}

/// Wave 8a (2026-05-04): comm names of package managers and related
/// system-update tooling across the major Linux distros (and macOS
/// Homebrew, since the agent runs there too).
///
/// All entries match `event.details.comm` exactly. Linux truncates
/// `comm` to 15 characters (TASK_COMM_LEN - 1), so long names are
/// pre-truncated here (e.g. `unattended-upgrade` → `unattended-upgr`,
/// `dpkg-statoverride` → `dpkg-statoverri`). Distro-agnostic by design:
/// covers apt, dpkg, snap, dnf/yum, rpm, zypper, pacman, apk, emerge,
/// xbps, flatpak, brew, PackageKit.
const PACKAGE_MANAGER_COMMS: &[&str] = &[
    // Debian / Ubuntu — apt family
    "apt",
    "apt-get",
    "apt-cache",
    "apt-config",
    "aptitude",
    "apt-listchanges",
    "apt-listbugs",
    // Debian / Ubuntu — dpkg family (truncated forms first where >15 chars)
    "dpkg",
    "dpkg-deb",
    "dpkg-query",
    "dpkg-divert",
    "dpkg-statoverri", // dpkg-statoverride truncated
    "dpkg-trigger",
    // Debian / Ubuntu — auto-update + restart helpers
    "unattended-upgr", // unattended-upgrade truncated
    "needrestart",
    // Snap (cross-distro)
    "snap",
    "snapd",
    "snap-update-ns",
    "snap-confine",
    "snap-mgmt",
    // RHEL / Fedora / Rocky / Alma — yum / dnf family
    "yum",
    "dnf",
    "dnf5",
    "microdnf",
    "yumdownloader",
    "rpm",
    "rpm-ostree",
    // SUSE
    "zypper",
    // Arch
    "pacman",
    "pacstrap",
    "makepkg",
    "yay",
    "paru",
    // Alpine
    "apk",
    "abuild",
    // Gentoo
    "emerge",
    "ebuild",
    "portageq",
    // Void
    "xbps-install",
    "xbps-remove",
    "xbps-query",
    // Cross-distro app distribution
    "flatpak",
    // macOS
    "brew",
    // Cross-distro service-style package backends
    "PackageKit",
    "packagekitd",
];

/// 2026-05-26 (CL-008 saturation fix): comm names of long-running
/// services that legitimately read sensitive files and make outbound
/// connections as part of their normal job description. Suppressed
/// for CL-008 only.
///
/// **Why this is necessary:** prod incident on 2026-05-26 saw CL-008
/// fire 80x in 2 min on a host running a vanilla LAMP/LEMP stack.
/// The chain shape (file.read + outbound connect) is exactly what
/// `nginx → php-fpm → mysqld` produces on every HTTP request —
/// nginx reads TLS certs + access logs, php-fpm reads
/// /etc/php/*/fpm/pool.d/, mysqld reads its data files + replication
/// state. The outbound side is the response to the client plus any
/// `mysqli_connect` from PHP. None of this is exfiltration; all of
/// it lit up CL-008.
///
/// **Why per-rule and not rule-agnostic:** the safety argument from
/// PR ε still applies. `apache2` / `nginx` / `mysqld` are plausible
/// pivot targets — an attacker that hijacks the web stack and uses
/// it to exfil data should still trigger e.g. `c2_callback` (kind
/// pattern is different) or `lateral_movement` (different entity
/// shape). The carve-out only relaxes the one chain that operationally
/// over-fires on this comm set.
///
/// **Comm truncation:** Linux truncates `comm` to 15 chars
/// (TASK_COMM_LEN - 1). Every entry below is <= 15 chars, so no
/// truncation gymnastics — the kernel emits these literally as
/// written.
///
/// All entries match `event.details.comm` exactly.
const CL008_SERVICE_DAEMON_COMMS: &[&str] = &[
    // Web servers
    "apache2", // Debian / Ubuntu
    "httpd",   // RHEL / Fedora / Rocky / Alma
    "nginx",   // most distros (master + workers share comm)
    "caddy",   // increasingly common
    // PHP-FPM (every Debian-tracked version through 8.3 — older / newer
    // versions land here when their packages ship). Workers inherit the
    // master's comm because the rename happens via prctl(PR_SET_NAME)
    // in argv[0], not execve.
    "php-fpm",
    "php-fpm7.4",
    "php-fpm8.0",
    "php-fpm8.1",
    "php-fpm8.2",
    "php-fpm8.3",
    // Relational databases
    "mysqld",
    "mysqld_safe", // 11 chars
    "mariadbd",    // 8 chars (MariaDB 10.5+; older versions still use mysqld)
    "postgres",    // 8 chars (master + autovacuum + WAL writer all share comm)
    // CrowdSec — defensive tooling co-deployed with the agent that
    // legitimately reads /var/log/* and posts to its central API.
    "crowdsec",
    "cscli",
];

/// PR ε (2026-05-04): comm names of InnerWarden's own binaries.
/// Correlation chains whose originating event has one of these comms
/// are agent self-traffic and must NOT be classified as attacker
/// activity regardless of the rule that wants to claim them.
///
/// Linux truncates `comm` to 15 characters (TASK_COMM_LEN - 1), so
/// `innerwarden-agent` (17 chars) appears as `innerwarden-age` in
/// `/proc/<pid>/comm` and in eBPF events. We pre-truncate here so
/// the exact-match comparison works against what the kernel actually
/// produces - the full untruncated names would never match.
///
/// **Deliberately excludes `tokio-rt-worker`**: that thread name is
/// emitted by every Tokio-based process, not just ours. Including it
/// here would let a malicious Tokio app bypass every correlation
/// rule. The CL-008-specific carve-out for `tokio-rt-worker` lives
/// inline in `event_comm_is_suppressed` instead, so it only relaxes
/// the one rule with a documented FP rate from the agent's own
/// outbound calls.
///
/// Distinct from the existing graph-level
/// [`crate::knowledge_graph::ingestion::is_self_traffic_incident`]
/// (which catches incidents AFTER they have been ingested into the
/// knowledge graph): this list short-circuits the chain at correlation
/// time so the chain is never CREATED to begin with.
///
/// AUDIT-CL008-SELF (2026-05-04 prod): pre-fix CL-008 fired 72x in
/// 30 min on prod, blocking outbound to 208.95.112.1 (an external
/// dependency the agent reaches), to Telegram, and to the host's
/// own cloud provider. All of these had `comm = tokio-rt-worker`
/// from the agent's outbound connect path; this list + the
/// CL-008 carve-out together stop them upstream of the chain.
const INNERWARDEN_SELF_COMMS: &[&str] = &[
    "innerwarden-age",  // innerwarden-agent (17 chars truncated)
    "innerwarden-sen",  // innerwarden-sensor (18 chars truncated)
    "innerwarden-ctl",  // 15 chars - exact
    "innerwarden-watc", // innerwarden-watchdog (20 chars truncated)
];

fn entity_type_str(et: &EntityType) -> &'static str {
    match et {
        EntityType::Ip => "ip",
        EntityType::User => "user",
        EntityType::Container => "container",
        EntityType::Path => "path",
        EntityType::Service => "service",
    }
}

fn classify_layer(source: &str, kind: &str) -> Layer {
    // Check hypervisor (Ring -1)
    if source == "hypervisor"
        || kind.starts_with("hypervisor.")
        || kind.contains("cpuid")
        || kind.contains("vmexit")
        || kind.contains("blue_pill")
    {
        Layer::Hypervisor
    // Check firmware (Ring -2)
    } else if source == "smm"
        || kind.starts_with("firmware.")
        || kind.contains("msr")
        || kind.contains("acpi")
        || kind.contains("uefi")
        || kind.contains("tpm")
        || kind.contains("spi")
    {
        Layer::Firmware
    // Network before Kernel (eBPF can produce network events)
    } else if kind.starts_with("network.")
        || kind.starts_with("dns.")
        || kind.contains("outbound")
        || kind.contains("bind_listen")
    {
        Layer::Network
    } else if kind.starts_with("honeypot") {
        Layer::Honeypot
    } else if source == "ebpf"
        || source == "killchain"
        || kind.starts_with("killchain.")
        || kind.starts_with("privilege.")
        || kind.starts_with("lsm.")
        || kind == "kernel_module_load"
        || kind.starts_with("dup.")
        || kind == "mprotect"
    {
        Layer::Kernel
    } else {
        Layer::Userspace
    }
}

// ---------------------------------------------------------------------------
// Built-in rules
// ---------------------------------------------------------------------------
//
// The 68 cross-layer correlation rules live in
// `correlation_engine_yaml/builtin/00-builtin.yml` (embedded via include_str!).
// Spec 055 Phase 5 (2026-05-28) replaced the previous ~1770-line `builtin_rules()`
// Rust literal with a thin wrapper around the YAML loader so the YAML file is
// the single source of truth. The wrapper signature is preserved so existing
// test callers (firmware_tick, killchain_inline, tests.rs, this module's own
// tests) need no changes.

#[cfg(test)]
pub fn builtin_rules_for_test() -> Vec<CorrelationRule> {
    builtin_rules()
}

fn builtin_rules() -> Vec<CorrelationRule> {
    crate::correlation_engine_yaml::load_builtin()
        .expect("00-builtin.yml is embedded and tested; parse failure is a build-time bug")
}

impl CorrelationEngine {
    /// Check for Multi-Low elevation: 3+ different Low detectors for the same
    /// IP within 600 seconds should elevate to High.
    ///
    /// Called after observe(). Returns an AttackChain if the threshold is met.
    pub fn check_multi_low_elevation(&mut self) -> Option<AttackChain> {
        let now = Utc::now();
        let cutoff = now - chrono::Duration::seconds(600);

        // Group recent low-severity events by IP
        let mut ip_detectors: HashMap<String, Vec<CorrelationEvent>> = HashMap::new();
        for event in &self.event_window {
            if event.ts < cutoff {
                continue;
            }
            if event.severity != Severity::Low {
                continue;
            }
            for entity in &event.entities {
                if entity.r#type == EntityType::Ip {
                    ip_detectors
                        .entry(entity.value.clone())
                        .or_default()
                        .push(event.clone());
                }
            }
        }

        for (ip, events) in &ip_detectors {
            // Wave 6: e.kind is `Arc<str>` so deref via `&*` to get `&str`.
            // Avoids the unstable `Arc<str>::as_str` (Rust feature gate
            // `str_as_str`).
            let unique_kinds: HashSet<&str> = events.iter().map(|e| &*e.kind).collect();
            if unique_kinds.len() >= 3 {
                let cooldown_key = format!("CL-010:ip:{ip}");
                if self.chain_cooldowns.contains_key(&cooldown_key) {
                    continue;
                }

                let chain_id = format!("CHAIN-{:04}", self.next_chain_id);
                self.next_chain_id += 1;

                let summary = format!(
                    "Multi-vector reconnaissance from {}: {} different low-severity detectors in 10 minutes ({})",
                    ip,
                    unique_kinds.len(),
                    unique_kinds.into_iter().collect::<Vec<_>>().join(", ")
                );

                info!(chain_id = %chain_id, ip = %ip, "CL-010 multi-low elevation");

                self.chain_cooldowns
                    .insert(cooldown_key, now + chrono::Duration::seconds(600));

                return Some(AttackChain {
                    chain_id,
                    rule_id: "CL-010".into(),
                    rule_name: "Multi-Low Severity Elevation".into(),
                    start_ts: events.first().map(|e| e.ts).unwrap_or(now),
                    last_ts: events.last().map(|e| e.ts).unwrap_or(now),
                    events: events.clone(),
                    stages_matched: events.len(),
                    stages_total: events.len(),
                    confidence: 0.75,
                    layers_involved: events
                        .iter()
                        .map(|e| e.layer)
                        .collect::<HashSet<_>>()
                        .into_iter()
                        .collect(),
                    severity: Severity::High,
                    summary,
                });
            }
        }

        None
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use innerwarden_core::entities::EntityRef;
    use innerwarden_core::event::Event;

    /// Wave 6 (AUDIT-WAVE6-INTERN) anchor: pushing 10 000 events that
    /// share `source`/`kind` strings into a `CorrelationEngine`'s
    /// `event_window` must produce one Arc<str> per distinct value,
    /// not 10 000 independent String allocations. Verified by
    /// pointer-equality on the resulting `Arc<str>` fields.
    ///
    /// Pre-Wave-6 the type was `String`, so `event_window` of length
    /// 10 000 with kind="ssh.login_failed" paid ~250 KB just for that
    /// one repeated string. With `Arc<str>` interning the same window
    /// pays one 24-byte Arc + one 16-byte heap allocation, full stop.
    #[test]
    fn correlation_event_source_and_kind_share_arc_allocations() {
        // Build N CorrelationEvents from raw `Event` shapes that share
        // source/kind. The CorrelationEvent::From<Event> impl is the
        // production interning point.
        let mut engine = CorrelationEngine::new();
        for _ in 0..1000 {
            let raw_event = Event {
                ts: Utc::now(),
                host: "h".into(),
                source: "auth_log".into(),
                kind: "ssh.login_failed".into(),
                severity: Severity::Medium,
                summary: "s".into(),
                details: serde_json::json!({}),
                tags: vec![],
                entities: vec![EntityRef::ip("1.2.3.4")],
            };
            let ce = CorrelationEngine::classify_event(&raw_event);
            engine.event_window.push_back(ce);
        }
        assert_eq!(engine.event_window.len(), 1000);
        // Pointer-equality on every entry's source — they MUST share
        // the same Arc<str> backing allocation. If the impl ever
        // regresses to `String`, this fails: two `String` instances
        // never share heap memory even when their content matches.
        let first_source = engine.event_window[0].source.clone();
        let first_kind = engine.event_window[0].kind.clone();
        for (i, ce) in engine.event_window.iter().enumerate() {
            assert!(
                std::sync::Arc::ptr_eq(&ce.source, &first_source),
                "event[{i}].source should share Arc with event[0].source — \
                 the interner deduplicates 'auth_log' across the window"
            );
            assert!(
                std::sync::Arc::ptr_eq(&ce.kind, &first_kind),
                "event[{i}].kind should share Arc with event[0].kind — \
                 the interner deduplicates 'ssh.login_failed' across the window"
            );
        }
    }

    fn make_event(layer: Layer, kind: &str, ip: &str) -> CorrelationEvent {
        CorrelationEvent {
            ts: Utc::now(),
            layer,
            source: intern("test"),
            kind: intern(kind),
            severity: Severity::Medium,
            entities: vec![EntityRef::ip(ip)],
            details: serde_json::json!({}),
            incident_id: String::new(),
        }
    }

    fn make_event_at(layer: Layer, kind: &str, ip: &str, ts: DateTime<Utc>) -> CorrelationEvent {
        CorrelationEvent {
            ts,
            layer,
            source: intern("test"),
            kind: intern(kind),
            severity: Severity::Medium,
            entities: vec![EntityRef::ip(ip)],
            details: serde_json::json!({}),
            incident_id: String::new(),
        }
    }

    #[test]
    fn engine_starts_empty() {
        let engine = CorrelationEngine::new();
        // 47 original (CL-001 → CL-047) + 20 spec 050-PR7 (CL-051 → CL-070)
        // + CL-071 (kernel devnode exposure chain)
        // + CL-072 (Spec 070 privilege-provenance → goal-action chain).
        assert_eq!(engine.rule_count(), 69);
        assert_eq!(engine.pending_count(), 0);
    }

    #[test]
    fn single_event_starts_pending_chain() {
        let mut engine = CorrelationEngine::new();
        let ev = make_event(Layer::Firmware, "firmware.msr_write", "10.0.0.1");
        engine.observe(ev);

        // Should have started CL-001 and CL-004 (both start with firmware.*)
        assert!(engine.pending_count() >= 1);
        assert!(engine.drain_completed().is_empty());
    }

    /// 2026-05-08 anchor (fix/chains-tab-honesty-bundle): when the
    /// engine completes a chain whose stage events arrived in the
    /// `matched_events` vec out of chronological order (rule order
    /// independence + event-delivery race), the duration in the
    /// summary string MUST NOT go negative. Operator's prod
    /// 2026-05-08 dashboard had multiple chains with summaries like
    /// `"...: 2 stages across 1 layers in -2s"`. The fix sorts
    /// `matched_events` by `ts` before computing `start_ts` and
    /// `last_ts` so the duration is the actual chronological window.
    #[test]
    fn complete_chain_summary_duration_is_nonnegative_with_out_of_order_stage_events() {
        let mut engine = CorrelationEngine::new();
        let ip = "10.0.0.1";
        let later = Utc::now();
        let earlier = later - chrono::Duration::seconds(10);

        // Feed stage 2's event FIRST (earlier in time), then stage 1
        // arriving LATER but with an EARLIER timestamp. The ordering
        // here mimics what happens when events of the same logical
        // attack arrive on parallel channels and the second one to
        // be observed has the earlier wall-clock ts.
        let mut e2 = make_event_at(Layer::Userspace, "ssh_bruteforce", ip, later);
        e2.severity = Severity::High;
        engine.observe(make_event_at(Layer::Network, "port_scan", ip, later));
        let _ = engine.drain_completed();
        engine.observe(make_event_at(
            Layer::Network,
            "data_exfiltration",
            ip,
            earlier,
        ));

        for chain in engine.drain_completed() {
            let secs = (chain.last_ts - chain.start_ts).num_seconds();
            assert!(
                secs >= 0,
                "chain duration MUST NOT go negative — got {} seconds for rule {} \
                 (summary: {:?})",
                secs,
                chain.rule_id,
                chain.summary
            );
            // Summary string must also reflect the non-negative duration.
            assert!(
                !chain.summary.contains("in -"),
                "chain summary must not contain a negative duration token: {:?}",
                chain.summary
            );
        }
    }

    #[test]
    fn complete_chain_cl002_recon_to_exfil() {
        let mut engine = CorrelationEngine::new();
        let ip = "10.0.0.1";

        // Stage 1: port_scan
        engine.observe(make_event(Layer::Network, "port_scan", ip));
        let _ = engine.drain_completed(); // may trigger partial matches

        // Stage 2: ssh_bruteforce (same IP)
        engine.observe(make_event(Layer::Userspace, "ssh_bruteforce", ip));
        let _ = engine.drain_completed(); // CL-025 may trigger here

        // Stage 3: data_exfiltration (same IP)
        engine.observe(make_event(Layer::Network, "data_exfiltration", ip));

        let chains = engine.drain_completed();
        assert!(
            chains.iter().any(|c| c.rule_id == "CL-002"),
            "expected CL-002 in {:?}",
            chains.iter().map(|c| &c.rule_id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn chain_requires_entity_match() {
        let mut engine = CorrelationEngine::new();

        // Stage 1: port_scan from IP A
        engine.observe(make_event(Layer::Network, "port_scan", "10.0.0.1"));

        // Stage 2: ssh_bruteforce from IP B (different IP — should NOT advance CL-002)
        engine.observe(make_event(Layer::Userspace, "ssh_bruteforce", "10.0.0.2"));

        // Stage 3: data_exfiltration from IP B
        engine.observe(make_event(Layer::Network, "data_exfiltration", "10.0.0.2"));

        // CL-002 should NOT complete (IP mismatch between stage 1 and 2)
        let chains = engine.drain_completed();
        assert!(chains.iter().all(|c| c.rule_id != "CL-002"));
    }

    #[test]
    fn chain_expires_after_window() {
        let mut engine = CorrelationEngine::new();
        let ip = "10.0.0.1";
        let now = Utc::now();

        // Stage 1 at T=0
        engine.observe(make_event_at(Layer::Network, "port_scan", ip, now));

        // Stage 2 at T=2000s (beyond CL-002 window of 1800s)
        let later = now + chrono::Duration::seconds(2000);
        engine.observe(make_event_at(Layer::Userspace, "ssh_bruteforce", ip, later));

        // Pending chain should have expired
        // New chain started from stage 2, but stage 3 not met
        let chains = engine.drain_completed();
        assert!(chains.is_empty());
    }

    #[test]
    fn multi_low_elevation() {
        let mut engine = CorrelationEngine::new();
        let ip = "10.0.0.1";

        // 3 different low-severity detectors for the same IP
        let mut ev1 = make_event(Layer::Network, "port_scan", ip);
        ev1.severity = Severity::Low;
        engine.observe(ev1);

        let mut ev2 = make_event(Layer::Userspace, "user_agent_scanner", ip);
        ev2.severity = Severity::Low;
        engine.observe(ev2);

        let mut ev3 = make_event(Layer::Network, "web_scan", ip);
        ev3.severity = Severity::Low;
        engine.observe(ev3);

        let chain = engine.check_multi_low_elevation();
        assert!(chain.is_some());
        let chain = chain.unwrap();
        assert_eq!(chain.rule_id, "CL-010");
        assert_eq!(chain.severity, Severity::High);
    }

    #[test]
    fn multi_low_needs_3_different_kinds() {
        let mut engine = CorrelationEngine::new();
        let ip = "10.0.0.1";

        // Same kind twice + one different = only 2 unique kinds
        let mut ev1 = make_event(Layer::Network, "port_scan", ip);
        ev1.severity = Severity::Low;
        engine.observe(ev1);

        let mut ev2 = make_event(Layer::Network, "port_scan", ip);
        ev2.severity = Severity::Low;
        engine.observe(ev2);

        let mut ev3 = make_event(Layer::Userspace, "web_scan", ip);
        ev3.severity = Severity::Low;
        engine.observe(ev3);

        let chain = engine.check_multi_low_elevation();
        assert!(chain.is_none());
    }

    #[test]
    fn classify_layer_firmware() {
        assert_eq!(classify_layer("smm", "firmware.check"), Layer::Firmware);
        assert_eq!(
            classify_layer("sensor", "firmware.msr_write"),
            Layer::Firmware
        );
    }

    #[test]
    fn classify_layer_kernel() {
        assert_eq!(
            classify_layer("ebpf", "privilege.escalation"),
            Layer::Kernel
        );
    }

    #[test]
    fn classify_layer_network() {
        assert_eq!(
            classify_layer("ebpf", "network.outbound_connect"),
            Layer::Network
        );
    }

    #[test]
    fn classify_layer_honeypot() {
        assert_eq!(classify_layer("honeypot", "honeypot_ssh"), Layer::Honeypot);
    }

    #[test]
    fn cooldown_prevents_duplicate_chains() {
        let mut engine = CorrelationEngine::new();
        let ip = "10.0.0.1";

        // Complete CL-002 first time (may also trigger CL-025)
        engine.observe(make_event(Layer::Network, "port_scan", ip));
        engine.observe(make_event(Layer::Userspace, "ssh_bruteforce", ip));
        engine.observe(make_event(Layer::Network, "data_exfiltration", ip));
        let chains = engine.drain_completed();
        assert!(!chains.is_empty(), "expected at least CL-002");
        assert!(chains.iter().any(|c| c.rule_id == "CL-002"));

        // Try same sequence again — should be suppressed by cooldown
        engine.observe(make_event(Layer::Network, "port_scan", ip));
        engine.observe(make_event(Layer::Userspace, "ssh_bruteforce", ip));
        engine.observe(make_event(Layer::Network, "data_exfiltration", ip));
        assert_eq!(engine.drain_completed().len(), 0);
    }

    #[test]
    fn glob_pattern_matching() {
        let stage = RuleStage {
            layer: None,
            kind_patterns: vec!["firmware.*".into()],
            entity_must_match: false,
        };
        let ev = make_event(Layer::Firmware, "firmware.msr_write", "10.0.0.1");
        assert!(matches_stage(&stage, &ev, &HashSet::new(), "test"));

        let ev2 = make_event(Layer::Kernel, "privilege.escalation", "10.0.0.1");
        assert!(!matches_stage(&stage, &ev2, &HashSet::new(), "test"));
    }

    #[test]
    fn or_pattern_matching() {
        let stage = RuleStage {
            layer: None,
            kind_patterns: vec!["ssh_bruteforce|credential_stuffing".into()],
            entity_must_match: false,
        };
        let ev1 = make_event(Layer::Userspace, "ssh_bruteforce", "10.0.0.1");
        assert!(matches_stage(&stage, &ev1, &HashSet::new(), "test"));

        let ev2 = make_event(Layer::Userspace, "credential_stuffing", "10.0.0.1");
        assert!(matches_stage(&stage, &ev2, &HashSet::new(), "test"));

        let ev3 = make_event(Layer::Userspace, "port_scan", "10.0.0.1");
        assert!(!matches_stage(&stage, &ev3, &HashSet::new(), "test"));
    }

    // Wave 8a anchor (2026-05-04): operator-hit prod bug — CL-008
    // (Data Exfiltration via eBPF Sequence) blocked Ubuntu archive
    // mirrors, GitHub Pages CDN, Telegram (the agent's own notification
    // infra) and Oracle Cloud during a routine `apt upgrade` on
    // 2026-05-04 (32 critical incidents in one day, all auto-block via
    // UFW with dry_run=false). Root cause: the rule's stages
    // (file.read_access + network.outbound_connect) trigger on every
    // package-manager run that opens /etc/* and connects to a mirror.
    // This anchor pins the per-rule comm suppression that makes
    // CL-008 ignore events whose `details.comm` is a known package
    // manager. It is distro-agnostic (covers apt/dpkg/snap/dnf/yum/
    // rpm/zypper/pacman/apk/emerge/xbps/flatpak/brew/PackageKit).
    #[test]
    fn cl008_does_not_match_when_originating_process_is_a_package_manager() {
        // Ubuntu apt upgrade reading /var/cache/apt files and connecting
        // to archive.ubuntu.com (91.189.91.46 = real prod block).
        let mut ev_read = make_event(Layer::Userspace, "file.read_access", "127.0.0.1");
        ev_read.details =
            serde_json::json!({"pid": 1234, "comm": "apt-get", "path": "/etc/apt/sources.list"});
        let mut ev_connect = make_event(Layer::Network, "network.outbound_connect", "91.189.91.46");
        ev_connect.details = serde_json::json!({"pid": 1234, "comm": "apt-get", "dst_ip": "91.189.91.46", "dst_port": 80});

        let stages = &[
            RuleStage {
                layer: None,
                kind_patterns: vec!["file.read_access".into()],
                entity_must_match: false,
            },
            RuleStage {
                layer: Some(Layer::Network),
                kind_patterns: vec!["network.outbound_connect".into()],
                entity_must_match: true,
            },
        ];

        // CL-008 must reject both stages when comm is apt-get (suppression active).
        assert!(
            !matches_stage(&stages[0], &ev_read, &HashSet::new(), "CL-008"),
            "CL-008 stage 1 must NOT match apt-get reading /etc/apt — \
             that's a package upgrade, not exfil. Pinned by Wave 8a after \
             the 2026-05-04 prod incident where 32 critical chains fired \
             during apt upgrade and blocked Ubuntu mirrors via UFW."
        );

        let mut entities: HashSet<String> = HashSet::new();
        entities.insert("ip:91.189.91.46".to_string());
        assert!(
            !matches_stage(&stages[1], &ev_connect, &entities, "CL-008"),
            "CL-008 stage 2 must NOT match apt-get connecting to a \
             repository mirror. See ANCHOR_TESTS.md Wave 8a entry."
        );
    }

    #[test]
    fn cl008_still_matches_for_non_package_manager_processes() {
        // Same shape as the test above but the comm is a generic shell —
        // the rule MUST still fire here; suppression is a tight allowlist,
        // not a hole that disables the chain.
        let mut ev_read = make_event(Layer::Userspace, "file.read_access", "127.0.0.1");
        ev_read.details = serde_json::json!({"pid": 999, "comm": "bash", "path": "/etc/shadow"});
        let mut ev_connect = make_event(Layer::Network, "network.outbound_connect", "203.0.113.7");
        ev_connect.details = serde_json::json!({"pid": 999, "comm": "bash", "dst_ip": "203.0.113.7", "dst_port": 4444});

        let stage1 = RuleStage {
            layer: None,
            kind_patterns: vec!["file.read_access".into()],
            entity_must_match: false,
        };
        let stage2 = RuleStage {
            layer: Some(Layer::Network),
            kind_patterns: vec!["network.outbound_connect".into()],
            entity_must_match: true,
        };

        assert!(matches_stage(&stage1, &ev_read, &HashSet::new(), "CL-008"));

        let mut entities: HashSet<String> = HashSet::new();
        entities.insert("ip:203.0.113.7".to_string());
        assert!(matches_stage(&stage2, &ev_connect, &entities, "CL-008"));
    }

    // Wave 8a (2026-05-04): unattended-upgrade and dpkg-statoverride
    // are both >15 chars. Linux truncates `comm` at TASK_COMM_LEN-1 = 15.
    // The suppression list MUST contain the truncated forms or the bug
    // returns silently for anyone running unattended-upgrades (the Ubuntu
    // default, including the prod host that hit this on 2026-05-04).
    #[test]
    fn cl008_suppression_handles_15char_truncated_comms() {
        for comm in &["unattended-upgr", "dpkg-statoverri", "snap-update-ns"] {
            let mut ev = make_event(Layer::Userspace, "file.read_access", "127.0.0.1");
            ev.details = serde_json::json!({"pid": 1, "comm": comm, "path": "/etc/passwd"});
            let stage = RuleStage {
                layer: None,
                kind_patterns: vec!["file.read_access".into()],
                entity_must_match: false,
            };
            assert!(
                !matches_stage(&stage, &ev, &HashSet::new(), "CL-008"),
                "comm {comm:?} (truncated at 15 chars by the Linux kernel) \
                 must be in PACKAGE_MANAGER_COMMS — see neighbour comments."
            );
        }
    }

    // Wave 8a (2026-05-04): suppression is opt-in by rule_id. Other
    // chains must still fire on package-manager activity if their kind
    // patterns match — we only carve out CL-008 today.
    #[test]
    fn comm_suppression_does_not_leak_to_other_rules() {
        let mut ev = make_event(Layer::Userspace, "file.read_access", "127.0.0.1");
        ev.details = serde_json::json!({"pid": 1, "comm": "apt-get", "path": "/etc/passwd"});
        let stage = RuleStage {
            layer: None,
            kind_patterns: vec!["file.read_access".into()],
            entity_must_match: false,
        };
        // A made-up rule id must NOT inherit CL-008's suppression list.
        assert!(matches_stage(&stage, &ev, &HashSet::new(), "CL-XXX"));
        // The dedicated helper agrees.
        assert!(!event_comm_is_suppressed("CL-XXX", &ev));
        assert!(event_comm_is_suppressed("CL-008", &ev));
    }

    #[test]
    fn cl008_no_comm_field_does_not_panic_and_falls_through() {
        // Real events from older sensors might not carry `comm`. Make sure
        // suppression returns false (event proceeds to normal kind/entity
        // matching) instead of panicking or accidentally suppressing.
        let mut ev = make_event(Layer::Userspace, "file.read_access", "127.0.0.1");
        ev.details = serde_json::json!({"pid": 1, "path": "/etc/passwd"});
        assert!(!event_comm_is_suppressed("CL-008", &ev));
    }

    // ── PR ε (2026-05-04) — InnerWarden self-traffic suppression ──────
    //
    // Pre-fix the prod CL-008 was firing 72x in 30 min and blocking
    // outbound to:
    //   - 208.95.112.1 (a real external dependency the agent reaches)
    //   - 149.154.166.110 (Telegram - agent's own notification infra,
    //     would have been blocked but for the operator's allowlist)
    //   - 147.154.x (Oracle Cloud - the agent's OWN cloud provider)
    // All had comm = tokio-rt-worker from the agent's outbound connect
    // path. Wave 8a's PACKAGE_MANAGER_COMMS only covered apt/dpkg/etc.;
    // these anchors pin the broader self-traffic carve-out.

    #[test]
    fn cl008_suppressed_when_originating_comm_is_innerwarden_agent() {
        // Truncated comm shape that the kernel actually emits
        // (TASK_COMM_LEN - 1 = 15 chars, so `innerwarden-agent` becomes
        // `innerwarden-age`). The agent's outbound call to e.g. AbuseIPDB
        // must NOT trigger CL-008 even though the chain shape (file.read
        // + outbound connect) technically matches.
        let mut ev_read = make_event(Layer::Userspace, "file.read_access", "127.0.0.1");
        ev_read.details = serde_json::json!({
            "pid": 12345, "comm": "innerwarden-age", "path": "/etc/innerwarden/license.key"
        });
        let mut ev_connect = make_event(Layer::Network, "network.outbound_connect", "208.95.112.1");
        ev_connect.details = serde_json::json!({
            "pid": 12345, "comm": "innerwarden-age", "dst_ip": "208.95.112.1", "dst_port": 443
        });

        assert!(
            event_comm_is_suppressed("CL-008", &ev_read),
            "innerwarden-age (truncated) reading the license file must be suppressed"
        );
        assert!(
            event_comm_is_suppressed("CL-008", &ev_connect),
            "innerwarden-age (truncated) outbound connect must be suppressed"
        );
    }

    #[test]
    fn cl008_suppressed_when_originating_comm_is_tokio_rt_worker() {
        // Tokio runtime workers carry the literal string `tokio-rt-worker`
        // (15 chars exactly). The agent's HTTP / Redis / DNS calls all
        // happen on these threads; the eBPF connect() events therefore
        // carry `comm = tokio-rt-worker` in their details. The exact
        // shape that drove the AUDIT-CL008-SELF prod incident.
        let mut ev = make_event(
            Layer::Network,
            "network.outbound_connect",
            "149.154.166.110",
        );
        ev.details = serde_json::json!({
            "pid": 12346, "comm": "tokio-rt-worker", "dst_ip": "149.154.166.110", "dst_port": 443
        });
        assert!(
            event_comm_is_suppressed("CL-008", &ev),
            "tokio-rt-worker outbound to Telegram (149.154.166.110) must be suppressed"
        );
    }

    #[test]
    fn innerwarden_binary_self_traffic_suppression_is_rule_agnostic() {
        // PR ε: unlike the package-manager carve-out (Wave 8a, opt-in by
        // rule_id), suppression for our OWN binary names applies to EVERY
        // rule. A chain that wants to claim agent self-traffic for any
        // reason is wrong about the threat model. The binary names are
        // unambiguous - no third-party process produces `innerwarden-age`
        // - so the rule-agnostic suppression is safe.
        //
        // Anti-regression for accidentally attaching the list to
        // `rule_comm_suppressions` (which would scope it to CL-008 only).
        let mut ev = make_event(Layer::Network, "network.outbound_connect", "147.154.234.47");
        ev.details = serde_json::json!({
            "pid": 12347, "comm": "innerwarden-age", "dst_ip": "147.154.234.47", "dst_port": 443
        });
        for rule_id in &["CL-001", "CL-002", "CL-008", "CL-011", "CL-XXX-future"] {
            assert!(
                event_comm_is_suppressed(rule_id, &ev),
                "innerwarden-age outbound must be suppressed regardless of rule_id (rule={rule_id:?})"
            );
        }
    }

    #[test]
    fn tokio_rt_worker_only_suppressed_on_cl008_not_other_rules() {
        // PR ε: `tokio-rt-worker` is the thread name Tokio gives every
        // runtime worker, NOT something specific to the InnerWarden
        // agent. If a malicious Tokio-based attacker tool fires e.g. a
        // credential-theft chain (CL-011) using this same comm, we
        // MUST still see the chain. The carve-out is deliberately
        // CL-008-only because that one rule has a documented prod FP
        // rate from the agent's own outbound calls - all other rules
        // see `tokio-rt-worker` as a normal comm.
        //
        // Anti-regression for promoting `tokio-rt-worker` to
        // `INNERWARDEN_SELF_COMMS` (which would create a workspace-wide
        // blind spot for any Tokio-based malware).
        let mut ev = make_event(Layer::Network, "network.outbound_connect", "203.0.113.99");
        ev.details = serde_json::json!({
            "pid": 999, "comm": "tokio-rt-worker", "dst_ip": "203.0.113.99", "dst_port": 4444
        });

        // CL-008: suppressed (the documented FP class).
        assert!(
            event_comm_is_suppressed("CL-008", &ev),
            "CL-008 must suppress tokio-rt-worker (matches PR ε docs)"
        );
        // Every other rule: NOT suppressed - the chain still has to
        // fire if the kind patterns / entities line up.
        for rule_id in &["CL-001", "CL-002", "CL-011", "CL-014", "CL-XXX-future"] {
            assert!(
                !event_comm_is_suppressed(rule_id, &ev),
                "rule {rule_id:?} must NOT suppress tokio-rt-worker - this comm is not InnerWarden-specific"
            );
        }
    }

    // ── 2026-05-26 — CL-008 saturation fix: service-daemon suppression ──
    //
    // Prod 2026-05-26: CL-008 fired 80x in 2 min on a host running a
    // vanilla LAMP/LEMP stack. Every nginx → php-fpm → mysqld pipeline
    // matched the chain shape (file.read + outbound connect) because
    // that is literally how a PHP-backed HTTP request works. Pre-this
    // fix the suppression list only covered package managers + Tokio
    // workers + InnerWarden binaries; web/db daemons were left out.

    #[test]
    fn cl008_suppressed_when_comm_is_service_daemon_web_server() {
        // Apache (apache2 on Debian/Ubuntu, httpd on RHEL/Fedora/Rocky),
        // nginx, and Caddy all fall into this bucket. The originating
        // event in prod was `nginx` reading the TLS private key, but
        // any of the four would have produced the same chain.
        for comm in &["apache2", "httpd", "nginx", "caddy"] {
            let mut ev = make_event(Layer::Userspace, "file.read_access", "127.0.0.1");
            ev.details = serde_json::json!({
                "pid": 1, "comm": comm, "path": "/etc/letsencrypt/live/example.com/privkey.pem"
            });
            assert!(
                event_comm_is_suppressed("CL-008", &ev),
                "web server {comm:?} reading TLS private key must be suppressed for CL-008 — \
                 it does this on every cert reload, not as exfiltration"
            );
        }
    }

    #[test]
    fn cl008_suppressed_when_comm_is_service_daemon_php_fpm() {
        // PHP-FPM master + workers all carry the same `comm` because
        // the worker rename happens via PR_SET_NAME on argv[0], not
        // execve. Every supported Debian-packaged version belongs here.
        for comm in &[
            "php-fpm",
            "php-fpm7.4",
            "php-fpm8.0",
            "php-fpm8.1",
            "php-fpm8.2",
            "php-fpm8.3",
        ] {
            let mut ev = make_event(Layer::Network, "network.outbound_connect", "10.0.0.5");
            ev.details = serde_json::json!({
                "pid": 1, "comm": comm, "dst_ip": "10.0.0.5", "dst_port": 3306
            });
            assert!(
                event_comm_is_suppressed("CL-008", &ev),
                "PHP-FPM {comm:?} mysqli_connect to MySQL must be suppressed for CL-008 — \
                 it does this on every HTTP request that hits a DB"
            );
        }
    }

    #[test]
    fn cl008_suppressed_when_comm_is_service_daemon_database() {
        // mysqld + the newer mariadbd + Postgres. All three legitimately
        // read their own data files + emit outbound for replication,
        // backups, or — for Postgres — pg_basebackup / pglogical.
        for comm in &["mysqld", "mysqld_safe", "mariadbd", "postgres"] {
            let mut ev = make_event(Layer::Userspace, "file.read_access", "127.0.0.1");
            ev.details = serde_json::json!({
                "pid": 1, "comm": comm, "path": "/var/lib/mysql/users/users.ibd"
            });
            assert!(
                event_comm_is_suppressed("CL-008", &ev),
                "database daemon {comm:?} reading its own data file must be suppressed for CL-008"
            );
        }
    }

    #[test]
    fn cl008_suppressed_when_comm_is_service_daemon_crowdsec() {
        // CrowdSec (`crowdsec`) + its CLI (`cscli`) are defensive
        // tooling commonly deployed alongside InnerWarden. CrowdSec
        // tails /var/log/* (file.read) and posts to its central API
        // (outbound) — same chain shape as exfiltration.
        for comm in &["crowdsec", "cscli"] {
            let mut ev = make_event(Layer::Network, "network.outbound_connect", "203.0.113.10");
            ev.details = serde_json::json!({
                "pid": 1, "comm": comm, "dst_ip": "203.0.113.10", "dst_port": 443
            });
            assert!(
                event_comm_is_suppressed("CL-008", &ev),
                "CrowdSec component {comm:?} outbound to its API must be suppressed for CL-008"
            );
        }
    }

    #[test]
    fn service_daemon_suppression_does_not_leak_to_other_rules() {
        // Anti-regression: the new CL-008 carve-out must NOT bleed
        // into rule-agnostic territory. If an attacker hijacks the web
        // stack and uses nginx / php-fpm to drive a credential-theft
        // chain (CL-011) or a lateral-movement chain, those rules must
        // still fire. Same safety argument that pinned `tokio-rt-worker`
        // to CL-008 only.
        for comm in &["apache2", "nginx", "php-fpm", "mysqld", "crowdsec"] {
            let mut ev = make_event(Layer::Network, "network.outbound_connect", "203.0.113.99");
            ev.details = serde_json::json!({
                "pid": 999, "comm": comm, "dst_ip": "203.0.113.99", "dst_port": 4444
            });
            assert!(
                event_comm_is_suppressed("CL-008", &ev),
                "{comm:?} must be suppressed for CL-008 (per service-daemon carve-out)"
            );
            for rule_id in &["CL-001", "CL-002", "CL-011", "CL-014", "CL-XXX-future"] {
                assert!(
                    !event_comm_is_suppressed(rule_id, &ev),
                    "rule {rule_id:?} must NOT suppress {comm:?} — service-daemon \
                     comms aren't InnerWarden-specific; a hijacked web stack still has to fire"
                );
            }
        }
    }

    #[test]
    fn self_traffic_suppression_does_not_match_full_untruncated_names() {
        // Anti-regression: someone reading the source might "fix" the
        // truncated entries by adding the full names too. That's
        // wrong - the kernel NEVER produces them on Linux because of
        // TASK_COMM_LEN, so the full name in the list adds dead weight
        // and could shadow a legitimate match if a future eBPF program
        // ever exposed an untruncated name via /proc/<pid>/cmdline.
        // The list pins the kernel-truth shape.
        let untruncated_full_names = [
            "innerwarden-agent",    // 17 chars, truncated to innerwarden-age
            "innerwarden-sensor",   // 18 chars, truncated to innerwarden-sen
            "innerwarden-watchdog", // 20 chars, truncated to innerwarden-watc
        ];
        for full in &untruncated_full_names {
            let mut ev = make_event(Layer::Network, "network.outbound_connect", "10.0.0.1");
            ev.details = serde_json::json!({"pid": 1, "comm": full, "dst_ip": "10.0.0.1"});
            assert!(
                !event_comm_is_suppressed("CL-008", &ev),
                "full untruncated comm {full:?} must NOT match - the kernel never emits it"
            );
        }
    }

    #[test]
    fn self_traffic_suppression_keeps_real_attacker_comms_alive() {
        // Anti-regression: the carve-out is a tight allowlist, NOT a
        // hole that disables CL-008. Common attacker tooling comms
        // (curl, wget, nc, python, perl, ssh) must STILL be allowed
        // through to chain matching.
        for comm in &["curl", "wget", "nc", "python3", "perl", "ssh", "bash"] {
            let mut ev = make_event(Layer::Network, "network.outbound_connect", "203.0.113.99");
            ev.details = serde_json::json!({"pid": 999, "comm": comm, "dst_ip": "203.0.113.99"});
            assert!(
                !event_comm_is_suppressed("CL-008", &ev),
                "comm {comm:?} must NOT be suppressed - it is plausible attacker tooling"
            );
        }
    }

    // ─── spec 050-PR7 — Cross-tactic chain rule tests (CL-051 → CL-070) ───

    fn assert_chain_fires(engine: &mut CorrelationEngine, expected_rule_id: &str) {
        let chains = engine.drain_completed();
        assert!(
            chains.iter().any(|c| c.rule_id == expected_rule_id),
            "expected {} to fire — got [{}]",
            expected_rule_id,
            chains
                .iter()
                .map(|c| c.rule_id.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    #[test]
    fn cl_051_discovery_to_privesc() {
        let mut engine = CorrelationEngine::new();
        let ip = "10.0.0.51";
        engine.observe(make_event(Layer::Userspace, "nmap_scan", ip));
        engine.observe(make_event(Layer::Userspace, "setuid_exploit_pattern", ip));
        assert_chain_fires(&mut engine, "CL-051");
    }

    #[test]
    fn cl_052_privesc_to_lateral() {
        let mut engine = CorrelationEngine::new();
        let ip = "10.0.0.52";
        engine.observe(make_event(Layer::Userspace, "capabilities_abuse", ip));
        engine.observe(make_event(Layer::Userspace, "lateral_egress_ssh", ip));
        assert_chain_fires(&mut engine, "CL-052");
    }

    #[test]
    fn cl_053_collection_to_exfil() {
        let mut engine = CorrelationEngine::new();
        let ip = "10.0.0.53";
        engine.observe(make_event(
            Layer::Userspace,
            "automated_file_collection",
            ip,
        ));
        engine.observe(make_event(Layer::Userspace, "lateral_egress_scp_rsync", ip));
        assert_chain_fires(&mut engine, "CL-053");
    }

    #[test]
    fn cl_054_web_shell_to_c2() {
        let mut engine = CorrelationEngine::new();
        let ip = "10.0.0.54";
        engine.observe(make_event(Layer::Userspace, "web_shell", ip));
        engine.observe(make_event(Layer::Userspace, "c2_web_tunnel", ip));
        assert_chain_fires(&mut engine, "CL-054");
    }

    #[test]
    fn cl_055_persistence_to_defense_evasion() {
        let mut engine = CorrelationEngine::new();
        let ip = "10.0.0.55";
        engine.observe(make_event(Layer::Userspace, "pam_module_change", ip));
        engine.observe(make_event(Layer::Userspace, "auditd_disable", ip));
        assert_chain_fires(&mut engine, "CL-055");
    }

    #[test]
    fn cl_056_defense_evasion_to_impact() {
        let mut engine = CorrelationEngine::new();
        let ip = "10.0.0.56";
        engine.observe(make_event(Layer::Userspace, "auditd_disable", ip));
        engine.observe(make_event(Layer::Userspace, "data_destruction_pattern", ip));
        assert_chain_fires(&mut engine, "CL-056");
    }

    #[test]
    fn cl_057_discovery_burst_to_collection() {
        let mut engine = CorrelationEngine::new();
        let ip = "10.0.0.57";
        engine.observe(make_event(Layer::Userspace, "discovery_burst", ip));
        engine.observe(make_event(Layer::Userspace, "archive_pwd_protected", ip));
        assert_chain_fires(&mut engine, "CL-057");
    }

    #[test]
    fn cl_058_initial_access_to_foothold() {
        let mut engine = CorrelationEngine::new();
        let ip = "10.0.0.58";
        engine.observe(make_event(Layer::Userspace, "ssh_bruteforce", ip));
        engine.observe(make_event(Layer::Userspace, "reverse_shell", ip));
        assert_chain_fires(&mut engine, "CL-058");
    }

    #[test]
    fn cl_059_foothold_to_persistence() {
        let mut engine = CorrelationEngine::new();
        let ip = "10.0.0.59";
        engine.observe(make_event(Layer::Userspace, "reverse_shell", ip));
        engine.observe(make_event(
            Layer::Userspace,
            "startup_script_persistence",
            ip,
        ));
        assert_chain_fires(&mut engine, "CL-059");
    }

    #[test]
    fn cl_060_c2_to_discovery() {
        let mut engine = CorrelationEngine::new();
        let ip = "10.0.0.60";
        engine.observe(make_event(Layer::Userspace, "c2_callback", ip));
        engine.observe(make_event(Layer::Userspace, "nmap_scan", ip));
        assert_chain_fires(&mut engine, "CL-060");
    }

    #[test]
    fn cl_061_discovery_to_c2() {
        let mut engine = CorrelationEngine::new();
        let ip = "10.0.0.61";
        engine.observe(make_event(Layer::Userspace, "wordlist_scan", ip));
        engine.observe(make_event(Layer::Userspace, "c2_protocol_tunneling", ip));
        assert_chain_fires(&mut engine, "CL-061");
    }

    #[test]
    fn cl_062_reverse_shell_to_privesc() {
        let mut engine = CorrelationEngine::new();
        let ip = "10.0.0.62";
        engine.observe(make_event(Layer::Userspace, "reverse_shell", ip));
        engine.observe(make_event(Layer::Userspace, "setuid_exploit_pattern", ip));
        assert_chain_fires(&mut engine, "CL-062");
    }

    #[test]
    fn cl_063_privesc_to_persistence() {
        let mut engine = CorrelationEngine::new();
        let ip = "10.0.0.63";
        engine.observe(make_event(Layer::Userspace, "setuid_exploit_pattern", ip));
        engine.observe(make_event(Layer::Userspace, "pam_module_change", ip));
        assert_chain_fires(&mut engine, "CL-063");
    }

    #[test]
    fn cl_064_persistence_to_lateral() {
        let mut engine = CorrelationEngine::new();
        let ip = "10.0.0.64";
        engine.observe(make_event(Layer::Userspace, "systemd_persistence", ip));
        engine.observe(make_event(Layer::Userspace, "lateral_egress_ssh", ip));
        assert_chain_fires(&mut engine, "CL-064");
    }

    #[test]
    fn cl_065_lateral_to_collection() {
        let mut engine = CorrelationEngine::new();
        let ip = "10.0.0.65";
        engine.observe(make_event(Layer::Userspace, "lateral_egress_ssh", ip));
        engine.observe(make_event(Layer::Userspace, "clipboard_read", ip));
        assert_chain_fires(&mut engine, "CL-065");
    }

    #[test]
    fn cl_066_collection_to_lateral_exfil() {
        let mut engine = CorrelationEngine::new();
        let ip = "10.0.0.66";
        engine.observe(make_event(
            Layer::Userspace,
            "automated_file_collection",
            ip,
        ));
        engine.observe(make_event(Layer::Userspace, "lateral_egress_scp_rsync", ip));
        assert_chain_fires(&mut engine, "CL-066");
    }

    #[test]
    fn cl_067_full_kill_chain() {
        let mut engine = CorrelationEngine::new();
        let ip = "10.0.0.67";
        engine.observe(make_event(Layer::Userspace, "ssh_bruteforce", ip));
        engine.observe(make_event(Layer::Userspace, "reverse_shell", ip));
        engine.observe(make_event(Layer::Userspace, "pam_module_change", ip));
        engine.observe(make_event(Layer::Userspace, "auditd_disable", ip));
        engine.observe(make_event(Layer::Userspace, "data_destruction_pattern", ip));
        assert_chain_fires(&mut engine, "CL-067");
    }

    #[test]
    fn cl_068_wiper_precursor() {
        let mut engine = CorrelationEngine::new();
        let ip = "10.0.0.68";
        engine.observe(make_event(Layer::Userspace, "selinux_apparmor_disable", ip));
        engine.observe(make_event(Layer::Userspace, "discovery_anomaly", ip));
        engine.observe(make_event(Layer::Userspace, "data_destruction_pattern", ip));
        assert_chain_fires(&mut engine, "CL-068");
    }

    #[test]
    fn cl_069_insider_exfil() {
        let mut engine = CorrelationEngine::new();
        let ip = "10.0.0.69";
        engine.observe(make_event(Layer::Userspace, "shell.command_exec", ip));
        engine.observe(make_event(
            Layer::Userspace,
            "automated_file_collection",
            ip,
        ));
        engine.observe(make_event(Layer::Userspace, "lateral_egress_scp_rsync", ip));
        assert_chain_fires(&mut engine, "CL-069");
    }

    #[test]
    fn cl_072_provenance_to_goal_action() {
        // Spec 070: illegitimate privilege provenance (root joined a non-root-
        // owned user namespace) followed by a goal action (write /etc/sudoers)
        // chains into one Critical incident — the technique-independent
        // "exploit caught" signal.
        let mut engine = CorrelationEngine::new();
        let ip = "10.0.0.72";
        engine.observe(make_event(
            Layer::Userspace,
            "namespace.setns_unpriv_owner",
            ip,
        ));
        engine.observe(make_event(Layer::Userspace, "sensitive_write", ip));
        assert_chain_fires(&mut engine, "CL-072");
    }

    #[test]
    fn cl_072_untrusted_root_exec_to_persistence() {
        // Untrusted root execution -> persistence is the same invariant via a
        // different provenance signal and goal action.
        let mut engine = CorrelationEngine::new();
        let ip = "10.0.0.73";
        engine.observe(make_event(Layer::Userspace, "execution.untrusted_root", ip));
        engine.observe(make_event(Layer::Userspace, "crontab_persistence", ip));
        assert_chain_fires(&mut engine, "CL-072");
    }

    #[test]
    fn cl_072_privesc_alone_does_not_fire() {
        // A provenance signal with no goal action must NOT chain (no false
        // "exploit" on a bare escalation).
        let mut engine = CorrelationEngine::new();
        let ip = "10.0.0.74";
        engine.observe(make_event(Layer::Userspace, "privesc", ip));
        let chains = engine.drain_completed();
        assert!(
            !chains.iter().any(|c| c.rule_id == "CL-072"),
            "CL-072 must not fire on a provenance signal alone"
        );
    }

    #[test]
    fn cl_070_pam_credential_theft_chain() {
        let mut engine = CorrelationEngine::new();
        // PAM tamper from attacker_ip, then victim auth success, then
        // lateral pivot — identity rotates, entity_must_match=false.
        engine.observe(make_event(
            Layer::Userspace,
            "pam_module_change",
            "10.0.0.70",
        ));
        engine.observe(make_event(
            Layer::Userspace,
            "ssh.login_success",
            "10.0.0.71",
        ));
        engine.observe(make_event(
            Layer::Userspace,
            "lateral_egress_ssh",
            "10.0.0.72",
        ));
        assert_chain_fires(&mut engine, "CL-070");
    }

    /// Helper for path-entity events (CL-071 is the first rule that
    /// pivots on a path entity instead of an IP entity).
    fn make_path_event(layer: Layer, kind: &str, path: &str) -> CorrelationEvent {
        CorrelationEvent {
            ts: Utc::now(),
            layer,
            source: intern("test"),
            kind: intern(kind),
            severity: Severity::Medium,
            entities: vec![EntityRef::path(path)],
            details: serde_json::json!({}),
            incident_id: String::new(),
        }
    }

    #[test]
    fn cl_071_kernel_devnode_exposure_to_privesc_chain() {
        let mut engine = CorrelationEngine::new();
        let exposed = "/dev/infiniband/uverbs0";
        // Stage 1: detector emits the exposure (Medium). Entity = path.
        engine.observe(make_path_event(
            Layer::Userspace,
            "integrity.devnode_exposed",
            exposed,
        ));
        // Stage 2: a process actually opens / writes the same path
        // (entity_must_match=true keeps unrelated devnode opens from
        // chaining a different exposure into the wrong incident).
        engine.observe(make_path_event(
            Layer::Userspace,
            "sensitive_write",
            exposed,
        ));
        // Stage 3: subsequent privesc anywhere on the host. Entity
        // does NOT have to match — the exploit chain may pivot to a
        // different process / user.
        engine.observe(make_event(Layer::Userspace, "privesc", "10.0.0.171"));
        assert_chain_fires(&mut engine, "CL-071");
    }

    #[test]
    fn cl_071_does_not_fire_without_matching_path_in_stage_2() {
        let mut engine = CorrelationEngine::new();
        // Exposure on uverbs0…
        engine.observe(make_path_event(
            Layer::Userspace,
            "integrity.devnode_exposed",
            "/dev/infiniband/uverbs0",
        ));
        // …but the sensitive_write hit /etc/passwd, a completely
        // different path. Stage 2 entity_must_match must reject this.
        engine.observe(make_path_event(
            Layer::Userspace,
            "sensitive_write",
            "/etc/passwd",
        ));
        engine.observe(make_event(Layer::Userspace, "privesc", "10.0.0.172"));
        let chains = engine.drain_completed();
        assert!(
            !chains.iter().any(|c| c.rule_id == "CL-071"),
            "CL-071 must NOT fire when stage-2 entity differs from stage-1"
        );
    }

    #[test]
    fn cl_071_does_not_fire_with_only_exposure_signal() {
        // The exposure alone is a hardening hint, not a chain. Without
        // stage 2 (open) AND stage 3 (privesc) the rule must stay
        // silent so it doesn't dilute Critical signal noise.
        let mut engine = CorrelationEngine::new();
        engine.observe(make_path_event(
            Layer::Userspace,
            "integrity.devnode_exposed",
            "/dev/kvm",
        ));
        let chains = engine.drain_completed();
        assert!(
            !chains.iter().any(|c| c.rule_id == "CL-071"),
            "CL-071 must NOT fire on the exposure signal alone"
        );
    }

    // ─── Post-Caldera 2026-05-17 tuning: legacy detector variants ──────────
    // These tests anchor the OR-pattern updates added after the first
    // Caldera run, where the chain rules were not firing because the
    // legacy detectors emit `data_exfil_cmd` / `data_archive` /
    // `suspicious_archive` instead of the new PR1-6 names that PR7
    // originally listed.

    #[test]
    fn cl_053_fires_on_legacy_data_archive_then_data_exfil_cmd() {
        let mut engine = CorrelationEngine::new();
        let ip = "10.0.0.153";
        engine.observe(make_event(Layer::Userspace, "data_archive", ip));
        engine.observe(make_event(Layer::Userspace, "data_exfil_cmd", ip));
        assert_chain_fires(&mut engine, "CL-053");
    }

    #[test]
    fn cl_053_fires_on_suspicious_archive_variant() {
        let mut engine = CorrelationEngine::new();
        let ip = "10.0.0.253";
        engine.observe(make_event(Layer::Userspace, "suspicious_archive", ip));
        engine.observe(make_event(Layer::Userspace, "data_exfil_cmd", ip));
        assert_chain_fires(&mut engine, "CL-053");
    }

    #[test]
    fn cl_057_fires_on_legacy_data_archive_after_discovery() {
        let mut engine = CorrelationEngine::new();
        let ip = "10.0.0.157";
        engine.observe(make_event(Layer::Userspace, "discovery_burst", ip));
        engine.observe(make_event(Layer::Userspace, "data_archive", ip));
        assert_chain_fires(&mut engine, "CL-057");
    }

    #[test]
    fn cl_066_fires_on_data_archive_then_data_exfil_cmd() {
        let mut engine = CorrelationEngine::new();
        let ip = "10.0.0.166";
        engine.observe(make_event(Layer::Userspace, "data_archive", ip));
        engine.observe(make_event(Layer::Userspace, "data_exfil_cmd", ip));
        assert_chain_fires(&mut engine, "CL-066");
    }

    #[test]
    fn cl_069_fires_on_legacy_archive_and_exfil_variants() {
        let mut engine = CorrelationEngine::new();
        let ip = "10.0.0.169";
        engine.observe(make_event(Layer::Userspace, "shell.command_exec", ip));
        engine.observe(make_event(Layer::Userspace, "suspicious_archive", ip));
        engine.observe(make_event(Layer::Userspace, "data_exfil_cmd", ip));
        assert_chain_fires(&mut engine, "CL-069");
    }
}
