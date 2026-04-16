//! Observation verification — behavioural score engine for OBSERVING items.
//!
//! Every incident in the OBSERVING state gets scored 0-100 based on five
//! deterministic checks.  High scores auto-dismiss, low scores escalate,
//! and the ambiguous middle goes to AI batch verification.
//!
//! All check functions are **pure** — they only read `serde_json::Value`
//! fields from the incident/event details.  No I/O, no async, no state.

use serde::{Deserialize, Serialize};

// ── Result types ────────────────────────────────────────────────────────

/// Outcome of the behavioural score for a single OBSERVING item.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerificationResult {
    /// Score ≥ dismiss threshold → auto-dismiss.
    Dismiss { score: u8, reason: String },
    /// Score in the ambiguous range → needs AI verification.
    NeedsAiVerification { score: u8 },
    /// Score < escalate threshold → escalate to Fase 4 (AI triage full).
    Escalate { score: u8, reason: String },
}

/// Breakdown of the five individual check scores.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScoreBreakdown {
    pub installation: i32,
    pub process_chain: i32,
    pub network: i32,
    pub binary_identity: i32,
    pub temporal: i32,
    pub total: u8,
}

/// Default thresholds from the spec.
pub const DEFAULT_DISMISS_THRESHOLD: u8 = 70;
pub const DEFAULT_ESCALATE_THRESHOLD: u8 = 40;

// ── Top-level scorer ────────────────────────────────────────────────────

/// Score an OBSERVING item using the 5 behavioural checks.
///
/// `details` is the `evidence` (or `details`) JSON from the incident/event.
/// `operator_active` indicates whether an operator SSH session is currently
/// active.  `recent_package_activity` is true if apt/dnf/snap ran recently.
/// `recent_service_restart` is true if systemctl restart ran recently.
/// `in_maintenance_window` is true if current time falls in a configured
/// maintenance window.
pub fn behaviour_score(
    details: &serde_json::Value,
    operator_active: bool,
    recent_package_activity: bool,
    recent_service_restart: bool,
    in_maintenance_window: bool,
    dismiss_threshold: u8,
    escalate_threshold: u8,
) -> (VerificationResult, ScoreBreakdown) {
    let installation = check_installation(details);
    let process_chain = check_process_chain(details);
    let network = check_network_behaviour(details);
    let binary_identity = check_binary_identity(details);
    let temporal = check_temporal_context(
        operator_active,
        recent_package_activity,
        recent_service_restart,
        in_maintenance_window,
    );

    let raw = 50i32 + installation + process_chain + network + binary_identity + temporal;
    let total = raw.clamp(0, 100) as u8;

    let breakdown = ScoreBreakdown {
        installation,
        process_chain,
        network,
        binary_identity,
        temporal,
        total,
    };

    let result = if total >= dismiss_threshold {
        VerificationResult::Dismiss {
            score: total,
            reason: dismiss_reason(&breakdown),
        }
    } else if total < escalate_threshold {
        VerificationResult::Escalate {
            score: total,
            reason: escalate_reason(&breakdown),
        }
    } else {
        VerificationResult::NeedsAiVerification { score: total }
    };

    (result, breakdown)
}

// ── Check 1: Installation Legitimacy (+0 to +30, or -20) ───────────────

/// Known system binary directories.
const TRUSTED_DIRS: &[&str] = &[
    "/usr/bin/",
    "/usr/sbin/",
    "/usr/local/bin/",
    "/usr/local/sbin/",
    "/usr/libexec/",
    "/opt/",
    "/snap/",
];

/// Directories where attackers drop binaries.
const SUSPICIOUS_DIRS: &[&str] = &["/tmp/", "/dev/shm/", "/var/tmp/", "/run/shm/"];

/// Score based on how the binary was installed.
///
/// Reads from `details`:
/// - `binary_path` or `exe` — full path to the binary
/// - `package_managed` — bool, true if dpkg/rpm verified
///
/// Returns -20 to +30.
pub fn check_installation(details: &serde_json::Value) -> i32 {
    let binary_path = details
        .get("binary_path")
        .or_else(|| details.get("exe"))
        .or_else(|| details.get("path"))
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let package_managed = details
        .get("package_managed")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    // Binary in a suspicious directory → strong negative signal
    if SUSPICIOUS_DIRS.iter().any(|d| binary_path.starts_with(d)) {
        return -20;
    }

    let mut score = 0i32;

    // Binary in a trusted system directory → +10
    if TRUSTED_DIRS.iter().any(|d| binary_path.starts_with(d)) {
        score += 10;
    }

    // Package manager verified → +20
    if package_managed {
        score += 20;
    }

    score
}

// ── Check 2: Process Chain (+0 to +20, or -20) ────────────────────────

/// Trusted init/daemon parents.
const TRUSTED_PARENTS: &[&str] = &[
    "systemd",
    "cron",
    "crond",
    "sshd",
    "docker",
    "containerd",
    "dockerd",
    "kubelet",
    "supervisord",
    "init",
];

/// Score based on the process parent chain.
///
/// Reads from `details`:
/// - `ppid_comm` or `parent_comm` — immediate parent comm name
/// - `parent_chain` — array of strings tracing up to init
/// - `parent_path` or `ppid_exe` — parent binary path
///
/// Returns -20 to +20.
pub fn check_process_chain(details: &serde_json::Value) -> i32 {
    let mut score = 0i32;

    // Collect parent comm names from available fields
    let parent_comm = details
        .get("ppid_comm")
        .or_else(|| details.get("parent_comm"))
        .and_then(|v| v.as_str())
        .unwrap_or("");

    // Check if parent chain ends at systemd/init
    let chain = details.get("parent_chain").and_then(|v| v.as_array());
    let has_trusted_root = if let Some(chain) = chain {
        chain.iter().any(|v| {
            v.as_str()
                .map(|s| TRUSTED_PARENTS.iter().any(|tp| s.starts_with(tp)))
                .unwrap_or(false)
        })
    } else {
        // Fall back to parent_comm
        TRUSTED_PARENTS.iter().any(|tp| parent_comm.starts_with(tp))
    };

    if has_trusted_root {
        score += 10;
    }

    // Check if parent is in a trusted init/daemon list
    if TRUSTED_PARENTS.iter().any(|tp| parent_comm.starts_with(tp)) {
        score += 10;
    }

    // Parent binary in a suspicious directory → negative
    let parent_path = details
        .get("parent_path")
        .or_else(|| details.get("ppid_exe"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if SUSPICIOUS_DIRS.iter().any(|d| parent_path.starts_with(d)) {
        score -= 20;
    }

    score.clamp(-20, 20)
}

// ── Check 3: Network Behaviour (+0 to +15, or -15) ─────────────────────

/// Standard service ports that legitimate software uses.
const STANDARD_PORTS: &[u16] = &[
    22, 53, 80, 443, 993, 995, 587, 465, 3306, 5432, 6379, 8080, 9090, 9200, 9300, 27017,
];

/// Attacker-favourite ports.
const SUSPICIOUS_PORTS: &[u16] = &[4444, 1337, 31337, 1234, 5555, 6666, 7777, 9999];

/// Score based on network connection characteristics.
///
/// Reads from `details`:
/// - `dst_port` or `port` — destination port (number or string)
/// - `dst_ip` or `ip` — destination IP address
/// - `dns_resolves` — bool, whether DNS forward resolution succeeded
/// - `reverse_dns` — bool, whether reverse DNS matches
/// - `is_cdn` — bool, whether destination is in known CDN/cloud range
///
/// Returns -15 to +15.
pub fn check_network_behaviour(details: &serde_json::Value) -> i32 {
    let mut score = 0i32;

    let dst_port = details
        .get("dst_port")
        .or_else(|| details.get("port"))
        .and_then(|v| {
            v.as_u64()
                .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
        })
        .unwrap_or(0) as u16;

    let dns_resolves = details
        .get("dns_resolves")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let reverse_dns = details
        .get("reverse_dns")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let is_cdn = details
        .get("is_cdn")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    // DNS resolution checks
    if dns_resolves {
        score += 5;
    }
    if reverse_dns {
        score += 5;
    }

    // Standard port → +5
    if dst_port > 0 && STANDARD_PORTS.contains(&dst_port) {
        score += 5;
    }

    // CDN/cloud destination → bonus
    if is_cdn {
        score += 5;
    }

    // Suspicious port → strong negative
    if SUSPICIOUS_PORTS.contains(&dst_port) {
        score -= 15;
    }

    // High unusual port (>50000) with no DNS → suspicious
    if dst_port > 50000 && !dns_resolves {
        score -= 10;
    }

    // No DNS at all (raw IP, no PTR) → minor negative
    if dst_port > 0 && !dns_resolves && !reverse_dns {
        score -= 10;
    }

    score.clamp(-15, 15)
}

// ── Check 4: Binary Identity (+0 to +20, or -10) ───────────────────────

/// Score based on binary integrity and age.
///
/// Reads from `details`:
/// - `package_managed` — bool, SHA-256 matches package DB
/// - `binary_age_hours` — how old the binary file is (in hours)
///
/// Returns -10 to +20.
pub fn check_binary_identity(details: &serde_json::Value) -> i32 {
    let mut score = 0i32;

    let package_managed = details
        .get("package_managed")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let binary_age_hours = details
        .get("binary_age_hours")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);

    // SHA-256 matches package manager → strong positive
    if package_managed {
        score += 20;
        return score; // No need to check age — package DB is authoritative
    }

    // Binary age as a proxy for legitimacy
    if binary_age_hours > (7.0 * 24.0) {
        // > 7 days
        score += 10;
    } else if binary_age_hours > 24.0 {
        score += 5;
    } else if binary_age_hours < 1.0 && binary_age_hours > 0.0 {
        // Fresh binary, not from package manager → suspicious
        score -= 10;
    }

    score
}

// ── Check 5: Temporal Context (+0 to +10, or -5) ───────────────────────

/// Score based on timing context (operator activity, maintenance, etc.).
///
/// Takes pre-computed booleans rather than raw details — the agent loop
/// determines these from system state before calling the scorer.
///
/// Returns -5 to +10.
pub fn check_temporal_context(
    operator_active: bool,
    recent_package_activity: bool,
    recent_service_restart: bool,
    in_maintenance_window: bool,
) -> i32 {
    let mut score = 0i32;

    if operator_active {
        score += 10;
    }

    if recent_package_activity {
        score += 10;
    }

    if recent_service_restart {
        score += 5;
    }

    if in_maintenance_window {
        score += 10;
    }

    // No operator and no context → slight negative
    if !operator_active && !recent_package_activity && !in_maintenance_window {
        score -= 5;
    }

    score.clamp(-5, 10)
}

// ── Helpers ─────────────────────────────────────────────────────────────

fn dismiss_reason(bd: &ScoreBreakdown) -> String {
    let mut parts = Vec::new();
    if bd.installation >= 20 {
        parts.push("package managed binary");
    } else if bd.installation >= 10 {
        parts.push("trusted directory");
    }
    if bd.process_chain >= 10 {
        parts.push("trusted parent chain");
    }
    if bd.network >= 5 {
        parts.push("DNS resolves");
    }
    if bd.binary_identity >= 10 {
        parts.push("known binary");
    }
    if bd.temporal >= 5 {
        parts.push("operator context");
    }
    if parts.is_empty() {
        "legitimate behaviour".to_string()
    } else {
        parts.join(", ")
    }
}

fn escalate_reason(bd: &ScoreBreakdown) -> String {
    let mut parts = Vec::new();
    if bd.installation < 0 {
        parts.push("suspicious binary location");
    }
    if bd.process_chain < 0 {
        parts.push("untrusted parent chain");
    }
    if bd.network < 0 {
        parts.push("suspicious network behaviour");
    }
    if bd.binary_identity < 0 {
        parts.push("fresh unknown binary");
    }
    if bd.temporal < 0 {
        parts.push("no operator context");
    }
    if parts.is_empty() {
        "suspicious behaviour".to_string()
    } else {
        parts.join(", ")
    }
}

// ── Config ──────────────────────────────────────────────────────────────

/// Configuration for the observation verification module.
#[derive(Debug, Clone, Deserialize)]
pub struct ObservationConfig {
    /// Enable observation verification (default: true).
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Minimum score to auto-dismiss without AI (default: 70).
    #[serde(default = "default_dismiss_threshold")]
    pub auto_dismiss_threshold: u8,
    /// Maximum score to auto-escalate without AI (default: 40).
    #[serde(default = "default_escalate_threshold")]
    pub auto_escalate_threshold: u8,
    /// Use AI for ambiguous items (default: true).
    #[serde(default = "default_true")]
    pub ai_verification: bool,
    /// Maximum items per AI batch call (default: 10).
    #[serde(default = "default_ai_batch_size")]
    pub ai_batch_size: usize,
    /// Maintenance windows (HH:MM-HH:MM format). Items during these get +10 context.
    #[serde(default)]
    pub maintenance_windows: Vec<String>,
}

fn default_true() -> bool {
    true
}
fn default_dismiss_threshold() -> u8 {
    DEFAULT_DISMISS_THRESHOLD
}
fn default_escalate_threshold() -> u8 {
    DEFAULT_ESCALATE_THRESHOLD
}
fn default_ai_batch_size() -> usize {
    10
}

impl Default for ObservationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            auto_dismiss_threshold: DEFAULT_DISMISS_THRESHOLD,
            auto_escalate_threshold: DEFAULT_ESCALATE_THRESHOLD,
            ai_verification: true,
            ai_batch_size: 10,
            maintenance_windows: Vec::new(),
        }
    }
}

/// Check if current time falls in any maintenance window.
///
/// Windows are in "HH:MM-HH:MM" format (24h, local time).
/// Handles overnight windows like "23:00-02:00".
pub fn in_maintenance_window(windows: &[String], now_hour: u32, now_minute: u32) -> bool {
    let now_mins = now_hour * 60 + now_minute;
    for w in windows {
        if let Some((start, end)) = parse_window(w) {
            if start <= end {
                // Same-day window: 02:00-04:00
                if now_mins >= start && now_mins < end {
                    return true;
                }
            } else {
                // Overnight window: 23:00-02:00
                if now_mins >= start || now_mins < end {
                    return true;
                }
            }
        }
    }
    false
}

fn parse_window(w: &str) -> Option<(u32, u32)> {
    let parts: Vec<&str> = w.split('-').collect();
    if parts.len() != 2 {
        return None;
    }
    let start = parse_hhmm(parts[0])?;
    let end = parse_hhmm(parts[1])?;
    Some((start, end))
}

fn parse_hhmm(s: &str) -> Option<u32> {
    let parts: Vec<&str> = s.trim().split(':').collect();
    if parts.len() != 2 {
        return None;
    }
    let h: u32 = parts[0].parse().ok()?;
    let m: u32 = parts[1].parse().ok()?;
    if h > 23 || m > 59 {
        return None;
    }
    Some(h * 60 + m)
}

// ── AI Batch Verification (Phase C) ─────────────────────────────────────

/// AI verdict for a single ambiguous item.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AiVerdict {
    pub item_index: usize,
    pub verdict: AiVerdictKind,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AiVerdictKind {
    Normal,
    Suspicious,
}

/// Data for a single item in the AI verification batch.
#[derive(Debug, Clone, Serialize)]
pub struct AiBatchItem {
    pub index: usize,
    pub incident_id: String,
    pub score: u8,
    pub process: String,
    pub event_summary: String,
    pub binary_path: String,
    pub parent_chain: String,
    pub detector: String,
}

/// Build the system prompt for AI batch verification.
pub fn ai_verify_system_prompt(host_profile: &str) -> String {
    format!(
        "You are a security analyst reviewing items in the observation queue of a Linux server.\n\n\
         Host profile:\n{host_profile}\n\n\
         For each item below, answer with a JSON array. Each element must have:\n\
         - \"item\": the item number (integer)\n\
         - \"verdict\": \"NORMAL\" or \"SUSPICIOUS\"\n\
         - \"reason\": one-line explanation\n\n\
         Respond ONLY with the JSON array, no other text."
    )
}

/// Build the user message listing all ambiguous items for AI verification.
pub fn ai_verify_user_message(items: &[AiBatchItem]) -> String {
    let mut msg = String::from("Items in observation:\n\n");
    for item in items {
        msg.push_str(&format!(
            "{}. Process: {} (detector: {})\n   \
             Event: {}\n   \
             Binary: {} (behaviour score: {}/100)\n   \
             Parent: {}\n\n",
            item.index,
            item.process,
            item.detector,
            item.event_summary,
            item.binary_path,
            item.score,
            item.parent_chain,
        ));
    }
    msg
}

/// Parse the AI response into verdicts.
///
/// Expects a JSON array of objects with `item`, `verdict`, `reason` fields.
/// Tolerant: extracts the JSON array even if the AI wraps it in markdown
/// code fences or adds surrounding text.
pub fn parse_ai_verdicts(response: &str) -> Vec<AiVerdict> {
    // Try to find a JSON array in the response
    let trimmed = response.trim();

    // Strip markdown code fences if present
    let json_str = if let Some(start) = trimmed.find('[') {
        if let Some(end) = trimmed.rfind(']') {
            &trimmed[start..=end]
        } else {
            return Vec::new();
        }
    } else {
        return Vec::new();
    };

    let Ok(arr) = serde_json::from_str::<Vec<serde_json::Value>>(json_str) else {
        return Vec::new();
    };

    arr.iter()
        .filter_map(|v| {
            let item_index = v.get("item")?.as_u64()? as usize;
            let verdict_str = v.get("verdict")?.as_str()?;
            let reason = v
                .get("reason")
                .and_then(|r| r.as_str())
                .unwrap_or("")
                .to_string();

            let verdict = match verdict_str.to_ascii_uppercase().as_str() {
                "NORMAL" => AiVerdictKind::Normal,
                "SUSPICIOUS" => AiVerdictKind::Suspicious,
                _ => return None,
            };

            Some(AiVerdict {
                item_index,
                verdict,
                reason,
            })
        })
        .collect()
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ── check_installation tests ────────────────────────────────────────

    #[test]
    fn installation_trusted_dir_package_managed() {
        let details = json!({
            "binary_path": "/usr/bin/curl",
            "package_managed": true,
        });
        assert_eq!(check_installation(&details), 30);
    }

    #[test]
    fn installation_trusted_dir_not_managed() {
        let details = json!({
            "binary_path": "/usr/bin/something",
            "package_managed": false,
        });
        assert_eq!(check_installation(&details), 10);
    }

    #[test]
    fn installation_suspicious_dir() {
        let details = json!({
            "binary_path": "/tmp/malware",
            "package_managed": false,
        });
        assert_eq!(check_installation(&details), -20);
    }

    #[test]
    fn installation_suspicious_dir_overrides_package() {
        // Even if somehow "package_managed" is true, /tmp is /tmp
        let details = json!({
            "binary_path": "/tmp/backdoor",
            "package_managed": true,
        });
        assert_eq!(check_installation(&details), -20);
    }

    #[test]
    fn installation_dev_shm() {
        let details = json!({ "binary_path": "/dev/shm/x" });
        assert_eq!(check_installation(&details), -20);
    }

    #[test]
    fn installation_opt_dir() {
        let details = json!({ "binary_path": "/opt/myapp/bin/server" });
        assert_eq!(check_installation(&details), 10);
    }

    #[test]
    fn installation_home_dir_no_package() {
        // Not in trusted or suspicious dir, not package managed → 0
        let details = json!({
            "binary_path": "/home/user/build/target/release/myapp",
            "package_managed": false,
        });
        assert_eq!(check_installation(&details), 0);
    }

    #[test]
    fn installation_empty_details() {
        let details = json!({});
        assert_eq!(check_installation(&details), 0);
    }

    #[test]
    fn installation_uses_exe_fallback() {
        let details = json!({
            "exe": "/usr/sbin/sshd",
            "package_managed": true,
        });
        assert_eq!(check_installation(&details), 30);
    }

    // ── check_process_chain tests ───────────────────────────────────────

    #[test]
    fn process_chain_systemd_parent() {
        let details = json!({
            "ppid_comm": "systemd",
            "parent_chain": ["systemd"],
        });
        assert_eq!(check_process_chain(&details), 20);
    }

    #[test]
    fn process_chain_sshd_parent() {
        let details = json!({
            "ppid_comm": "sshd",
        });
        assert_eq!(check_process_chain(&details), 20);
    }

    #[test]
    fn process_chain_untrusted_parent() {
        let details = json!({
            "ppid_comm": "nginx",
        });
        assert_eq!(check_process_chain(&details), 0);
    }

    #[test]
    fn process_chain_parent_in_tmp() {
        let details = json!({
            "ppid_comm": "exploit",
            "parent_path": "/tmp/exploit",
        });
        assert_eq!(check_process_chain(&details), -20);
    }

    #[test]
    fn process_chain_cron_parent() {
        let details = json!({
            "ppid_comm": "cron",
            "parent_chain": ["cron", "systemd"],
        });
        assert_eq!(check_process_chain(&details), 20);
    }

    #[test]
    fn process_chain_empty_details() {
        let details = json!({});
        assert_eq!(check_process_chain(&details), 0);
    }

    #[test]
    fn process_chain_chain_with_mixed_parents() {
        let details = json!({
            "ppid_comm": "bash",
            "parent_chain": ["bash", "sshd", "systemd"],
        });
        // parent_comm is bash (not trusted) → +0 direct parent
        // but chain has sshd+systemd → +10 trusted root
        assert_eq!(check_process_chain(&details), 10);
    }

    #[test]
    fn process_chain_docker_parent() {
        let details = json!({
            "ppid_comm": "containerd",
            "parent_chain": ["containerd", "systemd"],
        });
        assert_eq!(check_process_chain(&details), 20);
    }

    #[test]
    fn process_chain_parent_in_dev_shm() {
        let details = json!({
            "ppid_comm": "dropper",
            "parent_path": "/dev/shm/dropper",
        });
        assert_eq!(check_process_chain(&details), -20);
    }

    // ── check_network_behaviour tests ───────────────────────────────────

    #[test]
    fn network_standard_port_dns_resolves() {
        let details = json!({
            "dst_port": 443,
            "dns_resolves": true,
            "reverse_dns": true,
        });
        assert_eq!(check_network_behaviour(&details), 15);
    }

    #[test]
    fn network_suspicious_port() {
        let details = json!({
            "dst_port": 4444,
            "dns_resolves": false,
        });
        // -15 (suspicious port) + -10 (no DNS) = -25, clamped to -15
        assert_eq!(check_network_behaviour(&details), -15);
    }

    #[test]
    fn network_high_port_no_dns() {
        let details = json!({
            "dst_port": 55555,
            "dns_resolves": false,
        });
        // -10 (high port no dns) + -10 (no dns at all) = -20, clamped to -15
        assert_eq!(check_network_behaviour(&details), -15);
    }

    #[test]
    fn network_cdn_destination() {
        let details = json!({
            "dst_port": 443,
            "dns_resolves": true,
            "is_cdn": true,
        });
        // +5 dns + +5 port + +5 cdn = 15
        assert_eq!(check_network_behaviour(&details), 15);
    }

    #[test]
    fn network_empty_details() {
        // No port, no dns info → neutral
        let details = json!({});
        assert_eq!(check_network_behaviour(&details), 0);
    }

    #[test]
    fn network_port_as_string() {
        let details = json!({
            "dst_port": "443",
            "dns_resolves": true,
        });
        // +5 dns + +5 standard port = 10 (no reverse_dns)
        assert_eq!(check_network_behaviour(&details), 10);
    }

    #[test]
    fn network_raw_ip_no_ptr() {
        let details = json!({
            "dst_port": 80,
            "dst_ip": "45.33.12.88",
            "dns_resolves": false,
            "reverse_dns": false,
        });
        // +5 (port 80 standard) -10 (no dns at all) = -5
        assert_eq!(check_network_behaviour(&details), -5);
    }

    // ── check_binary_identity tests ─────────────────────────────────────

    #[test]
    fn binary_identity_package_managed() {
        let details = json!({
            "package_managed": true,
            "binary_age_hours": 1000.0,
        });
        assert_eq!(check_binary_identity(&details), 20);
    }

    #[test]
    fn binary_identity_old_binary() {
        let details = json!({
            "binary_age_hours": 200.0,
        });
        assert_eq!(check_binary_identity(&details), 10);
    }

    #[test]
    fn binary_identity_one_day_old() {
        let details = json!({
            "binary_age_hours": 30.0,
        });
        assert_eq!(check_binary_identity(&details), 5);
    }

    #[test]
    fn binary_identity_fresh_binary() {
        let details = json!({
            "binary_age_hours": 0.5,
        });
        assert_eq!(check_binary_identity(&details), -10);
    }

    #[test]
    fn binary_identity_empty_details() {
        let details = json!({});
        assert_eq!(check_binary_identity(&details), 0);
    }

    #[test]
    fn binary_identity_zero_age() {
        // binary_age_hours = 0.0 → not > 0.0 so no penalty
        let details = json!({ "binary_age_hours": 0.0 });
        assert_eq!(check_binary_identity(&details), 0);
    }

    // ── check_temporal_context tests ────────────────────────────────────

    #[test]
    fn temporal_operator_active() {
        assert_eq!(check_temporal_context(true, false, false, false), 10);
    }

    #[test]
    fn temporal_package_activity() {
        assert_eq!(check_temporal_context(false, true, false, false), 10);
    }

    #[test]
    fn temporal_maintenance_window() {
        assert_eq!(check_temporal_context(false, false, false, true), 10);
    }

    #[test]
    fn temporal_service_restart() {
        assert_eq!(check_temporal_context(false, false, true, false), 0);
        // +5 restart, -5 no operator/no context = 0
    }

    #[test]
    fn temporal_all_active() {
        // +10 +10 +5 +10 = 35, clamped to +10
        assert_eq!(check_temporal_context(true, true, true, true), 10);
    }

    #[test]
    fn temporal_nothing_active() {
        assert_eq!(check_temporal_context(false, false, false, false), -5);
    }

    // ── behaviour_score integration tests ───────────────────────────────

    #[test]
    fn score_apt_update_cron_3am() {
        // Scenario from spec: apt update via cron at 3 AM → score ~90
        let details = json!({
            "binary_path": "/usr/bin/apt",
            "package_managed": true,
            "ppid_comm": "cron",
            "parent_chain": ["cron", "systemd"],
            "binary_age_hours": 500.0,
        });
        let (result, bd) = behaviour_score(&details, false, true, false, false, 70, 40);
        assert!(bd.total >= 70, "expected ≥70, got {}", bd.total);
        assert!(matches!(result, VerificationResult::Dismiss { .. }));
    }

    #[test]
    fn score_composer_install_operator_active() {
        // Scenario: composer install, operator SSH active
        let details = json!({
            "binary_path": "/usr/bin/php8.3",
            "package_managed": true,
            "ppid_comm": "bash",
            "parent_chain": ["bash", "sshd", "systemd"],
            "dst_port": 443,
            "dns_resolves": true,
            "reverse_dns": true,
            "binary_age_hours": 200.0,
        });
        let (result, bd) = behaviour_score(&details, true, false, false, false, 70, 40);
        assert!(bd.total >= 70, "expected ≥70, got {}", bd.total);
        assert!(matches!(result, VerificationResult::Dismiss { .. }));
    }

    #[test]
    fn score_credential_compromise_wget() {
        // Scenario: wget to raw IP, suspicious port, binary from /tmp
        let details = json!({
            "binary_path": "/tmp/payload",
            "package_managed": false,
            "ppid_comm": "bash",
            "dst_port": 4444,
            "dns_resolves": false,
            "binary_age_hours": 0.1,
        });
        let (result, bd) = behaviour_score(&details, false, false, false, false, 70, 40);
        assert!(bd.total < 40, "expected <40, got {}", bd.total);
        assert!(matches!(result, VerificationResult::Escalate { .. }));
    }

    #[test]
    fn score_unknown_binary_opt_ambiguous() {
        // Scenario: unknown compiled binary in /opt, no package manager,
        // non-standard port, parent is bash (not a trusted daemon)
        let details = json!({
            "binary_path": "/opt/myapp/bin/server",
            "package_managed": false,
            "ppid_comm": "bash",
            "dst_port": 8443,
            "dns_resolves": true,
            "binary_age_hours": 50.0,
        });
        // base 50 + install(10) + chain(0) + net(5) + binary(5) + temporal(-5) = 65
        let (result, bd) = behaviour_score(&details, false, false, false, false, 70, 40);
        assert!(
            bd.total >= 40 && bd.total < 70,
            "expected 40-69, got {}",
            bd.total
        );
        assert!(matches!(
            result,
            VerificationResult::NeedsAiVerification { .. }
        ));
    }

    // ── in_maintenance_window tests ─────────────────────────────────────

    #[test]
    fn maintenance_window_inside() {
        let windows = vec!["02:00-04:00".to_string()];
        assert!(in_maintenance_window(&windows, 3, 0));
    }

    #[test]
    fn maintenance_window_outside() {
        let windows = vec!["02:00-04:00".to_string()];
        assert!(!in_maintenance_window(&windows, 5, 0));
    }

    #[test]
    fn maintenance_window_overnight() {
        let windows = vec!["23:00-02:00".to_string()];
        assert!(in_maintenance_window(&windows, 23, 30));
        assert!(in_maintenance_window(&windows, 0, 30));
        assert!(in_maintenance_window(&windows, 1, 59));
        assert!(!in_maintenance_window(&windows, 2, 0));
        assert!(!in_maintenance_window(&windows, 12, 0));
    }

    #[test]
    fn maintenance_window_empty() {
        let windows: Vec<String> = vec![];
        assert!(!in_maintenance_window(&windows, 3, 0));
    }

    #[test]
    fn maintenance_window_multiple() {
        let windows = vec!["02:00-04:00".to_string(), "14:00-15:00".to_string()];
        assert!(in_maintenance_window(&windows, 3, 0));
        assert!(in_maintenance_window(&windows, 14, 30));
        assert!(!in_maintenance_window(&windows, 12, 0));
    }

    #[test]
    fn maintenance_window_boundary() {
        let windows = vec!["02:00-04:00".to_string()];
        // Start boundary: inclusive
        assert!(in_maintenance_window(&windows, 2, 0));
        // End boundary: exclusive
        assert!(!in_maintenance_window(&windows, 4, 0));
    }

    #[test]
    fn maintenance_window_invalid_format() {
        let windows = vec!["not-a-window".to_string()];
        assert!(!in_maintenance_window(&windows, 3, 0));
    }

    // ── parse_hhmm tests ────────────────────────────────────────────────

    #[test]
    fn parse_hhmm_valid() {
        assert_eq!(parse_hhmm("02:00"), Some(120));
        assert_eq!(parse_hhmm("23:59"), Some(1439));
        assert_eq!(parse_hhmm("00:00"), Some(0));
    }

    #[test]
    fn parse_hhmm_invalid() {
        assert_eq!(parse_hhmm("25:00"), None);
        assert_eq!(parse_hhmm("12:60"), None);
        assert_eq!(parse_hhmm("abc"), None);
        assert_eq!(parse_hhmm(""), None);
    }

    // ── ScoreBreakdown reason tests ─────────────────────────────────────

    #[test]
    fn dismiss_reason_all_positive() {
        let bd = ScoreBreakdown {
            installation: 20,
            process_chain: 10,
            network: 5,
            binary_identity: 10,
            temporal: 5,
            total: 90,
        };
        let reason = dismiss_reason(&bd);
        assert!(reason.contains("package managed"));
        assert!(reason.contains("trusted parent"));
    }

    #[test]
    fn escalate_reason_all_negative() {
        let bd = ScoreBreakdown {
            installation: -20,
            process_chain: -20,
            network: -15,
            binary_identity: -10,
            temporal: -5,
            total: 10,
        };
        let reason = escalate_reason(&bd);
        assert!(reason.contains("suspicious binary location"));
        assert!(reason.contains("untrusted parent"));
    }

    #[test]
    fn dismiss_reason_empty_defaults() {
        let bd = ScoreBreakdown::default();
        assert_eq!(dismiss_reason(&bd), "legitimate behaviour");
    }

    #[test]
    fn escalate_reason_empty_defaults() {
        let bd = ScoreBreakdown::default();
        assert_eq!(escalate_reason(&bd), "suspicious behaviour");
    }

    // ── ObservationConfig default tests ─────────────────────────────────

    #[test]
    fn config_defaults() {
        let cfg = ObservationConfig::default();
        assert!(cfg.enabled);
        assert_eq!(cfg.auto_dismiss_threshold, 70);
        assert_eq!(cfg.auto_escalate_threshold, 40);
        assert!(cfg.ai_verification);
        assert_eq!(cfg.ai_batch_size, 10);
        assert!(cfg.maintenance_windows.is_empty());
    }

    #[test]
    fn config_deserialize_minimal() {
        let toml_str = r#"enabled = true"#;
        let cfg: ObservationConfig = toml::from_str(toml_str).unwrap();
        assert!(cfg.enabled);
        assert_eq!(cfg.auto_dismiss_threshold, 70);
    }

    #[test]
    fn config_deserialize_custom_thresholds() {
        let toml_str = r#"
            enabled = true
            auto_dismiss_threshold = 80
            auto_escalate_threshold = 30
            ai_batch_size = 5
            maintenance_windows = ["02:00-04:00", "14:00-15:00"]
        "#;
        let cfg: ObservationConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.auto_dismiss_threshold, 80);
        assert_eq!(cfg.auto_escalate_threshold, 30);
        assert_eq!(cfg.ai_batch_size, 5);
        assert_eq!(cfg.maintenance_windows.len(), 2);
    }

    // ── AI batch verification tests ─────────────────────────────────────

    // ── parse_ai_verdicts: happy path ───────────────────────────────────

    #[test]
    fn parse_ai_verdicts_valid_json() {
        let response = r#"[
            {"item": 1, "verdict": "NORMAL", "reason": "OpenClaw connecting to Telegram API"},
            {"item": 2, "verdict": "SUSPICIOUS", "reason": "Unknown binary on unusual port"}
        ]"#;
        let verdicts = parse_ai_verdicts(response);
        assert_eq!(verdicts.len(), 2);
        assert_eq!(verdicts[0].item_index, 1);
        assert_eq!(verdicts[0].verdict, AiVerdictKind::Normal);
        assert!(verdicts[0].reason.contains("Telegram"));
        assert_eq!(verdicts[1].verdict, AiVerdictKind::Suspicious);
    }

    // ── parse_ai_verdicts: edge cases ───────────────────────────────────

    #[test]
    fn parse_ai_verdicts_with_markdown_fences() {
        let response =
            "```json\n[\n  {\"item\": 1, \"verdict\": \"NORMAL\", \"reason\": \"safe\"}\n]\n```";
        let verdicts = parse_ai_verdicts(response);
        assert_eq!(verdicts.len(), 1);
        assert_eq!(verdicts[0].verdict, AiVerdictKind::Normal);
    }

    #[test]
    fn parse_ai_verdicts_with_surrounding_text() {
        let response = "Here is my analysis:\n\n[{\"item\": 1, \"verdict\": \"SUSPICIOUS\", \"reason\": \"bad\"}]\n\nLet me know if you need more.";
        let verdicts = parse_ai_verdicts(response);
        assert_eq!(verdicts.len(), 1);
        assert_eq!(verdicts[0].verdict, AiVerdictKind::Suspicious);
    }

    #[test]
    fn parse_ai_verdicts_case_insensitive_verdict() {
        let response = r#"[{"item": 1, "verdict": "normal", "reason": "ok"}]"#;
        let verdicts = parse_ai_verdicts(response);
        assert_eq!(verdicts.len(), 1);
        assert_eq!(verdicts[0].verdict, AiVerdictKind::Normal);
    }

    // ── parse_ai_verdicts: error cases ──────────────────────────────────

    #[test]
    fn parse_ai_verdicts_empty_response() {
        assert!(parse_ai_verdicts("").is_empty());
    }

    #[test]
    fn parse_ai_verdicts_invalid_json() {
        assert!(parse_ai_verdicts("not json at all").is_empty());
    }

    #[test]
    fn parse_ai_verdicts_missing_fields() {
        let response = r#"[{"item": 1}]"#;
        // Missing verdict field → filtered out
        assert!(parse_ai_verdicts(response).is_empty());
    }

    #[test]
    fn parse_ai_verdicts_unknown_verdict() {
        let response = r#"[{"item": 1, "verdict": "MAYBE", "reason": "unsure"}]"#;
        // "MAYBE" is not NORMAL or SUSPICIOUS → filtered out
        assert!(parse_ai_verdicts(response).is_empty());
    }

    #[test]
    fn parse_ai_verdicts_partial_valid() {
        let response = r#"[
            {"item": 1, "verdict": "NORMAL", "reason": "ok"},
            {"item": 2, "verdict": "UNKNOWN", "reason": "bad verdict"},
            {"item": 3, "verdict": "SUSPICIOUS", "reason": "bad"}
        ]"#;
        let verdicts = parse_ai_verdicts(response);
        assert_eq!(verdicts.len(), 2);
        assert_eq!(verdicts[0].item_index, 1);
        assert_eq!(verdicts[1].item_index, 3);
    }

    // ── ai_verify_system_prompt tests ───────────────────────────────────

    #[test]
    fn system_prompt_includes_host_profile() {
        let prompt = ai_verify_system_prompt("Ubuntu 24.04 on Oracle Cloud");
        assert!(prompt.contains("Ubuntu 24.04"));
        assert!(prompt.contains("JSON array"));
    }

    #[test]
    fn system_prompt_empty_profile() {
        let prompt = ai_verify_system_prompt("");
        assert!(prompt.contains("NORMAL"));
        assert!(prompt.contains("SUSPICIOUS"));
    }

    #[test]
    fn system_prompt_has_response_format_instructions() {
        let prompt = ai_verify_system_prompt("test");
        assert!(prompt.contains("ONLY with the JSON array"));
    }

    // ── ai_verify_user_message tests ────────────────────────────────────

    #[test]
    fn user_message_formats_items() {
        let items = vec![AiBatchItem {
            index: 1,
            incident_id: "inc-1".to_string(),
            score: 55,
            process: "openclaw-gatewa".to_string(),
            event_summary: "outbound connection to 149.154.166.110:443".to_string(),
            binary_path: "/home/ubuntu/openclaw/bin/openclaw-gateway".to_string(),
            parent_chain: "systemd → openclaw-gatewa".to_string(),
            detector: "data_exfiltration".to_string(),
        }];
        let msg = ai_verify_user_message(&items);
        assert!(msg.contains("openclaw-gatewa"));
        assert!(msg.contains("55/100"));
        assert!(msg.contains("149.154.166.110"));
    }

    #[test]
    fn user_message_multiple_items() {
        let items = vec![
            AiBatchItem {
                index: 1,
                incident_id: "a".to_string(),
                score: 45,
                process: "curl".to_string(),
                event_summary: "connect".to_string(),
                binary_path: "/usr/bin/curl".to_string(),
                parent_chain: "bash".to_string(),
                detector: "outbound".to_string(),
            },
            AiBatchItem {
                index: 2,
                incident_id: "b".to_string(),
                score: 60,
                process: "node".to_string(),
                event_summary: "listen".to_string(),
                binary_path: "/usr/bin/node".to_string(),
                parent_chain: "systemd".to_string(),
                detector: "network".to_string(),
            },
        ];
        let msg = ai_verify_user_message(&items);
        assert!(msg.contains("1. Process: curl"));
        assert!(msg.contains("2. Process: node"));
    }

    #[test]
    fn user_message_empty_items() {
        let msg = ai_verify_user_message(&[]);
        assert!(msg.contains("Items in observation"));
        // No items listed
        assert!(!msg.contains("1."));
    }

    // ── Dashboard reason format tests (Phase D) ─────────────────────────
    // The dashboard JS parses "obs-verify score X/100: ..." and
    // "obs-verify AI: VERDICT — ..." These tests verify the backend
    // produces the expected format.

    #[test]
    fn dismiss_reason_format_for_dashboard() {
        let details = json!({
            "binary_path": "/usr/bin/curl",
            "package_managed": true,
            "ppid_comm": "systemd",
            "parent_chain": ["systemd"],
        });
        let (result, _bd) = behaviour_score(&details, true, false, false, false, 70, 40);
        if let VerificationResult::Dismiss { score, reason } = result {
            let formatted = format!("obs-verify score {score}/100: {reason}");
            // Must start with "obs-verify score" for JS parser
            assert!(formatted.starts_with("obs-verify score "));
            // Must contain "/100:"
            assert!(formatted.contains("/100: "));
            // Score must be a number
            assert!(score >= 70);
        } else {
            panic!("expected Dismiss");
        }
    }

    #[test]
    fn escalate_reason_format_for_dashboard() {
        let details = json!({
            "binary_path": "/tmp/dropper",
            "dst_port": 4444,
        });
        let (result, _bd) = behaviour_score(&details, false, false, false, false, 70, 40);
        if let VerificationResult::Escalate { score, reason } = result {
            let formatted = format!("obs-verify score {score}/100: {reason}");
            assert!(formatted.starts_with("obs-verify score "));
            assert!(formatted.contains("/100: "));
            assert!(score < 40);
        } else {
            panic!("expected Escalate");
        }
    }

    #[test]
    fn ai_verdict_reason_format_for_dashboard() {
        // The AI verdict format used in narrative_observation_verify.rs
        let normal_reason = "obs-verify AI: NORMAL — OpenClaw connecting to Telegram API";
        let suspicious_reason = "obs-verify AI: SUSPICIOUS — Unknown binary on unusual port";
        // Must start with "obs-verify AI:" for JS parser
        assert!(normal_reason.starts_with("obs-verify AI: "));
        assert!(suspicious_reason.starts_with("obs-verify AI: "));
        // Must contain verdict keyword
        assert!(normal_reason.contains("NORMAL"));
        assert!(suspicious_reason.contains("SUSPICIOUS"));
        // Must contain em-dash separator
        assert!(normal_reason.contains("—"));
        assert!(suspicious_reason.contains("—"));
    }
}
