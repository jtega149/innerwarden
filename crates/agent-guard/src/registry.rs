//! Agent registry — tracks connected agents and their sessions.
//!
//! Agents connect via API or are discovered via `innerwarden agent scan`.
//! Each connected agent gets an ID, a session tracker, and a policy.
//! Multiple instances of the same agent type are supported.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

use chrono::{DateTime, Utc};

use crate::session::SessionTracker;
use crate::signatures::{Kind, SignatureIndex};

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

/// A connected agent instance.
#[derive(Debug)]
pub struct ConnectedAgent {
    pub id: String,
    pub name: String,
    pub instance_label: String,
    pub pid: u32,
    pub kind: Kind,
    pub integration: String,
    pub connected_at: DateTime<Utc>,
    pub session: SessionTracker,
    pub policy: AgentPolicy,
    pub stats: AgentStats,
}

/// Policy applied to a connected agent.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AgentPolicy {
    /// warn = notify, guard = block dangerous, kill = block everything suspicious
    pub mode: String,
    /// Block access to sensitive paths (.ssh, .env, .aws)
    pub block_sensitive_paths: bool,
    /// Wrap MCP servers with inspection proxy
    pub wrap_mcp: bool,
    /// Max tool calls per minute (0 = unlimited)
    pub max_calls_per_minute: u32,
}

impl Default for AgentPolicy {
    fn default() -> Self {
        Self {
            mode: "warn".to_string(),
            block_sensitive_paths: true,
            wrap_mcp: true,
            max_calls_per_minute: 30,
        }
    }
}

/// Runtime stats for a connected agent.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct AgentStats {
    pub tool_calls: u64,
    pub blocked: u64,
    pub warnings: u64,
    pub files_accessed: u64,
}

/// The registry of all connected agents.
#[derive(Debug)]
pub struct Registry {
    agents: HashMap<String, ConnectedAgent>,
    index: SignatureIndex,
}

impl Registry {
    pub fn new() -> Self {
        Self {
            agents: HashMap::new(),
            index: SignatureIndex::new(),
        }
    }

    /// Connect an agent by PID. Returns the agent ID.
    pub fn connect(
        &mut self,
        name: &str,
        pid: u32,
        instance_label: Option<&str>,
    ) -> Result<String, String> {
        // Check if this PID is already connected
        if self.agents.values().any(|a| a.pid == pid) {
            return Err(format!("pid {pid} already connected"));
        }

        let id = format!("ag-{:04x}", NEXT_ID.fetch_add(1, Ordering::Relaxed));

        let (kind, integration) = if let Some(sig) = self.index.identify(name) {
            (sig.kind, format!("{:?}", sig.integration).to_lowercase())
        } else {
            (Kind::Tool, "monitored".to_string())
        };

        let label = instance_label
            .unwrap_or(&format!("{name}-{pid}"))
            .to_string();

        let agent = ConnectedAgent {
            id: id.clone(),
            name: name.to_string(),
            instance_label: label,
            pid,
            kind,
            integration,
            connected_at: Utc::now(),
            session: SessionTracker::new(),
            policy: AgentPolicy::default(),
            stats: AgentStats::default(),
        };

        tracing::info!(
            agent_id = %id,
            name = %agent.name,
            pid,
            label = %agent.instance_label,
            kind = ?kind,
            "agent connected"
        );

        self.agents.insert(id.clone(), agent);
        Ok(id)
    }

    /// Disconnect an agent by ID.
    pub fn disconnect(&mut self, agent_id: &str) -> bool {
        if let Some(agent) = self.agents.remove(agent_id) {
            tracing::info!(
                agent_id,
                name = %agent.name,
                pid = agent.pid,
                tool_calls = agent.stats.tool_calls,
                blocked = agent.stats.blocked,
                "agent disconnected"
            );
            true
        } else {
            false
        }
    }

    /// Get a connected agent by ID (mutable, for recording events).
    pub fn get_mut(&mut self, agent_id: &str) -> Option<&mut ConnectedAgent> {
        self.agents.get_mut(agent_id)
    }

    /// Get a connected agent by PID.
    pub fn by_pid(&self, pid: u32) -> Option<&ConnectedAgent> {
        self.agents.values().find(|a| a.pid == pid)
    }

    /// Get a connected agent by PID (mutable).
    pub fn by_pid_mut(&mut self, pid: u32) -> Option<&mut ConnectedAgent> {
        self.agents.values_mut().find(|a| a.pid == pid)
    }

    /// List all connected agents.
    pub fn list(&self) -> Vec<AgentSummary> {
        self.agents
            .values()
            .map(|a| AgentSummary {
                id: a.id.clone(),
                name: a.name.clone(),
                instance_label: a.instance_label.clone(),
                pid: a.pid,
                kind: format!("{:?}", a.kind).to_lowercase(),
                integration: a.integration.clone(),
                connected_at: a.connected_at,
                tool_calls: a.stats.tool_calls,
                blocked: a.stats.blocked,
                warnings: a.stats.warnings,
            })
            .collect()
    }

    /// Count connected agents by kind.
    pub fn count_agents(&self) -> usize {
        self.agents
            .values()
            .filter(|a| a.kind == Kind::Agent)
            .count()
    }

    pub fn count_tools(&self) -> usize {
        self.agents
            .values()
            .filter(|a| a.kind == Kind::Tool)
            .count()
    }

    pub fn count_total(&self) -> usize {
        self.agents.len()
    }

    // ---------------------------------------------------------------------
    // Persistence (2026-05-18)
    //
    // Pre-existing: the registry was in-memory only. Every restart of the
    // agent process — including the watchdog-driven binary swap shipped in
    // #681 — wiped the ag-id assignments. The operator hit this twice in
    // the same hour after PRs #683 and #684 deployed: a known-good
    // OpenClaw at pid 1109 → ag-0001 binding vanished, the dashboard
    // returned `{"agents": [], "total": 0}`, and the operator would have
    // had to re-run `innerwarden agent connect` after every restart.
    //
    // Fix: snapshot the registry to a JSON file in the agent's data dir
    // after every connect/disconnect. Rehydrate on dashboard boot. The
    // tracked `session: SessionTracker` is per-process runtime state and
    // is reset to fresh on restore — only the durable identity (id, name,
    // pid, policy, stats) carries forward.
    // ---------------------------------------------------------------------

    /// Serialize the live agents to a snapshot suitable for `save_to`.
    /// Pure so the snapshot shape stays tested without touching disk.
    pub fn snapshot(&self) -> RegistrySnapshot {
        let agents = self
            .agents
            .values()
            .map(|a| PersistedAgent {
                id: a.id.clone(),
                name: a.name.clone(),
                instance_label: a.instance_label.clone(),
                pid: a.pid,
                kind: a.kind,
                integration: a.integration.clone(),
                connected_at: a.connected_at,
                policy: a.policy.clone(),
                stats: a.stats.clone(),
            })
            .collect();
        RegistrySnapshot {
            schema_version: 1,
            next_id: NEXT_ID.load(Ordering::Relaxed),
            agents,
        }
    }

    /// Atomic save: write JSON to `<path>.tmp` then rename. Linux
    /// rename is atomic on the same filesystem, so a crash mid-write
    /// can never leave a half-written snapshot at `path`. Fail-soft:
    /// callers should log the error but not crash the agent.
    pub fn save_to(&self, path: &std::path::Path) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let body = serde_json::to_string_pretty(&self.snapshot())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, body)?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    }

    /// Construct a registry from a previously-saved snapshot. The
    /// global `NEXT_ID` counter is reseeded above the highest seen
    /// ag-id so future `connect` calls do not collide with restored
    /// ones. A missing file is NOT an error — a clean install / first
    /// boot simply starts empty. Corrupt JSON IS an error so the
    /// operator sees the problem instead of silently losing state.
    pub fn restore_from(path: &std::path::Path) -> std::io::Result<Self> {
        if !path.exists() {
            return Ok(Self::new());
        }
        let body = std::fs::read_to_string(path)?;
        let snapshot: RegistrySnapshot = serde_json::from_str(&body)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        // Reseed NEXT_ID. Take the max of the persisted counter and
        // (max parsed ag-id + 1): the counter handles the case where
        // an agent was connected then disconnected (we lost the
        // disconnect but the counter remembers we burned the id), the
        // parsed-max handles snapshots from older code that didn't
        // persist next_id.
        let max_parsed = snapshot
            .agents
            .iter()
            .filter_map(|a| {
                a.id.strip_prefix("ag-")
                    .and_then(|hex| u64::from_str_radix(hex, 16).ok())
            })
            .max()
            .unwrap_or(0);
        let seed = snapshot.next_id.max(max_parsed + 1);
        NEXT_ID.store(seed, Ordering::Relaxed);

        let mut agents = HashMap::with_capacity(snapshot.agents.len());
        for p in snapshot.agents {
            agents.insert(
                p.id.clone(),
                ConnectedAgent {
                    id: p.id,
                    name: p.name,
                    instance_label: p.instance_label,
                    pid: p.pid,
                    kind: p.kind,
                    integration: p.integration,
                    connected_at: p.connected_at,
                    session: SessionTracker::new(),
                    policy: p.policy,
                    stats: p.stats,
                },
            );
        }

        Ok(Self {
            agents,
            index: SignatureIndex::new(),
        })
    }
}

/// Wire format for the persisted registry. Versioned so future
/// schema changes can branch on `schema_version`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RegistrySnapshot {
    pub schema_version: u32,
    pub next_id: u64,
    pub agents: Vec<PersistedAgent>,
}

/// One entry in the snapshot. Mirrors `ConnectedAgent` minus the
/// per-process runtime state (`SessionTracker`) which is reset on
/// restore.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PersistedAgent {
    pub id: String,
    pub name: String,
    pub instance_label: String,
    pub pid: u32,
    pub kind: Kind,
    pub integration: String,
    pub connected_at: DateTime<Utc>,
    pub policy: AgentPolicy,
    pub stats: AgentStats,
}

// `AgentStats` needs `Deserialize` for the round-trip; the existing
// `serde::Serialize` derive on the struct definition does not include
// it, so we add a separate impl block here. Keeping the change scoped
// to this file (the field set is small and stable).
impl<'de> serde::Deserialize<'de> for AgentStats {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        struct Mirror {
            #[serde(default)]
            tool_calls: u64,
            #[serde(default)]
            blocked: u64,
            #[serde(default)]
            warnings: u64,
            #[serde(default)]
            files_accessed: u64,
        }
        let m = Mirror::deserialize(deserializer)?;
        Ok(AgentStats {
            tool_calls: m.tool_calls,
            blocked: m.blocked,
            warnings: m.warnings,
            files_accessed: m.files_accessed,
        })
    }
}

impl Default for Registry {
    fn default() -> Self {
        Self::new()
    }
}

/// Summary for API/CLI output.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AgentSummary {
    pub id: String,
    pub name: String,
    pub instance_label: String,
    pub pid: u32,
    pub kind: String,
    pub integration: String,
    pub connected_at: DateTime<Utc>,
    pub tool_calls: u64,
    pub blocked: u64,
    pub warnings: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_and_list() {
        let mut reg = Registry::new();
        let id = reg.connect("openclaw", 1234, Some("work-agent")).unwrap();
        assert!(id.starts_with("ag-"));

        let list = reg.list();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].name, "openclaw");
        assert_eq!(list[0].instance_label, "work-agent");
        assert_eq!(list[0].kind, "agent");
    }

    #[test]
    fn multiple_instances_same_agent() {
        let mut reg = Registry::new();
        let id1 = reg.connect("openclaw", 1000, Some("personal")).unwrap();
        let id2 = reg.connect("openclaw", 2000, Some("work")).unwrap();
        assert_ne!(id1, id2);
        assert_eq!(reg.count_agents(), 2);
    }

    #[test]
    fn reject_duplicate_pid() {
        let mut reg = Registry::new();
        reg.connect("openclaw", 1234, None).unwrap();
        assert!(reg.connect("zeroclaw", 1234, None).is_err());
    }

    #[test]
    fn disconnect() {
        let mut reg = Registry::new();
        let id = reg.connect("openclaw", 1234, None).unwrap();
        assert_eq!(reg.count_total(), 1);
        assert!(reg.disconnect(&id));
        assert_eq!(reg.count_total(), 0);
    }

    #[test]
    fn by_pid() {
        let mut reg = Registry::new();
        reg.connect("openclaw", 1234, None).unwrap();
        assert!(reg.by_pid(1234).is_some());
        assert!(reg.by_pid(9999).is_none());
    }

    #[test]
    fn unknown_agent_connects_as_tool() {
        let mut reg = Registry::new();
        reg.connect("my-custom-agent", 5555, None).unwrap();
        let list = reg.list();
        assert_eq!(list[0].kind, "tool");
        assert_eq!(list[0].integration, "monitored");
    }

    #[test]
    fn mixed_agents_and_tools() {
        let mut reg = Registry::new();
        reg.connect("openclaw", 1000, None).unwrap();
        reg.connect("claude", 2000, None).unwrap();
        reg.connect("ollama", 3000, None).unwrap();
        assert_eq!(reg.count_agents(), 1); // only openclaw
        assert_eq!(reg.count_tools(), 1); // claude
        assert_eq!(reg.count_total(), 3);
    }

    // -----------------------------------------------------------------
    // Persistence (2026-05-18) — regression anchors for the agent-guard
    // registry losing all state on every agent restart. Operator saw
    // {"agents": [], "total": 0} from /api/agent-guard/agents
    // immediately after the watchdog dance from PRs #683/#684 swapped
    // the agent binary. Without these tests the in-memory-only
    // behaviour could regress invisibly.
    // -----------------------------------------------------------------

    fn unique_pid() -> u32 {
        // The NEXT_ID counter is a global static, so we randomise pids
        // across persistence tests to avoid collisions with sibling
        // tests in the same module (registry insists pids be unique).
        // Using `std::process::id() ^ time_nanos` keeps the pid unique
        // per test invocation without pulling in a random crate.
        let t = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos();
        (std::process::id() ^ t) & 0x7fff_ffff
    }

    #[test]
    fn snapshot_round_trips_through_save_to_and_restore_from() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("registry.json");
        let pid = unique_pid();

        let mut reg = Registry::new();
        let id = reg.connect("openclaw", pid, Some("prod")).unwrap();
        // Tweak stats so we can prove they round-trip too.
        let agent = reg.get_mut(&id).unwrap();
        agent.stats.tool_calls = 17;
        agent.stats.blocked = 3;
        agent.policy.mode = "guard".to_string();
        agent.policy.max_calls_per_minute = 60;

        reg.save_to(&path).expect("save_to");

        let restored = Registry::restore_from(&path).expect("restore_from");
        let listed = restored.list();
        assert_eq!(listed.len(), 1);
        let entry = &listed[0];
        assert_eq!(entry.id, id);
        assert_eq!(entry.name, "openclaw");
        assert_eq!(entry.instance_label, "prod");
        assert_eq!(entry.pid, pid);
        assert_eq!(entry.kind, "agent");
        assert_eq!(entry.integration, "official");
        assert_eq!(entry.tool_calls, 17);
        assert_eq!(entry.blocked, 3);
        // Policy is not on AgentSummary; reach into the registry directly.
        let agent = restored.by_pid(pid).expect("restored agent by pid");
        assert_eq!(agent.policy.mode, "guard");
        assert_eq!(agent.policy.max_calls_per_minute, 60);
    }

    #[test]
    fn restore_from_missing_file_returns_empty_registry() {
        // Clean-install / first-boot case. Must not be an error.
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("does-not-exist.json");
        let reg = Registry::restore_from(&path).expect("missing file ok");
        assert_eq!(reg.count_total(), 0);
    }

    #[test]
    fn restore_from_corrupt_json_returns_invalid_data_error() {
        // Don't silently lose state — surface the corruption so the
        // operator sees it.
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("corrupt.json");
        std::fs::write(&path, "this is not json {{ broken").unwrap();
        let err = Registry::restore_from(&path).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn restore_seeds_next_id_above_restored_ids_so_future_connects_dont_collide() {
        // The exact failure this guards against: snapshot has ag-0001,
        // we restart, NEXT_ID resets to 1, next connect tries to mint
        // ag-0001 again and overwrites the restored agent.
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("registry.json");
        let pid_a = unique_pid();
        let pid_b = unique_pid().wrapping_add(1);

        // Pre-write a snapshot with a high-numbered id but a low
        // next_id — exercises the "parse max id + 1" branch.
        let snapshot = RegistrySnapshot {
            schema_version: 1,
            next_id: 1,
            agents: vec![PersistedAgent {
                id: "ag-0042".to_string(),
                name: "openclaw".to_string(),
                instance_label: "test".to_string(),
                pid: pid_a,
                kind: Kind::Agent,
                integration: "official".to_string(),
                connected_at: chrono::Utc::now(),
                policy: AgentPolicy::default(),
                stats: AgentStats::default(),
            }],
        };
        std::fs::write(&path, serde_json::to_string(&snapshot).unwrap()).unwrap();

        let mut reg = Registry::restore_from(&path).expect("restore_from");
        // Existing agent restored.
        assert!(reg.by_pid(pid_a).is_some());

        // New connect must NOT reuse ag-0042.
        let new_id = reg.connect("claude", pid_b, None).unwrap();
        assert_ne!(new_id, "ag-0042");
        // Must be strictly above 0x42 = 66.
        let parsed = u64::from_str_radix(new_id.trim_start_matches("ag-"), 16).unwrap();
        assert!(
            parsed > 0x42,
            "new id {new_id} should be > ag-0042 to avoid collision"
        );
    }

    #[test]
    fn save_to_is_atomic_via_rename() {
        // The .tmp side-file must not linger after a successful save —
        // an orphaned .tmp would mean we crashed mid-rename, which
        // never happens on a clean save.
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("registry.json");
        let mut reg = Registry::new();
        reg.connect("openclaw", unique_pid(), None).unwrap();
        reg.save_to(&path).expect("save");
        assert!(path.exists());
        assert!(
            !path.with_extension("json.tmp").exists(),
            "tmp file must be renamed away on success"
        );
    }
}
