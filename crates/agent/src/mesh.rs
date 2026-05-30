//! Mesh network integration - wraps innerwarden-mesh for the agent.
//!
//! Always compiled. Disabled by default via config (`mesh.enabled = false`).

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::path::Path;

use innerwarden_mesh::config::{MeshConfig, PeerEntry};
use innerwarden_mesh::node::MeshNode;
pub use innerwarden_mesh::{AdvisorySuppression, MeshTickResult};

use crate::config::MeshNetworkConfig;

/// Spec 062 Phase 6b — best-effort audit of a received suppression advisory.
/// Honesty invariant: a peer-influenced suppression is never silent. One line
/// per advisory to `mesh_advisory_suppressions-<date>.jsonl`, recording the
/// peer, shape, trust, and whether it passed THIS host's local gate.
pub fn append_advisory_audit(
    data_dir: &Path,
    adv: &AdvisorySuppression,
    applied: bool,
    now: chrono::DateTime<chrono::Utc>,
) {
    use std::io::Write;
    let date = now.format("%Y-%m-%d");
    let path = data_dir.join(format!("mesh_advisory_suppressions-{date}.jsonl"));
    let line = serde_json::json!({
        "ts": now.to_rfc3339(),
        "peer": adv.node_id,
        "detector": adv.detector,
        "ip": adv.ip,
        "shape": adv.shape(),
        "peer_dismissals": adv.dismissals,
        "peer_trust": adv.peer_trust,
        "applied": applied,
    });
    match std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        Ok(mut f) => {
            let _ = writeln!(f, "{line}");
        }
        Err(e) => tracing::warn!(path = %path.display(), "mesh advisory audit append failed: {e}"),
    }
}

/// Spec 062 Phase 6b — apply a batch of drained suppression advisories under
/// THIS host's local second gate, recording corroboration and auditing each.
///
/// The gate (only runs when `corroboration_enabled`): the shape must already be
/// dismissed locally at least once (`genuine_dismissals >= 1`) AND have zero
/// weighty history. Only then does the advisory record a distinct-peer
/// corroboration — it can never originate a suppression. Every advisory is
/// audited (applied or not). Returns the number that passed the gate.
///
/// Extracted from the slow-loop mesh tick so the gate is unit-testable.
pub fn apply_advisory_suppressions(
    m: &mut MeshIntegration,
    advisories: &[AdvisorySuppression],
    store: Option<&innerwarden_store::Store>,
    corroboration_enabled: bool,
    data_dir: &Path,
    now: chrono::DateTime<chrono::Utc>,
) -> usize {
    let mut applied = 0usize;
    for adv in advisories {
        let mut ok = false;
        if corroboration_enabled {
            if let Some(store) = store {
                if let Ok(stats) = store.shape_dismissal_stats(
                    &adv.detector,
                    &adv.ip,
                    crate::learned_suppression::EXCLUDED_DISMISS_PROVIDERS,
                    crate::learned_suppression::ACTIONED_TYPES,
                ) {
                    if stats.genuine_dismissals >= 1 && stats.actioned == 0 {
                        m.record_corroboration(&adv.shape(), &adv.node_id);
                        ok = true;
                        applied += 1;
                    }
                }
            }
        }
        append_advisory_audit(data_dir, adv, ok, now);
    }
    applied
}

fn mesh_config_from_agent_config(cfg: &MeshNetworkConfig) -> MeshConfig {
    MeshConfig {
        enabled: cfg.enabled,
        bind: cfg.bind.clone(),
        peers: cfg
            .peers
            .iter()
            .map(|p| PeerEntry {
                endpoint: p.endpoint.clone(),
                public_key: p.public_key.clone(),
                label: p.label.clone(),
            })
            .collect(),
        poll_secs: cfg.poll_secs,
        auto_broadcast: cfg.auto_broadcast,
        max_signals_per_hour: cfg.max_signals_per_hour,
        max_staged: 10_000,
        initial_trust: 0.5,
    }
}

#[allow(dead_code)]
pub struct MeshIntegration {
    node: MeshNode,
    /// Spec 062 Phase 6b — per-shape set of high-trust peers that have advised
    /// suppressing it AND that passed this host's local gate (the shape is
    /// already dismissed here). `corroboration_for` returns the set size, so
    /// repeat advisories from the same peer never inflate the count.
    corroboration: HashMap<String, HashSet<String>>,
}

#[allow(dead_code)]
impl MeshIntegration {
    pub fn new(cfg: &MeshNetworkConfig, data_dir: &Path) -> anyhow::Result<Self> {
        let mesh_cfg = mesh_config_from_agent_config(cfg);
        let node = MeshNode::new(mesh_cfg, data_dir)?;
        Ok(Self {
            node,
            corroboration: HashMap::new(),
        })
    }

    pub async fn start_listener(
        &self,
    ) -> anyhow::Result<(SocketAddr, tokio::task::JoinHandle<()>)> {
        self.node.start_listener().await
    }

    pub async fn discover_peers(&mut self) {
        self.node.discover_peers().await;
    }

    pub async fn broadcast_local_block(
        &self,
        ip: &str,
        detector: &str,
        confidence: f32,
        evidence: &[u8],
        ttl_secs: u64,
    ) {
        self.node
            .broadcast_local_block(ip, detector, confidence, evidence, ttl_secs)
            .await;
    }

    pub fn tick(&mut self) -> MeshTickResult {
        self.node.tick()
    }

    /// Spec 062 Phase 6b — broadcast a local learned suppression to peers
    /// (advisory; peers apply their own local gate).
    pub async fn broadcast_local_suppression(
        &self,
        detector: &str,
        ip: &str,
        dismissals: u64,
        ttl_secs: u64,
    ) {
        self.node
            .broadcast_local_suppression(detector, ip, dismissals, ttl_secs)
            .await;
    }

    /// Drain the inbound suppression advisories from the mesh layer. The caller
    /// (slow loop) applies the local second gate and feeds survivors back via
    /// [`record_corroboration`](Self::record_corroboration).
    pub fn drain_advisory_suppressions(&mut self) -> Vec<AdvisorySuppression> {
        self.node.drain_advisory_suppressions()
    }

    /// Record that `node_id` corroborated `shape` (already passed the local
    /// gate). Idempotent per peer — the count is the distinct-peer set size.
    pub fn record_corroboration(&mut self, shape: &str, node_id: &str) {
        self.corroboration
            .entry(shape.to_string())
            .or_default()
            .insert(node_id.to_string());
    }

    /// Distinct high-trust peers corroborating a shape's suppression.
    pub fn corroboration_for(&self, shape: &str) -> u64 {
        self.corroboration
            .get(shape)
            .map(|s| s.len() as u64)
            .unwrap_or(0)
    }

    pub async fn rediscover_if_needed(&mut self) {
        self.node.rediscover_if_needed().await;
    }

    pub fn is_mesh_blocked(&self, ip: &str) -> bool {
        self.node.is_mesh_blocked(ip)
    }

    pub fn confirm_local_incident(&self, ip: &str) {
        self.node.confirm_local_incident(ip);
    }

    pub fn persist(&self) -> anyhow::Result<()> {
        self.node.persist()
    }

    pub fn node_id(&self) -> &str {
        self.node.node_id()
    }

    pub fn peer_count(&self) -> usize {
        self.node.peer_count()
    }

    pub fn staged_count(&self) -> usize {
        self.node.staged_count()
    }

    pub fn active_block_count(&self) -> usize {
        self.node.active_block_count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::MeshPeerEntry;

    #[test]
    fn mesh_config_builder_maps_core_flags_and_peers() {
        // Mapping path: the adapter must preserve runtime flags and convert
        // every peer entry from agent config into mesh-native peers.
        let cfg = MeshNetworkConfig {
            enabled: true,
            bind: "0.0.0.0:4444".to_string(),
            peers: vec![MeshPeerEntry {
                endpoint: "https://peer-a.mesh".to_string(),
                public_key: "pubkey-a".to_string(),
                label: Some("peer-a".to_string()),
            }],
            poll_secs: 42,
            auto_broadcast: false,
            max_signals_per_hour: 777,
        };

        let mesh = mesh_config_from_agent_config(&cfg);
        assert!(mesh.enabled);
        assert_eq!(mesh.bind, "0.0.0.0:4444");
        assert_eq!(mesh.poll_secs, 42);
        assert!(!mesh.auto_broadcast);
        assert_eq!(mesh.max_signals_per_hour, 777);
        assert_eq!(mesh.peers.len(), 1);
        assert_eq!(mesh.peers[0].endpoint, "https://peer-a.mesh");
        assert_eq!(mesh.peers[0].public_key, "pubkey-a");
    }

    #[test]
    fn mesh_config_builder_preserves_optional_peer_label() {
        // Metadata path: peer labels are optional and should survive the
        // conversion so operator-facing peer naming remains intact.
        let cfg = MeshNetworkConfig {
            enabled: false,
            bind: "127.0.0.1:4450".to_string(),
            peers: vec![
                MeshPeerEntry {
                    endpoint: "https://peer-labeled.mesh".to_string(),
                    public_key: "pubkey-labeled".to_string(),
                    label: Some("trusted-peer".to_string()),
                },
                MeshPeerEntry {
                    endpoint: "https://peer-unlabeled.mesh".to_string(),
                    public_key: "pubkey-unlabeled".to_string(),
                    label: None,
                },
            ],
            poll_secs: 60,
            auto_broadcast: true,
            max_signals_per_hour: 200,
        };

        let mesh = mesh_config_from_agent_config(&cfg);
        assert_eq!(mesh.peers[0].label.as_deref(), Some("trusted-peer"));
        assert_eq!(mesh.peers[1].label, None);
    }

    #[test]
    fn mesh_config_builder_applies_fixed_safety_limits() {
        // Safety path: the integration enforces fixed mesh limits that are
        // intentionally not user-configurable from agent.toml.
        let cfg = MeshNetworkConfig {
            enabled: true,
            bind: "127.0.0.1:4451".to_string(),
            peers: Vec::new(),
            poll_secs: 30,
            auto_broadcast: true,
            max_signals_per_hour: 1000,
        };

        let mesh = mesh_config_from_agent_config(&cfg);
        assert_eq!(mesh.max_staged, 10_000);
        assert_eq!(mesh.initial_trust, 0.5);
    }

    fn mk_advisory(detector: &str, ip: &str, peer: &str) -> AdvisorySuppression {
        AdvisorySuppression {
            node_id: peer.to_string(),
            detector: detector.to_string(),
            ip: ip.to_string(),
            dismissals: 9,
            peer_trust: 0.9,
        }
    }

    fn seed_dismiss(store: &innerwarden_store::Store, incident_id: &str, ip: &str) {
        store
            .insert_decision(&innerwarden_store::decisions::DecisionRow {
                ts: chrono::Utc::now().to_rfc3339(),
                incident_id: incident_id.into(),
                action_type: "dismiss".into(),
                target_ip: Some(ip.into()),
                target_user: None,
                confidence: 1.0,
                auto_executed: true,
                reason: Some("test".into()),
                data: serde_json::json!({ "ai_provider": "noise-gate" }).to_string(),
            })
            .unwrap();
    }

    fn mesh_for_test(dir: &std::path::Path) -> MeshIntegration {
        let cfg = MeshNetworkConfig {
            enabled: false,
            bind: "127.0.0.1:0".to_string(),
            peers: Vec::new(),
            poll_secs: 30,
            auto_broadcast: false,
            max_signals_per_hour: 100,
        };
        MeshIntegration::new(&cfg, dir).unwrap()
    }

    #[test]
    fn apply_advisory_gate_records_only_locally_dismissed_shapes() {
        let dir = tempfile::tempdir().unwrap();
        let store = innerwarden_store::Store::open(dir.path()).unwrap();
        let ip = "169.254.169.254";
        // imds_ssrf is dismissed locally twice; web_scan never.
        seed_dismiss(&store, &format!("imds_ssrf:{ip}:1"), ip);
        seed_dismiss(&store, &format!("imds_ssrf:{ip}:2"), ip);
        let mut m = mesh_for_test(dir.path());
        let advisories = vec![
            mk_advisory("imds_ssrf", ip, "peer-a"),
            mk_advisory("web_scan", "8.8.8.8", "peer-a"), // never dismissed locally
        ];
        let applied = apply_advisory_suppressions(
            &mut m,
            &advisories,
            Some(&store),
            true,
            dir.path(),
            chrono::Utc::now(),
        );
        assert_eq!(
            applied, 1,
            "only the locally-dismissed shape passes the gate"
        );
        assert_eq!(m.corroboration_for(&format!("imds_ssrf|{ip}")), 1);
        assert_eq!(m.corroboration_for("web_scan|8.8.8.8"), 0);
        // Both advisories are audited regardless.
        let date = chrono::Utc::now().format("%Y-%m-%d");
        let audit = std::fs::read_to_string(
            dir.path()
                .join(format!("mesh_advisory_suppressions-{date}.jsonl")),
        )
        .unwrap();
        assert_eq!(audit.lines().count(), 2);
        assert!(audit.contains("\"applied\":true"));
        assert!(audit.contains("\"applied\":false"));
    }

    #[test]
    fn apply_advisory_records_nothing_when_corroboration_disabled() {
        let dir = tempfile::tempdir().unwrap();
        let store = innerwarden_store::Store::open(dir.path()).unwrap();
        let ip = "169.254.169.254";
        seed_dismiss(&store, &format!("imds_ssrf:{ip}:1"), ip);
        let mut m = mesh_for_test(dir.path());
        let advisories = vec![mk_advisory("imds_ssrf", ip, "peer-a")];
        let applied = apply_advisory_suppressions(
            &mut m,
            &advisories,
            Some(&store),
            false,
            dir.path(),
            chrono::Utc::now(),
        );
        assert_eq!(applied, 0, "disabled → never records");
        assert_eq!(m.corroboration_for(&format!("imds_ssrf|{ip}")), 0);
        // Still audited (applied=false) for visibility.
        let date = chrono::Utc::now().format("%Y-%m-%d");
        assert!(dir
            .path()
            .join(format!("mesh_advisory_suppressions-{date}.jsonl"))
            .exists());
    }

    #[test]
    fn corroboration_counts_distinct_peers_only() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = MeshNetworkConfig {
            enabled: false,
            bind: "127.0.0.1:0".to_string(),
            peers: Vec::new(),
            poll_secs: 30,
            auto_broadcast: false,
            max_signals_per_hour: 100,
        };
        let mut m = MeshIntegration::new(&cfg, dir.path()).unwrap();
        let shape = "imds_ssrf|169.254.169.254";
        assert_eq!(m.corroboration_for(shape), 0);
        m.record_corroboration(shape, "peer-a");
        m.record_corroboration(shape, "peer-a"); // dup: same peer, no inflation
        m.record_corroboration(shape, "peer-b");
        assert_eq!(m.corroboration_for(shape), 2);
        // A different shape is independent.
        assert_eq!(m.corroboration_for("web_scan|8.8.8.8"), 0);
    }
}
