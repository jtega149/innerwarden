//! Mesh network integration - wraps innerwarden-mesh for the agent.
//!
//! Always compiled. Disabled by default via config (`mesh.enabled = false`).

use std::net::SocketAddr;
use std::path::Path;

use innerwarden_mesh::config::{MeshConfig, PeerEntry};
use innerwarden_mesh::node::MeshNode;
pub use innerwarden_mesh::MeshTickResult;

use crate::config::MeshNetworkConfig;

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
}

#[allow(dead_code)]
impl MeshIntegration {
    pub fn new(cfg: &MeshNetworkConfig, data_dir: &Path) -> anyhow::Result<Self> {
        let mesh_cfg = mesh_config_from_agent_config(cfg);
        let node = MeshNode::new(mesh_cfg, data_dir)?;
        Ok(Self { node })
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
}
