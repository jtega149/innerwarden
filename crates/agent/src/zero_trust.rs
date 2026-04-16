//! Graduated enforcement state machine (spec 020 Phase F-partial).
//!
//! Supports `learning` and `notify` modes for the free product.
//! The `enforce` mode is gated behind the paid active-defence product.
//!
//! In `learning` mode, unknown binaries and connections are recorded
//! but no alerts are generated.  In `notify` mode, alerts are sent
//! but no enforcement happens.

use serde::{Deserialize, Serialize};

// ── Enforcement mode ────────────────────────────────────────────────────

/// The enforcement mode for a zero-trust subsystem.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EnforcementMode {
    /// Record unknown entities without alerting. Building baseline.
    #[default]
    Learning,
    /// Alert on unknown entities but do not block.
    Notify,
    /// Block unknown entities at the kernel level (paid only).
    Enforce,
}

impl EnforcementMode {
    /// Whether this mode should record observations to the baseline.
    pub fn should_record(&self) -> bool {
        // All modes record to baseline
        true
    }

    /// Whether this mode should generate alerts for unknown entities.
    pub fn should_alert(&self) -> bool {
        matches!(self, Self::Notify | Self::Enforce)
    }

    /// Whether this mode should block unknown entities.
    pub fn should_block(&self) -> bool {
        matches!(self, Self::Enforce)
    }

    /// Whether this mode is available in the free product.
    pub fn is_free(&self) -> bool {
        matches!(self, Self::Learning | Self::Notify)
    }

    /// Human-readable label for dashboard display.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Learning => "Learning",
            Self::Notify => "Notify",
            Self::Enforce => "Enforce",
        }
    }
}

// ── Zero Trust config ───────────────────────────────────────────────────

/// Configuration for zero-trust enforcement.
#[derive(Debug, Clone, Deserialize)]
pub struct ZeroTrustConfig {
    /// Enforcement mode for execution gate (unknown binaries).
    #[serde(default)]
    pub execution_mode: EnforcementMode,
    /// Enforcement mode for network micro-segmentation.
    #[serde(default)]
    pub network_mode: EnforcementMode,
}

impl Default for ZeroTrustConfig {
    fn default() -> Self {
        Self {
            execution_mode: EnforcementMode::Learning,
            network_mode: EnforcementMode::Learning,
        }
    }
}

impl ZeroTrustConfig {
    /// Validate the config: enforce mode requires paid product.
    /// Returns errors for invalid configurations.
    pub fn validate(&self, has_active_defence: bool) -> Vec<String> {
        let mut errors = Vec::new();
        if self.execution_mode == EnforcementMode::Enforce && !has_active_defence {
            errors.push(
                "execution_mode = \"enforce\" requires innerwarden-active-defence".to_string(),
            );
        }
        if self.network_mode == EnforcementMode::Enforce && !has_active_defence {
            errors
                .push("network_mode = \"enforce\" requires innerwarden-active-defence".to_string());
        }
        errors
    }

    /// Effective execution mode: downgrades enforce → notify if paid product is missing.
    pub fn effective_execution_mode(&self, has_active_defence: bool) -> EnforcementMode {
        if self.execution_mode == EnforcementMode::Enforce && !has_active_defence {
            EnforcementMode::Notify
        } else {
            self.execution_mode
        }
    }

    /// Effective network mode: downgrades enforce → notify if paid product is missing.
    pub fn effective_network_mode(&self, has_active_defence: bool) -> EnforcementMode {
        if self.network_mode == EnforcementMode::Enforce && !has_active_defence {
            EnforcementMode::Notify
        } else {
            self.network_mode
        }
    }
}

// ── Observation record ──────────────────────────────────────────────────

/// An observation recorded during learning/notify mode.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Observation {
    /// What was observed (binary hash, process comm, connection destination).
    pub entity: String,
    /// Type: "binary", "connection", "process".
    pub kind: String,
    /// First seen timestamp.
    pub first_seen: chrono::DateTime<chrono::Utc>,
    /// Last seen timestamp.
    pub last_seen: chrono::DateTime<chrono::Utc>,
    /// Number of times observed.
    pub count: u64,
}

impl Observation {
    /// Create a new observation.
    pub fn new(entity: &str, kind: &str) -> Self {
        let now = chrono::Utc::now();
        Self {
            entity: entity.to_string(),
            kind: kind.to_string(),
            first_seen: now,
            last_seen: now,
            count: 1,
        }
    }

    /// Update the observation with a new sighting.
    pub fn observe(&mut self) {
        self.last_seen = chrono::Utc::now();
        self.count += 1;
    }
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── EnforcementMode: 3+ tests per method ────────────────────────────

    #[test]
    fn mode_should_record_all() {
        assert!(EnforcementMode::Learning.should_record());
        assert!(EnforcementMode::Notify.should_record());
        assert!(EnforcementMode::Enforce.should_record());
    }

    #[test]
    fn mode_should_alert() {
        assert!(!EnforcementMode::Learning.should_alert());
        assert!(EnforcementMode::Notify.should_alert());
        assert!(EnforcementMode::Enforce.should_alert());
    }

    #[test]
    fn mode_should_block() {
        assert!(!EnforcementMode::Learning.should_block());
        assert!(!EnforcementMode::Notify.should_block());
        assert!(EnforcementMode::Enforce.should_block());
    }

    #[test]
    fn mode_is_free() {
        assert!(EnforcementMode::Learning.is_free());
        assert!(EnforcementMode::Notify.is_free());
        assert!(!EnforcementMode::Enforce.is_free());
    }

    #[test]
    fn mode_labels() {
        assert_eq!(EnforcementMode::Learning.label(), "Learning");
        assert_eq!(EnforcementMode::Notify.label(), "Notify");
        assert_eq!(EnforcementMode::Enforce.label(), "Enforce");
    }

    #[test]
    fn mode_default_is_learning() {
        assert_eq!(EnforcementMode::default(), EnforcementMode::Learning);
    }

    #[test]
    fn mode_serializes() {
        let json = serde_json::to_string(&EnforcementMode::Notify).unwrap();
        assert_eq!(json, "\"notify\"");
    }

    #[test]
    fn mode_deserializes() {
        let m: EnforcementMode = serde_json::from_str("\"enforce\"").unwrap();
        assert_eq!(m, EnforcementMode::Enforce);
    }

    #[test]
    fn mode_deserializes_case() {
        // serde rename_all = lowercase, so "Learning" should fail
        let r = serde_json::from_str::<EnforcementMode>("\"Learning\"");
        assert!(r.is_err());
    }

    // ── ZeroTrustConfig tests ───────────────────────────────────────────

    #[test]
    fn config_default() {
        let cfg = ZeroTrustConfig::default();
        assert_eq!(cfg.execution_mode, EnforcementMode::Learning);
        assert_eq!(cfg.network_mode, EnforcementMode::Learning);
    }

    #[test]
    fn config_deserialize_toml() {
        let toml = r#"
            execution_mode = "notify"
            network_mode = "learning"
        "#;
        let cfg: ZeroTrustConfig = toml::from_str(toml).unwrap();
        assert_eq!(cfg.execution_mode, EnforcementMode::Notify);
        assert_eq!(cfg.network_mode, EnforcementMode::Learning);
    }

    #[test]
    fn config_deserialize_default() {
        let cfg: ZeroTrustConfig = toml::from_str("").unwrap();
        assert_eq!(cfg.execution_mode, EnforcementMode::Learning);
    }

    // ── validate tests ──────────────────────────────────────────────────

    #[test]
    fn validate_free_modes_ok() {
        let cfg = ZeroTrustConfig {
            execution_mode: EnforcementMode::Notify,
            network_mode: EnforcementMode::Learning,
        };
        assert!(cfg.validate(false).is_empty());
    }

    #[test]
    fn validate_enforce_without_licence() {
        let cfg = ZeroTrustConfig {
            execution_mode: EnforcementMode::Enforce,
            network_mode: EnforcementMode::Enforce,
        };
        let errors = cfg.validate(false);
        assert_eq!(errors.len(), 2);
        assert!(errors[0].contains("active-defence"));
    }

    #[test]
    fn validate_enforce_with_licence() {
        let cfg = ZeroTrustConfig {
            execution_mode: EnforcementMode::Enforce,
            network_mode: EnforcementMode::Enforce,
        };
        assert!(cfg.validate(true).is_empty());
    }

    // ── effective_*_mode tests ──────────────────────────────────────────

    #[test]
    fn effective_mode_downgrades_without_licence() {
        let cfg = ZeroTrustConfig {
            execution_mode: EnforcementMode::Enforce,
            network_mode: EnforcementMode::Enforce,
        };
        assert_eq!(cfg.effective_execution_mode(false), EnforcementMode::Notify);
        assert_eq!(cfg.effective_network_mode(false), EnforcementMode::Notify);
    }

    #[test]
    fn effective_mode_keeps_with_licence() {
        let cfg = ZeroTrustConfig {
            execution_mode: EnforcementMode::Enforce,
            network_mode: EnforcementMode::Enforce,
        };
        assert_eq!(cfg.effective_execution_mode(true), EnforcementMode::Enforce);
        assert_eq!(cfg.effective_network_mode(true), EnforcementMode::Enforce);
    }

    #[test]
    fn effective_mode_free_unchanged() {
        let cfg = ZeroTrustConfig {
            execution_mode: EnforcementMode::Notify,
            network_mode: EnforcementMode::Learning,
        };
        assert_eq!(cfg.effective_execution_mode(false), EnforcementMode::Notify);
        assert_eq!(cfg.effective_network_mode(false), EnforcementMode::Learning);
    }

    // ── Observation tests ───────────────────────────────────────────────

    #[test]
    fn observation_new() {
        let o = Observation::new("/usr/bin/curl", "binary");
        assert_eq!(o.entity, "/usr/bin/curl");
        assert_eq!(o.kind, "binary");
        assert_eq!(o.count, 1);
    }

    #[test]
    fn observation_observe_increments() {
        let mut o = Observation::new("10.0.0.1:443", "connection");
        o.observe();
        o.observe();
        assert_eq!(o.count, 3);
    }

    #[test]
    fn observation_serializes() {
        let o = Observation::new("nginx", "process");
        let json = serde_json::to_string(&o).unwrap();
        assert!(json.contains("nginx"));
        assert!(json.contains("process"));
    }
}
