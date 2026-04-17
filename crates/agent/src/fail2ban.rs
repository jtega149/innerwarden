//! Fail2ban integration - DEPRECATED.
//!
//! Inner Warden's native detectors + XDP firewall supersede fail2ban.
//! This module is kept as a no-op stub for config compatibility.

#[derive(Debug, Clone)]
pub struct Fail2BanState {
    _private: (),
}

impl Fail2BanState {
    pub fn new(_cfg: &crate::config::Fail2BanConfig) -> Self {
        tracing::info!("{}", fail2ban_deprecation_message());
        Self { _private: () }
    }
}

/// No-op sync tick - fail2ban integration is deprecated.
#[allow(clippy::too_many_arguments)]
pub async fn sync_tick(
    _state: &mut Fail2BanState,
    _blocklist: &mut crate::skills::Blocklist,
    _skill_registry: &crate::skills::SkillRegistry,
    _cfg: &crate::config::AgentConfig,
    _decision_writer: &mut Option<crate::decisions::DecisionWriter>,
    _host: &str,
    _telegram: Option<&std::sync::Arc<crate::telegram::TelegramClient>>,
) {
    // No-op: fail2ban sync is deprecated
    let _ = fail2ban_sync_is_noop();
}

fn fail2ban_deprecation_message() -> &'static str {
    "Fail2ban integration is deprecated - InnerWarden's native detectors + XDP firewall are superior"
}

fn fail2ban_sync_is_noop() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_accepts_config_and_constructs_state() {
        // Verifies deprecated adapter remains constructible for legacy config compatibility.
        let cfg = crate::config::Fail2BanConfig::default();
        let _state = Fail2BanState::new(&cfg);
    }

    #[test]
    fn deprecation_message_mentions_native_detectors_and_xdp() {
        // Guards operator-facing wording so deprecation guidance remains explicit.
        let msg = fail2ban_deprecation_message();
        assert!(msg.contains("deprecated"));
        assert!(msg.contains("native detectors"));
        assert!(msg.contains("XDP"));
    }

    #[test]
    fn sync_tick_marker_reports_noop_behavior() {
        // Documents intentional no-op behavior for the deprecated sync path.
        assert!(fail2ban_sync_is_noop());
    }
}
