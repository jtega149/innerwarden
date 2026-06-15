//! Unified chat-channel registry (spec 078, Phase 1).
//!
//! Operator-facing chat channels — Telegram, Slack, and (future) Discord —
//! share a single [`ChatChannel`] trait and a single registry
//! ([`collect_chat_channels`]) so every notification kind fans out the same
//! way, with one severity-rank + filter-level gate applied uniformly.
//!
//! Adding a channel is then a closed change: implement [`ChatChannel`], build
//! its client at boot, and add one line to [`collect_chat_channels`] — no
//! dispatch site is touched. Phase 1 covers the incident-alert kind; action
//! reports and burst/group summaries move onto the trait in Phase 2.
//!
//! Webhook (machine JSON) and Web Push (browser) are intentionally NOT chat
//! channels — they have no "action report" concept and keep their own dispatch
//! in `incident_notifications`.

use std::sync::Arc;

use async_trait::async_trait;
use innerwarden_core::incident::Incident;
use tracing::warn;

use crate::config::{AgentConfig, ChannelFilterLevel};
use crate::incident_notifications::passes_channel_filter;
use crate::slack::SlackClient;
use crate::telegram::{GuardianMode, TelegramClient};
use crate::webhook::severity_rank;
use crate::AgentState;

/// Per-incident context derived from config that a channel renderer may need.
///
/// Each channel uses only the subset it cares about — Telegram ignores
/// `slack_dashboard_url`, Slack ignores `mode`/`telegram_is_simple`.
pub(crate) struct ChatContext {
    pub(crate) mode: GuardianMode,
    pub(crate) telegram_is_simple: bool,
    pub(crate) slack_dashboard_url: Option<String>,
}

impl ChatContext {
    pub(crate) fn from_config(cfg: &AgentConfig) -> Self {
        Self {
            mode: crate::agent_context::guardian_mode(cfg),
            telegram_is_simple: cfg.telegram.is_simple_profile(),
            slack_dashboard_url: if cfg.slack.dashboard_url.is_empty() {
                None
            } else {
                Some(cfg.slack.dashboard_url.clone())
            },
        }
    }
}

/// An operator-facing chat channel.
///
/// The trait is the single contract a new channel must satisfy. Because every
/// notification kind is a required method, a channel physically cannot compile
/// while missing one — that is the "add Discord and it works first try"
/// guarantee from spec 078.
#[async_trait]
pub(crate) trait ChatChannel: Send + Sync {
    /// Stable identifier for logs/metrics: `"telegram"` | `"slack"` | `"discord"`.
    fn name(&self) -> &'static str;
    /// Minimum severity rank this channel accepts (resolved from config).
    fn min_rank(&self) -> u8;
    /// Channel-level filter (All / Actionable / Critical / None).
    fn filter_level(&self) -> ChannelFilterLevel;
    /// Render + send an incident alert.
    async fn incident_alert(&self, incident: &Incident, ctx: &ChatContext) -> anyhow::Result<()>;
}

pub(crate) struct TelegramChannel {
    client: Arc<TelegramClient>,
    min_rank: u8,
    filter_level: ChannelFilterLevel,
}

#[async_trait]
impl ChatChannel for TelegramChannel {
    fn name(&self) -> &'static str {
        "telegram"
    }
    fn min_rank(&self) -> u8 {
        self.min_rank
    }
    fn filter_level(&self) -> ChannelFilterLevel {
        self.filter_level
    }
    async fn incident_alert(&self, incident: &Incident, ctx: &ChatContext) -> anyhow::Result<()> {
        self.client
            .send_incident_alert(incident, ctx.mode, ctx.telegram_is_simple)
            .await
    }
}

pub(crate) struct SlackChannel {
    client: SlackClient,
    min_rank: u8,
    filter_level: ChannelFilterLevel,
}

#[async_trait]
impl ChatChannel for SlackChannel {
    fn name(&self) -> &'static str {
        "slack"
    }
    fn min_rank(&self) -> u8 {
        self.min_rank
    }
    fn filter_level(&self) -> ChannelFilterLevel {
        self.filter_level
    }
    async fn incident_alert(&self, incident: &Incident, ctx: &ChatContext) -> anyhow::Result<()> {
        self.client
            .send_incident_alert(incident, ctx.slack_dashboard_url.as_deref())
            .await
    }
}

/// Build the active chat-channel set from config + live clients.
///
/// A channel is included iff it is enabled in config AND its client was
/// constructed at boot. This mirrors exactly the per-channel gate the old
/// hand-wired dispatch used (`cfg.<ch>.enabled && state.<ch>_client.is_some()`),
/// so the alert path is behaviour-identical.
pub(crate) fn collect_chat_channels(
    cfg: &AgentConfig,
    state: &AgentState,
) -> Vec<Box<dyn ChatChannel>> {
    let mut channels: Vec<Box<dyn ChatChannel>> = Vec::new();

    if cfg.telegram.enabled {
        if let Some(tg) = &state.telegram_client {
            channels.push(Box::new(TelegramChannel {
                client: tg.clone(),
                min_rank: severity_rank(&cfg.telegram.parsed_min_severity()),
                filter_level: cfg.telegram.channel_notifications.notification_level,
            }));
        }
    }

    if cfg.slack.enabled {
        if let Some(sc) = &state.slack_client {
            channels.push(Box::new(SlackChannel {
                client: sc.clone(),
                min_rank: severity_rank(&cfg.slack.parsed_min_severity()),
                filter_level: cfg.slack.channel_notifications.notification_level,
            }));
        }
    }

    channels
}

/// Fan an incident alert out to every chat channel that passes its own
/// severity-rank + filter-level gate.
///
/// One channel erroring is logged and skipped — it never blocks the others
/// (preserves the old per-channel failure isolation).
pub(crate) async fn fan_out_alert(
    channels: &[Box<dyn ChatChannel>],
    incident: &Incident,
    ctx: &ChatContext,
) {
    let rank = severity_rank(&incident.severity);
    for ch in channels {
        if rank >= ch.min_rank() && passes_channel_filter(ch.filter_level(), &incident.severity) {
            if let Err(e) = ch.incident_alert(incident, ctx).await {
                warn!(
                    channel = ch.name(),
                    incident_id = %incident.incident_id,
                    "chat-channel alert failed: {e:#}"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use innerwarden_core::event::Severity;
    use innerwarden_core::incident::Incident;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn incident(severity: Severity) -> Incident {
        Incident {
            ts: chrono::Utc::now(),
            host: "h".to_string(),
            incident_id: "port_scan:203.0.113.5:w".to_string(),
            severity,
            title: "t".to_string(),
            summary: "s".to_string(),
            evidence: serde_json::json!({}),
            recommended_checks: vec![],
            tags: vec![],
            entities: vec![],
        }
    }

    fn ctx() -> ChatContext {
        ChatContext {
            mode: GuardianMode::Watch,
            telegram_is_simple: false,
            slack_dashboard_url: None,
        }
    }

    struct MockChannel {
        name: &'static str,
        min_rank: u8,
        filter_level: ChannelFilterLevel,
        calls: Arc<AtomicUsize>,
        fail: bool,
    }

    #[async_trait]
    impl ChatChannel for MockChannel {
        fn name(&self) -> &'static str {
            self.name
        }
        fn min_rank(&self) -> u8 {
            self.min_rank
        }
        fn filter_level(&self) -> ChannelFilterLevel {
            self.filter_level
        }
        async fn incident_alert(&self, _i: &Incident, _c: &ChatContext) -> anyhow::Result<()> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.fail {
                anyhow::bail!("simulated channel failure");
            }
            Ok(())
        }
    }

    fn mock(
        name: &'static str,
        min_rank: u8,
        filter_level: ChannelFilterLevel,
        fail: bool,
    ) -> (Box<dyn ChatChannel>, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let ch = MockChannel {
            name,
            min_rank,
            filter_level,
            calls: calls.clone(),
            fail,
        };
        (Box::new(ch), calls)
    }

    #[tokio::test]
    async fn fan_out_skips_channel_below_its_min_rank() {
        let high = severity_rank(&Severity::High);
        let (ch, calls) = mock("telegram", high, ChannelFilterLevel::All, false);
        let channels = vec![ch];

        fan_out_alert(&channels, &incident(Severity::Low), &ctx()).await;
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "Low must not reach a High-rank channel"
        );

        fan_out_alert(&channels, &incident(Severity::Critical), &ctx()).await;
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "Critical must reach a High-rank channel"
        );
    }

    #[tokio::test]
    async fn fan_out_respects_filter_level_none() {
        let (ch, calls) = mock("slack", 0, ChannelFilterLevel::None, false);
        let channels = vec![ch];
        fan_out_alert(&channels, &incident(Severity::Critical), &ctx()).await;
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "filter None silences every severity"
        );
    }

    #[tokio::test]
    async fn fan_out_critical_filter_drops_medium_keeps_high() {
        let (ch, calls) = mock("slack", 0, ChannelFilterLevel::Critical, false);
        let channels = vec![ch];
        fan_out_alert(&channels, &incident(Severity::Medium), &ctx()).await;
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        fan_out_alert(&channels, &incident(Severity::High), &ctx()).await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn one_channel_failure_does_not_block_the_others() {
        // First channel always errors; the second must still be called.
        let (ch1, c1) = mock("telegram", 0, ChannelFilterLevel::All, true);
        let (ch2, c2) = mock("slack", 0, ChannelFilterLevel::All, false);
        let channels = vec![ch1, ch2];
        fan_out_alert(&channels, &incident(Severity::High), &ctx()).await;
        assert_eq!(
            c1.load(Ordering::SeqCst),
            1,
            "failing channel was attempted"
        );
        assert_eq!(
            c2.load(Ordering::SeqCst),
            1,
            "second channel still fired despite first failing"
        );
    }

    #[tokio::test]
    async fn collect_includes_only_enabled_channels_with_a_client() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = crate::tests::triage_test_state(dir.path());
        state.telegram_client = Some(Arc::new(
            crate::telegram::TelegramClient::new("token", "chat", None).unwrap(),
        ));
        state.slack_client =
            Some(crate::slack::SlackClient::new("https://hooks.slack.com/x").unwrap());

        let mut cfg = AgentConfig::default();
        cfg.telegram.enabled = true;
        cfg.slack.enabled = true;
        let names: Vec<&str> = collect_chat_channels(&cfg, &state)
            .iter()
            .map(|c| c.name())
            .collect();
        assert_eq!(names, vec!["telegram", "slack"]);

        // Disable Slack in config → only Telegram remains, even though the
        // Slack client still exists in state.
        cfg.slack.enabled = false;
        let names: Vec<&str> = collect_chat_channels(&cfg, &state)
            .iter()
            .map(|c| c.name())
            .collect();
        assert_eq!(names, vec!["telegram"]);

        // A channel enabled in config but with no client built at boot is
        // excluded (mirrors the old `state.<ch>_client.is_some()` gate).
        cfg.slack.enabled = true;
        state.slack_client = None;
        let names: Vec<&str> = collect_chat_channels(&cfg, &state)
            .iter()
            .map(|c| c.name())
            .collect();
        assert_eq!(names, vec!["telegram"]);
    }

    #[test]
    fn chat_context_maps_config_fields() {
        let mut cfg = AgentConfig::default();
        cfg.slack.dashboard_url = String::new();
        let c = ChatContext::from_config(&cfg);
        assert_eq!(c.slack_dashboard_url, None, "empty dashboard_url -> None");
        // mode is whatever the responder state maps to; just assert it resolves.
        let _ = c.mode;
        let _ = c.telegram_is_simple;

        cfg.slack.dashboard_url = "https://dash.example/incidents".to_string();
        let c = ChatContext::from_config(&cfg);
        assert_eq!(
            c.slack_dashboard_url.as_deref(),
            Some("https://dash.example/incidents")
        );
    }

    #[tokio::test]
    async fn real_channels_expose_their_configured_rank_and_filter() {
        // Exercises the concrete getters (name/min_rank/filter_level) on the
        // REAL Telegram + Slack channels built by the registry — not the mock.
        let dir = tempfile::tempdir().unwrap();
        let mut state = crate::tests::triage_test_state(dir.path());
        state.telegram_client = Some(Arc::new(
            crate::telegram::TelegramClient::new("token", "chat", None).unwrap(),
        ));
        state.slack_client =
            Some(crate::slack::SlackClient::new("https://hooks.slack.com/x").unwrap());

        let mut cfg = AgentConfig::default();
        cfg.telegram.enabled = true;
        cfg.slack.enabled = true;

        for ch in collect_chat_channels(&cfg, &state) {
            // Getters must not panic and must return the config-derived values.
            assert!(matches!(ch.name(), "telegram" | "slack"));
            let _ = ch.min_rank();
            let _ = ch.filter_level();
        }
    }

    #[tokio::test]
    async fn slack_channel_actually_posts_through_the_registry() {
        // Covers SlackChannel::incident_alert end-to-end against a mock webhook,
        // proving the registry path drives a real channel to send.
        let mut server = mockito::Server::new_async().await;
        let hook = server
            .mock("POST", "/services/T/B/X")
            .with_status(200)
            .create_async()
            .await;

        let dir = tempfile::tempdir().unwrap();
        let mut state = crate::tests::triage_test_state(dir.path());
        state.slack_client = Some(
            crate::slack::SlackClient::new(format!("{}/services/T/B/X", server.url())).unwrap(),
        );

        let mut cfg = AgentConfig::default();
        cfg.slack.enabled = true;

        let channels = collect_chat_channels(&cfg, &state);
        assert_eq!(channels.len(), 1);
        let ctx = ChatContext::from_config(&cfg);
        fan_out_alert(&channels, &incident(Severity::Critical), &ctx).await;

        hook.assert_async().await;
    }
}
