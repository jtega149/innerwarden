use std::path::Path;

use tracing::{info, warn};

use crate::agent_context::guardian_mode;
use crate::config::ChannelFilterLevel;
use crate::notification_pipeline::{self, GroupAction};
use crate::{config, state_store, web_push, webhook, AgentState};

pub(crate) struct NotificationThresholds {
    pub(crate) webhook_min_rank: Option<u8>,
    pub(crate) telegram_min_rank: Option<u8>,
    pub(crate) slack_min_rank: Option<u8>,
}

pub(crate) fn compute_notification_thresholds(
    cfg: &config::AgentConfig,
    state: &AgentState,
) -> NotificationThresholds {
    let webhook_min_rank = if cfg.webhook.enabled && !cfg.webhook.url.is_empty() {
        Some(webhook::severity_rank(&cfg.webhook.parsed_min_severity()))
    } else {
        None
    };

    let telegram_min_rank = if cfg.telegram.enabled && state.telegram_client.is_some() {
        Some(webhook::severity_rank(&cfg.telegram.parsed_min_severity()))
    } else {
        None
    };

    let slack_min_rank = if cfg.slack.enabled && state.slack_client.is_some() {
        Some(webhook::severity_rank(&cfg.slack.parsed_min_severity()))
    } else {
        None
    };

    NotificationThresholds {
        webhook_min_rank,
        telegram_min_rank,
        slack_min_rank,
    }
}

/// Check if a first-alert should pass the channel filter.
/// For the first alert, auto_resolved is always false (obvious gate runs after dispatch).
fn passes_channel_filter(
    level: ChannelFilterLevel,
    severity: &innerwarden_core::event::Severity,
) -> bool {
    match level {
        ChannelFilterLevel::All | ChannelFilterLevel::Actionable => true,
        ChannelFilterLevel::None => false,
        ChannelFilterLevel::Critical => {
            matches!(
                severity,
                innerwarden_core::event::Severity::High
                    | innerwarden_core::event::Severity::Critical
            )
        }
    }
}

pub(crate) async fn dispatch_incident_notifications(
    incident: &innerwarden_core::incident::Incident,
    data_dir: &Path,
    cfg: &config::AgentConfig,
    state: &mut AgentState,
    thresholds: &NotificationThresholds,
) {
    // Notification cooldown - suppress duplicate alerts for the same entity
    // within a 10-minute window. Prevents alert spam during sustained attacks.
    let notify_cutoff =
        chrono::Utc::now() - chrono::Duration::seconds(crate::NOTIFICATION_COOLDOWN_SECS);
    let notify_keys = crate::notification_cooldown_keys(incident);
    let notify_suppressed = notify_keys.iter().any(|k| {
        state
            .store
            .get_cooldown(state_store::CooldownTable::Notification, k)
            .is_some_and(|ts| ts > notify_cutoff)
    });

    if notify_suppressed {
        info!(
            incident_id = %incident.incident_id,
            "notification cooldown: suppressing duplicate alert"
        );
        return;
    }

    // Environment-aware suppression: cloud timing anomalies, admin routine.
    if notification_pipeline::should_suppress_for_environment(incident, &state.environment_profile)
    {
        info!(
            incident_id = %incident.incident_id,
            "notification suppressed: environment profile (cloud/timing)"
        );
        return;
    }

    // Insert into grouping engine — determines if this is first-in-group or suppressed.
    let action = state.grouping_engine.insert(incident);

    let incident_rank = webhook::severity_rank(&incident.severity);

    match action {
        GroupAction::NotifyImmediately => {
            // First incident in group — dispatch to channels that pass both
            // severity threshold AND channel notification level filter.

            // Webhook
            if let Some(min_rank) = thresholds.webhook_min_rank {
                let level = cfg.webhook.channel_notifications.notification_level;
                if incident_rank >= min_rank && passes_channel_filter(level, &incident.severity) {
                    if let Err(e) = webhook::send_incident(
                        &cfg.webhook.url,
                        cfg.webhook.timeout_secs,
                        incident,
                        &cfg.webhook.format,
                    )
                    .await
                    {
                        state.telemetry.observe_error("webhook");
                        warn!(incident_id = %incident.incident_id, "webhook failed: {e:#}");
                    }
                }
            }

            // Telegram T.1 — only immediate threats get individual notifications.
            // Everything else is deferred to the daily digest.
            if let Some(min_rank) = thresholds.telegram_min_rank {
                let level = cfg.telegram.channel_notifications.notification_level;
                if incident_rank >= min_rank && passes_channel_filter(level, &incident.severity) {
                    let is_critical = matches!(
                        incident.severity,
                        innerwarden_core::event::Severity::Critical
                    );
                    let is_threat = notification_pipeline::is_immediate_threat(incident);

                    // Reset daily budget counter on date change.
                    let today = chrono::Local::now().date_naive();
                    if state.telegram_budget_date != Some(today) {
                        state.telegram_daily_sent = 0;
                        state.telegram_deferred.clear();
                        state.telegram_budget_date = Some(today);
                    }

                    let within_budget = state.telegram_daily_sent < cfg.telegram.daily_budget;

                    if is_threat && within_budget || is_critical {
                        // Send immediately — real threat or Critical.
                        if let Some(ref tg) = state.telegram_client {
                            let mode = guardian_mode(cfg);
                            let is_simple = cfg.telegram.is_simple_profile();
                            if let Err(e) = tg.send_incident_alert(incident, mode, is_simple).await
                            {
                                warn!(incident_id = %incident.incident_id, "Telegram alert failed: {e:#}");
                            } else if !is_critical {
                                state.telegram_daily_sent += 1;
                            }
                        }
                    } else {
                        // Defer to daily digest — not an immediate threat or budget exhausted.
                        let detector = incident
                            .incident_id
                            .split(':')
                            .next()
                            .unwrap_or("unknown")
                            .to_string();
                        *state.telegram_deferred.entry(detector).or_insert(0) += 1;
                        info!(
                            incident_id = %incident.incident_id,
                            "notification deferred to digest (not immediate threat)"
                        );
                    }
                }
            }

            // Slack
            if let Some(min_rank) = thresholds.slack_min_rank {
                let level = cfg.slack.channel_notifications.notification_level;
                if incident_rank >= min_rank && passes_channel_filter(level, &incident.severity) {
                    if let Some(ref sc) = state.slack_client {
                        let dashboard_url = if cfg.slack.dashboard_url.is_empty() {
                            None
                        } else {
                            Some(cfg.slack.dashboard_url.as_str())
                        };
                        if let Err(e) = sc.send_incident_alert(incident, dashboard_url).await {
                            warn!(incident_id = %incident.incident_id, "Slack alert failed: {e:#}");
                        }
                    }
                }
            }

            // Web Push — respects its own channel filter.
            let wp_level = cfg.web_push.channel_notifications.notification_level;
            if passes_channel_filter(wp_level, &incident.severity) {
                web_push::notify_incident(incident, data_dir, &cfg.web_push).await;
            }
        }
        GroupAction::Suppress => {
            // Subsequent incident in group — suppressed. Group summary will be
            // emitted by the periodic tick in the agent loop.
            info!(
                incident_id = %incident.incident_id,
                "notification grouped: suppressing individual alert"
            );
        }
    }

    // Mark notification cooldown for all entities in this incident.
    let now = chrono::Utc::now();
    for k in &notify_keys {
        state
            .store
            .set_cooldown(state_store::CooldownTable::Notification, k, now);
    }
}
