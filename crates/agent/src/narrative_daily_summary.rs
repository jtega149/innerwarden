use std::collections::{HashMap, HashSet};
use std::path::Path;

use chrono::Timelike as _;
use tracing::{info, warn};

use crate::{config, narrative, telegram, AgentState};

/// Incident IDs the agent auto-resolved as benign today, read from the
/// canonical decisions log. Spec 044 honesty fix (2026-05-31): the daily
/// digest's "real compromises" / "high-severity threats" counts iterate
/// incidents by posture-adjusted severity but, before this, ignored the
/// *decision* — so an incident the agent had already DISMISSED as a false
/// positive (the host's own `imds_ssrf` metadata polling, `dns_tunneling` to
/// its own VCN DNS, `kill_chain` apt/wget DATA_EXFIL — all dismissed but still
/// Critical/High by raw severity) was counted as a "real compromise". That
/// inflated the headline and buried any genuine breach in the noise.
///
/// A `dismiss` or `ignore` decision means the agent judged the incident
/// benign; those are excluded from the threat counts (they already feed the
/// separate "auto-resolved" line). Incidents with no decision yet, or with a
/// real action (block/monitor/honeypot/needs_review), are NOT excluded — a
/// genuinely pending or actioned threat must still be counted.
///
/// This is the SAFE, comprehensive FP fix: it changes no detector and can
/// never hide a real attack — it only declines to call "compromise" what the
/// agent itself already decided was not one.
fn auto_resolved_incident_ids(data_dir: &Path, today: &str) -> HashSet<String> {
    let path = data_dir.join(format!("decisions-{today}.jsonl"));
    let mut ids = HashSet::new();
    let Ok(content) = std::fs::read_to_string(&path) else {
        return ids;
    };
    for line in content.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        let action = v.get("action_type").and_then(|a| a.as_str()).unwrap_or("");
        if action == "dismiss" || action == "ignore" {
            if let Some(id) = v.get("incident_id").and_then(|i| i.as_str()) {
                ids.insert(id.to_string());
            }
        }
    }
    ids
}

/// Regenerate daily markdown summary and send Telegram digest when due.
pub(crate) async fn maybe_write_daily_summary_and_digest(
    data_dir: &Path,
    today: &str,
    events_count: usize,
    cfg: &config::AgentConfig,
    state: &mut AgentState,
) {
    // Regenerate daily summary when there are new events, subject to a minimum
    // rewrite interval to avoid thrashing on busy hosts.
    const NARRATIVE_MIN_INTERVAL_SECS: u64 = 300; // 5 minutes
    const NARRATIVE_MAX_STALE_SECS: u64 = 1800; // 30 minutes
    if cfg.narrative.enabled && events_count > 0 {
        let elapsed = state
            .last_narrative_at
            .map(|t| t.elapsed().as_secs())
            .unwrap_or(u64::MAX); // None → never written → always write
        let should_write =
            elapsed >= NARRATIVE_MIN_INTERVAL_SECS || elapsed >= NARRATIVE_MAX_STALE_SECS;
        if should_write {
            // Generate synthetic events from accumulated counters (no file I/O)
            let all_events_synthetic = state.narrative_acc.synthetic_events();
            let all_incidents_ref = &state.narrative_acc.incidents;

            let host = all_incidents_ref
                .first()
                .map(|i| i.host.as_str())
                .unwrap_or("unknown");

            let responder_hint = narrative::ResponderHint {
                enabled: cfg.responder.enabled,
                dry_run: cfg.responder.dry_run,
                has_block_ip: cfg
                    .responder
                    .allowed_skills
                    .iter()
                    .any(|s| s.starts_with("block-ip")),
            };
            let md = narrative::generate_with_responder(
                today,
                host,
                &all_events_synthetic,
                all_incidents_ref,
                cfg.correlation.window_seconds,
                responder_hint,
            );
            if let Err(e) = narrative::write(data_dir, today, &md) {
                state.telemetry.observe_error("narrative_writer");
                warn!("failed to write daily summary: {e:#}");
            } else {
                state.last_narrative_at = Some(std::time::Instant::now());
                info!(date = today, "daily summary updated");

                // Daily digest ("Daily Security Briefing") — fans out to every
                // operator chat channel (Telegram + Slack + Discord), not just
                // Telegram. Spec 078 migrated alerts/action-reports/burst
                // summaries to the registry; this is the daily report doing the
                // same so Slack-only boxes (and shared channels) get it too.
                if let Some(hour) = cfg.telegram.daily_summary_hour {
                    let now_local = chrono::Local::now();
                    let today_naive = now_local.date_naive();
                    let already_sent = state.last_daily_summary_telegram == Some(today_naive);
                    if !already_sent && now_local.hour() >= u32::from(hour) {
                        let text = build_daily_digest_text(cfg, state, data_dir, today);
                        let mut sent_any = false;

                        // Telegram keeps its own send_text_message path: unlike
                        // send_alert_html (used by the registry summary), it has
                        // no per-hour alert cap, so a busy day can never drop the
                        // daily digest.
                        if let Some(tg) = state.telegram_client.clone() {
                            match tg.send_text_message(&text).await {
                                Ok(()) => {
                                    sent_any = true;
                                    info!(date = today, "daily Telegram digest sent");
                                }
                                Err(e) => warn!("failed to send daily Telegram digest: {e:#}"),
                            }
                        }

                        // Slack / Discord via the chat-channel registry; Telegram
                        // is already handled above (skip it to avoid a double send).
                        let channels =
                            crate::notification_channels::collect_chat_channels(cfg, state);
                        for ch in channels.iter().filter(|c| c.name() != "telegram") {
                            match ch.summary(&text).await {
                                Ok(()) => {
                                    sent_any = true;
                                    info!(channel = ch.name(), date = today, "daily digest sent");
                                }
                                Err(e) => {
                                    warn!(channel = ch.name(), "failed to send daily digest: {e:#}")
                                }
                            }
                        }

                        // Mark sent once it reached at least one channel, so a
                        // restart after the hour does not re-fire (pre-2026-05-09
                        // bug: in-memory-only marker re-emitted "Daily Security
                        // Briefing" on every restart) and a transient
                        // single-channel failure does not loop all day.
                        if sent_any {
                            state.last_daily_summary_telegram = Some(today_naive);
                            state.store.set_last_daily_briefing_date(today_naive);
                        }
                    }
                }
            }
        }
    }
}

fn build_daily_digest_text(
    cfg: &config::AgentConfig,
    state: &mut AgentState,
    data_dir: &Path,
    today: &str,
) -> String {
    let is_simple = cfg.telegram.is_simple_profile();
    // Incidents the agent already dismissed/ignored as benign — excluded from
    // the "real compromises" / "high-severity" threat counts so a false
    // positive the agent auto-resolved is not reported as a compromise.
    let auto_resolved = auto_resolved_incident_ids(data_dir, today);
    // Count incidents by severity and top detector.
    let mut incidents_today: u32 = 0;
    let mut critical_count: u32 = 0;
    let mut high_count: u32 = 0;
    let mut detector_counts: HashMap<String, u32> = HashMap::new();
    for inc in &state.narrative_acc.incidents {
        incidents_today += 1;
        let det = telegram::extract_detector_pub(&inc.incident_id);
        *detector_counts.entry(det.to_string()).or_insert(0) += 1;
        // A dismissed/ignored incident is, by the agent's own decision, not a
        // threat — it feeds the "auto-resolved" line, not "real compromises".
        if auto_resolved.contains(&inc.incident_id) {
            continue;
        }
        // Effective severity: posture-aware downgrade (spec 044 Phase 3).
        let (effective, _reason) =
            crate::posture::downgrade::effective_severity(inc, det, &state.host_posture);
        match effective {
            innerwarden_core::event::Severity::Critical => {
                critical_count += 1;
            }
            innerwarden_core::event::Severity::High => {
                high_count += 1;
            }
            _ => {}
        }
    }
    // "Autonomous decisions" = the count of decisions the agent actually
    // recorded today, read from the canonical hash-chained decisions log
    // (NUMBER_CONSISTENCY: "decisions made today"). Previously this read
    // `graph_count(kg, "decisions")` — an in-memory KG count that collapses
    // toward 0 after a restart (and showed "Made 0 autonomous decisions"
    // in prod while the log held 726). The log is restart-robust.
    let decisions_today = crate::decisions::count_decisions_for_date(data_dir, today) as u32;
    let (top_detector, top_count) = detector_counts
        .iter()
        .max_by_key(|(_, c)| *c)
        .map(|(d, c)| (d.as_str(), *c))
        .unwrap_or(("none", 0));
    let pipeline_stats = state.grouping_engine.drain_digest_stats();
    // Drain deferred incidents for digest breakdown.
    let mut deferred: Vec<(String, u32)> = state.telegram_deferred.drain().collect();
    deferred.sort_by(|a, b| b.1.cmp(&a.1));

    // Host header so a shared chat channel (Telegram / Slack / Discord across
    // several boxes) shows which server the briefing is from. Prefer the host
    // the incidents are stamped with (sensor `host_id`, same label real alerts
    // carry); fall back to the system hostname.
    let host = state
        .narrative_acc
        .incidents
        .first()
        .map(|i| i.host.clone())
        .filter(|h| !h.is_empty() && h != "unknown")
        .unwrap_or_else(daily_digest_host_fallback);

    let digest = telegram::format_daily_digest_enriched(
        incidents_today,
        decisions_today,
        critical_count,
        high_count,
        top_detector,
        top_count,
        is_simple,
        &telegram::PipelineDigestStats {
            suppressed_count: pipeline_stats.suppressed_count,
            auto_resolved_groups: pipeline_stats.auto_resolved_groups,
            needs_review_groups: pipeline_stats.needs_review_groups,
            deferred,
        },
    );
    format!("🖥 <b>{}</b>\n{digest}", html_escape_host(&host))
}

/// System hostname for the digest header when no incident carries a host.
fn daily_digest_host_fallback() -> String {
    std::env::var("HOSTNAME")
        .ok()
        .filter(|h| !h.is_empty())
        .or_else(|| {
            std::fs::read_to_string("/etc/hostname")
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|h| !h.is_empty())
        })
        .unwrap_or_else(|| "unknown".to_string())
}

/// Minimal HTML escape for the host label in the Telegram-HTML digest header.
fn html_escape_host(h: &str) -> String {
    h.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn cfg_with_narrative() -> config::AgentConfig {
        let mut cfg = config::AgentConfig::default();
        cfg.narrative.enabled = true;
        cfg
    }

    #[tokio::test]
    async fn daily_summary_writes_once_and_honors_minimum_rewrite_interval() {
        let dir = TempDir::new().expect("tempdir");
        let cfg = cfg_with_narrative();
        let mut state = crate::tests::triage_test_state(dir.path());
        state
            .narrative_acc
            .events_by_kind
            .insert("ssh.login_failed".to_string(), 3);
        state
            .narrative_acc
            .ingest_incidents(&[crate::tests::test_incident("203.0.113.10")]);

        maybe_write_daily_summary_and_digest(dir.path(), "2026-05-13", 3, &cfg, &mut state).await;

        let summary_path = dir.path().join("summary-2026-05-13.md");
        let first = std::fs::read_to_string(&summary_path).expect("summary should be written");
        assert!(first.contains("test-host"));
        assert!(state.last_narrative_at.is_some());

        std::fs::write(&summary_path, "sentinel").expect("overwrite summary");
        maybe_write_daily_summary_and_digest(dir.path(), "2026-05-13", 3, &cfg, &mut state).await;
        assert_eq!(
            std::fs::read_to_string(&summary_path).expect("summary should still exist"),
            "sentinel"
        );
    }

    #[tokio::test]
    async fn daily_digest_fans_out_to_slack_when_due() {
        // No telegram client (the Azure / Slack-only case) — the digest must
        // still reach Slack through the chat-channel registry.
        let mut server = mockito::Server::new_async().await;
        let hook = server
            .mock("POST", "/services/T/B/X")
            .with_status(200)
            .create_async()
            .await;

        let dir = TempDir::new().expect("tempdir");
        let mut cfg = cfg_with_narrative();
        cfg.telegram.daily_summary_hour = Some(0); // hour gate: now >= 0 → due
        cfg.slack.enabled = true;

        let mut state = crate::tests::triage_test_state(dir.path());
        state.slack_client = Some(
            crate::slack::SlackClient::new(format!("{}/services/T/B/X", server.url())).unwrap(),
        );
        state.last_daily_summary_telegram = None;
        state
            .narrative_acc
            .events_by_kind
            .insert("ssh.login_failed".to_string(), 3);
        state
            .narrative_acc
            .ingest_incidents(&[crate::tests::test_incident("203.0.113.10")]);

        maybe_write_daily_summary_and_digest(dir.path(), "2026-05-13", 3, &cfg, &mut state).await;

        hook.assert_async().await;
        // Dedup marker set → won't re-fire today.
        assert!(state.last_daily_summary_telegram.is_some());
    }

    #[tokio::test]
    async fn daily_summary_skips_when_disabled_or_no_events() {
        let dir = TempDir::new().expect("tempdir");
        let mut cfg = cfg_with_narrative();
        let mut state = crate::tests::triage_test_state(dir.path());

        maybe_write_daily_summary_and_digest(dir.path(), "2026-05-13", 0, &cfg, &mut state).await;
        assert!(!dir.path().join("summary-2026-05-13.md").exists());

        cfg.narrative.enabled = false;
        maybe_write_daily_summary_and_digest(dir.path(), "2026-05-13", 5, &cfg, &mut state).await;
        assert!(!dir.path().join("summary-2026-05-13.md").exists());
    }

    #[test]
    fn build_daily_digest_text_counts_effective_severity_and_drains_deferred() {
        let dir = TempDir::new().expect("tempdir");
        let mut cfg = cfg_with_narrative();
        cfg.telegram.user_profile = "technical".to_string();
        let mut state = crate::tests::triage_test_state(dir.path());
        let mut critical = crate::tests::test_incident_with_kind("203.0.113.20", "kernel_panic");
        critical.severity = innerwarden_core::event::Severity::Critical;
        let high = crate::tests::test_incident_with_kind("203.0.113.21", "ssh_bruteforce");
        state.narrative_acc.ingest_incidents(&[critical, high]);
        state.telegram_deferred.insert("port_scan".to_string(), 4);
        state
            .telegram_deferred
            .insert("ssh_bruteforce".to_string(), 2);

        let text = build_daily_digest_text(&cfg, &mut state, dir.path(), "2026-05-13");

        // Host header (from the incident host) so a shared channel shows which box.
        assert!(text.starts_with("🖥"), "digest leads with a host header");
        assert!(text.contains("test-host"));
        assert!(text.contains("Incidents: 2"));
        assert!(text.contains("Critical: 1 | High: 1"));
        assert!(text.contains("Deferred:"));
        assert!(text.contains("port_scan=4"));
        assert!(state.telegram_deferred.is_empty());
    }

    #[test]
    fn digest_excludes_dismissed_incidents_from_threat_counts() {
        // Honesty fix (2026-05-31): an incident the agent DISMISSED as a false
        // positive (e.g. imds_ssrf / dns_tunneling / kill_chain self-traffic)
        // must NOT inflate "real compromises" / "high-severity" even though its
        // raw severity is Critical/High. It still counts toward total incidents
        // (and the auto-resolved line), just not the threat headline.
        let dir = TempDir::new().expect("tempdir");
        let mut cfg = cfg_with_narrative();
        cfg.telegram.user_profile = "technical".to_string();
        let mut state = crate::tests::triage_test_state(dir.path());

        let mut dismissed_crit = crate::tests::test_incident_with_kind("203.0.113.30", "imds_ssrf");
        dismissed_crit.severity = innerwarden_core::event::Severity::Critical;
        let mut real_crit = crate::tests::test_incident_with_kind("203.0.113.31", "reverse_shell");
        real_crit.severity = innerwarden_core::event::Severity::Critical;
        let dismissed_id = dismissed_crit.incident_id.clone();
        state
            .narrative_acc
            .ingest_incidents(&[dismissed_crit, real_crit]);

        // The agent dismissed the imds_ssrf one as a false positive.
        let line = format!(
            r#"{{"ts":"2026-05-13T00:00:00Z","incident_id":"{dismissed_id}","host":"h","ai_provider":"orphan-recovery","action_type":"dismiss","confidence":1.0,"auto_executed":true,"dry_run":false,"reason":"fp","estimated_threat":"none","execution_result":"dismissed"}}"#
        );
        std::fs::write(dir.path().join("decisions-2026-05-13.jsonl"), line).unwrap();

        let text = build_daily_digest_text(&cfg, &mut state, dir.path(), "2026-05-13");

        // 2 incidents seen, but only the non-dismissed Critical is a compromise.
        assert!(text.contains("Incidents: 2"), "total incidents unchanged");
        assert!(
            text.contains("Critical: 1 | High: 0"),
            "dismissed Critical must be excluded from the threat count: {text}"
        );
    }

    #[test]
    fn digest_autonomous_decisions_reads_canonical_log_not_kg() {
        // Regression for the 2026-05-29 operator report: the briefing showed
        // "Made 0 autonomous decisions" while decisions-<date>.jsonl held 726
        // (the number was read from the restart-fragile KG, not the log).
        let dir = TempDir::new().expect("tempdir");
        let mut cfg = cfg_with_narrative();
        cfg.telegram.user_profile = "simple".to_string(); // enriched briefing
        let mut state = crate::tests::triage_test_state(dir.path());
        // Five real decisions persisted for the day; the KG stays empty.
        let line = r#"{"ts":"2026-05-13T00:00:00Z","incident_id":"i","host":"h","ai_provider":"x","action_type":"block_ip","confidence":1.0,"auto_executed":true,"dry_run":false,"reason":"r","estimated_threat":"high","execution_result":"ok"}"#;
        std::fs::write(
            dir.path().join("decisions-2026-05-13.jsonl"),
            format!("{line}\n{line}\n{line}\n{line}\n{line}\n"),
        )
        .unwrap();

        let text = build_daily_digest_text(&cfg, &mut state, dir.path(), "2026-05-13");
        assert!(
            text.contains("Made <b>5</b> autonomous decisions"),
            "briefing must reflect the 5 decisions in the log, got: {text}"
        );
    }
}

// 2026-05-09 spec 044 Phase 3: the previous in-file `effective_severity`
// function assumed `PasswordAuthentication=no` globally and demoted every
// `ssh_bruteforce` regardless of the host's actual sshd config. That
// assumption was right on this prod host but wrong as a generic policy.
// The replacement lives in `crates/agent/src/posture/downgrade.rs` and
// reads the live posture snapshot via `state.host_posture`. Tests moved
// with it (see posture::downgrade::tests). The pre-spec-044 commit
// history preserves the original rule reasoning if you need to see it.
