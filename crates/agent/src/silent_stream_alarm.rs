//! Detect when a previously-active telemetry stream goes silent.
//!
//! The dashboard already surfaces a passive "⚠ N telemetry streams
//! report zero today" warning, but the 2026-05-26 prod incident
//! proved that is not enough: auditd silently broke for 10 hours
//! after a log rotation, and the operator only noticed because they
//! looked at the dashboard. This module promotes the silence to an
//! active alert by emitting an Incident through the normal
//! notification stack, so the operator hears about it on Telegram /
//! Slack / webhook (whatever their notification config wires up).
//!
//! ## Decision shape
//!
//! Per source, given today's count + a 7-day baseline + a "hours
//! into the day so far" clock:
//!
//!   - Alert when the baseline is high (≥ `min_baseline_per_day`),
//!     today's count is zero, the UTC day is far enough along
//!     (≥ `alert_after_hours`), and the same source has NOT been
//!     alerted within `cooldown_hours`. The asymmetry between the
//!     baseline magnitude and the current zero is what flags a
//!     legit silence.
//!   - Skip when the baseline is below the floor (no real signal
//!     to compare against — fresh installs, brand-new collectors).
//!   - Skip in the first `alert_after_hours` of the UTC day so a
//!     daily reset at midnight UTC doesn't fire a chorus of false
//!     alerts before the day has had a chance to produce events.
//!   - Skip when the same source fired an alert recently
//!     (`cooldown_hours` cap), so an operator who has acknowledged
//!     the silence isn't paged every 30 seconds.
//!   - Emit a `Recovery` decision when a previously-alerted source
//!     starts producing events again, so the alert thread closes
//!     instead of going stale.
//!
//! The whole policy is pure functions tested in this file. The
//! integration glue (SQLite queries, incident construction,
//! notification dispatch) lives outside `should_decide` so the
//! policy tests do not need a tokio runtime or a database fixture.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Snapshot of one telemetry stream's posture at the moment the
/// silent-stream check runs. Carries everything the pure policy
/// (`should_decide`) needs — the source name itself stays in the
/// caller's loop variable since the integration layer already keys
/// its per-source state map by that name.
#[derive(Debug, Clone)]
pub(crate) struct StreamSnapshot {
    /// Events written to SQLite for this source from 00:00 UTC today
    /// up to `now`.
    pub(crate) count_today: u64,
    /// Total events written for this source over the trailing
    /// `baseline_days` window (excluding today). Divided by
    /// `baseline_days` to get `baseline_per_day` in `should_decide`.
    pub(crate) count_baseline: u64,
    /// Length of the trailing window used to compute the baseline.
    /// Defaults to 7 in `check_silent_streams`; surfaced here so
    /// tests can drive shorter windows.
    pub(crate) baseline_days: u32,
}

/// Per-source state persisted across slow-loop ticks. Loaded from
/// the SQLite kv store under the `silent_stream_alert` namespace.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate) struct StreamAlertState {
    /// Timestamp of the last `Alert` dispatched for this source.
    /// `None` when the source has never alerted.
    pub(crate) last_alerted_ts: Option<DateTime<Utc>>,
    /// Set when an Alert fires; cleared on Recovery. Drives the
    /// "stream came back online, close the thread" message.
    pub(crate) alert_open: bool,
}

/// Operator-tunable thresholds. See [`SilentStreamConfig::default`]
/// for the production defaults.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SilentStreamConfig {
    /// Whether the check fires at all. Off by default in
    /// `Config::test_default`-style configs; on by default in prod
    /// via the slow_loop wiring's `unwrap_or(SilentStreamConfig::default())`.
    pub(crate) enabled: bool,
    /// Minimum events-per-day average the source must average
    /// across the baseline window before silence is alertable.
    /// Floor prevents the alert from firing on collectors that
    /// have never produced meaningful volume (fresh installs,
    /// brand-new wires).
    pub(crate) min_baseline_per_day: f64,
    /// How far into the UTC day the check must be before silence
    /// is alertable. Prevents a midnight UTC daily reset from
    /// triggering a flood of "0 events today" alerts at 00:00-00:05
    /// when the day genuinely has not had time to accumulate events.
    pub(crate) alert_after_hours: u32,
    /// Cooldown between successive alerts for the same source.
    /// An operator who has acknowledged the silence should not be
    /// paged again until the cooldown elapses.
    pub(crate) cooldown_hours: u32,
}

impl Default for SilentStreamConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            // 100 events/day floor: ssh_bruteforce on a quiet host
            // generates roughly this much when there is any internet
            // exposure. exec_audit on Oracle prod averages ~200k/day.
            // Setting the floor lower would surface false positives
            // for actually-empty collectors; higher would miss
            // legitimately-broken auth_log readers.
            min_baseline_per_day: 100.0,
            // 2 hours into the day: with 24 hours of baseline and
            // 0 events through hour 2 from a source that averages
            // 100/day, the expected count by hour 2 was ~8 — a
            // zero is conclusive.
            alert_after_hours: 2,
            // 6 hours of quiet between alerts: enough that the
            // operator can act on the first page; not so long that
            // a sustained breakage goes unmentioned through a
            // workday.
            cooldown_hours: 6,
        }
    }
}

/// Per-source decision returned by [`should_decide`]. The integration
/// layer maps `Alert` and `Recovery` to incident dispatches; the
/// `Skip*` variants are observability tags (logged + counted, not
/// dispatched).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AlertDecision {
    /// Stream went silent and meets every gate — dispatch.
    Alert,
    /// Stream was previously alerted, is producing events again —
    /// close the thread.
    Recovery,
    /// Baseline below `min_baseline_per_day` — no meaningful signal
    /// to compare against.
    SkipBaselineLow,
    /// UTC day is too young (`hours_into_day < alert_after_hours`).
    SkipTooEarly,
    /// Same source alerted within `cooldown_hours`.
    SkipCooldown,
    /// Source is producing events today AND no open alert — normal
    /// healthy state, nothing to do.
    SkipHealthy,
}

/// Pure policy. Given a snapshot of the stream, the persisted alert
/// state, the configured thresholds, and the current UTC clock,
/// decide what action to take.
pub(crate) fn should_decide(
    snap: &StreamSnapshot,
    state: &StreamAlertState,
    cfg: &SilentStreamConfig,
    now: DateTime<Utc>,
) -> AlertDecision {
    // Recovery branch comes first: if the stream is producing
    // events again, a previously-open alert must close even when
    // every other gate would say "skip". Otherwise an operator who
    // sees the stream come back gets no closing notification.
    if state.alert_open && snap.count_today > 0 {
        return AlertDecision::Recovery;
    }

    // Healthy state: producing events, no open alert. Most common
    // branch — return early before evaluating any other gate.
    if snap.count_today > 0 {
        return AlertDecision::SkipHealthy;
    }

    // Baseline gate. Compute per-day rate from the trailing window.
    // Division by zero is impossible — `baseline_days` is u32 and
    // the caller (`check_silent_streams`) enforces ≥ 1.
    let baseline_per_day = if snap.baseline_days == 0 {
        0.0
    } else {
        snap.count_baseline as f64 / snap.baseline_days as f64
    };
    if baseline_per_day < cfg.min_baseline_per_day {
        return AlertDecision::SkipBaselineLow;
    }

    // Hours-into-day gate. `chrono::Datelike + Timelike` would work
    // but is more API surface than necessary — convert to seconds-
    // since-midnight via the `time` field of `now.time()`.
    let secs_into_day = now
        .time()
        .signed_duration_since(chrono::NaiveTime::from_hms_opt(0, 0, 0).unwrap())
        .num_seconds()
        .max(0) as u64;
    let hours_into_day = (secs_into_day / 3600) as u32;
    if hours_into_day < cfg.alert_after_hours {
        return AlertDecision::SkipTooEarly;
    }

    // Cooldown gate.
    if let Some(last) = state.last_alerted_ts {
        let cooldown_secs = cfg.cooldown_hours as i64 * 3600;
        let elapsed = now.signed_duration_since(last).num_seconds();
        if elapsed < cooldown_secs {
            return AlertDecision::SkipCooldown;
        }
    }

    AlertDecision::Alert
}

// ---------------------------------------------------------------------------
// Integration layer — slow-loop entry point + SQLite glue.
// ---------------------------------------------------------------------------

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use anyhow::Result;
use innerwarden_core::entities::EntityRef;
use innerwarden_core::event::Severity;
use innerwarden_core::incident::Incident;
use innerwarden_store::Store;
use tracing::{info, warn};

use crate::{config, incident_notifications, AgentState};

const KV_NAMESPACE: &str = "silent_stream_alert";
const BASELINE_DAYS: u32 = 7;

/// Per-source today + trailing-window counts pulled from SQLite. Pure
/// data — feeds [`should_decide`] in the same module.
///
/// Returns a map of `source -> (count_today, count_baseline)`. Sources
/// that appear only in one of the two windows are still represented
/// (with 0 for the missing side) so the policy can see "high baseline,
/// zero today" cases — which is exactly the breakage the module exists
/// to catch.
fn query_source_counts(store: &Store) -> Result<HashMap<String, (u64, u64)>> {
    let conn = store.conn()?;
    let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
    let baseline_start = (chrono::Utc::now() - chrono::Duration::days(BASELINE_DAYS as i64))
        .format("%Y-%m-%d")
        .to_string();

    let mut combined: HashMap<String, (u64, u64)> = HashMap::new();

    let today_pattern = format!("{today}%");
    let mut stmt =
        conn.prepare("SELECT source, COUNT(*) FROM events WHERE ts LIKE ?1 GROUP BY source")?;
    let rows = stmt.query_map([today_pattern.as_str()], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
    })?;
    for row in rows.flatten() {
        combined.entry(row.0).or_insert((0, 0)).0 = row.1 as u64;
    }
    drop(stmt);

    let mut stmt = conn.prepare(
        "SELECT source, COUNT(*) FROM events WHERE ts >= ?1 AND ts < ?2 GROUP BY source",
    )?;
    let rows = stmt.query_map([baseline_start.as_str(), today.as_str()], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
    })?;
    for row in rows.flatten() {
        combined.entry(row.0).or_insert((0, 0)).1 = row.1 as u64;
    }

    Ok(combined)
}

fn load_state(store: &Store, source: &str) -> StreamAlertState {
    match store.kv_get_str(KV_NAMESPACE, source) {
        Ok(Some(json)) => serde_json::from_str(&json).unwrap_or_default(),
        _ => StreamAlertState::default(),
    }
}

fn save_state(store: &Store, source: &str, state: &StreamAlertState) {
    match serde_json::to_vec(state) {
        Ok(bytes) => {
            if let Err(e) = store.kv_set(KV_NAMESPACE, source, &bytes) {
                warn!(source, error = %e, "silent_stream: failed to persist alert state");
            }
        }
        Err(e) => warn!(source, error = %e, "silent_stream: failed to serialize alert state"),
    }
}

/// Build the incident the alarm dispatches. Kept as its own fn so
/// future tests can pin the shape (kind, severity, summary) without
/// going through the full slow_loop fixture.
fn build_alert_incident(
    source: &str,
    snap: &StreamSnapshot,
    now: chrono::DateTime<chrono::Utc>,
) -> Incident {
    let baseline_per_day = if snap.baseline_days == 0 {
        0.0
    } else {
        snap.count_baseline as f64 / snap.baseline_days as f64
    };
    Incident {
        ts: now,
        host: "agent".to_string(),
        incident_id: format!(
            "telemetry.stream_silence:{}:{}",
            source,
            now.format("%Y-%m-%dT%HZ")
        ),
        // High severity so the notification pipeline pushes immediately
        // via Telegram/Slack/webhook instead of bundling into the daily
        // briefing's "handled silently" list. A silent telemetry stream
        // means a detector is blind. Operator must be paged, not summarised.
        severity: Severity::High,
        title: format!("Telemetry stream silent: {source}"),
        summary: format!(
            "Source `{source}` has produced 0 events today; trailing {}-day baseline was \
             {:.0} events/day. Likely causes: collector daemon stopped, log file rotated and \
             not reopened, or upstream feed broke. Verify `systemctl status <collector>` \
             and rerun `innerwarden status` to confirm.",
            snap.baseline_days, baseline_per_day
        ),
        evidence: serde_json::json!({
            "source": source,
            "count_today": snap.count_today,
            "baseline_days": snap.baseline_days,
            "baseline_per_day": baseline_per_day,
        }),
        recommended_checks: vec![
            format!("systemctl status (or equivalent) of the {source} collector / daemon"),
            "Check the most recent log file on disk for stale mtime".to_string(),
            "Inspect `journalctl` for collector crash / restart loops".to_string(),
        ],
        tags: vec![
            "telemetry_silence".to_string(),
            "self_monitoring".to_string(),
        ],
        entities: vec![EntityRef::service(source.to_string())],
    }
}

fn build_recovery_incident(
    source: &str,
    snap: &StreamSnapshot,
    now: chrono::DateTime<chrono::Utc>,
) -> Incident {
    Incident {
        ts: now,
        host: "agent".to_string(),
        incident_id: format!(
            "telemetry.stream_recovery:{}:{}",
            source,
            now.format("%Y-%m-%dT%HZ")
        ),
        severity: Severity::Info,
        title: format!("Telemetry stream recovered: {source}"),
        summary: format!(
            "Source `{source}` is producing events again ({} events today). \
             Previous silent-stream alert can be closed.",
            snap.count_today
        ),
        evidence: serde_json::json!({
            "source": source,
            "count_today": snap.count_today,
        }),
        recommended_checks: vec![],
        tags: vec![
            "telemetry_recovery".to_string(),
            "self_monitoring".to_string(),
        ],
        entities: vec![EntityRef::service(source.to_string())],
    }
}

/// Slow-loop entry point. Iterates every source with a SQLite footprint
/// in the trailing baseline window, computes a decision per the pure
/// policy, dispatches Alert / Recovery incidents through the existing
/// notification stack, and persists per-source state in the SQLite kv.
///
/// Cheap when nothing fires (two grouped COUNT queries + a kv read per
/// source). The dispatcher itself short-circuits on its own cooldown so
/// duplicate alerts within the 10-minute notification cooldown window
/// also do not actually notify.
///
/// Soft-fail by design: SQLite errors are logged and swallowed so a
/// transient db lock cannot kill the slow loop.
pub(crate) async fn check_silent_streams(
    cfg: &config::AgentConfig,
    state: &mut AgentState,
    data_dir: &Path,
    silent_cfg: &SilentStreamConfig,
) {
    if !silent_cfg.enabled {
        return;
    }

    let store: Arc<Store> = match state.sqlite_store.as_ref() {
        Some(s) => s.clone(),
        None => return, // sqlite optional — silently skip when off
    };

    let counts = match query_source_counts(&store) {
        Ok(c) => c,
        Err(e) => {
            warn!(error = %e, "silent_stream: source count query failed; skipping tick");
            return;
        }
    };

    let now = chrono::Utc::now();
    let thresholds = incident_notifications::compute_notification_thresholds(cfg, state);

    for (source, (count_today, count_baseline)) in counts {
        let snap = StreamSnapshot {
            count_today,
            count_baseline,
            baseline_days: BASELINE_DAYS,
        };
        let mut st = load_state(&store, &source);
        let decision = should_decide(&snap, &st, silent_cfg, now);
        match decision {
            AlertDecision::Alert => {
                info!(source = %source, baseline = count_baseline, "silent_stream: dispatching silence alert");
                let inc = build_alert_incident(&source, &snap, now);
                incident_notifications::dispatch_incident_notifications(
                    &inc,
                    data_dir,
                    cfg,
                    state,
                    &thresholds,
                )
                .await;
                st.last_alerted_ts = Some(now);
                st.alert_open = true;
                save_state(&store, &source, &st);
            }
            AlertDecision::Recovery => {
                info!(source = %source, "silent_stream: dispatching recovery notice");
                let inc = build_recovery_incident(&source, &snap, now);
                incident_notifications::dispatch_incident_notifications(
                    &inc,
                    data_dir,
                    cfg,
                    state,
                    &thresholds,
                )
                .await;
                st.alert_open = false;
                save_state(&store, &source, &st);
            }
            AlertDecision::SkipBaselineLow
            | AlertDecision::SkipTooEarly
            | AlertDecision::SkipCooldown
            | AlertDecision::SkipHealthy => {
                // Silent skips — by design. The dashboard's existing
                // passive "telemetry streams report zero" indicator
                // is still the place to see the full per-source state.
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests — pure policy anchors. No tokio, no SQLite, no fixtures.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    /// Convenience: today at the given hour:minute UTC. The date
    /// is fixed at 2026-05-26 so the time-of-day comparisons in
    /// `should_decide` are deterministic across whatever wall clock
    /// the test runner sits on.
    fn at_utc(hh: u32, mm: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 5, 26, hh, mm, 0).unwrap()
    }

    /// A snapshot of a healthy noisy collector: 200k baseline / 7d,
    /// so the per-day rate is ~28k — well above the 100/day floor.
    /// `count_today` is parameterised by the caller. The `_source`
    /// arg is documentation-only — it labels the test case in failure
    /// output and matches the real call site shape where the loop
    /// variable carries the source name alongside the snapshot.
    fn noisy_snapshot(_source: &str, count_today: u64) -> StreamSnapshot {
        StreamSnapshot {
            count_today,
            count_baseline: 200_000,
            baseline_days: 7,
        }
    }

    fn default_state() -> StreamAlertState {
        StreamAlertState::default()
    }

    #[test]
    fn alerts_when_high_baseline_zero_today_after_min_hours_with_no_prior_alert() {
        // The textbook auditd-broke-10h-ago case. Baseline says we
        // expect ~28k events/day from this collector; today shows
        // zero through 10 hours; no prior alert state. This is the
        // case the module exists for — must dispatch.
        let snap = noisy_snapshot("auditd", 0);
        let st = default_state();
        let cfg = SilentStreamConfig::default();
        let now = at_utc(10, 0);
        assert_eq!(should_decide(&snap, &st, &cfg, now), AlertDecision::Alert);
    }

    #[test]
    fn skip_baseline_low_when_collector_has_never_produced_meaningful_volume() {
        // Fresh install: a collector wired but with only 10 events
        // total over the baseline window. Per-day rate ~1.4 is well
        // below the 100/day floor — silence here is the normal
        // resting state, not a malfunction.
        let snap = StreamSnapshot {
            count_today: 0,
            count_baseline: 10,
            baseline_days: 7,
        };
        let cfg = SilentStreamConfig::default();
        assert_eq!(
            should_decide(&snap, &default_state(), &cfg, at_utc(15, 0)),
            AlertDecision::SkipBaselineLow
        );
    }

    #[test]
    fn skip_too_early_in_the_utc_day_even_for_a_high_baseline_collector() {
        // 00:30 UTC: the day has had 30 minutes to produce events.
        // Some collectors batch their first emit and can legitimately
        // show 0 events at this hour. The `alert_after_hours` gate
        // suppresses the alert until the day has had time to settle.
        let snap = noisy_snapshot("auth_log", 0);
        let cfg = SilentStreamConfig::default();
        assert_eq!(
            should_decide(&snap, &default_state(), &cfg, at_utc(0, 30)),
            AlertDecision::SkipTooEarly
        );
    }

    #[test]
    fn skip_cooldown_when_same_source_alerted_recently() {
        // Same source fired an alert 30 minutes ago and the stream
        // is still silent. The 6-hour cooldown should suppress the
        // second alert — the operator already knows; paging again
        // now would just be noise. `alert_open: false` reflects the
        // realistic shape after the cooldown opened: the prior alert
        // was acknowledged (which clears the open flag) and the
        // stream simply hasn't recovered yet.
        let snap = noisy_snapshot("nginx", 0);
        let now = at_utc(12, 0);
        let st = StreamAlertState {
            last_alerted_ts: Some(now - chrono::Duration::minutes(30)),
            alert_open: false,
        };
        let cfg = SilentStreamConfig::default();
        assert_eq!(
            should_decide(&snap, &st, &cfg, now),
            AlertDecision::SkipCooldown
        );
    }

    #[test]
    fn alert_fires_again_after_cooldown_window_elapses() {
        // Same shape as the cooldown test, but with the last_alerted
        // timestamp pushed 7 hours back (past the 6-hour default
        // cooldown). The stream is still silent, so the alert MUST
        // re-fire so a multi-day breakage doesn't drop into silent
        // failure mode after the first page.
        let snap = noisy_snapshot("nginx", 0);
        let now = at_utc(12, 0);
        let st = StreamAlertState {
            last_alerted_ts: Some(now - chrono::Duration::hours(7)),
            alert_open: false,
        };
        let cfg = SilentStreamConfig::default();
        assert_eq!(should_decide(&snap, &st, &cfg, now), AlertDecision::Alert);
    }

    #[test]
    fn recovery_fires_when_previously_alerted_source_starts_emitting_again() {
        // Operator was paged; collector came back online (count_today
        // jumped from 0 to 12). The thread must close so the operator
        // gets a positive "OK, it's back" signal.
        let snap = noisy_snapshot("auditd", 12);
        let now = at_utc(14, 0);
        let st = StreamAlertState {
            last_alerted_ts: Some(now - chrono::Duration::hours(3)),
            alert_open: true,
        };
        let cfg = SilentStreamConfig::default();
        assert_eq!(
            should_decide(&snap, &st, &cfg, now),
            AlertDecision::Recovery
        );
    }

    #[test]
    fn healthy_path_is_silent_no_alert_no_state_change() {
        // Most common case across most ticks: collector is producing
        // events and no alert is open. Should be a no-op skip —
        // no incident dispatched, no state write.
        let snap = noisy_snapshot("ebpf", 42_000);
        let cfg = SilentStreamConfig::default();
        assert_eq!(
            should_decide(&snap, &default_state(), &cfg, at_utc(15, 0)),
            AlertDecision::SkipHealthy
        );
    }

    #[test]
    fn baseline_days_zero_treats_baseline_as_zero_does_not_panic() {
        // Defensive — if the SQLite query somehow returns a zero
        // window, we must not panic on the divide. Behavior in this
        // case is "no baseline to compare against", same as a
        // fresh-install collector.
        let snap = StreamSnapshot {
            count_today: 0,
            count_baseline: 1_000_000,
            baseline_days: 0,
        };
        let cfg = SilentStreamConfig::default();
        assert_eq!(
            should_decide(&snap, &default_state(), &cfg, at_utc(15, 0)),
            AlertDecision::SkipBaselineLow
        );
    }

    // -----------------------------------------------------------------
    // Integration-layer anchors. These exercise the non-policy helpers
    // (`build_alert_incident`, `build_recovery_incident`, `load_state`,
    // `save_state`) without needing an `AgentState` fixture or a real
    // notification stack. `query_source_counts` + `check_silent_streams`
    // would require a live `Store` plus more wiring; field validation
    // covers those (every prod tick exercises them).
    // -----------------------------------------------------------------

    #[test]
    fn alert_incident_carries_source_baseline_and_recommended_checks() {
        // Pin the incident shape: an operator paged in the middle of
        // the night needs the source name, the gap signal (today=0
        // vs baseline=X/day), and an actionable first step. If any
        // of those drops out of the shape this test fails loudly.
        let snap = StreamSnapshot {
            count_today: 0,
            count_baseline: 1_400, // 200/day
            baseline_days: 7,
        };
        let inc = build_alert_incident("auditd", &snap, at_utc(10, 0));

        assert_eq!(inc.severity, Severity::High);
        assert!(
            inc.title.contains("auditd"),
            "title must name the source: {}",
            inc.title
        );
        assert!(
            inc.summary.contains("200")
                && (inc.summary.contains("baseline") || inc.summary.contains("events/day")),
            "summary must surface the baseline magnitude: {}",
            inc.summary
        );
        assert!(
            inc.recommended_checks
                .iter()
                .any(|c| c.contains("systemctl")),
            "first recommended check must point at systemctl: {:?}",
            inc.recommended_checks
        );
        assert!(
            inc.tags.contains(&"telemetry_silence".to_string())
                && inc.tags.contains(&"self_monitoring".to_string()),
            "tags must include both telemetry_silence and self_monitoring: {:?}",
            inc.tags
        );
        // Evidence carries the raw numbers so a future dashboard
        // tile / log analysis can extract them without re-parsing
        // the summary.
        assert_eq!(
            inc.evidence.get("source").and_then(|v| v.as_str()),
            Some("auditd")
        );
        assert_eq!(
            inc.evidence.get("count_today").and_then(|v| v.as_u64()),
            Some(0)
        );
    }

    #[test]
    fn recovery_incident_uses_info_severity_and_closes_the_thread() {
        // Recovery should NOT be Medium / High — operator should not
        // be paged with the same urgency for a positive event. The
        // Info severity prevents the recovery from being noisier than
        // the alert that opened the thread.
        let snap = StreamSnapshot {
            count_today: 42,
            count_baseline: 1_400,
            baseline_days: 7,
        };
        let inc = build_recovery_incident("auditd", &snap, at_utc(14, 0));

        assert_eq!(inc.severity, Severity::Info);
        assert!(
            inc.title.contains("recovered"),
            "title must say recovered: {}",
            inc.title
        );
        assert!(
            inc.tags.contains(&"telemetry_recovery".to_string()),
            "recovery tag missing: {:?}",
            inc.tags
        );
        assert_eq!(
            inc.evidence.get("count_today").and_then(|v| v.as_u64()),
            Some(42)
        );
    }

    #[test]
    fn load_state_returns_default_when_kv_namespace_empty() {
        // Fresh-install path: a source the agent has never alerted
        // on must load as the default `StreamAlertState`, not panic
        // and not produce a synthetic timestamp.
        let store = Store::open_memory().expect("memory store");
        let st = load_state(&store, "auditd");
        assert!(st.last_alerted_ts.is_none());
        assert!(!st.alert_open);
    }

    #[test]
    fn save_state_then_load_state_round_trips_through_sqlite_kv() {
        // The integration loop relies on this round-trip to enforce
        // the cooldown across slow_loop ticks. If serde shape drifts
        // (renamed field, added required field without serde default)
        // the round-trip silently loses the value and every tick
        // re-alerts — the exact spam the cooldown exists to prevent.
        let store = Store::open_memory().expect("memory store");
        let now = at_utc(10, 0);
        let original = StreamAlertState {
            last_alerted_ts: Some(now),
            alert_open: true,
        };
        save_state(&store, "auditd", &original);

        let round_tripped = load_state(&store, "auditd");
        assert_eq!(round_tripped.alert_open, true);
        assert_eq!(round_tripped.last_alerted_ts, Some(now));
    }

    #[test]
    fn query_source_counts_empty_db_returns_empty_map() {
        // A brand-new agent with no events in SQLite must produce an
        // empty map (zero allocations into `combined`), not panic on
        // the COUNT/GROUP BY against an empty table.
        let store = Store::open_memory().expect("memory store");
        let counts = query_source_counts(&store).expect("query");
        assert!(
            counts.is_empty(),
            "fresh db must yield no sources: {counts:?}"
        );
    }
}
