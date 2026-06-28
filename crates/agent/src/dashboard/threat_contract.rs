//! Single source of truth for "how does the dashboard classify a
//! decision into an operator-visible status?".
//!
//! Pre-2026-04-29 this logic was duplicated across 6 sites with 5
//! divergent results:
//!
//! * `/api/overview` mapped `monitor` to `observing` while
//!   everywhere else used `monitoring`.
//! * `build_pivots_from_graph` kept the previous outcome on
//!   `ignore` (keeper pattern) while `determine_outcome` mapped to
//!   `dismissed`.
//! * `/api/overview` and `/api/incidents` counted `block_ip`
//!   decisions regardless of execution_result while
//!   `determine_outcome` required execution success.
//! * `build_pivots_from_graph` Detector branch used
//!   `_ => "resolved"` for unknown decisions while `api_incidents`
//!   used the same fallback for already-handled ones, blurring
//!   "operator must look" with "we acted on this".
//!
//! The architectural audit (`ideias/reports/AUDIT_2026-04-23.md`,
//! root cause RC-2) made this the highest-priority structural fix
//! before the refactor work in I-01/I-02 can move forward. This
//! module is the canonical answer; every endpoint and helper must
//! call into it instead of inlining a `match`.

/// Outcome strings the front-end and tests already key on. Pinned
/// here so a future change has to update one place, not six.
pub(super) const OUTCOME_BLOCKED: &str = "blocked";
pub(super) const OUTCOME_HONEYPOT: &str = "honeypot";
pub(super) const OUTCOME_MONITORING: &str = "monitoring";
pub(super) const OUTCOME_DISMISSED: &str = "dismissed";
pub(super) const OUTCOME_OPEN: &str = "open";

/// Classify one decision (plus its execution_result, when known)
/// into a stable outcome string. ALL dashboard surfaces must route
/// through this function so the same `(decision, exec_result)` pair
/// always yields the same outcome string regardless of which
/// endpoint produces it.
///
/// Inputs:
/// * `decision` -- the `decision` string from a graph Incident node
///   (`block_ip` | `kill_process` | `suspend_user_sudo` |
///   `block_container` | `monitor` | `honeypot` | `ignore` |
///   `dismiss` | `escalate` | `request_confirmation` | other).
///   `None` means the AI has not produced a decision yet.
/// * `exec_result` -- the response_lifecycle execution result, when
///   captured. `None` means "decision recorded but no execution
///   evidence" -- treated as success for backwards compat with the
///   pre-2026-04-29 path that never required execution evidence.
///
/// Returns one of the OUTCOME_* constants. Caller MUST NOT
/// hard-code the strings; use the constants.
pub(super) fn classify_decision(decision: Option<&str>, exec_result: Option<&str>) -> &'static str {
    let exec_ok = exec_result.is_none_or(exec_result_indicates_success);
    match decision {
        Some("block_ip")
        | Some("kill_process")
        | Some("suspend_user_sudo")
        | Some("block_container") => {
            if exec_ok {
                OUTCOME_BLOCKED
            } else {
                OUTCOME_OPEN
            }
        }
        Some("honeypot") => {
            if exec_ok {
                OUTCOME_HONEYPOT
            } else {
                OUTCOME_OPEN
            }
        }
        Some("monitor") => {
            if exec_ok {
                OUTCOME_MONITORING
            } else {
                OUTCOME_OPEN
            }
        }
        Some("ignore") | Some("dismiss") => OUTCOME_DISMISSED,
        Some("escalate") | Some("request_confirmation") => OUTCOME_OPEN,
        // Operator-initiated corrections (2026-06-10). The dashboard's
        // operator-action endpoints write rows the operator's click drives:
        // an override carries `operator_override:<action>`, so classify it by
        // the underlying action — that is what makes "Dismiss" actually clear
        // a case out of "Needs your attention", "Mark monitored" move it to
        // Observing, etc., instead of being an inert unknown string that stays
        // stuck in the attention KPI. The SQLite read path selects the LATEST
        // decision per incident (ROW_NUMBER ... rn=1), so the operator's row —
        // the newest — wins.
        Some(s) if s.starts_with("operator_override:") => {
            let inner = &s["operator_override:".len()..];
            // One level of indirection: never infinite (the suffix is a base
            // action, never another `operator_override:` prefix).
            classify_decision(Some(inner), exec_result)
        }
        // Operator un-blocked the IP: they have judged it safe, so the case is
        // resolved (leaves both "blocked" and "needs attention"). A failed
        // unblock keeps it open so the operator notices the firewall did not
        // comply.
        Some("operator_unblock") => {
            if exec_ok {
                OUTCOME_DISMISSED
            } else {
                OUTCOME_OPEN
            }
        }
        // Queued unblock request (operator clicked Unblock; the agent loop
        // executes it within ~30s). Treat as resolved-by-operator-intent so it
        // leaves "Needs your attention" immediately rather than lingering.
        Some("operator_unblock_request") => OUTCOME_DISMISSED,
        // Operator re-opened a previously-handled incident: back to attention.
        Some("operator_reopen") => OUTCOME_OPEN,
        None => OUTCOME_OPEN,
        // Unknown decision strings are operator-visible but
        // unactionable -- bucket them as `open` so they show up in
        // the "needs attention" KPI rather than getting silently
        // counted as blocked/resolved.
        Some(_) => OUTCOME_OPEN,
    }
}

/// Pivots aggregate multiple incidents (and therefore multiple
/// decisions) under one row. The aggregate outcome follows a
/// deterministic precedence so the IP / User / Detector pivots
/// always agree on what to display.
///
/// Precedence: `blocked` > `honeypot` > `open` > `monitoring` >
/// `dismissed`.
///
/// Rationale:
/// * `blocked` wins because operator-relevant containment is the
///   loudest signal -- if any incident on this entity was blocked,
///   the entity is currently treated as a threat that was contained.
/// * `honeypot` next: routing to honeypot is also a containment
///   action, just the engagement variant.
/// * `open` ranks above `monitoring` (the operator-centric rule):
///   if ANY incident on this entity is open (no decision yet), the
///   entity needs the operator's attention, even if other incidents
///   on the same entity got `monitor` decisions. Burying an open
///   item under a `monitoring` aggregate hides unresolved work.
/// * `monitoring` next: the AI made a deliberate "watch but do not
///   act" call.
/// * `dismissed` ranks last because the AI explicitly said this is
///   not interesting -- an entity with one dismissal AND one open
///   incident still needs the operator's eyes (so `open` wins).
pub(super) fn aggregate_outcomes<I, S>(individual: I) -> &'static str
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut saw_honeypot = false;
    let mut saw_open = false;
    let mut saw_monitoring = false;
    let mut saw_dismissed = false;
    for outcome in individual {
        match outcome.as_ref() {
            OUTCOME_BLOCKED => return OUTCOME_BLOCKED,
            OUTCOME_HONEYPOT => saw_honeypot = true,
            OUTCOME_OPEN => saw_open = true,
            OUTCOME_MONITORING => saw_monitoring = true,
            OUTCOME_DISMISSED => saw_dismissed = true,
            _ => saw_open = true,
        }
    }
    if saw_honeypot {
        return OUTCOME_HONEYPOT;
    }
    if saw_open {
        return OUTCOME_OPEN;
    }
    if saw_monitoring {
        return OUTCOME_MONITORING;
    }
    if saw_dismissed {
        return OUTCOME_DISMISSED;
    }
    OUTCOME_OPEN
}

/// Three KPI buckets the Threats tab left-rail tiles count:
/// `Blocked`, `Observing`, `Attention`. Computed from the outcome
/// string returned by `classify_decision` so the Home overview
/// counts agree with the per-row outcome the operator sees in the
/// list.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum KpiBucket {
    Blocked,
    Observing,
    Attention,
    /// Dismissed / explicitly-handled outcomes are not counted in
    /// any of the three operator-visible KPIs. They still appear
    /// in the list (under a "dismissed" group) but should not
    /// inflate "Blocked" or "Needs attention".
    None,
}

pub(super) fn kpi_bucket(outcome: &str) -> KpiBucket {
    match outcome {
        OUTCOME_BLOCKED | OUTCOME_HONEYPOT => KpiBucket::Blocked,
        OUTCOME_MONITORING => KpiBucket::Observing,
        OUTCOME_OPEN => KpiBucket::Attention,
        OUTCOME_DISMISSED => KpiBucket::None,
        _ => KpiBucket::Attention,
    }
}

/// Phase 3 (audit RC-4): kernel-evidence block state for a single IP.
///
/// The pre-fix dashboard surfaced "blocked" as one undifferentiated
/// label that meant three different things depending on which endpoint
/// emitted it:
///
/// * **decision was made** ("we issued a block_ip yesterday")
/// * **block currently active in the kernel** ("ufw/xdp/iptables
///   still rejecting traffic from this IP")
/// * **block expired** ("we blocked this IP last week, TTL passed")
///
/// `BlockState` separates the three so the operator can finally tell
/// them apart in the UI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(super) enum BlockState {
    /// xdp_block_times has an unexpired entry for this IP. The block
    /// is still live in the kernel.
    BlockedNow {
        since_ms: i64,
        ttl_secs: i64,
        /// Seconds until the TTL expires (`ttl_secs - elapsed`).
        /// Clamped to 0 so the front-end can render a countdown
        /// without worrying about negatives.
        expires_in_secs: i64,
    },
    /// xdp_block_times has an entry but the TTL has elapsed -- the
    /// block has rolled off the kernel even though the agent still
    /// remembers having issued it.
    BlockedHistorical { last_block_ms: i64 },
    /// No block evidence for this IP in xdp_block_times. This is the
    /// default for operator-relevant IPs whose decisions never made
    /// it past the response_lifecycle (failed exec, dry_run, etc).
    Open,
}

pub(super) fn block_state_for_ip(
    sqlite: Option<&std::sync::Arc<innerwarden_store::Store>>,
    ip: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> BlockState {
    let Some(store) = sqlite else {
        return BlockState::Open;
    };
    let bytes = match store.kv_get("xdp_block_times", ip) {
        Ok(Some(b)) => b,
        _ => return BlockState::Open,
    };
    let val: serde_json::Value = match serde_json::from_slice(&bytes) {
        Ok(v) => v,
        Err(_) => return BlockState::Open,
    };
    let blocked_at_ms = val["blocked_at_ms"].as_i64().unwrap_or(0);
    let ttl_secs = val["ttl_secs"].as_i64().unwrap_or(0);
    let now_ms = now.timestamp_millis();
    let elapsed_secs = (now_ms - blocked_at_ms) / 1000;
    // ttl_secs == 0 means "no TTL set" -- treat as still active
    // (matches the slow_loop's xdp cleanup which only expires entries
    // with a positive ttl).
    if ttl_secs == 0 || elapsed_secs < ttl_secs {
        BlockState::BlockedNow {
            since_ms: blocked_at_ms,
            ttl_secs,
            expires_in_secs: (ttl_secs - elapsed_secs).max(0),
        }
    } else {
        BlockState::BlockedHistorical {
            last_block_ms: blocked_at_ms,
        }
    }
}

fn exec_result_indicates_success(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    // The agent's skill executors emit a small set of result strings:
    // * "ok" / "ok: ..." for clean success
    // * "Blocked: <ip>" for block_ip / similar (legacy format)
    // * "executed" for skills that don't have richer output
    // * "success: ..." for some custom skills
    // Anything else (including "error: ...", "failed: ...",
    // "skipped: ...") is treated as not-executed.
    lower.starts_with("ok")
        || lower.starts_with("blocked")
        || lower == "executed"
        || lower.starts_with("success")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_block_ip_with_ok_execution_is_blocked() {
        assert_eq!(
            classify_decision(Some("block_ip"), Some("ok")),
            OUTCOME_BLOCKED
        );
        assert_eq!(
            classify_decision(Some("block_ip"), Some("Blocked: 1.2.3.4")),
            OUTCOME_BLOCKED
        );
    }

    #[test]
    fn classify_block_ip_with_failed_execution_is_open() {
        // The pre-fix bug: `/api/overview` counted block_ip as
        // "blocked" regardless of execution outcome, inflating
        // blocked_count by every kernel-level rejected block.
        assert_eq!(
            classify_decision(Some("block_ip"), Some("error: ufw rejected")),
            OUTCOME_OPEN
        );
        assert_eq!(
            classify_decision(Some("block_ip"), Some("failed")),
            OUTCOME_OPEN
        );
    }

    #[test]
    fn classify_block_ip_without_execution_evidence_keeps_blocked() {
        // Backwards compat: pre-2026-04-29 endpoints never tracked
        // execution_result; pretending every decision succeeded
        // matches their old behaviour so this PR doesn't silently
        // demote previously-counted blocks.
        assert_eq!(classify_decision(Some("block_ip"), None), OUTCOME_BLOCKED);
    }

    #[test]
    fn classify_monitor_returns_monitoring() {
        // Was "observing" in `/api/overview` and "monitored" in
        // `/api/incidents` and "monitoring" in pivots. One string
        // wins: monitoring.
        assert_eq!(
            classify_decision(Some("monitor"), Some("ok")),
            OUTCOME_MONITORING
        );
    }

    #[test]
    fn classify_ignore_and_dismiss_collapse_to_dismissed() {
        // `dismiss` is the prod observation (the AI emits it; the
        // earlier code paths only matched `ignore` and silently
        // dropped `dismiss` into the catch-all "resolved" bucket).
        assert_eq!(classify_decision(Some("ignore"), None), OUTCOME_DISMISSED);
        assert_eq!(classify_decision(Some("dismiss"), None), OUTCOME_DISMISSED);
    }

    #[test]
    fn classify_escalate_and_request_confirmation_are_open() {
        // Both mean "operator must look" -- bucket as open so the
        // attention KPI counts them.
        assert_eq!(classify_decision(Some("escalate"), None), OUTCOME_OPEN);
        assert_eq!(
            classify_decision(Some("request_confirmation"), None),
            OUTCOME_OPEN
        );
    }

    #[test]
    fn classify_unknown_decision_is_open_not_resolved() {
        // The pre-fix bug: `_ => "resolved"` quietly swept any
        // unknown decision into "we handled this" instead of
        // surfacing it.
        assert_eq!(
            classify_decision(Some("future_action_x"), None),
            OUTCOME_OPEN
        );
    }

    #[test]
    fn classify_no_decision_is_open() {
        assert_eq!(classify_decision(None, None), OUTCOME_OPEN);
    }

    // ── Operator-action classification (2026-06-10) ──────────────────
    // Operator buttons write rows that must DRIVE the case outcome, not
    // sit inertly in "needs attention". These anchor that contract.

    #[test]
    fn classify_operator_override_dismiss_resolves_case() {
        // The headline fix: Dismiss must remove the case from attention.
        assert_eq!(
            classify_decision(Some("operator_override:dismiss"), Some("ok")),
            OUTCOME_DISMISSED
        );
        assert_eq!(
            classify_decision(Some("operator_override:ignore"), None),
            OUTCOME_DISMISSED
        );
    }

    #[test]
    fn classify_operator_override_monitor_moves_to_observing() {
        assert_eq!(
            classify_decision(Some("operator_override:monitor"), Some("ok")),
            OUTCOME_MONITORING
        );
    }

    #[test]
    fn classify_operator_override_block_ip_is_blocked() {
        assert_eq!(
            classify_decision(Some("operator_override:block_ip"), Some("ok")),
            OUTCOME_BLOCKED
        );
    }

    #[test]
    fn classify_operator_override_request_confirmation_stays_open() {
        assert_eq!(
            classify_decision(Some("operator_override:request_confirmation"), None),
            OUTCOME_OPEN
        );
    }

    #[test]
    fn classify_operator_unblock_resolves_on_success_open_on_failure() {
        assert_eq!(
            classify_decision(Some("operator_unblock"), Some("ok")),
            OUTCOME_DISMISSED
        );
        // A failed unblock must NOT silently read as resolved — the operator
        // needs to see the firewall did not comply.
        assert_eq!(
            classify_decision(Some("operator_unblock"), Some("failed: ufw error")),
            OUTCOME_OPEN
        );
    }

    #[test]
    fn classify_operator_unblock_request_leaves_attention() {
        assert_eq!(
            classify_decision(Some("operator_unblock_request"), None),
            OUTCOME_DISMISSED
        );
    }

    #[test]
    fn classify_operator_reopen_returns_to_attention() {
        assert_eq!(
            classify_decision(Some("operator_reopen"), Some("ok")),
            OUTCOME_OPEN
        );
    }

    #[test]
    fn aggregate_blocked_wins_over_everything() {
        let outcomes = vec![
            OUTCOME_DISMISSED,
            OUTCOME_OPEN,
            OUTCOME_BLOCKED,
            OUTCOME_MONITORING,
        ];
        assert_eq!(aggregate_outcomes(outcomes), OUTCOME_BLOCKED);
    }

    #[test]
    fn aggregate_open_beats_dismissed() {
        // The pre-fix bug in pivots: the keeper pattern preserved
        // an old `monitoring` outcome when a later `ignore` came
        // in. Now we follow precedence -- if any incident on this
        // entity is open, the entity is open.
        let outcomes = vec![OUTCOME_DISMISSED, OUTCOME_OPEN];
        assert_eq!(aggregate_outcomes(outcomes), OUTCOME_OPEN);
    }

    #[test]
    fn aggregate_monitoring_beats_open_only_if_no_open() {
        let only_monitor = vec![OUTCOME_MONITORING];
        assert_eq!(aggregate_outcomes(only_monitor), OUTCOME_MONITORING);
        let mixed = vec![OUTCOME_MONITORING, OUTCOME_OPEN];
        assert_eq!(aggregate_outcomes(mixed), OUTCOME_OPEN);
    }

    #[test]
    fn aggregate_empty_input_is_open() {
        let empty: Vec<&str> = vec![];
        assert_eq!(aggregate_outcomes(empty), OUTCOME_OPEN);
    }

    #[test]
    fn kpi_bucket_maps_outcomes_correctly() {
        assert_eq!(kpi_bucket(OUTCOME_BLOCKED), KpiBucket::Blocked);
        assert_eq!(kpi_bucket(OUTCOME_HONEYPOT), KpiBucket::Blocked);
        assert_eq!(kpi_bucket(OUTCOME_MONITORING), KpiBucket::Observing);
        assert_eq!(kpi_bucket(OUTCOME_OPEN), KpiBucket::Attention);
        assert_eq!(kpi_bucket(OUTCOME_DISMISSED), KpiBucket::None);
    }

    // ── Phase 3: BlockState anchors ─────────────────────────────────
    //
    // Three anchors for the kernel-evidence path. Each constructs a
    // real `innerwarden_store::Store` (in-memory rusqlite) and writes
    // the same JSON shape the response_lifecycle uses
    // (`{blocked_at_ms, ttl_secs}`), so any future drift between the
    // writer and the reader fails this test instead of silently
    // making the dashboard show stale "blocked" badges.

    fn make_store() -> std::sync::Arc<innerwarden_store::Store> {
        std::sync::Arc::new(innerwarden_store::Store::open_memory().expect("open_memory"))
    }

    #[test]
    fn block_state_open_when_no_sqlite_store() {
        let now = chrono::Utc::now();
        assert_eq!(block_state_for_ip(None, "1.2.3.4", now), BlockState::Open);
    }

    #[test]
    fn block_state_open_when_ip_not_in_xdp_block_times() {
        let store = make_store();
        let now = chrono::Utc::now();
        assert_eq!(
            block_state_for_ip(Some(&store), "9.9.9.9", now),
            BlockState::Open
        );
    }

    #[test]
    fn block_state_blocked_now_when_ttl_not_yet_elapsed() {
        let store = make_store();
        let now = chrono::Utc::now();
        let blocked_at_ms = now.timestamp_millis() - 30_000; // 30s ago
        let payload = serde_json::json!({
            "blocked_at_ms": blocked_at_ms,
            "ttl_secs": 3600,
        });
        store
            .kv_set(
                "xdp_block_times",
                "1.2.3.4",
                &serde_json::to_vec(&payload).unwrap(),
            )
            .expect("kv_set");
        let state = block_state_for_ip(Some(&store), "1.2.3.4", now);
        match state {
            BlockState::BlockedNow {
                since_ms,
                ttl_secs,
                expires_in_secs,
            } => {
                assert_eq!(since_ms, blocked_at_ms);
                assert_eq!(ttl_secs, 3600);
                // 3600 - 30 == 3570
                assert_eq!(expires_in_secs, 3570);
            }
            other => panic!("expected BlockedNow, got {other:?}"),
        }
    }

    #[test]
    fn block_state_blocked_historical_when_ttl_elapsed() {
        let store = make_store();
        let now = chrono::Utc::now();
        // Blocked 2h ago with a 1h TTL → expired.
        let blocked_at_ms = now.timestamp_millis() - 7_200_000;
        let payload = serde_json::json!({
            "blocked_at_ms": blocked_at_ms,
            "ttl_secs": 3600,
        });
        store
            .kv_set(
                "xdp_block_times",
                "1.2.3.4",
                &serde_json::to_vec(&payload).unwrap(),
            )
            .expect("kv_set");
        let state = block_state_for_ip(Some(&store), "1.2.3.4", now);
        match state {
            BlockState::BlockedHistorical { last_block_ms } => {
                assert_eq!(last_block_ms, blocked_at_ms);
            }
            other => panic!("expected BlockedHistorical, got {other:?}"),
        }
    }

    #[test]
    fn block_state_serialises_with_kind_tag_for_frontend() {
        // The front-end keys on `block_state.kind` to render the
        // BlockedNow countdown vs BlockedHistorical "expired" badge.
        // Anchor the wire format so a Serialize derive change does
        // not silently break the badge.
        let now_ms = 1_730_000_000_000;
        let json_now = serde_json::to_string(&BlockState::BlockedNow {
            since_ms: now_ms,
            ttl_secs: 3600,
            expires_in_secs: 3000,
        })
        .unwrap();
        assert!(json_now.contains("\"kind\":\"blocked_now\""), "{json_now}");
        assert!(json_now.contains("\"expires_in_secs\":3000"));

        let json_hist = serde_json::to_string(&BlockState::BlockedHistorical {
            last_block_ms: now_ms,
        })
        .unwrap();
        assert!(
            json_hist.contains("\"kind\":\"blocked_historical\""),
            "{json_hist}"
        );

        let json_open = serde_json::to_string(&BlockState::Open).unwrap();
        assert_eq!(json_open, r#"{"kind":"open"}"#);
    }

    #[test]
    fn classify_decision_returns_canonical_strings_only() {
        // Anchor: the front-end's outcome handling lists exactly
        // five strings (`outcomeBadgeHtml` in helpers.js). Any new
        // outcome string emitted from `classify_decision` is a
        // contract-breaking change -- this test exists so a future
        // edit that introduces a sixth string fails CI.
        let canonical = [
            OUTCOME_BLOCKED,
            OUTCOME_HONEYPOT,
            OUTCOME_MONITORING,
            OUTCOME_DISMISSED,
            OUTCOME_OPEN,
        ];
        let decisions = [
            None,
            Some("block_ip"),
            Some("kill_process"),
            Some("suspend_user_sudo"),
            Some("block_container"),
            Some("honeypot"),
            Some("monitor"),
            Some("ignore"),
            Some("dismiss"),
            Some("escalate"),
            Some("request_confirmation"),
            Some("future_unknown_action"),
            // Operator-action rows must also map to canonical strings only.
            Some("operator_override:dismiss"),
            Some("operator_override:monitor"),
            Some("operator_override:block_ip"),
            Some("operator_override:request_confirmation"),
            Some("operator_override:future_unknown"),
            Some("operator_unblock"),
            Some("operator_unblock_request"),
            Some("operator_reopen"),
        ];
        let exec_results = [None, Some("ok"), Some("error: rejected"), Some("executed")];
        for d in decisions {
            for er in exec_results {
                let outcome = classify_decision(d, er);
                assert!(
                    canonical.contains(&outcome),
                    "classify_decision({:?}, {:?}) = {:?} is not one of the five canonical strings",
                    d,
                    er,
                    outcome
                );
            }
        }
    }
}
