# Feature Specification: Knowledge Graph Phase 7 — Single Source of Truth

**Feature Branch**: `013-graph-single-source`
**Created**: 2026-04-10
**Status**: Planned
**Priority**: P3 (architecture debt, no runtime impact — all deferred items are nightly/startup)
**Depends on**: 012-eliminate-jsonl (Phase 6, complete)

## Origin

Phase 6 (012-eliminate-jsonl) eliminated ~25 JSONL reads and 2 redundant writes from runtime paths. All dashboard, bot, agent context, and report generation now use the knowledge graph as primary source. However, 4 categories of JSONL reads could not be converted due to fundamental gaps in what the graph stores.

This spec captures those gaps and the changes needed to close them.

## Gap 1: False Positive Tracking (from Phase 6D T018-T019)

**Problem**: Operators report false positives via Telegram (`/fp` command). These are written to `fp-reports-{date}.jsonl` by `telegram::log_false_positive()`. The neural lifecycle reads 7 days of FP reports during nightly retrain to adjust the autoencoder. The graph has no concept of FP reports.

**Current JSONL reads**:
- `neural_lifecycle.rs:942` — `read_fp_report_detectors()` scans 7 days of `fp-reports-*.jsonl`
- `neural_lifecycle.rs:986` — `read_fp_report_counts()` same scan, counts by (detector, entity)
- `narrative_autofp.rs:18` — calls `read_fp_report_counts()` for auto-FP processing

**Solution**: Add FP tracking to Incident nodes.

Schema change in `types.rs` Node::Incident:
```rust
Node::Incident {
    // ... existing fields ...
    false_positive: bool,           // NEW: operator marked as FP
    fp_reporter: Option<String>,    // NEW: who reported (operator name)
    fp_reported_at: Option<DateTime<Utc>>, // NEW: when
}
```

When operator reports FP via Telegram:
1. Find Incident node by incident_id in graph
2. Set `false_positive = true`, `fp_reporter`, `fp_reported_at`
3. Keep writing `fp-reports-*.jsonl` for audit trail (write-only)

Neural lifecycle query: `graph.nodes_of_type(Incident).filter(|n| n.false_positive && n.ts > cutoff)`

**Effort**: 1 day
**Files**: `types.rs`, `telegram.rs` (FP handler), `neural_lifecycle.rs`, `narrative_autofp.rs`

---

## Gap 2: Multi-Day Graph Persistence (from Phase 6B T011, 6D T020)

**Problem**: The graph snapshot holds current state only. Functions that need historical data across multiple days still read JSONL:

- `decision_cooldown.rs:159` — `load_startup_decision_state()` reads today + yesterday `decisions-*.jsonl` at boot to rebuild blocklist and cooldowns
- `neural_lifecycle.rs:1321` — `load_blocked_ips()` reads ALL historical `decisions-*.jsonl` during nightly retrain
- `report.rs:408,539` — `compute_day_counters()` reads previous day's JSONL for trend analysis
- `report.rs:807` — `compute_recent_window()` reads today + yesterday for 6-hour window

**Solution**: Daily graph snapshots.

Instead of one `graph-snapshot.json`, save dated snapshots:
```
graph-snapshot-2026-04-10.json  (today, updated every 60s)
graph-snapshot-2026-04-09.json  (yesterday, frozen at midnight)
graph-snapshot-2026-04-08.json  (2 days ago)
```

Retention: keep last N days (configurable, default 7). At midnight, freeze current snapshot as dated file, start new day.

For startup: load today's snapshot (or latest available). For trend analysis: load yesterday's snapshot. For nightly retrain: query last 7 days of dated snapshots.

**Effort**: 2-3 days
**Files**: `persistence.rs`, `main.rs` (midnight rollover), `decision_cooldown.rs`, `neural_lifecycle.rs`, `report.rs`

---

## Gap 3: Telemetry Data Domain (from Phase 6D T021, 6E T025)

**Problem**: `telemetry-*.jsonl` stores agent operational metrics (not attack data):
- `ai_sent_count`, `ai_decision_count`, `avg_decision_latency_ms`
- `gate_pass_count`, `events_by_collector`, `incidents_by_detector`
- `errors_by_component`, `dry_run_execution_count`, `real_execution_count`

Read by: dashboard overview (sleeping mode), Prometheus metrics endpoint, report generation.

The graph stores attack topology (processes, IPs, files). Telemetry is agent health — different domain.

**Options** (pick one):
1. **Add TelemetrySnapshot to graph** — New node type `Telemetry { tick, ai_sent_count, ... }`. Pro: single source. Con: pollutes attack graph with operational data.
2. **In-memory telemetry ring** — Replace JSONL with in-memory ring buffer of last N snapshots. Pro: no disk reads. Con: lost on restart.
3. **Prometheus as source of truth** — Push metrics to Prometheus, read from Prometheus. Pro: industry standard. Con: adds dependency.
4. **Keep JSONL** — Telemetry writes are small (~1KB/snapshot), reads are fast (cached). Lowest risk.

**Recommendation**: Option 4 (keep JSONL) for now. Telemetry JSONL is small, cached, and works. Convert when a Prometheus-first architecture is adopted.

**Effort**: 0 (keep) or 2 days (ring buffer)

---

## Gap 4: Monthly Threat Report History (from Phase 6C T016)

**Problem**: `threat_report.rs:257` iterates 30 days of JSONL files (`events-*.jsonl`, `incidents-*.jsonl`, `decisions-*.jsonl`) for the monthly report. The graph only has today's data.

**Solution**: Depends on Gap 2 (daily snapshots). Once dated snapshots exist, the monthly report can load each day's snapshot and aggregate.

**Effort**: 1 day (after Gap 2 is done)
**Dependency**: Gap 2

---

## Gap 5: Event-Level Timestamps (from Phase 6C T015)

**Problem**: `compute_recent_window()` in `report.rs` filters individual events by 6-hour timestamp. The graph stores events as edges, but edges don't have a dedicated "event" identity — they're structural relations (Process→ConnectedTo→Ip). Filtering edges by a 6-hour window is possible but the graph's `event_timeline` uses 5-minute buckets (HH:MM keys), not precise timestamps per event.

**Solution**: The graph already has `event_timeline: BTreeMap<String, HashMap<String, usize>>` with 5-min buckets. For a 6-hour window, sum the last 72 buckets. Approximate but sufficient for a report metric.

**Effort**: 0.5 day
**Files**: `report.rs`

---

## Priority and Sequencing

| Gap | Effort | Impact | Depends on | Recommended priority |
|-----|--------|--------|------------|---------------------|
| 1. FP tracking | 1 day | Neural training accuracy | — | P2 (do with next neural work) |
| 2. Daily snapshots | 2-3 days | Unlocks gaps 4, partial 3 | — | P2 (prerequisite) |
| 3. Telemetry | 0 days | None (keep JSONL) | — | P4 (defer) |
| 4. Monthly report | 1 day | Monthly report quality | Gap 2 | P3 |
| 5. Event timestamps | 0.5 day | Report accuracy | — | P3 |

**Total**: ~5 days of work. Not urgent — all affected code paths are nightly, startup, or monthly. No runtime impact.

## What Does NOT Belong Here

- Detector migration (spec 010) — separate concern, much higher priority
- Realtime detectors (spec 011) — separate concern
- Dashboard Phase 2 (spec 009) — separate concern
- GNN/ML (Phase 5.2-5.4) — research, not architecture
- Multi-host graph sync (Phase 7.5) — product feature, not debt
- AlphaZero (Phase 7.7) — research

## Verification

1. After Gap 1: Delete `fp-reports-*.jsonl` → neural retrain still uses FP data from graph
2. After Gap 2: Delete yesterday's JSONL → startup blocklist loads from dated snapshot
3. After Gap 4: Monthly report generates from dated snapshots, no JSONL reads
4. After all: only audit trail JSONL remains (decisions hash chain, honeypot evidence, sensor writes)
