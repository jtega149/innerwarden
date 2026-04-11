# Tasks: Phase 6 — Eliminate JSONL Dependency

**Input**: `.specify/features/012-eliminate-jsonl/`

## Phase 6A: Dashboard — Graph Only (no JSONL reads)

- [x] T001 Remove `compute_overview()` JSONL fallback in `data_api.rs` — converted to `compute_overview_from_graph()`, old version #[cfg(test)] only
- [x] T002 Remove `read_jsonl()` usage from `dashboard/helpers.rs` — function kept for compliance (admin-actions) only. All other dashboard reads converted to graph.
- [x] T003 Update `dashboard/sensors.rs` — kill chain counts + collector source counts from graph
- [x] T004 Dashboard JSONL reads eliminated: agent_api.rs (security-context, check-ip), live_feed.rs (MITRE), compliance.rs (blocked IPs), investigation.rs (export endpoint)
- [x] T005 Verify: `cargo check` clean, 553 agent tests pass, zero JSONL reads in production dashboard paths

**Checkpoint**: Dashboard fully graph-powered. No JSONL reads except compliance hash chain.

## Phase 6B: Bot Commands + Agent Context — Graph Only

- [x] T006 New `graph_count()` in bot_helpers.rs — counts incidents/decisions from graph Incident nodes
- [x] T007 New `graph_last_incidents()` — formats last N incidents from graph with severity icons, entity, age
- [x] T008 New `graph_last_decisions()` + `graph_last_incidents_raw()` — graph-based Telegram display + AI context
- [x] T009 All bot_commands.rs callers updated: /status, /threats, /decisions, /start, /ask use graph helpers
- [x] T010 agent_context.rs `build_agent_context()` takes `&KnowledgeGraph`, counts from graph. narrative_daily_summary.rs updated.
- [x] T011 DEFERRED to Phase 6F: `load_startup_decision_state()` reads yesterday+today JSONL at boot — graph snapshot may lack historical data

**Checkpoint**: Bot and agent context use graph. Zero JSONL reads in runtime.

## Phase 6C: Reports — Graph Only

- [x] T012-T014 `generate()` loads graph snapshot, uses `compute_for_date_from_graph()`. Falls back to JSONL when graph empty (tests, first run).
- [x] T015 DEFERRED to 6F: `compute_recent_window()` needs per-event timestamps the graph doesn't store. `build_operational_telemetry()` reads telemetry JSONL (agent metrics, not attack data). Both once-per-report, low impact.
- [x] T016 Monthly threat report keeps JSONL — graph lacks 30-day history. Added info-level log explaining historical JSONL usage.
- [x] T017 Fallback strategy: graph preferred when populated (node_count > 0), JSONL for empty graph or historical dates. Previous-day trend analysis uses JSONL (graph has no yesterday).

**Checkpoint**: Reports generate from graph. Historical dates fallback to JSONL with deprecation warning.

## Phase 6D: Neural Training — Graph Only

- [x] T018 DEFERRED to 6F: FP reports (`fp-reports-*.jsonl`) not tracked in graph. Needs schema change: add `false_positive: bool` to Incident nodes.
- [x] T019 DEFERRED to 6F: Same — `read_fp_report_counts()` reads 7 days of FP JSONL. Graph lacks FP tracking.
- [x] T020 DEFERRED to 6F: `load_blocked_ips()` reads ALL historical `decisions-*.jsonl`. Graph only has today. Nightly retrain (3 AM), not runtime.
- [x] T021 DEFERRED to 6F: `read_latest_snapshot()` reads telemetry (AI latency, tick counts, gate pass, errors). Different data domain — agent health, not attack topology. Graph doesn't store these.

**Checkpoint**: Phase 6D fully deferred — all 4 tasks need either graph schema changes (FP tracking), multi-day persistence, or new data domains (telemetry). Nightly-only functions, not runtime impact.

## Phase 6E: Eliminate Redundant Writes

- [x] T022 Removed `incidents-graph-*.jsonl` write — data already ingested into graph before write
- [x] T023 Removed `incidents-trigger-*.jsonl` write — same pattern, graph has the data
- [x] T024 DEFERRED: agent-guard JSONL is an audit trail for AI agent security events. Ingesting as Incident nodes requires mapping alert fields → Incident schema (feature addition, not elimination).
- [x] T025 DEFERRED: telemetry JSONL stores agent metrics (AI latency, tick counts) not in graph. Read by dashboard, reports, prometheus. Can't stop writing until consumers converted.
- [x] T026 TTL cleanup already covers all 11 node types. FIXED: Incident expiry now correctly keeps `block_ip`/`kill_process`/`suspend_user_sudo`/`block_container` permanent (was matching `"block"` which never matched).

**Checkpoint**: Only essential JSONL writes remain: decisions (hash chain), sensor events/incidents (sensor writes these), honeypot evidence.

## Phase 6F: Graph Persistence Hardening

- [x] T027 Integrity check on load: verifies index consistency (0 indexed but N nodes = corruption), prunes dangling edges, rebuilds adjacency
- [x] T028 SKIPPED: incremental snapshot adds complexity for marginal IO gain. Full snapshot is <5MB, writes every 60s. Revisit if snapshot grows >50MB.
- [x] T029 Snapshot rotation: keeps last 3 backups (.json.1, .json.2, .json.3). Rotated before each write.
- [x] T030 Backup fallback on corruption: if main snapshot corrupted, tries .1 → .2 → .3 before starting fresh. 2 new tests.

**Checkpoint**: Graph persistence is reliable. Agent recovers from snapshot corruption.

## Verification

| Test | Success Criteria |
|------|-----------------|
| Dashboard no JSONL | Delete events/incidents/decisions JSONL → dashboard works |
| Bot commands | `/status` works without JSONL files |
| Daily report | Generates correctly from graph |
| Neural training | Nightly retrain succeeds with graph data |
| No redundant files | `ls incidents-graph-*.jsonl` → empty after 24h |
| Memory | Stable or decreased vs baseline |
| Snapshot recovery | Delete snapshot → agent rebuilds from JSONL → works |
| `cargo test` | All pass |
