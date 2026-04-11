# Feature Specification: Phase 6 — Eliminate JSONL Dependency

**Feature Branch**: `012-eliminate-jsonl`
**Created**: 2026-04-10
**Status**: Planned
**Input**: Knowledge graph Phases 1-5 complete. Graph is already primary source for dashboard APIs. But agent still reads events/incidents from JSONL, writes decisions/telemetry to JSONL, and uses JSONL for reports/neural training.

## Origin

The knowledge graph runs in-memory with all events, incidents, and decisions. But the agent still:
- **Reads** events from `events-*.jsonl` (sensor writes these, agent reads with cursor)
- **Reads** incidents from `incidents-*.jsonl` (sensor detectors write, agent reads for AI triage)
- **Writes** decisions to `decisions-*.jsonl` (hash-chained audit trail)
- **Writes** telemetry to `telemetry-*.jsonl`
- **Reads** JSONL in 15+ places for reports, bot commands, neural training, compliance

Total: ~30 JSONL read/write operations across 18 files.

## Problem

1. **Dual storage**: Same data exists in JSONL files AND knowledge graph. Double CPU, double IO.
2. **Reader polling**: `reader.rs` reads JSONL with byte offset cursor — polling a file that the sensor writes. The graph already has this data from `ingest()`.
3. **Memory**: Graph holds everything in-memory. JSONL also loads data into memory when read. Redundant.
4. **Complexity**: Every new feature must update both JSONL and graph paths.

## Strategy: Graph as Primary, JSONL as Audit Trail

**NOT full elimination.** Instead:
- **Graph becomes the ONLY read source** — all queries go to graph, never to JSONL
- **JSONL becomes write-only audit trail** — append-only, never read back by agent
- **Decisions JSONL stays** — hash-chained integrity required for compliance
- **Honeypot evidence JSONL stays** — forensic artifacts need long-term storage

This means: eliminate ~25 JSONL READ operations, keep ~8 WRITE operations.

## What Changes

### Phase 6A: Stop Reading Events JSONL
The sensor writes `events-*.jsonl`. The agent reads them via `reader.rs` cursor. But `graph.ingest()` already processes these events. The graph IS the processed result.

**Change**: Agent reads events via Redis Streams (already supported) or direct IPC, not JSONL. For deployments without Redis, sensor events go directly into the graph via shared memory or Unix socket.

**Actually simpler**: The agent already calls `graph.ingest(event)` for every event in `process_events_tick()`. After ingestion, the event data is in the graph. The JSONL read is redundant — the agent already has the data. We just need to make all downstream consumers use the graph instead of re-reading JSONL.

### Phase 6B: Stop Reading Incidents JSONL
Same pattern: `reader.rs` reads incidents, feeds to `process_incidents_tick()` which then ingests into graph. After Phase 3, graph detectors also generate incidents directly.

**Change**: All incident queries go to graph. `bot_helpers`, `report.rs`, `threat_report.rs`, `neural_lifecycle.rs` all switch from `read_jsonl()` to graph queries.

### Phase 6C: Stop Reading Decisions JSONL
Decisions are written to JSONL with hash chain (compliance). But decision DATA is also stored in graph incident nodes.

**Change**: All decision reads go to graph. Keep decision WRITES to JSONL for hash chain integrity. The graph is the query source, JSONL is the audit archive.

### Phase 6D: Stop Reading Telemetry JSONL
Telemetry snapshots (metrics per tick) are written to JSONL. Dashboard reads latest snapshot for overview.

**Change**: Compute telemetry metrics on-demand from graph. No need to persist snapshots — graph has all the data.

### Phase 6E: Eliminate Redundant JSONL Writes
Graph detectors and triggers already write their incidents to `incidents-graph-*.jsonl` and `incidents-trigger-*.jsonl`. These are redundant — the incidents are already in the graph.

**Change**: Stop writing `incidents-graph-*.jsonl` and `incidents-trigger-*.jsonl`. The graph snapshot (`graph-snapshot.json`) persists this data.

---

## What Does NOT Change

| JSONL File | Why Keep |
|-----------|---------|
| `events-*.jsonl` | **Sensor writes this** — can't change sensor behavior. Agent just stops reading it. |
| `incidents-*.jsonl` | **Sensor detectors write this** — agent stops reading, but file stays for audit. |
| `decisions-*.jsonl` | **Hash-chained audit trail** — compliance requirement. Keep write, stop read. |
| `honeypot/listener-session-*.jsonl` | **Forensic evidence** — raw attacker interaction. Keep for training + investigation. |

---

## User Scenarios & Testing

### User Story 1 — Dashboard Uses Graph Only (Priority: P1)

All dashboard API endpoints use knowledge graph, never JSONL.

**Independent Test**: Delete all JSONL files from data_dir. Dashboard still shows all data correctly from graph.

**Acceptance Scenarios**:

1. **Given** no JSONL files in data_dir, **When** dashboard overview loaded, **Then** shows correct counts from graph.
2. **Given** graph has 100 incidents, **When** `/api/incidents` called, **Then** returns 100 items (not 0 from missing JSONL).
3. **Given** `compute_overview()` JSONL fallback removed, **When** dashboard sleeping, **Then** returns zeros (acceptable — graph handles active state).

### User Story 2 — Bot Commands Use Graph (Priority: P2)

Telegram bot commands (`/status`, `/menu`) read from graph, not JSONL.

**Acceptance Scenarios**:

1. **Given** Telegram `/status`, **When** executed, **Then** shows incident/decision counts from graph.
2. **Given** no JSONL files, **When** `/status` executed, **Then** still works correctly.

### User Story 3 — Report Generation Uses Graph (Priority: P2)

Daily and monthly reports generated from graph queries, not JSONL parsing.

**Acceptance Scenarios**:

1. **Given** daily report requested, **When** `report.rs` runs, **Then** generates report from graph data.
2. **Given** monthly report, **When** `threat_report.rs` runs, **Then** reads graph for all dates in month.

### User Story 4 — Neural Training Uses Graph (Priority: P3)

Autoencoder training reads FP reports and blocked IPs from graph, not JSONL.

**Acceptance Scenarios**:

1. **Given** nightly retrain, **When** `neural_lifecycle.rs` needs FP data, **Then** queries graph decision nodes.
2. **Given** blocked IPs needed for baseline exclusion, **When** queried, **Then** graph returns all `action_type=block_ip` decisions.

### User Story 5 — No Redundant Writes (Priority: P2)

Graph detector and trigger incidents stop writing to separate JSONL files.

**Acceptance Scenarios**:

1. **Given** graph detector fires, **When** incident created, **Then** only ingested into graph (no `incidents-graph-*.jsonl` written).
2. **Given** trigger fires, **When** incident created, **Then** only ingested into graph (no `incidents-trigger-*.jsonl` written).
3. **Given** graph snapshot exists, **When** agent restarts, **Then** all graph incidents restored from snapshot.

---

## Files to Modify

| File | Changes | Priority |
|------|---------|----------|
| `dashboard/data_api.rs` | Remove `compute_overview()` JSONL fallback | P1 |
| `dashboard/helpers.rs` | Remove `read_jsonl()` calls, use graph | P1 |
| `dashboard/sensors.rs` | Remove JSONL reads, use graph | P1 |
| `dashboard/compliance.rs` | Keep decision JSONL read for hash chain only | P1 |
| `bot_helpers.rs` | Replace `count_jsonl_lines()` with graph query | P2 |
| `bot_commands.rs` | Replace JSONL reads with graph queries | P2 |
| `report.rs` | Replace `parse_events_file()` etc. with graph queries | P2 |
| `threat_report.rs` | Replace JSONL reads with graph date-range queries | P2 |
| `neural_lifecycle.rs` | Replace FP/decision JSONL reads with graph queries | P3 |
| `agent_context.rs` | Replace `count_jsonl_lines()` with graph query | P3 |
| `decision_cooldown.rs` | Replace JSONL read with graph decision query | P2 |
| `main.rs` | Remove `incidents-graph-*.jsonl` and `incidents-trigger-*.jsonl` writes | P2 |
| `data_retention.rs` | Add graph node expiration alongside file retention | P3 |

## Risks

1. **Graph snapshot corruption**: If snapshot fails to load, agent has no data. Mitigated by: keep JSONL writes as backup, snapshot validation on load.
2. **Memory growth**: Without JSONL retention, graph must handle its own retention. Already has TTL + 50MB cap + LRU pruning.
3. **Monthly reports**: Reports span 30 days. Graph snapshot only has today's data. Need: either keep JSONL for historical queries, or persist graph snapshots per-day.

## Verification

1. `cargo test` — all pass
2. Delete all JSONL files → dashboard works
3. Telegram bot commands work without JSONL
4. Daily report generates from graph
5. No `incidents-graph-*.jsonl` or `incidents-trigger-*.jsonl` created
6. Memory usage stable or decreased
