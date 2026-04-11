# Tasks: Knowledge Graph Phase 3 — Detector Migration

**Input**: `.specify/features/010-detector-migration-phase3/`
**Target file**: `crates/agent/src/knowledge_graph/detectors.rs` (currently 901 lines, 8 detectors)

## Phase 3A: Easy Migrations (10 detectors)

Each follows the existing pattern: query graph → check cooldown → return Vec<GraphIncident>.

- [x] T001-T010 All 10 Phase 3A detectors implemented and wired into run_all(). Including cgroup_abuse added 2026-04-10.
- [x] T011 All wired into run_all()
- [x] T012 29 tests total (19 existing + 10 new: crypto_miner, user_creation, scanner_ua, docker_anomaly, host_drift, credential_stuffing, sudo_abuse, dns_tunnel, correlation_chains, c2_beacon)

**Checkpoint**: `cargo test` passes. 18 graph detectors running. Deploy to production, compare with sensor output for 24h.

---

## Phase 3B: Medium Migrations — Aggregation Detectors (8 detectors)

These need aggregation helpers. Add `count_edges_in_window()` and `aggregate_by_entity()` to graph.rs first.

- [x] T013-T014 edges_in_window() helper exists in graph.rs. Aggregation done inline per detector.
- [x] T015-T022 All 8 Phase 3B detectors implemented. host_drift uses system binary allowlist + /tmp individual fire. sudo_abuse bug fixed (was checking outgoing, now uses incoming_edges). proto_anomaly, port_scan, credential_stuffing, dns_tunnel, network_sniffing, sensitive_write all working.
- [x] T023 All wired into run_all()
- [x] T024 Tests added for port_scan, credential_stuffing, sudo_abuse, dns_tunnel, host_drift

**Checkpoint**: 26 graph detectors running. host_drift incidents reduced from ~823 to <50/day. proto_anomaly from ~205 to <50/day.

---

## Phase 3C: Top 10 Correlation Rules as Graph Paths

Convert CL-001 to CL-010 from sliding window state machines to graph path queries.

- [x] T025-T034 Implemented as data-driven `detect_correlation_chains()` with `CORRELATION_RULES` array (10 rules: CL-002, CL-003, CL-005, CL-010, CL-011, CL-012, CL-014, CL-015, CL-024, CL-029). CL-010 (multi-low elevation) has special handling. Stages check with temporal ordering.
- [x] T035 Wired into run_all() with "graph_corr:" cooldown namespace
- [x] T036 Test added for CL-010 multi-low elevation

**Checkpoint**: Graph handles multi-stage attack detection. Correlation engine can be simplified (but not removed yet).

---

## Phase 3D: Dedup + Sensor Disable

- [x] T037 Graph incidents use `graph_` prefix in incident_id — no struct change needed
- [x] T038 `should_suppress_sensor()` checks graph recent_detections with 60s window + sensor→graph name mapping (17 detector names mapped)
- [x] T039 Config flag `graph_only_detectors: Vec<String>` added to AgentConfig. When detector name is in this list, sensor version is always suppressed. Wired into main.rs incident loop.
- [ ] T040 Dedup metrics (graph_detection_count, sensor_suppressed_count) — deferred, add when monitoring in production

**Checkpoint**: No duplicate incidents. Validated detectors run graph-only.

---

## Verification Matrix

| Phase | Test | Success Criteria |
|-------|------|-----------------|
| 3A | 24h parallel run | Graph ≥95% recall, ≤50% FP rate vs sensor |
| 3B | host_drift count | <50/day (vs 823 today) |
| 3B | proto_anomaly count | <50/day (vs 205 today) |
| 3C | CL-002 test | Multi-stage attack detected from graph path |
| 3D | Incident count | No increase vs sensor-only baseline |
| All | Graph tick time | <500ms |
| All | Memory | <50MB |
| All | `cargo test` | All tests pass |
