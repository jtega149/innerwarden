# Implementation Plan: Knowledge Graph Phase 3 — Detector Migration

**Branch**: `010-detector-migration-phase3` | **Date**: 2026-04-10 | **Spec**: `spec.md`

## Summary

Migrate 18 sensor detectors + 10 correlation rules to knowledge graph queries. Reduce incident noise by 30%+ through aggregation. Parallel running with sensor during migration, then disable sensor versions after validation.

## Technical Context

**Primary file**: `crates/agent/src/knowledge_graph/detectors.rs` (901 lines → ~2500 lines after)
**Pattern**: Each detector is a function: query graph → check cooldown → return `Vec<GraphIncident>`
**Execution**: Every 30s in agent slow loop via `graph.run_all()`
**Testing**: `cargo test -p innerwarden-agent`
**Validation**: 24h parallel run on production (130.162.171.105)

## Constitution Check

| Gate | Status |
|------|--------|
| I. Sensor is Deterministic | PASS — sensor untouched, graph detectors run in agent |
| II. Zero FP Over Missing Detections | PASS — parallel running, never disable without 1 week validation |
| III. Spec-Anchored Development | PASS — spec.md with acceptance scenarios |
| IV. User Experience First | PASS — fewer incidents = cleaner dashboard |
| V. English Commits | PASS |
| VI. Test Before Commit | PASS — 1 test per detector minimum |
| VII. CLAUDE.md Local Only | PASS |
| VIII. Minimal Changes | PASS — all in detectors.rs + graph.rs helpers |

## Phases

### Phase 3A (Week 1-2): 10 Easy Detectors
- T001-T012: 10 `detect_*` functions + wiring + tests
- Single graph query each, no new node types
- Expected: ~200 fewer incidents/day

### Phase 3B (Week 3-4): 8 Medium Detectors + Aggregation
- T013-T024: aggregation helpers + 8 detectors + tests
- Key wins: host_drift 823→<50, proto_anomaly 205→<50
- Expected: ~300 fewer incidents/day total

### Phase 3C (Week 5-6): 10 Correlation Rules
- T025-T036: convert CL-001 to CL-010 to graph path queries
- Multi-stage attack detection via structural queries

### Phase 3D (Week 6): Dedup + Disable
- T037-T040: suppress duplicates, validate, disable sensor versions
- Config flag for graph-only detectors

## Keep on Sensor (NOT migrated)
ssh_bruteforce, execution_guard, ransomware, rootkit, integrity_alert, sigma_rule, yara_scan, web_shell — these are fundamentally per-event/statistical/signature and cannot benefit from graph queries.

## Verification

1. `cargo test` — all pass
2. Deploy parallel: `graph_only_detectors = []` (both run)
3. 24h comparison: graph recall ≥95%
4. Enable graph-only: `graph_only_detectors = ["kernel_module", "user_creation", ...]`
5. Monitor for 1 week
6. Final metric: incidents/day reduced 30%+
