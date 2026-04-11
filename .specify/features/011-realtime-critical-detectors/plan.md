# Implementation Plan: Real-Time Critical Detectors

**Branch**: `011-realtime-critical-detectors` | **Date**: 2026-04-10 | **Spec**: `spec.md`

## Summary

Convert 4 CRITICAL graph detectors from 30s batch tick to real-time edge-insert triggers. Reverse shell, fileless execution, container escape, and service stop will detect within <2s instead of waiting for the next 30s tick. O(1) checks in the hot path. Shared cooldown prevents duplicates with existing 30s versions.

## Technical Context

**Hot path**: `graph.ingest(event)` → `add_edge()` → `check_critical_triggers()` — per-event, must be fast
**Cold path**: `run_all()` every 30s — existing detectors, unchanged
**Shared state**: `GraphDetectorState` cooldown tracker — triggers and 30s detectors use same keys
**Performance budget**: <1% overhead on `add_edge()` (4 index lookups per edge)

## Key Design Decisions

1. **Triggers in graph.rs, not detectors.rs**: Because they run inside `add_edge()` which is in graph.rs. The trigger functions themselves can be in a separate module or in detectors.rs with `pub` visibility.

2. **Return incidents from ingest()**: Currently `ingest()` returns `()`. Changing to `Vec<Incident>` allows the caller (main.rs fast loop) to handle trigger incidents immediately — write to JSONL, notify, etc.

3. **Shared cooldown**: Trigger fires at t=0, sets cooldown key. At t=30 when tick runs, same key is in cooldown → tick suppressed. No duplicate incidents.

4. **Pattern**: Each trigger checks "does adding THIS edge complete a known attack pattern?" by looking at the source node's existing edges. This is 1 `outgoing_edges()` call per trigger — already an indexed HashMap lookup.

## Constitution Check

| Gate | Status |
|------|--------|
| I. Sensor is Deterministic | PASS — sensor untouched |
| II. Zero FP Over Missing | PASS — 30s tick remains as fallback |
| III. Spec-Anchored | PASS |
| IV. UX First | PASS — faster detection = better security |
| V. English Commits | PASS |
| VI. Test Before Commit | PASS — 6 tests planned |
| VII. CLAUDE.md | PASS |
| VIII. Minimal Changes | PASS — 4 functions + plumbing |

## Phases

### Phase A: Plumbing (T001-T003)
- Change `ingest()` signature
- Add `check_critical_triggers()` dispatch in `add_edge()`
- Collect and handle trigger incidents in main.rs

### Phase B: Triggers (T004-T007)
- 4 trigger functions, each <30 lines
- O(1) edge checks per trigger

### Phase C: Tests (T008-T013)
- 6 tests + benchmark

## Verification

Deploy → simulate reverse shell → incident appears in dashboard within 2s (not 30s).
