# Implementation Plan: Phase 6 — Eliminate JSONL Dependency

**Branch**: `012-eliminate-jsonl` | **Date**: 2026-04-10 | **Spec**: `spec.md`

## Summary

Convert the agent from JSONL-primary to graph-primary data flow. Stop reading JSONL files (~25 read operations across 18 files). Keep essential JSONL writes (decisions hash chain, sensor output, honeypot evidence). Remove redundant JSONL writes (graph/trigger incidents, telemetry). Harden graph persistence.

## Technical Context

**Current**: Sensor → JSONL → Agent reads JSONL → Graph + JSONL (dual storage)
**Target**: Sensor → JSONL (audit) → Agent reads JSONL once → Graph (primary) → All queries from graph

**Key insight**: The agent already ingests everything into the graph. The JSONL reads are redundant — they're re-reading data that's already in memory. The fix is: redirect all consumers (dashboard, bot, reports, neural) to query the graph instead of reading JSONL files.

## Strategy: Inside-Out

Start from the consumers closest to the graph (dashboard — already mostly graph-powered) and work outward:

1. **Dashboard** (6A) — already 90% graph, remove last JSONL fallbacks
2. **Bot + Agent** (6B) — replace `count_jsonl_lines()` calls
3. **Reports** (6C) — replace `parse_*_file()` calls
4. **Neural** (6D) — replace FP/decision reads
5. **Writes** (6E) — remove redundant JSONL output
6. **Persistence** (6F) — harden snapshot for reliability

## Constitution Check

| Gate | Status |
|------|--------|
| I. Sensor Deterministic | PASS — sensor untouched, still writes JSONL |
| II. Zero FP | PASS — data unchanged, only read source changes |
| III. Spec-Anchored | PASS |
| IV. UX First | PASS — faster queries, less disk IO |
| V. English Commits | PASS |
| VI. Test Before Commit | PASS |
| VII. CLAUDE.md | PASS |
| VIII. Minimal Changes | PASS — consumer redirects, not data model changes |

## Risks

1. **Graph snapshot corruption** → agent loses all data → Mitigated by T030 (JSONL rebuild fallback)
2. **Monthly reports need historical data** → graph only has today → Mitigated by T017 (JSONL fallback for old dates)
3. **Decision hash chain** → must remain in JSONL → explicitly kept (no change)

## Timeline

- Phase 6A (dashboard): 1 day
- Phase 6B (bot/agent): 1 day
- Phase 6C (reports): 2 days
- Phase 6D (neural): 1 day
- Phase 6E (writes): 1 day
- Phase 6F (persistence): 2 days
- **Total: ~8 days**
