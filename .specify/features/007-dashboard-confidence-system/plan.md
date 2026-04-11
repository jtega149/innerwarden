# Implementation Plan: Dashboard Confidence System

**Branch**: `007-dashboard-confidence-system` | **Date**: 2026-04-10 | **Spec**: `spec.md`
**Input**: Feature specification from `.specify/features/007-dashboard-confidence-system/spec.md`

## Summary

Transform the entire InnerWarden dashboard from a fear-based alert system into a confidence system. Backend adds `unresolved_count`, `effective_severity`, and enriched outcomes. Frontend rewrites color logic, language, feed aggregation, and visual hierarchy across all 10 views. Core principle: GREEN when the system handles threats, RED only when human action is needed.

## Technical Context

**Language/Version**: Rust (edition 2021, workspace) + HTML/CSS/JS (inline in single file)
**Primary Dependencies**: axum, serde, chrono, innerwarden-core (existing)
**Frontend**: Single HTML file embedded via `include_str!()` — no build system, no framework
**Testing**: `cargo test -p innerwarden-agent` + manual browser verification on production
**Target Platform**: Linux server (production: Oracle Cloud Ubuntu, 130.162.171.105:8787)
**Constraints**: Zero new dependencies. No new files except this spec. All views must be updated.

## Constitution Check

| Gate | Status |
|------|--------|
| I. Sensor is Deterministic | PASS — all changes in agent crate, sensor untouched |
| II. Zero FP Over Missing Detections | PASS — only display/UX changes + additive API fields |
| III. Spec-Anchored Development | PASS — spec.md written first, plan follows spec |
| IV. User Experience First | PASS — entire feature IS user experience improvement |
| V. English Commits, Portuguese Conversations | PASS — code and commits in English |
| VI. Test Before Commit | PASS — cargo test + browser verification |
| VII. CLAUDE.md Local Only | PASS — no CLAUDE.md committed |
| VIII. Minimal Changes | PASS — scoped to dashboard module + data_api |

## Source Code (affected files)

```text
crates/agent/src/dashboard/
├── data_api.rs           # MODIFIED — add unresolved_count, effective_severity, severity_breakdown
├── compliance.rs         # MODIFIED — soften hash chain language
├── live_feed.rs          # MODIFIED — add outcome field to LiveFeedItem
├── investigation.rs      # MODIFIED — journey narrative tone (contained vs blocked)
├── intelligence.rs       # MODIFIED — pattern class humanized labels (if backend-rendered)
├── sensors.rs            # NO CHANGE — gauge logic is frontend JS
├── mod.rs                # NO CHANGE — no new routes
└── frontend/html/
    └── index.html        # MODIFIED — CSS + JS + HTML across all 10 views (~200 lines changed)
```

## Architecture

### Data Flow (new fields)

```
Knowledge Graph → api_overview() → OverviewResponse {
  ...existing fields...
  + unresolved_count: usize        // incidents where decision is None
  + safely_resolved: usize         // blocked + killed + contained + monitored + honeypot
  + severity_breakdown: HashMap    // {critical: N, high: N, ...}
}

Knowledge Graph → api_incidents() → IncidentView {
  ...existing fields...
  + effective_severity: String     // downgraded if blocked: critical→medium, high→low
  + confidence: Option<f32>        // AI decision confidence
}
```

### Frontend Color Decision Tree

```
getUnresolved() → { total, unresolved, handled }
  │
  ├─ unresolved > 0 → DANGER (red)
  │   - Hero: "Action Required — X unresolved threats"
  │   - KPI: red number showing unresolved count
  │   - Gauge: based on unresolved only
  │
  ├─ total > 0 && unresolved == 0 → SAFE (green)
  │   - Hero: "All Threats Contained"
  │   - KPI: green number showing total handled
  │   - Gauge: NOMINAL
  │
  └─ total == 0 → SAFE (green)
      - Hero: "All Clear"
      - KPI: accent "0"
      - Gauge: NOMINAL
```

### Feed Aggregation Algorithm

```
incidents[] → aggregateIncidents() → groups[]
  │
  ├─ Group by: detector_slug + outcome
  ├─ Sort: open first (full opacity), then contained, then noise
  ├─ Single event (count=1): render as individual row
  └─ Multiple events (count>1): render as summary row
      "SSH login attempts — 50 events" + "CONTAINED" badge + "50x" count
```

## Phases

### Phase 1: Backend (Rust)
Add `unresolved_count`, `safely_resolved`, `severity_breakdown` to OverviewResponse.
Add `effective_severity` and `confidence` to IncidentView.
Soften compliance hash chain language.
Add `outcome` to LiveFeedItem.

### Phase 2: CSS + Helpers (Frontend)
New semantic CSS classes (outcome-contained, badge-contained, etc.).
Remove hardcoded red from KPI HTML elements.
Add mobile responsive table wrapper.
Add JS helpers: getUnresolved(), DETECTOR_LABELS, aggregateIncidents().

### Phase 3: Home View (Frontend)
Rewrite updateHomeBanner() with unresolved logic.
Rewrite updateHomeKpis() with contextual colors.
Rewrite buildHomeFeed() with aggregation + green CONTAINED badges.

### Phase 4: Investigate View (Frontend)
Fix updateStatusHero() with unresolved logic.
Fix buildActivityFeed() with aggregation + colors.
Fix KPI strip colors.
Fix attacker cards: pulse dot, severity dimming, outcome badges.

### Phase 5: Sensors View (Frontend)
Fix threat gauge to use unresolved only.
Fix incidents HUD card for handled context.
Improve source labels.

### Phase 6: All Other Views (Frontend)
Status: firmware/hypervisor labels, OFF badge colors.
Compliance: chain integrity language, ISO control names.
Report: KPI labels, trend context.
Intel: pattern labels, risk tooltips.
Monthly: campaign type labels, week format.
Responses: backend tooltips, mobile tables.
Honeypot: CSS variable colors.

### Phase 7: SSE + Empty States + Polish
Toast notifications with outcome-aware colors.
Consistent empty states across all views.

## Verification

1. `cargo test -p innerwarden-agent` — all tests pass
2. `cargo check --package innerwarden-agent` — compiles
3. Deploy to production: rsync → build → stop → copy → start
4. Browser verification (all 12 user story scenarios from spec.md)
5. Mobile check: narrow viewport, verify tables scroll, nav works
