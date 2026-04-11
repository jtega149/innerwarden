# Implementation Plan: Incident Humanization Layer

**Branch**: `008-incident-humanization` | **Date**: 2026-04-10 | **Spec**: `spec.md`

## Summary

Add a presentation layer between raw sensor incident data and the journey timeline UI. Human titles from DETECTOR_LABELS (already exists from 007), collapsible detail sections, "so what?" context lines, clean text rendering, and outcome-aware card styling. Frontend-only changes in the single HTML file.

## Technical Context

**Language**: HTML/CSS/JS inline in `index.html` (embedded in Rust binary via `include_str!`)
**Key function**: `renderEntry()` in `index.html` — renders each timeline entry (incident, decision, honeypot, forensics)
**Existing infrastructure**: `DETECTOR_LABELS` map, `humanLabel()` function, `outcomeBadgeHtml()`, `esc()` function
**No Rust changes needed**

## Constitution Check

| Gate | Status |
|------|--------|
| I. Sensor is Deterministic | PASS — sensor untouched |
| II. Zero FP Over Missing Detections | PASS — display-only changes |
| III. Spec-Anchored Development | PASS — spec.md written first |
| IV. User Experience First | PASS — entire feature IS UX |
| V. English Commits | PASS |
| VI. Test Before Commit | PASS — cargo check + browser |
| VII. CLAUDE.md Local Only | PASS |
| VIII. Minimal Changes | PASS — single function area |

## Architecture

### Current flow
```
Incident Node (graph) → api/journey → JourneyEntry { kind: "incident", data: {...} }
  → renderEntry(entry) → full raw title + summary inline
```

### New flow
```
Incident Node (graph) → api/journey → JourneyEntry { kind: "incident", data: {...} }
  → renderEntry(entry)
    → humanTitle(detector, rawTitle)     # "Suspicious SSH connection"
    → contextLine(outcome, severity)     # "Handled automatically — no action needed"
    → [Show details] → rawTitle + summary + evidence (collapsed)
```

## Implementation

### Phase 1: Human title mapping + context lines
- Add `humanTitle(detector, rawTitle)` — uses DETECTOR_LABELS, extracts IP if present, builds "what happened" string
- Add `contextLine(outcome, severity)` — returns the "so what?" line based on outcome
- Modify `renderEntry()` for `kind === 'incident'` — replace raw title with humanTitle, add context line

### Phase 2: Collapsible detail
- Add CSS for `.detail-toggle` button and `.detail-body` collapsible section
- Move raw title, summary, evidence into `.detail-body` (hidden by default)
- Add "Show details" / "Hide details" toggle button

### Phase 3: Clean text rendering
- Fix double-escaping: the `esc()` output goes into `innerHTML`, so entities are interpreted. But some paths may double-escape. Audit and fix.
- For raw JSON view: keep as-is (code display)

### Phase 4: Outcome-aware card styling
- Add CSS classes: `.entry-contained` (opacity 0.7, green left border), `.entry-open` (full opacity, red left border), `.entry-noise` (opacity 0.5)
- Apply class in renderEntry() based on incident outcome

## Verification

1. `cargo check --package innerwarden-agent`
2. Deploy to production
3. Browser: human titles, context lines, collapsible details, clean text, visual weight
