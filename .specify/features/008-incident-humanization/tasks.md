# Tasks: Incident Humanization Layer

**Input**: `.specify/features/008-incident-humanization/`

## Phase 1: Human Titles + Context Lines

- [ ] T001 [US1] Add `humanTitle(detector, rawTitle, ip)` function in `index.html` — maps detector slug to human title using DETECTOR_LABELS, appends IP if available, strips technical detail
- [ ] T002 [US3] Add `contextLine(outcome, severity)` function in `index.html` — returns "so what?" text: blocked→"Handled automatically", open→"Needs review", ignored→"Classified as noise", monitored→"Being monitored", honeypot→"Redirected to honeypot"
- [ ] T003 [US1] [US3] Modify `renderEntry()` for `kind === 'incident'` in `index.html` — replace raw title with humanTitle output, add context line below

**Checkpoint**: Timeline shows human titles + context. Raw text still visible (will be collapsed in Phase 2).

## Phase 2: Collapsible Detail

- [ ] T004 [US2] Add CSS classes `.detail-toggle`, `.detail-body` in `index.html` — toggle button styling, body hidden by default
- [ ] T005 [US2] Modify `renderEntry()` for `kind === 'incident'` in `index.html` — wrap raw title + summary + tags in `.detail-body` with "Show details" toggle
- [ ] T006 [US2] Add `toggleDetail(btn)` JS function in `index.html` — toggle `.detail-body` visibility and button text

**Checkpoint**: Incidents show human title by default, raw forensic detail behind "Show details".

## Phase 3: Clean Text

- [ ] T007 [US4] Audit `esc()` function usage in `renderEntry()` in `index.html` — identify double-escaping paths where entities appear as visible text
- [ ] T008 [US4] Fix double-escaping — ensure esc() output used as innerHTML is not re-escaped

**Checkpoint**: Zero "&#" artifacts in visible text.

## Phase 4: Outcome-Aware Card Styling

- [ ] T009 [US5] Add CSS classes `.entry-contained`, `.entry-open`, `.entry-noise` in `index.html` — opacity, border-left color, padding differences
- [ ] T010 [US5] Apply outcome class in `renderEntry()` for `kind === 'incident'` in `index.html`

**Checkpoint**: Visual weight hierarchy — open incidents prominent, contained receded, noise faded.

## Verification

| US | Test |
|----|------|
| US1 | Browser: every incident in timeline has human title, no jargon |
| US2 | Browser: "Show details" toggles forensic text |
| US3 | Browser: every incident has gray context line |
| US4 | Browser: search for "&#" → zero results |
| US5 | Browser: blocked cards dimmer, open cards prominent |
