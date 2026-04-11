# Tasks: Dashboard Confidence System

**Input**: Design documents from `.specify/features/007-dashboard-confidence-system/`
**Prerequisites**: plan.md (required), spec.md (required for user stories)

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story (US1–US12)
- Exact file paths included

---

## Phase 1: Backend (Rust)

**Purpose**: API enrichment — add unresolved count, effective severity, compliance language fix.

- [ ] T001 [P] [US2] Add `unresolved_count`, `safely_resolved`, `severity_breakdown` fields to OverviewResponse in `crates/agent/src/dashboard/data_api.rs` — compute from existing incident node loop (lines 46-68)
- [ ] T002 [P] [US3] Add `effective_severity` and `confidence` fields to IncidentView in `crates/agent/src/dashboard/data_api.rs` — downgrade logic: blocked critical→medium, blocked high→low, ignored→info, open→unchanged
- [ ] T003 [P] [US10] Soften hash chain language in `crates/agent/src/dashboard/compliance.rs` — "BROKEN - possible tampering" → "Verification failed — review recent changes"
- [ ] T004 [P] [US12] Add `outcome` field to LiveFeedItem in `crates/agent/src/dashboard/live_feed.rs` — map from decision field same as IncidentView

**Checkpoint**: `cargo test -p innerwarden-agent` passes. `/api/overview` returns `unresolved_count`. `/api/incidents` returns `effective_severity`.

---

## Phase 2: CSS + JS Helpers (Frontend)

**Purpose**: Foundation classes and utility functions that all view phases depend on.

- [ ] T005 [P] [US4] Add semantic CSS classes to `index.html` — `.outcome-contained`, `.badge-contained` (green), `.badge-unresolved` (red), `.badge-monitoring` (cyan), `.badge-noise` (dim), `.pulse-dot.contained` (green static)
- [ ] T006 [P] [US7] Remove hardcoded `style="color:#e74c3c"` from `homeKpiThreats` (line ~1450) and `kpi-confirmed` (line ~1575) in `index.html`
- [ ] T007 [P] [US10] Add `.responsive-table` CSS class for mobile horizontal scroll in `index.html`
- [ ] T008 [US1] Add `getUnresolved()` JS helper function in `index.html` — reads `window._lastOverview`, returns `{ total, unresolved, handled }`
- [ ] T009 [US6] Add `DETECTOR_LABELS` global map in `index.html` — single canonical map replacing duplicate locals in buildHomeFeed/buildActivityFeed
- [ ] T010 [US5] Add `aggregateIncidents()` JS helper function in `index.html` — groups by detector+outcome, sorts open first

**Checkpoint**: CSS classes available. Helpers callable. No visual changes yet.

---

## Phase 3: Home View (Frontend)

**Purpose**: Confidence-first Home view — banner, KPIs, aggregated feed.

- [ ] T011 [US1] Rewrite `updateHomeBanner()` in `index.html` — unresolved > 0 → DANGER "Action Required", else → SAFE "All Threats Contained" or "All Clear"
- [ ] T012 [US7] Rewrite `updateHomeKpis()` in `index.html` — rename "Active Threats" → "Threats Detected", contextual colors (red only if unresolved, green if handled, accent if zero)
- [ ] T013 [US5] [US4] [US6] Rewrite `buildHomeFeed()` in `index.html` — use aggregateIncidents(), DETECTOR_LABELS, green CONTAINED badges, sort open first
- [ ] T014 [US11] Update Home feed empty state in `index.html` — "No security events today — all systems nominal" in green

**Checkpoint**: Home view shows green when all threats handled. Feed aggregated. Labels humanized. Deploy and verify on production.

---

## Phase 4: Investigate View (Frontend)

**Purpose**: Consistent confidence UX in the main investigation view.

- [ ] T015 [US1] Rewrite `updateStatusHero()` in `index.html` — same unresolved logic as Home banner
- [ ] T016 [US5] [US4] [US6] Rewrite `buildActivityFeed()` in `index.html` — aggregation + green CONTAINED + humanized labels (same treatment as Home feed)
- [ ] T017 [US7] Update KPI strip colors in `refreshLeftLive()` in `index.html` — `kpi-confirmed` color dynamic based on unresolved
- [ ] T018 [US9] Fix attacker card pulse dot in `renderCard()` in `index.html` — green static for blocked, red pulse only for open
- [ ] T019 [US9] Fix attacker card severity badge in `renderCard()` in `index.html` — dim (opacity 0.5) when outcome is blocked/contained
- [ ] T020 [US4] Fix attacker card outcome badge in `renderCard()` in `index.html` — BLOCKED → CONTAINED in green

**Checkpoint**: Investigate view consistent with Home. Cards visually distinguish handled vs active. Deploy and verify.

---

## Phase 5: Sensors View (Frontend)

**Purpose**: Fix misleading threat gauge and incident card.

- [ ] T021 [US8] Rewrite `drawThreatGauge()` in `index.html` — use unresolved count instead of ai_confirmed total. Thresholds: 0=NOMINAL, 1+=GUARDED, 5+=ELEVATED, 10+=CRITICAL
- [ ] T022 [US8] Update gauge title in `index.html` — "Threat Level" → "Unresolved Threats"
- [ ] T023 [US10] Fix Incidents HUD card in `loadSensors()` in `index.html` — when all resolved, show GREEN with "(all handled)" context
- [ ] T024 [US10] Update idle source label in `loadSensors()` in `index.html` — "available but idle" → "Ready — not collecting"

**Checkpoint**: Gauge shows NOMINAL when all threats handled. Incidents card context-aware.

---

## Phase 6: All Other Views (Frontend)

**Purpose**: Language, color, and structure fixes across remaining 7 views.

### Status/Health View
- [ ] T025 [US10] Fix deep security labels in `loadStatus()` in `index.html` — "Ring -2" → "Firmware Layer", "Ring -1" → "Hypervisor Layer" with tooltips
- [ ] T026 [US10] Fix integration OFF badge in `loadStatus()` in `index.html` — RED → gray/muted (OFF is a config choice, not an error)
- [ ] T027 [US10] Fix kill chain display in `loadStatus()` in `index.html` — add "(all contained)" context when all blocked

### Compliance View
- [ ] T028 [US10] Fix ISO 27001 "not met" label in `loadCompliance()` in `index.html` — "Not met" → "Action needed" in amber
- [ ] T029 [US10] Add full control names to ISO items in `loadCompliance()` in `index.html` — not just "A.5.1"

### Report View
- [ ] T030 [US10] Fix KPI label in `renderReport()` in `index.html` — "High/Critical (6h)" → "High-Risk Alerts (6h)"
- [ ] T031 [US10] Add trend context in `renderReport()` in `index.html` — "22% more events than yesterday"

### Intel View
- [ ] T032 [US10] Humanize pattern class labels in `loadIntel()` in `index.html` — "regular_scanner" → "Regular Scanner", "targeted" → "Targeted Attack"
- [ ] T033 [US10] Fix "Visit Count" label in `showProfileDetail()` in `index.html` — → "Days Active"
- [ ] T034 [US10] Add risk score tooltip in `loadIntel()` in `index.html` — "0-40: Low, 40-70: Moderate, 70+: High"

### Monthly View
- [ ] T035 [US10] Humanize campaign correlation_type in `loadMonthly()` in `index.html` — "dna" → "Behavioral Pattern", "ioc" → "Shared Indicators"
- [ ] T036 [US10] Fix week label in `loadMonthly()` in `index.html` — "Week W##" → "Week of [date]"

### Responses View
- [ ] T037 [US10] Add backend tooltips in `loadResponses()` in `index.html` — "XDP = Kernel-level firewall", "UFW = Ubuntu firewall", etc.
- [ ] T038 [US10] Wrap tables in `.responsive-table` in `index.html` — Intel, Responses, Monthly, Report tables

### Honeypot View
- [ ] T039 [US10] Fix IOC colors in `renderHoneypot()` in `index.html` — replace hardcoded `#fcd34d` with `var(--warn)`

**Checkpoint**: Every view updated. No "Ring -2", no red OFF badges, no "BROKEN - tampering". All tables mobile-scrollable.

---

## Phase 7: SSE + Empty States + Polish (Frontend)

**Purpose**: Real-time notifications and consistency polish.

- [ ] T040 [US12] Fix toast notification colors in SSE handler in `index.html` — green border for contained events, red border for unresolved
- [ ] T041 [US11] Standardize empty states across all views in `index.html` — consistent icon + title + explanation pattern
- [ ] T042 [US4] Update `outcomeLabel()` function in `index.html` — `blocked` → "CONTAINED"

**Checkpoint**: Complete UX overhaul. All 12 user stories satisfied. Deploy to production and run full browser verification.

---

## Verification Matrix

| US | Description | Test Command / Action |
|----|-------------|----------------------|
| US1 | Confidence hero banner | Browser: Home + Investigate banners green when all handled |
| US2 | Backend unresolved count | `curl /api/overview \| jq .unresolved_count` |
| US3 | Effective severity | `curl /api/incidents \| jq '.[0].effective_severity'` |
| US4 | BLOCKED → CONTAINED | Browser: all feeds show green "CONTAINED" |
| US5 | Feed aggregation | Browser: 50 same-detector incidents → 1 aggregated row |
| US6 | Humanized labels | Browser: no "ssh_bruteforce", shows "SSH login attempts" |
| US7 | KPI color system | Browser: 0=accent, handled=green, unresolved=red |
| US8 | Threat gauge | Browser: Sensors gauge NOMINAL when all handled |
| US9 | Attacker card polish | Browser: green dot for contained, red pulse for open |
| US10 | All-views fix | Browser: each of 10 views, verify language + colors |
| US11 | Empty states | Browser: fresh state, every view shows meaningful message |
| US12 | SSE toasts | Trigger event, verify toast color matches outcome |
