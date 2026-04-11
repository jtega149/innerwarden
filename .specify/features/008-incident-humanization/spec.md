# Feature Specification: Incident Humanization Layer

**Feature Branch**: `008-incident-humanization`
**Created**: 2026-04-10
**Status**: Planned
**Input**: Dashboard shows raw sensor text like "Malformed SSH version string: SSH client from 190.0.63.226 sent malformed version: &#39;?&#39;. This may indicate a custom exploit tool or protocol fuzzer." — user stops, reads, doesn't understand, asks "is this normal?". Dashboard failed.

## Origin

The InnerWarden confidence system (007) fixed colors, aggregation, and language at the navigation level. But when a user clicks into a specific threat, they see raw forensic text from the sensor. The sensor writes for incident response analysts. The dashboard serves sysadmins and non-security users. There's no translation layer between the two.

Real example from production (2026-04-10):
- Raw: `[HIGH] Malformed SSH version string: SSH client from 190.0.63.226 sent malformed version: &#39;?&#39;. This may indicate a custom exploit tool or protocol fuzzer.`
- User reaction: "What is &#39;? Is this normal? Should I do something?"
- What they should see: "Suspicious connection — bot probing SSH port (no action needed)"

## Problem

1. **Incident titles are forensic jargon**: "Malformed SSH version string", "Threat intel match: IP in malicious feed", "Host drift: unknown executed from non-standard path". Non-security users don't know what action to take.
2. **Incident summaries are verbose**: Full technical detail shown inline. Evidence strings, field names, feed names, event kinds — all visible. The detail is valuable but shouldn't be the first thing you see.
3. **HTML entities leak into display**: `&#39;` instead of `'` because the `esc()` function sanitizes for XSS but the result is shown as text. User sees encoding artifacts.
4. **No "so what?" answer**: The most important question — "is this normal?" or "do I need to do something?" — is never answered. The user has to infer from severity + outcome + technical knowledge.
5. **Every incident looks equally important**: A blocked bot scan and an active reverse shell both render as full-height cards with identical layout.
6. **The journey timeline is a forensic tool**: Chapters, verdicts, raw JSON — useful for IR analysts, overwhelming for daily operations.

## Goals

- User clicks a threat → immediately understands: what happened, is it handled, do I need to act.
- Technical detail available but hidden behind "Show details".
- Plain language titles that answer "so what?".
- Outcome-aware presentation: contained incidents are visually calmer than active threats.
- Zero HTML entity artifacts in visible text.

---

## User Scenarios & Testing

### User Story 1 — Human Incident Titles (Priority: P1)

Every incident rendered in the journey timeline gets a human-readable title that answers "what happened + what was the result" instead of raw detector output.

**Why this priority**: The title is the first (and often only) thing the user reads. If it's clear, the user doesn't need to read anything else.

**Independent Test**: Open any threat in the Investigate view. Every incident card in the timeline should have a plain-language title. No technical jargon in the primary title line.

**Acceptance Scenarios**:

1. **Given** incident with detector=proto_anomaly and title="Malformed SSH version string", **When** rendered in journey timeline, **Then** shows "Suspicious SSH connection — bot/scanner probe" as the primary title.
2. **Given** incident with detector=threat_intel and title containing "IP in malicious feed", **When** rendered, **Then** shows "Known malicious IP detected" as the primary title.
3. **Given** incident with detector=host_drift, **When** rendered, **Then** shows "Unexpected process executed".
4. **Given** incident with detector=ssh_bruteforce, **When** rendered, **Then** shows "SSH login attempts".
5. **Given** incident with detector=dns_c2, **When** rendered, **Then** shows "DNS command-and-control activity".
6. **Given** unknown detector slug, **When** rendered, **Then** shows humanized slug (underscores → spaces, capitalized).

---

### User Story 2 — Collapsible Technical Detail (Priority: P1)

Raw sensor text (title, summary, evidence) is hidden behind a "Show details" toggle. The user sees the human title + outcome by default. Clicking "Show details" reveals the full forensic text.

**Why this priority**: Removes visual noise without losing information. IR analysts can still access everything.

**Independent Test**: Open a threat journey. Each incident card shows 2 lines max by default. Click "Show details" → full raw text expands. Click again → collapses.

**Acceptance Scenarios**:

1. **Given** incident card in timeline, **When** rendered, **Then** shows: human title + outcome badge + timestamp. No raw summary visible.
2. **Given** incident card, **When** user clicks "Show details", **Then** raw title, summary, evidence, and tags expand below.
3. **Given** expanded incident card, **When** user clicks "Hide details", **Then** collapses back to 2-line summary.
4. **Given** multiple incident cards, **When** one is expanded, **Then** others remain collapsed (independent toggle).

---

### User Story 3 — "So What?" Context Line (Priority: P2)

Each incident card includes a one-line contextual explanation answering "is this normal?" and "do I need to act?".

**Why this priority**: The single most important piece of information for a non-security user. Without it, they ask someone else (wasting time) or ignore it (missing real threats).

**Independent Test**: Every incident card in the timeline has a gray context line below the title. Contained incidents say "Handled automatically — no action needed". Active incidents say "Needs review — [reason]".

**Acceptance Scenarios**:

1. **Given** incident with outcome=blocked, **When** rendered, **Then** context line says "Handled automatically — no action needed" in muted color.
2. **Given** incident with outcome=ignored, **When** rendered, **Then** context line says "Classified as noise — no action needed".
3. **Given** incident with outcome=open and severity=high, **When** rendered, **Then** context line says "Needs review — no automated response taken" in warning color.
4. **Given** incident with outcome=monitored, **When** rendered, **Then** context line says "Being monitored — system is watching for escalation".
5. **Given** incident with outcome=honeypot, **When** rendered, **Then** context line says "Redirected to honeypot — attacker contained safely".

---

### User Story 4 — Clean Text Rendering (Priority: P1)

No HTML entities (&#39;, &amp;, &#x27;, etc.) visible in any user-facing text. The esc() function's output should be rendered as HTML, not double-escaped.

**Why this priority**: Visual polish. HTML artifacts make the product feel broken/unfinished.

**Independent Test**: Search the rendered dashboard for "&#" — zero results in any visible text.

**Acceptance Scenarios**:

1. **Given** incident title containing single quotes, **When** rendered, **Then** shows actual quote characters, not &#39;.
2. **Given** incident summary with angle brackets, **When** rendered, **Then** brackets are properly escaped for XSS safety but not double-escaped for display.
3. **Given** Raw JSON view, **When** expanded, **Then** raw data shown as-is (no entity substitution needed — it's code).

---

### User Story 5 — Outcome-Aware Card Weight (Priority: P3)

Contained incidents render as compact, calm cards. Active/open incidents render as prominent, attention-grabbing cards.

**Why this priority**: Visual hierarchy. The user's eye should be drawn to what needs action, not to what's already handled.

**Independent Test**: Mix of blocked and open incidents in timeline. Open incidents visually stand out. Blocked incidents are visually receded.

**Acceptance Scenarios**:

1. **Given** incident with outcome=blocked in timeline, **When** rendered, **Then** card has reduced opacity (0.7), compact padding, green left border.
2. **Given** incident with outcome=open in timeline, **When** rendered, **Then** card has full opacity, normal padding, red/amber left border.
3. **Given** incident with outcome=ignored in timeline, **When** rendered, **Then** card has low opacity (0.5), minimal padding.

---

## Scope

**Files to modify:**
- `crates/agent/src/dashboard/frontend/html/index.html` — journey timeline rendering (renderEntry function area), esc() function behavior
- No Rust backend changes needed — all data is already available, just needs frontend presentation layer

**What does NOT change:**
- Raw JSON export (stays full forensic detail)
- API responses (no changes)
- Sensor-side incident generation
- Other views (Home, Sensors, Report, etc.) — they already use DETECTOR_LABELS from 007

## Verification

1. `cargo check --package innerwarden-agent` — compiles
2. Browser: open Investigate → click any threat → timeline shows human titles
3. Browser: click "Show details" on an incident card → raw text expands
4. Browser: search page for "&#" → zero visible HTML entities
5. Browser: mix of blocked/open incidents → visual weight difference clear
