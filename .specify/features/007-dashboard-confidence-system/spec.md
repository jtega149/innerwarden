# Feature Specification: Dashboard Confidence System

**Feature Branch**: `007-dashboard-confidence-system`
**Created**: 2026-04-10
**Status**: Planned
**Input**: Production dashboard shows 23 blocked SSH attempts as "Active Defense — 23 threats" in red. Sysadmin panics. But the system already handled everything. Dashboard creates fear instead of confidence.

## Origin

Production server is working correctly — blocking attacks, filtering noise, auto-responding. But the dashboard UI makes it look like the server is under siege:
- "Active Defense — 23 threats" in RED when all 23 are blocked
- BLOCKED badges in RED (blocked = success, should be green)
- Raw incident lists showing 50 identical "Host drift" rows instead of "50 events (all contained)"
- Technical jargon: "Ring -2", "Chain integrity BROKEN", "credential_stuffing attack"
- Every view uses red/danger colors for handled situations
- Non-security users see the dashboard and think the server is compromised

## Problem

1. **Color system is fear-based**: RED for blocked threats. RED for zero threats. RED for handled situations. Red should mean "you need to act NOW".
2. **Language is alarming**: "Active Defense", "BLOCKED", "Chain integrity BROKEN", "possible tampering" — when the system is working perfectly.
3. **No noise aggregation**: 50 identical SSH brute force incidents = 50 separate rows. Should be 1 row: "SSH login attempts — 50 events (all contained)".
4. **No distinction between unresolved vs handled**: The core metric is `ai_confirmed` (total threats), not `unresolved` (threats needing action). A dashboard with 100 blocked threats and 0 unresolved should feel GREEN, not RED.
5. **All views affected**: Sensors, Report, Status, Compliance, Intel, Monthly, Responses — each has color, language, or structural problems.
6. **Backend doesn't expose unresolved count**: Frontend must compute it from `ai_confirmed - ai_responded`, lossy and fragile.
7. **Severity is static**: A "critical" SSH brute force that was auto-blocked still shows as CRITICAL. Effective severity should downgrade for handled incidents.

## Goals

- User opens dashboard → instantly knows: "Am I safe? Is anything serious happening?"
- GREEN is default. System blocking attacks = success = green.
- RED only for unresolved, confirmed threats that need human action.
- Aggregate noise into digestible summaries.
- Humanize language across all views.
- Backend provides proper `unresolved_count` and `effective_severity`.
- Every view updated — no "unchanged" views.

---

## User Scenarios & Testing

### User Story 1 — Confidence Hero Banner (Priority: P1)

The Home and Investigate status banners should communicate confidence, not fear. When all threats are handled, the banner is GREEN with reassuring language. RED only when something truly needs action.

**Why this priority**: First thing the user sees. Highest psychological impact. Drives the entire UX perception.

**Independent Test**: With 23 ai_confirmed and 23 ai_responded on production, Home banner shows GREEN "All Threats Contained". With 23 confirmed and 20 responded, shows RED "Action Required — 3 unresolved threats".

**Acceptance Scenarios**:

1. **Given** 23 confirmed threats and 23 auto-responded, **When** dashboard loads, **Then** Home banner shows GREEN "All Threats Contained" with shield icon.
2. **Given** 23 confirmed and 20 responded (3 unresolved), **When** dashboard loads, **Then** Home banner shows RED "Action Required — 3 unresolved threats".
3. **Given** 0 confirmed threats, **When** dashboard loads, **Then** Home banner shows GREEN "All Clear" with checkmark.
4. **Given** banner shows "All Threats Contained", **When** SSE refresh fires, **Then** banner updates live without page reload.
5. **Given** Investigate view open, **When** same data (23/23), **Then** right panel hero also shows GREEN, consistent with Home.

---

### User Story 2 — Backend Unresolved Count (Priority: P1)

The `/api/overview` endpoint should return `unresolved_count`, `safely_resolved`, and `severity_breakdown` so the frontend has authoritative data.

**Why this priority**: Foundation for all frontend status decisions. Without this, frontend guesses from `ai_confirmed - ai_responded` which is lossy.

**Independent Test**: Hit `/api/overview` on production, verify response includes `unresolved_count` field. Cross-check: unresolved_count + safely_resolved + ai_ignored ≈ incidents_count.

**Acceptance Scenarios**:

1. **Given** 23 incidents (20 blocked, 2 ignored, 1 open), **When** `/api/overview` called, **Then** response includes `unresolved_count: 1`, `safely_resolved: 20`.
2. **Given** all incidents blocked, **When** `/api/overview` called, **Then** `unresolved_count: 0`.
3. **Given** `severity_breakdown` field, **When** 5 critical + 10 high + 8 medium, **Then** response shows `{ "critical": 5, "high": 10, "medium": 8 }`.
4. **Given** no incidents today, **When** `/api/overview` called, **Then** `unresolved_count: 0`, `safely_resolved: 0`.

---

### User Story 3 — Effective Severity (Priority: P2)

Incidents that are auto-blocked should have downgraded `effective_severity`. SSH brute force marked "critical" but auto-blocked → effective severity "medium". This affects colors across all views.

**Why this priority**: Without this, every blocked attempt screams CRITICAL in red even though it's handled. Affects attacker cards, journey timeline, report KPIs.

**Independent Test**: Hit `/api/incidents`, verify each incident has `effective_severity` field. Blocked critical → effective "medium". Open critical → effective "critical".

**Acceptance Scenarios**:

1. **Given** incident with severity=critical and outcome=blocked, **When** `/api/incidents` called, **Then** `effective_severity: "medium"`.
2. **Given** incident with severity=critical and outcome=open, **When** `/api/incidents` called, **Then** `effective_severity: "critical"` (unchanged).
3. **Given** incident with outcome=ignored, **When** `/api/incidents` called, **Then** `effective_severity: "info"`.
4. **Given** incident with severity=high and outcome=monitored, **When** `/api/incidents` called, **Then** `effective_severity: "low"`.

---

### User Story 4 — BLOCKED → CONTAINED (Priority: P1)

All "BLOCKED" badges and labels become "CONTAINED" in GREEN. Blocked = the system worked = success. This applies to Home feed, Investigate feed, attacker cards, journey timeline, responses view.

**Why this priority**: Direct visual fix, high impact, touches every view. Blocked being red is the single biggest UX problem.

**Independent Test**: Open any view showing blocked incidents. All should say "CONTAINED" in green, never "BLOCKED" in red.

**Acceptance Scenarios**:

1. **Given** Home activity feed with blocked incidents, **When** page loads, **Then** badge shows "CONTAINED" with green background and green text.
2. **Given** Investigate activity feed with blocked incidents, **When** feed renders, **Then** same green "CONTAINED" badge.
3. **Given** attacker card with outcome=blocked, **When** card renders, **Then** badge shows green "CONTAINED", not red "BLOCKED".
4. **Given** journey timeline decision entry, **When** action=block_ip, **Then** narrative says "Threat **contained**" in green.
5. **Given** Responses view active table, **When** block is active, **Then** table context is neutral/green, not alarming red.

---

### User Story 5 — Feed Aggregation (Priority: P2)

Activity feeds (Home + Investigate) should aggregate identical incidents. 50 SSH brute force attempts from different IPs all blocked → 1 row: "SSH login attempts — 50 events (all contained)". Unresolved events appear individually at top.

**Why this priority**: Eliminates visual spam. The feed currently shows 50 identical alarming rows.

**Independent Test**: With 50 SSH bruteforce blocked incidents and 1 open port_scan, feed shows 2 rows: port_scan first (full opacity, red), SSH group second (green contained, count badge).

**Acceptance Scenarios**:

1. **Given** 50 ssh_bruteforce incidents all blocked, **When** Home feed renders, **Then** shows 1 aggregated row "SSH login attempts — 50 events" + green "CONTAINED" badge + "50x" count badge.
2. **Given** 1 open port_scan + 50 blocked ssh, **When** feed renders, **Then** port_scan row appears FIRST (unresolved), SSH group row below.
3. **Given** 3 open critical incidents, **When** feed renders, **Then** each open incident shown individually (not aggregated — each needs attention).
4. **Given** aggregated row clicked, **When** user clicks, **Then** navigates to Investigate view filtered by that detector.

---

### User Story 6 — Humanized Labels (Priority: P2)

Replace technical detector names with human-readable labels across all views. "credential_stuffing" → "Credential testing". "host_drift" → "Unexpected process". Single canonical map used everywhere.

**Why this priority**: Non-security users don't understand "execution_guard" or "user_agent_scanner".

**Independent Test**: Open Home feed, Investigate feed, Report. All detector references use human labels.

**Acceptance Scenarios**:

1. **Given** incident with detector=ssh_bruteforce, **When** rendered in any feed, **Then** shows "SSH login attempts".
2. **Given** incident with detector=host_drift, **When** rendered, **Then** shows "Unexpected process".
3. **Given** unknown detector slug, **When** rendered, **Then** fallback: replace underscores with spaces, capitalize first letter.

---

### User Story 7 — KPI Color System (Priority: P1)

KPI cards across Home and Investigate views should use contextual colors, not hardcoded red. Threats = 0 → accent. Threats = 23 but all handled → green. Threats with unresolved → red.

**Why this priority**: "0" in red feels wrong. "23" in red when all handled feels alarming.

**Independent Test**: Home view with 0 threats → accent "0". Home with 23 handled → green "23". Home with 3 unresolved → red "3".

**Acceptance Scenarios**:

1. **Given** 0 confirmed threats, **When** Home KPI renders, **Then** "Threats Detected" value "0" in accent color (cyan).
2. **Given** 23 confirmed + 23 responded, **When** Home KPI renders, **Then** value "23" in green.
3. **Given** 23 confirmed + 20 responded, **When** Home KPI renders, **Then** value "3" (unresolved count) in red.
4. **Given** Investigate KPI strip, **When** same data, **Then** consistent colors with Home.

---

### User Story 8 — Threat Gauge Fix (Priority: P2)

Sensors view threat gauge currently shows CRITICAL at ≥20 ai_confirmed (including blocked). Must use unresolved count only.

**Why this priority**: Misleading gauge drives wrong perception on Sensors tab.

**Independent Test**: 20 blocked threats + 0 unresolved → gauge shows NOMINAL (green). 5 unresolved → ELEVATED (amber).

**Acceptance Scenarios**:

1. **Given** 20 confirmed + 20 responded (0 unresolved), **When** Sensors view loads, **Then** gauge shows NOMINAL in green.
2. **Given** 5 unresolved threats, **When** gauge renders, **Then** shows ELEVATED in amber.
3. **Given** 10+ unresolved, **When** gauge renders, **Then** shows CRITICAL in red.
4. **Given** gauge title, **Then** reads "Unresolved Threats" not "Threat Level".

---

### User Story 9 — Attacker Card Polish (Priority: P3)

Attacker cards in Investigate left panel should visually distinguish handled vs active threats. Pulse dot: green/static for contained, red/pulsing only for unresolved. Severity badge: dimmed for handled.

**Why this priority**: Visual noise reduction on the most-used investigation view.

**Independent Test**: Card for fully-blocked IP shows green static dot + dimmed severity. Card for open incident shows red pulsing dot + full severity.

**Acceptance Scenarios**:

1. **Given** attacker card with outcome=blocked and recent activity, **When** card renders, **Then** dot is green and static (no pulse animation).
2. **Given** attacker card with outcome=open and recent activity, **When** card renders, **Then** dot is red and pulsing.
3. **Given** attacker card with outcome=blocked and severity=critical, **When** card renders, **Then** severity text "CRITICAL" shown at 50% opacity.

---

### User Story 10 — All-Views Language & Color Fix (Priority: P2)

Every dashboard view gets language and color corrections:
- **Status**: "Ring -2" → "Firmware Layer", "Ring -1" → "Hypervisor Layer". OFF badges gray not red.
- **Compliance**: "BROKEN - possible tampering" → "Verification failed — review recent changes". ISO controls show full name.
- **Report**: "High/Critical (6h)" → "High-Risk Alerts (6h)". Trend context added.
- **Intel**: Pattern labels humanized: "regular_scanner" → "Regular Scanner". "Visit Count" → "Days Active".
- **Monthly**: Campaign correlation_type: "dna" → "Behavioral Pattern". "Week W##" → "Week of [date]".
- **Responses**: Backend tooltips for XDP/iptables/UFW. Tables wrapped for mobile scroll.
- **Sensors**: "available but idle" → "Ready — not collecting". Incidents card: green for 0, context when all handled.
- **Honeypot**: IOC colors use CSS variables not hardcoded hex.

**Why this priority**: Consistency across all views. Each fix is small but cumulative effect is large.

**Independent Test**: Open each of the 10 views, verify no "Ring -2", no red "OFF" badges, no "BROKEN - tampering", no "regular_scanner", no hardcoded IOC hex colors.

**Acceptance Scenarios**:

1. **Given** Status view with firmware data, **When** rendered, **Then** shows "Firmware Layer" not "Ring -2".
2. **Given** Compliance view with intact chain, **When** rendered, **Then** shows "Chain integrity verified".
3. **Given** Compliance view with broken chain, **When** rendered, **Then** shows "Verification failed — review recent changes" in amber (not red).
4. **Given** integration card with enabled=false, **When** rendered, **Then** OFF badge is gray/muted, not red.
5. **Given** Report view, **When** rendered, **Then** KPI label says "High-Risk Alerts (6h)" not "High/Critical (6h)".
6. **Given** Intel profile with pattern_class=regular_scanner, **When** rendered, **Then** shows "Regular Scanner".
7. **Given** Monthly campaign with correlation_type=dna, **When** rendered, **Then** shows "Behavioral Pattern".
8. **Given** Responses table, **When** hovering backend badge "xdp", **Then** tooltip shows "Kernel-level firewall (fastest)".
9. **Given** all tables on mobile viewport, **When** narrowed to 400px, **Then** tables scroll horizontally without breaking layout.

---

### User Story 11 — Empty States (Priority: P3)

All views have consistent, informative empty states with icon, title, and explanation.

**Why this priority**: Polish. Prevents confusion when data hasn't arrived yet.

**Independent Test**: Fresh install with no data — every view shows meaningful empty message, never blank screen.

**Acceptance Scenarios**:

1. **Given** Home feed with 0 incidents, **When** rendered, **Then** shows "No security events today — all systems nominal" in green.
2. **Given** any view with no data, **When** rendered, **Then** shows icon + title + explanation (never just "Loading..." forever).

---

### User Story 12 — SSE Toast Redesign (Priority: P3)

Real-time toast notifications use outcome-aware colors. Contained = green toast. Unresolved = red toast.

**Why this priority**: Consistent with confidence system. Currently all alert toasts feel alarming.

**Independent Test**: Trigger a block event via SSE → green toast "Threat contained: [IP] blocked". Trigger open critical → red toast "New threat: [detector] from [IP]".

**Acceptance Scenarios**:

1. **Given** SSE alert event with outcome=blocked, **When** toast renders, **Then** green border + text "Threat contained".
2. **Given** SSE alert event with outcome=open severity=critical, **When** toast renders, **Then** red border + text "New threat detected".
