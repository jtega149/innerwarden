# Spec 022: Dashboard Test Coverage

**Created**: 2026-04-16
**Status**: DRAFT
**Priority**: P0 (dashboard has 9,709 lines of Rust + 5,160 lines of JS with 24 tests total — 0% coverage on 15 of 16 files)
**Depends on**: nothing

## Problem

The dashboard is the operator's primary interface. It has bugs in production:
- Module states showing wrong (Honeypot OFF when always_on, XDP ON when BPF not mounted)
- Button contrast unreadable (white on light blue)
- Data files showing "Absent" for SQLite-migrated data
- Graph tab unusable (removed)
- Baseline polluted with brute-force usernames
- Response lifecycle showing orphaned entries for invalid IPs

All of these were caught by the operator, not by tests. The dashboard has **24 tests in mod.rs** and **0 tests in the other 15 files** (9,709 lines total).

## Current state

| File | Lines | Tests | What it does |
|---|---|---|---|
| `mod.rs` | 1,634 | 24 | Router, TLS config, serve function |
| `investigation.rs` | 2,062 | 0 | Threat investigation journeys, timeline rendering |
| `agent_api.rs` | 732 | 0 | AI agent API (security-context, check-ip, check-command) |
| `data_api.rs` | 709 | 0 | Data export, incident queries, decision queries |
| `actions.rs` | 675 | 0 | Block IP, unblock, allowlist, honeypot actions |
| `live_feed.rs` | 652 | 0 | Real-time threat feed, SSE events |
| `intelligence.rs` | 572 | 0 | Intel tab: profiles, campaigns, chains, graph view |
| `types.rs` | 466 | 0 | Investigation types, phase classification, severity mapping |
| `auth.rs` | 452 | 0 | Session auth, Basic Auth, token management |
| `sensors.rs` | 432 | 0 | Health tab: status API, sensor collectors, data files |
| `helpers.rs` | 378 | 0 | HTML escaping, formatting, size display, truncation |
| `compliance.rs` | 330 | 0 | ISO 27001 controls, hash chain verification |
| `state.rs` | 247 | 0 | Dashboard state, action config, SSE connections |
| `sse.rs` | 151 | 0 | Server-Sent Events streaming |
| `push.rs` | 111 | 0 | Web Push notifications |
| `brain.rs` | 106 | 0 | Defender brain dashboard API |
| **Total** | **9,709** | **24** | |

## Approach

Dashboard code mixes HTTP handlers (need test harness) with pure logic (testable now). Strategy:

1. **Extract pure functions** from HTTP handlers (same pattern as spec 019)
2. **Test the logic**, not the HTTP layer
3. **Every file gets a `#[cfg(test)] mod tests`**

## Batches

Each batch is ONE AI session, ONE branch, ONE PR. All branch from `development`, PR target `development`.

### Batch 1 — Pure logic: types, helpers, state

**Branch**: `022-batch-1`
**Target**: ~30 tests

| File | Lines | What to test |
|---|---|---|
| `types.rs` | 466 | Phase classification from event kind (`classify_phase`). Severity to color/icon mapping. Investigation summary computation. Timeline entry construction. Status determination (observing/contained/blocked/needs_attention). |
| `helpers.rs` | 378 | HTML escaping (XSS prevention — CRITICAL). Size formatting (bytes → KB/MB/GB). Duration formatting. IP truncation. Percentage formatting. Timestamp formatting. |
| `state.rs` | 247 | `DashboardActionConfig` default values. SSE connection counter. Deep security snapshot construction. |

**Instructions for AI**:
1. `helpers.rs` is the highest priority — HTML escaping bugs = XSS vulnerabilities. Test every escape function with: `<script>`, `"quotes"`, `&amp;`, null bytes, Unicode.
2. `types.rs` classify_phase: test every event kind maps to correct phase (initial_access, execution, persistence, etc.)
3. Every test must verify a specific code path. No trivial tests.

### Batch 2 — Auth logic + compliance checks

**Branch**: `022-batch-2`
**Target**: ~25 tests

| File | Lines | What to test |
|---|---|---|
| `auth.rs` | 452 | Session creation/validation. Token generation (length, uniqueness). Session expiry check. Max sessions enforcement. Basic Auth header parsing. Login/logout flow logic. Session cleanup. |
| `compliance.rs` | 330 | ISO 27001 control mapping (12 controls → status). Hash chain verification logic (SHA-256 chain integrity). Data retention policy display. Admin actions audit trail. |

**Instructions for AI**:
1. `auth.rs` is security-critical. Test: expired tokens rejected, max sessions enforced, token format is correct length, Basic Auth header parsing handles malformed input.
2. `compliance.rs` hash chain: test that a broken chain is detected, that valid chains pass, that empty chains are handled.

### Batch 3 — Investigation journey logic

**Branch**: `022-batch-3`
**Target**: ~25 tests

| File | Lines | What to test |
|---|---|---|
| `investigation.rs` | 2,062 | Event phase classification. Timeline entry grouping (burst detection: "50 events" collapsed into one entry). Summary computation (incident count, decision count, honeypot session count). AI summary generation input. Status determination per IP. Investigation window calculation. |

**Instructions for AI**:
1. This is the largest file (2,062 lines). Focus on the pure classification and grouping logic.
2. Extract functions that compute summaries from data — these are testable without HTTP.
3. Test the burst detection: 50 similar events should collapse into "Brute-force burst (50 attempts)".
4. Test edge cases: IP with zero events, IP with only honeypot sessions, IP with decisions but no incidents.

### Batch 4 — Sensors/status logic + live feed

**Branch**: `022-batch-4`
**Target**: ~20 tests

| File | Lines | What to test |
|---|---|---|
| `sensors.rs` | 432 | Kill chain stats computation from graph nodes. File existence/size reporting. Mode determination (watch/guard/read_only). Graph stats computation (node counts by type). Collector status determination (ACTIVE/DETECTED/NOT_FOUND). |
| `live_feed.rs` | 652 | Threat feed entry construction. Severity-to-priority mapping. Feed deduplication logic. Feed sorting (most recent first). Max feed size enforcement. |

**Instructions for AI**:
1. `sensors.rs` was the source of multiple production bugs (XDP hardcoded ON, honeypot mode wrong, events.jsonl "Absent"). Test every status determination.
2. `live_feed.rs` dedup: test that the same IP appearing twice is deduplicated, that different IPs are kept separate.

### Batch 5 — Actions + agent API + intelligence

**Branch**: `022-batch-5`
**Target**: ~20 tests

| File | Lines | What to test |
|---|---|---|
| `actions.rs` | 675 | Block/unblock IP parameter validation. Allowlist add/remove logic. Action permission checks (responder enabled? dry_run?). |
| `agent_api.rs` | 732 | Security context computation (threat level from recent incidents). Check-IP response construction. Check-command integration with agent-guard. |
| `intelligence.rs` | 572 | Profile sorting (by risk score). Campaign detection display. Chain timeline construction. Baseline data formatting. Brain stats display. MITRE coverage computation. |

**Instructions for AI**:
1. `actions.rs`: test that block_ip rejects empty IP, rejects internal IP, rejects allowlisted IP.
2. `agent_api.rs`: test security-context threat level calculation (0 incidents = "calm", 1-5 = "elevated", 5+ = "high").
3. `intelligence.rs`: test that profile list is sorted by risk_score descending.

### Batch 6 — SSE, push, brain + remaining edge cases

**Branch**: `022-batch-6`
**Target**: ~15 tests

| File | Lines | What to test |
|---|---|---|
| `sse.rs` | 151 | SSE message formatting. Connection count tracking. |
| `push.rs` | 111 | Web Push subscription storage. VAPID key validation. |
| `brain.rs` | 106 | Brain stats JSON construction. Retrain status display. Agreement percentage calculation. |
| `data_api.rs` | 709 | Incident query parameter parsing (date range, severity filter, IP filter). Decision export format. Pagination logic. |

**Instructions for AI**:
1. Small files — focus on edge cases and error handling.
2. `data_api.rs` pagination: test page 0, page past end, negative page.

## Summary table

| Batch | Branch | Files | Target tests | Focus |
|---|---|---|---|---|
| 1 | `022-batch-1` | types, helpers, state | ~30 | Pure logic, HTML escaping |
| 2 | `022-batch-2` | auth, compliance | ~25 | Security, hash chains |
| 3 | `022-batch-3` | investigation | ~25 | Journey logic, burst detection |
| 4 | `022-batch-4` | sensors, live_feed | ~20 | Status bugs, dedup |
| 5 | `022-batch-5` | actions, agent_api, intelligence | ~20 | Validation, API contracts |
| 6 | `022-batch-6` | sse, push, brain, data_api | ~15 | Edge cases, formatting |
| **Total** | | **16 files** | **~135** | |

## Execution rules

1. **Branch from `development`**, PR target `development`.
2. **`cargo clippy --workspace -- -D warnings`** must pass.
3. **`cargo fmt`** before commit.
4. **Extract pure functions** from HTTP handlers — test the logic, not axum.
5. **No HTTP test harness** — that's a separate concern. Only test pure functions.
6. **HTML escaping tests are mandatory** — XSS in a security dashboard is unacceptable.
7. **Every test must have a comment** explaining what bug or code path it covers.
8. **Read existing 24 tests in mod.rs first** — don't duplicate.
9. **PR title**: `test(dashboard): batch N — description`

## Acceptance criteria

- [ ] All 16 dashboard files have `#[cfg(test)] mod tests`
- [ ] HTML escaping tested with XSS payloads
- [ ] Auth token validation tested (expiry, max sessions, malformed)
- [ ] Status determination tested for all module states (Honeypot always_on, XDP, Kill Chain)
- [ ] Investigation phase classification tested for all event kinds
- [ ] `make test` passes
- [ ] Coverage on dashboard goes from ~0% to ~30%+

## Bugs this would have caught

| Bug | File | Test that would catch it |
|---|---|---|
| Honeypot always_on shows OFF | sensors.rs | `test_honeypot_badge_always_on()` |
| XDP hardcoded ON | sensors.rs | `test_xdp_status_without_ebpf()` |
| Button contrast #fff on #78e5ff | (JS — not testable in Rust) | — |
| events.jsonl "Absent" | sensors.rs | `test_events_file_sqlite_migration()` |
| Kill Chain OFF without detections | sensors.rs | `test_killchain_on_with_tracker()` |
| Baseline brute-force pollution | (baseline.rs, not dashboard) | — |
| Invalid IPs reaching ufw | (decision_block_ip.rs) | — |
