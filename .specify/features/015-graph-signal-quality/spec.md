# Feature Specification: Knowledge Graph Signal Quality

**Feature Branch**: `015-graph-signal-quality`
**Created**: 2026-04-11
**Status**: Draft — execution scheduled for a follow-up session
**Priority**: P0 (blocks operator UX quality AND AI research data quality)
**Depends on**: nothing (independent from spec 017 Phase 1 work)

## Origin

While validating spec 017 Phase 1 (01-home) on production on 2026-04-11, the new calm Home layout landed correctly — but Recent Activity was dominated by 13+ "Graph User Creation" items, all labeled ACTIVE, all at high severity. The operator UX was broken by noise, not by the UX design.

Investigation into that noise revealed a systemic data-quality problem in the knowledge graph that is far more consequential than a single noisy detector. This spec captures the finding and defines the scope of the cleanup.

## Product principle

**Every node in the knowledge graph must earn its place by being useful for operator experience OR AI research and training. Noise that is useful for neither is waste — it inflates memory, dilutes training data, and destroys the dashboard experience.**

This is a hard rule, not a style preference. A detector that produces high-volume false positives is worse than a detector that produces nothing: the false positives pollute correlation chains, feed wrong signals to the neural model, consume memory, and erode trust in the UI.

## Investigation findings (2026-04-11, prod snapshot)

Data from `/var/lib/innerwarden/graph-snapshot-2026-04-11.json` on the production server:

### Incident node distribution

| Slug | Count | Share | Assessment |
|---|---|---|---|
| `kill_chain` (forming, medium) | 21,814 | 77.8% | Noise for operator; **useful for research** — near-miss LSM patterns feed AI training. Keep, already hidden in Home by spec 017 rules. |
| **`graph_user_creation`** | **3,954** | **14.1%** | **LIXO** — 100% false positives (see Bug 1 below). Delete detector, delete existing nodes, restructure ingestion. |
| `cross_layer_chain` | 760 | 2.7% | Legitimate correlation. Keep. |
| `proto_anomaly` | 591 | 2.1% | Legitimate. Keep. |
| `host_drift` | 316 | 1.1% | Legitimate (some FPs from agent's own binaries — acceptable). Keep. |
| `rootkit`, `dns_c2`, `kernel_module`, `sandbox_evasion`, `discovery_burst`, `graph_network_sniffing`, `graph_host_drift`, `graph_correlation`, `graph_discovery_burst` | <150 each | <3% total | Mostly legitimate. Subject to audit in this spec. |

**Total Incident nodes**: 28,050. **Node types total in graph**: ~29,566.

### The `graph_user_creation` victims (top 20 "users" triggering the detector)

| User | Count | What it actually is |
|---|---|---|
| `uid` | 156 | **Parser bug** — an ingestion path creates a User node with literal name `"uid"` (probably parsing strings like `uid:1001` wrong) |
| `admin`, `admin2`, `admian`, `AdminGPON`, `adminuser` | 23 each | SSH brute-force login attempt usernames |
| `ali`, `amir`, `ansible`, `anton`, `aidan`, `analisa` | 23 each | SSH brute-force attempts |
| `azureuser`, `bakuser`, `banxgg`, `belkinstyle`, `blockchain`, `bmuuser`, `bot` | 23 each | SSH brute-force attempts |

**Zero legitimate user creations**. 100% of the 3,954 incidents are false positives.

## Root causes

Three compounding bugs produce the 3,954 false-positive graph_user_creation incidents:

### Bug 1 — `detect_user_creation` detects presence, not creation

Location: `crates/agent/src/knowledge_graph/detectors.rs:2282` (function `detect_user_creation`).

Logic: on every detector tick (30s), iterate all `User` nodes in the graph, skip a hardcoded list of system users (`root`, `daemon`, ..., ~30 entries), and emit an incident for each remaining user. Per-user cooldown is 30 minutes.

Result: every non-system User node in the graph fires a `graph_user_creation` incident every 30 minutes forever. On a server with 175 User nodes (current prod), that is approximately 175 × 48 = 8,400 emissions per day in steady state, with 14-day retention producing the ~3,954 currently persisted.

The function's test comment says "user_index growth" but the actual code never implemented baseline-diff. It has always been a presence detector mislabeled as a creation detector.

### Bug 2 — Ingestion creates User nodes from SSH brute-force failures

Location: wherever `auth_log` events are ingested into the graph (likely `crates/agent/src/knowledge_graph/ingestion.rs` or the auth_log event handler).

Logic: every failed SSH login is ingested as an event that mentions a username. The ingestion path calls `ensure_user(username)` for each one, creating a User node for the attempted username. Once the node exists, it is indistinguishable from a real local user.

Result: the attacker's dictionary of usernames (admin, ansible, blockchain, ali, amir, bot, ...) is persisted as User nodes in the graph. This pollutes:
- The User namespace (cannot tell real users from attempted usernames)
- Detectors that iterate User nodes (Bug 1)
- Correlation rules referencing `user_creation`
- Neural model training features
- Attacker fingerprinting (the attacker's usernames leak into user-facing graph queries)

### Bug 3 — Parser bug creating a User node named `uid`

Location: unknown until investigated. Symptom: a User node with `name == "uid"` exists in the graph and fires `graph_user_creation` 156 times.

Hypothesis: some event parser reads a string like `"uid:1001 (user)"` or `"user=uid:1001"` and extracts `uid` as the username instead of `1001` or the resolved name. This is a single parser bug that should be easy to locate once `ensure_user` call sites are audited.

## Scope

**In scope**:
- Audit all 27 graph detectors listed in `crates/agent/src/knowledge_graph/detectors.rs` for the "presence-as-event" anti-pattern. Any detector that emits one incident per existing graph element per tick is in scope.
- Fix `detect_user_creation` to detect genuine creation via baseline diff, OR remove it entirely if creation can be detected from an ingestion event more cheaply.
- Fix auth_log ingestion so SSH brute-force failures do NOT create User nodes. Attempted usernames are tracked as a different, attacker-scoped field.
- Fix the `uid` parser bug (locate the offending event parser, correct the extraction).
- Garbage-collect existing polluted nodes in the production graph: delete all `graph_user_creation` incident nodes; delete User nodes that originated from auth failures only; delete the `uid` User node.
- Audit `CL-012 Multi-Persistence` and any other correlation rule referencing `user_creation` to confirm they still function after the fix.
- Document the "signal quality" principle in `CLAUDE.md` so future detectors are evaluated against it.

**In scope for the broader audit (lower priority but same spec)**:
- `graph_network_sniffing`, `graph_host_drift`, `graph_discovery_burst`, `graph_correlation`: inspect volumes and logic for similar smells. Not all of these are guilty, but the naming pattern `graph_*` suggests they may share the same presence-scan anti-pattern.
- `kill_chain forming` (medium, 21,814 nodes): not a bug — these are legitimate near-miss LSM patterns. Not in scope for deletion. **In scope for a decision**: should they be stored as Incident nodes at all, or as a lightweight counter/histogram on the related Process node? This is a design question for research value vs. memory cost.

**Out of scope**:
- Any spec 017 Phase 1 work (Home, Threats, Health, Intel UX). That work pauses until this spec is executed.
- Backend schema migration (e.g., spec 016 SQLite work). Independent.
- Adding new detectors. This spec is purely about cleaning up and fixing existing detectors.
- Tuning severity thresholds of detectors that are working correctly.

## Principles applied

1. **Every node must be useful for ops OR research.** If a detector produces data that fails both tests, the detector is wrong.
2. **Parser robustness at ingestion boundary.** Bad data at ingestion pollutes everything downstream. Fix it at the source, not at the display layer.
3. **Detectors should prefer baseline diff over presence scan** when the semantic is "something new happened". A presence scan is cheap but produces cumulative noise indistinguishable from static state.
4. **Research data and operator data can coexist in the graph** — but research-only data should be structurally distinct (different node type, or a tag/flag), so the operator view can filter it out without losing training signal.
5. **Cleanup of existing pollution is part of the fix.** Restoring signal quality requires both stopping new pollution AND removing accumulated garbage from the current graph snapshot.

## Proposed changes

### Change 1 — Audit all 27 graph detectors for the presence-as-event anti-pattern

**Where**: `crates/agent/src/knowledge_graph/detectors.rs`.

**Method**: for each `detect_*` function, answer these questions:
- Does it iterate `graph.nodes_of_type(...)` and emit per-node unconditionally? (smell)
- Does it maintain a baseline or seen-set to distinguish "new" from "existing"? (good)
- Does it have a cooldown AND a meaningful fire condition? (cooldown alone is not enough — it just slows the noise)
- Is the severity proportional to the detection confidence?

**Output**: a table in this spec's implementation commit listing all 27 detectors with a pass/fail verdict and the fix required for each failing one.

**Current known failures**: `detect_user_creation` (Bug 1). Others to be audited.

**Risk**: medium. Audit is code review, low risk. Fixes vary by detector and carry their own risk.

### Change 2 — Fix `detect_user_creation`

**Where**: `crates/agent/src/knowledge_graph/detectors.rs:2282`.

**Two options, pick during implementation**:

**Option A — Baseline diff (preserves existing function signature)**

- At agent startup, capture the set of User names present in the graph as a `baseline: HashSet<String>` in `GraphDetectorState`.
- On each tick, compute `current_users - baseline - system_users`. Emit for items in the difference.
- After emitting, add them to the baseline so they don't re-fire.
- Severity stays medium/high based on existing logic (has_privilege edge).

**Option B — Remove the detector, replace with ingestion-side event emission**

- Delete `detect_user_creation` entirely.
- In the ingestion path that calls `ensure_user(name)`, check if the user is new (not in graph yet). If new AND the event source is a legitimate creation event (e.g., `useradd`, `/etc/passwd` change, or a successful login from an external IP), emit a `graph_user_creation` incident inline.
- Auth failures do NOT count as creation events (covers Bug 2 by design).

**Recommendation**: Option B. It is architecturally cleaner (creation is an event, not a scan) and naturally fixes Bug 2. Option A is a mechanical fix that leaves the architecture smell in place.

**Risk**: medium. Requires touching ingestion paths and possibly correlation rules.

### Change 3 — Fix auth_log ingestion (no User node for brute-force attempts)

**Where**: whichever file handles auth_log events — likely `crates/agent/src/knowledge_graph/ingestion.rs` or an event-specific handler. Exact location determined in implementation.

**Fix**:

1. Distinguish successful vs failed authentication events at the ingestion layer.
2. **Failed auth**: do NOT call `ensure_user`. Instead, append the attempted username to a list/set on the source Ip node (new field: `attempted_usernames: Vec<String>`, deduplicated, bounded).
3. **Successful auth**: call `ensure_user` as today.
4. Add a query helper to `KnowledgeGraph` to retrieve attempted usernames for attacker fingerprinting (this replaces any code that currently reads User nodes expecting to find attacker-provided usernames).

**Result**: the User namespace contains only real local users. Attacker usernames are isolated on Ip nodes where they semantically belong.

**Risk**: medium-high. Schema change on Ip node. Requires migration for existing graph snapshots. Any code that currently reads User nodes expecting to find brute-force usernames (e.g., threat-dna behavioral fingerprinting) must be updated.

### Change 4 — Fix the `uid` parser bug

**Where**: unknown until investigated. Plan:

1. Grep for all call sites of `ensure_user` in `crates/agent/src/`.
2. For each call site, check the source string being passed.
3. Find the one that produces `name == "uid"` from input like `"uid:1001"` or similar.
4. Fix the parser to extract the numeric uid or resolve to the actual username.

**Risk**: low once located. The fix is a one-line parser correction.

### Change 5 — Garbage-collect existing pollution

**Where**: `/var/lib/innerwarden/graph-snapshot-YYYY-MM-DD.json` files on production and any other host. Executed via:

1. Stop the agent (so it does not overwrite the edited snapshot).
2. Back up the current snapshot.
3. Run a one-shot cleanup script (Rust or jq) to:
   - Delete all Incident nodes where `incident_id` starts with `graph_user_creation:`.
   - Delete all User nodes that originated from auth failures only (determined by: no SuccessfulLoginFrom or similar legitimate edge).
   - Delete the specific User node named `"uid"`.
   - Optionally: delete any Incident node that references a deleted User node (to avoid dangling edges).
   - Preserve all other nodes and edges.
4. Write the cleaned snapshot back.
5. Restart the agent (which loads the cleaned snapshot).

**Alternative**: implement the cleanup as a one-time migration in the agent itself, triggered by a CLI flag (`innerwarden-agent --cleanup-015-graph-signal-quality`). This is safer than editing the JSON file directly.

**Recommendation**: implement as an agent CLI migration. Keeps the cleanup code reviewable and runnable on any host, not just production.

**Risk**: medium. Destructive. Requires backup + verification. Must be reversible.

### Change 6 — Audit correlation rules referencing `user_creation`

**Where**: `crates/agent/src/knowledge_graph/detectors.rs` correlation rule definitions (around lines 1500+).

**Known reference**: `CL-012 Multi-Persistence` (line 1505) includes `user_creation` as a stage:
```rust
stages: &[
    &["crontab_persistence", "systemd_persistence"],
    &["ssh_key_injection", "user_creation"],
],
```

**Task**: after Change 2 lands, verify CL-012 still fires correctly for its intended pattern (real persistence via user account creation). If Change 2 makes `graph_user_creation` rarer (which it should), CL-012 will fire less — but the firings should be higher-signal. Validate this empirically after cleanup.

**Risk**: low. Read-only audit.

### Change 7 — Document the signal-quality principle in CLAUDE.md

**Where**: `CLAUDE.md` (root or nearest relevant).

**Addition**: new section `## Signal quality principle (spec 015)` that states the hard rule — every node in the graph must be useful for ops OR research — and links to this spec for the rationale.

**Goal**: prevent future detectors from regressing the principle.

**Risk**: none.

### Change 8 — Broader audit of other `graph_*` detectors

**Where**: `crates/agent/src/knowledge_graph/detectors.rs`. Functions starting with `detect_graph_*` or contributing to incidents with `graph_*` slugs.

**Suspects** (from prod snapshot volume analysis):
- `graph_network_sniffing` — 65 nodes
- `graph_host_drift` — 43 nodes
- `graph_correlation` — 36 nodes
- `graph_discovery_burst` — 30 nodes

**Task**: for each, apply the Change 1 audit checklist. Fix or document any that fail.

**Risk**: low audit, medium fixes depending on findings.

## Execution plan (for the follow-up session)

This spec is deliberately deferred to a fresh session. The execution order is:

1. **Re-read this spec**. Understand the philosophy and the 3 known bugs.
2. **Investigation phase** (read-only, ~1 hour on prod/local):
   - Grep all `ensure_user` call sites in `crates/agent/src/`
   - Read each `detect_*` function in `detectors.rs` and score against the Change 1 checklist
   - Pull a fresh graph snapshot from prod to reconfirm distributions
   - Locate Bug 3 (`uid` parser)
3. **Audit report**. Produce the per-detector verdict table. Commit as an intermediate artifact.
4. **Code changes** in this order (each its own commit on branch `015-graph-signal-quality`):
   - Change 4 (parser fix for `uid`) — smallest, builds confidence
   - Change 2 (fix `detect_user_creation` — probably option B)
   - Change 3 (auth_log ingestion split) — biggest change, most test coverage needed
   - Change 8 (other `graph_*` audits and fixes)
   - Change 6 (correlation rule validation)
   - Change 7 (CLAUDE.md signal-quality section)
5. **Build local, `make test`** — all tests must pass. Add new tests for the ingestion split and the fixed `detect_user_creation`.
6. **Cleanup migration (Change 5)**:
   - Implement as `innerwarden-agent --cleanup-015-graph-signal-quality` CLI flag
   - Test on VM with a copy of the prod snapshot
   - Verify the cleanup removes only the targeted nodes
7. **Deploy to VM first**, observe for 24 hours.
8. **Deploy to prod**:
   - Stop agent, back up snapshot, run cleanup, verify snapshot delta, restart agent
   - Confirm Recent Activity is clean (the 14% noise should be gone)
9. **Validation with spec 017 Phase 1 01-home**: reload Home on prod. The Recent Activity feed should now be dominated by legitimate high/critical events, not `graph_user_creation`. This is the downstream acceptance test for both 015 and 017.
10. **Resume spec 017 Phase 1** (02-threats, 03-health, 04-intel) in a subsequent session.

## Acceptance criteria

### Investigation

- [ ] Per-detector audit table produced and committed, covering all 27 `detect_*` functions in `detectors.rs`
- [ ] Bug 3 (`uid` parser) located and fixed
- [ ] All `ensure_user` call sites mapped and classified as "real user" or "parsed from untrusted event"

### Detector fix

- [ ] `detect_user_creation` no longer fires on existing graph users — only on genuinely new creations (baseline-diff or ingestion-event, whichever option is chosen)
- [ ] After deploy, `graph_user_creation` incident count over 24 hours drops from ~8,400/day to a handful (expected: 0–5/day on a stable server)
- [ ] `CL-012 Multi-Persistence` correlation rule still fires on genuine multi-persistence patterns (validated via a synthetic test or historical data)

### Ingestion fix

- [ ] Failed SSH logins no longer create User nodes (validated via live auth_log ingestion test)
- [ ] Successful SSH logins still create User nodes
- [ ] Attempted usernames from brute force are available via a new query (on Ip node or equivalent) for attacker fingerprinting
- [ ] `threat-dna` behavioral fingerprinting still has access to attempted usernames (via the new field) and produces the same or better fingerprints

### Cleanup

- [ ] The cleanup migration is implemented as a CLI flag, not a manual JSON edit
- [ ] Running the migration on a backed-up prod snapshot copy produces a verifiable delta (X nodes removed, Y edges removed, Z nodes preserved)
- [ ] After deploy + cleanup, the production graph has **zero** `graph_user_creation` Incident nodes
- [ ] After deploy + cleanup, the production graph has **zero** User nodes that were created purely from auth failures
- [ ] After deploy + cleanup, the User node named `"uid"` does not exist
- [ ] Memory usage of the agent process (RSS) drops measurably after cleanup (rough expectation: 5–15% reduction, depending on how much of the 14% bloat was in-memory)

### Downstream validation

- [ ] Spec 017 Phase 1 01-home Recent Activity feed, viewed on prod after cleanup, does NOT contain any `graph_user_creation` entry
- [ ] The Home hero, in normal operation without sensor stall, does NOT show `System Health Alert` just because of `graph_user_creation` noise (this is already the case because 017 doesn't use graph_user_creation as a trigger — but confirm)
- [ ] AI training pipeline, when next run, no longer includes `graph_user_creation` false-positive features (if any feature extractor references that detector)

### Documentation

- [ ] Signal quality principle section added to `CLAUDE.md`
- [ ] This spec updated with the audit table and final implementation notes
- [ ] Commit messages reference `spec 015` for traceability

## Risks and mitigations

### Risk — Cleanup destroys research-useful data

**Mitigation**: the cleanup targets only nodes that were verified false positives (`graph_user_creation` derived from brute-force usernames). Legitimate data is not touched. Backup the snapshot before running the migration. Keep the backup for at least 30 days post-deploy.

### Risk — `CL-012 Multi-Persistence` correlation rule breaks

**Mitigation**: validate the rule still fires on a synthetic multi-persistence scenario before/after the fix. If it breaks, either adjust the rule to use a different marker or restore `user_creation` in a cleaner form.

### Risk — `threat-dna` loses its attacker-username features

**Mitigation**: Change 3 preserves the data by moving it to a different location (`attempted_usernames` on Ip nodes). `threat-dna` code must be updated to read from the new location. This is part of the spec's scope, not a risk to defer.

### Risk — Migration corrupts the production graph

**Mitigation**: always run the migration on a copy first. Keep the agent stopped during migration so no concurrent writes happen. Verify node counts before and after. Have a documented rollback path (restore the backup snapshot).

### Risk — Other `graph_*` detectors have similar bugs

**Mitigation**: Change 8 audits them as part of this spec. Any additional fixes discovered during the audit are folded into this spec's scope. The spec is done when all 27 detectors pass the audit.

## Open questions

1. **Should `kill_chain forming` medium incidents (21,814 nodes, 77% of the graph) be restructured?** They are legitimate research data but consume 4x the space of everything else combined. Options:
   - Leave as-is (simplicity)
   - Compact into a histogram/counter on the related Process node (memory efficient)
   - Decided in implementation based on memory pressure measurements

2. **Should the cleanup migration be a one-shot (run once and remove the flag) or a permanent feature?** One-shot is safer. Permanent is useful if future false-positive waves surface — but that would mean the new wave is itself a bug needing a proper fix, not a sweep.

3. **Should detectors with `graph_*` prefix be removed entirely and re-implemented as ingestion-time emissions?** This is the architectural question underlying Change 2 Option B. Answering it may require a prototype.

## Related work

- **Spec 010 — Detector Migration (Phase 3)** introduced the 27 graph detectors. Spec 015 fixes the quality of that migration's output.
- **Spec 012 — Eliminate JSONL Dependency (Phase 6)** made the graph the single source of truth for dashboard queries. The Recent Activity flood on Home surfaced graph noise that was previously hidden when JSONL was the primary read path.
- **Spec 013 — Graph Single Source of Truth (Phase 7)** completed the transition. Any signal quality problem in the graph is now directly visible on the dashboard.
- **Spec 014 — Graph Full Connectivity** added new relation types and ingestion paths. The ingestion changes in Change 3 build on this work.
- **Spec 017 — Dashboard Operator UX** Phase 1 (00-shared + 01-home) is **paused** until 015 is executed. 017 cannot deliver its operator experience promises while the graph is producing 14% false-positive noise. The downstream validation of 015 (Home feed clean) is effectively the acceptance test for 017 Phase 1 to resume.

## Out of scope (explicit)

- **Other spec 017 pages** (02-threats, 03-health, 04-intel). 017 Phase 1 resumes after 015 lands.
- **Spec 016 SQLite unified store**. Independent. 015 operates on the current JSON snapshot format; 016 operates on the future SQLite format. Both are valid.
- **Adding new detectors or new correlation rules**. 015 is cleanup, not expansion.
- **Neural model retraining**. If the training pipeline used the polluted data, it may need a retrain — but that is a follow-up spec.
- **Sensor-side detector changes**. 015 is agent-side only. Any sensor detector behavior that contributes to User node pollution should be addressed here via the ingestion layer (Change 3), not by changing the sensor.

---

## Implementation notes for the follow-up session

- This spec was written in a session that was executing spec 017 Phase 1. The 017 work is committed on branch `017-dashboard-operator-ux` at commit `b35b72c` (01-home implementation deployed to prod 2026-04-11). That branch is paused, not abandoned.
- The graph snapshot referenced in this spec lives at `/var/lib/innerwarden/graph-snapshot-2026-04-11.json` on the production server (`ubuntu@130.162.171.105`, port 49222). Size: ~39 MB.
- The investigation that produced this spec is reconstructible from:
  - `git log` on branch `017-dashboard-operator-ux` (shows the 017 work that surfaced the noise)
  - `jq` queries on the graph snapshot for distribution analysis (examples in the Investigation section above)
- The user is aware of the detector bug and explicitly authorized: (a) stopping 017 Phase 1 work, (b) cleaning the 3,954 false-positive incidents, (c) executing the full 015 scope in a fresh session.
