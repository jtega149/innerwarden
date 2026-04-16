# Feature Specification: Coverage Closeout — Project-Wide

**Feature Branch**: `023-coverage-closeout`
**Created**: 2026-04-16
**Status**: DRAFT
**Priority**: P1 (45.14% → target 70%)
**Depends on**: nothing (parallel-friendly with 019 and 022)
**Related**: 019-test-coverage-gaps (batches 2–7 still outstanding), 022-dashboard-tests (dashboard-specific)

## Why this spec exists

Codecov (main, commit `a6ca20b`) reports **45.14% line coverage (21,073 / 46,677)**. PR comments fail coverage threshold on every patch touching under-tested files. Spec 019 planned up to ~50% via agent/ctl batches 2–7 (still pending) and spec 022 targets the dashboard (pending). This spec is the **third pillar**: close the remaining gaps across the modules neither 019 nor 022 touches, lift the project to ≥70%, and keep CI green on future patches.

Scope is tactical and bounded: **pure-logic extraction + unit tests**. No production behavior changes. No integration test harnesses. No e2e. Each batch is one AI session, one branch, one PR.

## Current state — worst offenders

Source of truth: Codecov UI on `main`. Numbers refresh every merge; use these as of 2026-04-16.

### Files at 0% coverage (by lines, descending)

| File | Lines | Crate | Why now |
|---|---|---|---|
| `sensor/src/main.rs` | 546 | sensor | Wiring + signal handling. Pull pure helpers (config parse, cursor init). |
| `ctl/src/commands/notify.rs` | 455 | ctl | Channel config + validation. Pure logic inside CLI command. |
| `sensor/src/config.rs` | 294 | sensor | Config struct defaults + validation. Trivial wins. |
| `ctl/src/commands/status.rs` | 283 | ctl | Service state interpretation, uptime calc. |
| `ctl/src/commands/ai.rs` | 195 | ctl | Provider validation, model name normalization. |
| `ctl/src/commands/response.rs` | 186 | ctl | Response lifecycle CLI wrappers. |
| `ctl/src/commands/integrations.rs` | 154 | ctl | Integration discovery + manifest parsing. |
| `sensor/src/collectors/firmware_integrity.rs` | 134 | sensor | Baseline hash comparison. |
| `agent/src/shield_inline.rs` | 123 | agent | Rate calc / SYN ratio (covered partly in 019 batch 5 — confirm outstanding). |
| `ctl/src/commands/update.rs` | 112 | ctl | Version parsing, rollback path. |
| `agent/src/bot_actions.rs` | 105 | agent | Callback dispatch (covered in 019 batch 7 — confirm). |
| `ctl/src/commands/firmware.rs` | 102 | ctl | Firmware subcommand arg parsing. |
| `smm/src/main.rs` | 96 | smm | One-shot probe runner. |
| `agent/src/firmware_tick.rs` | 96 | agent | Probe result classifier (covered partly in 019 batch 5). |
| `ctl/src/calibrate.rs` | 95 | ctl | Sensitivity mapping (019 batch 6). |
| `agent/src/hypervisor_tick.rs` | 82 | agent | Probe result classifier (019 batch 5). |
| `ctl/src/commands/responder.rs` | 79 | ctl | Responder CLI wrappers. |
| `agent/src/knowledge_graph/mod.rs` | 69 | agent | Public re-exports + trivial helpers. |
| `agent/src/redis_reader.rs` | 66 | agent | Redis consumer-group cursor logic. |
| `hypervisor/src/main.rs` | 63 | hypervisor | One-shot probe runner. |
| `ctl/src/commands/capability.rs` | 63 | ctl | Capability enum parsing. |
| `agent/src/incident_autodismiss.rs` | 29 | agent | Dismiss rules (small, covers quickly). |
| `agent/src/incident_honeypot_router.rs` | 29 | agent | Router match logic. |
| `agent/src/narrative_anomaly.rs` | 23 | agent | Threshold comparison. |
| `agent/src/incident_ai_failure.rs` | 8 | agent | Single helper, trivial. |

Plus 20+ files with <100 lines at 0% — trivial to cover in bulk.

### Worst large files with <20% coverage

| File | Lines | Coverage | Notes |
|---|---|---|---|
| `agent/src/main.rs` | 1,377 | 14.52% | Mostly wiring. Target the pure helpers we've added in other PRs (`honeypot_runtime`, `is_pid_in_own_tree`, validators). |
| `agent/src/skills/builtin/honeypot/mod.rs` | 1,323 | 16.93% | Session state machine (019 batch 7 — verify). |
| `ctl/src/commands/ops.rs` | 1,020 | 5.78% | Sensitivity tuning + fail2ban (019 batch 6). |
| `ctl/src/harden.rs` | 1,094 | 13.07% | Hardening steps per capability. Test the per-step logic separately. |
| `agent/src/telegram.rs` | 1,053 | 32.57% | Message formatting (most already pure). |
| `ctl/src/scan.rs` | 974 | 44.15% | Tier classification + recommendation. |
| `ctl/src/commands/setup.rs` | 570 | 7.72% | Preflight + confirmation logic. |
| `agent/src/knowledge_graph/ingestion.rs` | 761 | 36.79% | Event → node/edge mapping. |
| `agent/src/bot_commands.rs` | 411 | 20.44% | Parsing + permission checks. |
| `agent/src/dashboard/sensors.rs` | 284 | 2.11% | Module state determination (spec 022 batch 4). |
| `agent/src/dashboard/intelligence.rs` | 289 | 4.84% | Profile sorting (spec 022 batch 5). |
| `ctl/src/commands/history.rs` | 446 | 40.13% | Time range parsing, filters. |
| `agent/src/bot_helpers.rs` | 314 | 16.88% | HTML escape + format (019 batch 7). |
| `agent/src/neural_lifecycle.rs` | 423 | 38.53% | Training schedule, drift detection. |
| `agent/src/dashboard/actions.rs` | 277 | 10.11% | IP/user validation (spec 022 batch 5). |

### Crate-level view

| Crate | Lines | Covered | % | Gap to 70% |
|---|---|---|---|---|
| agent | ~24,000 | ~9,000 | ~37% | +7,800 lines |
| ctl | ~8,500 | ~2,300 | ~27% | +3,600 lines |
| sensor | ~10,500 | ~6,000 | ~57% | +1,300 lines |
| shield | ~1,200 | ~750 | ~63% | +90 lines |
| smm | ~1,700 | ~900 | ~53% | +300 lines |
| dna | ~700 | ~450 | ~64% | +40 lines |
| killchain | ~350 | ~280 | ~80% | 0 |
| agent-guard | ~400 | ~300 | ~75% | 0 |
| hypervisor | ~1,000 | ~450 | ~45% | +250 lines |
| store | ~450 | ~350 | ~78% | 0 |
| core | ~50 | ~40 | ~80% | 0 |

**Overall target**: 70% = +11,500 lines covered. Spec 019 + 022 cover ~6,000. This spec covers the remaining ~5,500.

## Approach

Same pattern as 019 and 022. Each file in scope gets a `#[cfg(test)] mod tests` with focused unit tests. Pure logic is extracted where entangled with I/O — **no behavior change**.

Three test archetypes we return to:

1. **Config/defaults** — assert default values, reject invalid values (empty, out-of-range, wrong type).
2. **Validation/parsing** — every `parse_*`, `classify_*`, `normalize_*` function gets a happy path + 2-3 edge cases.
3. **Deterministic mapping** — event kind → phase, severity → color, tier → label, capability → systemd path, etc. Every arm of every `match` gets a test.

Explicitly not covered:
- Subprocess execution (we test argument construction, not execution).
- HTTP handlers (spec 022 covers dashboard; the rest stay behind pure-function extraction).
- eBPF byte-code paths (integration territory).
- Real network calls (GeoIP, AbuseIPDB, Cloudflare, Telegram, Slack).

## Batches

Each batch is ONE AI session, ONE branch, ONE PR. Branch from `development`, PR target `development`, `cargo clippy --workspace -- -D warnings` + `cargo fmt --all --check` + `make test` must pass.

### Batch 1 — ctl commands: status, ai, capability, responder, core, mesh

**Branch**: `023-batch-1`
**Target**: ~35 tests
**Crate**: ctl

| File | Lines | Focus |
|---|---|---|
| `commands/status.rs` | 283 | Service state parsing, uptime formatting, aggregation per systemd unit. |
| `commands/ai.rs` | 195 | Provider name normalization, model validation, env var resolution. |
| `commands/capability.rs` | 63 | Capability enum `from_str` + display. |
| `commands/responder.rs` | 79 | Responder enable/disable argument parsing. |
| `commands/core.rs` | 43 | Core command help text + subcommand dispatch. |
| `commands/mesh.rs` | 48 | Mesh peer argument parsing. |

### Batch 2 — ctl commands: notify, integrations, update, firmware

**Branch**: `023-batch-2`
**Target**: ~35 tests
**Crate**: ctl

| File | Lines | Focus |
|---|---|---|
| `commands/notify.rs` | 455 | Channel config builder (Telegram/Slack/webhook). Validation: empty token, invalid URL, missing chat_id. Digest interval parsing (`"1h"`, `"30m"`, `"0"`). Alert level filtering. |
| `commands/integrations.rs` | 154 | Integration discovery: manifest merge, enable-check logic, search filter. |
| `commands/update.rs` | 112 | Version string parsing (semver), rollback path construction, precondition checks. |
| `commands/firmware.rs` | 102 | Subcommand arg parsing, probe label mapping. |

### Batch 3 — ctl: harden step logic

**Branch**: `023-batch-3`
**Target**: ~30 tests
**Crate**: ctl

| File | Lines | Focus |
|---|---|---|
| `harden.rs` | 1,094 | Per-step classification: sysctl diff evaluation, SSH config rule matching, UFW rule presence, fail2ban jail validation, cron allowlist check. Each step has a deterministic "is this hardened" predicate — extract and test every branch. Skip the actual file-writing paths. |

### Batch 4 — sensor: config + main + firmware_integrity

**Branch**: `023-batch-4`
**Target**: ~30 tests
**Crate**: sensor

| File | Lines | Focus |
|---|---|---|
| `config.rs` | 294 | Default values per section, invalid value rejection, bind-address parsing, data-dir resolution. |
| `main.rs` | 546 | Extract the sensor-init pure helpers: collector selection from flags, cursor-path resolution, sink selection logic. Leave the async setup alone. |
| `collectors/firmware_integrity.rs` | 134 | Baseline hash comparison, delta classification, anomaly threshold. |
| `collectors/sysctl_drift.rs` | 36 | Drift detection predicate. |
| `collectors/suid_inventory.rs` | 54 | SUID path classification (known vs unknown). |
| `sinks/state.rs` | 16 | Sink init / format. |
| `sinks/jsonl.rs` | 10 | Line serialization. |

### Batch 5 — agent inline ticks + small 0% files

**Branch**: `023-batch-5`
**Target**: ~30 tests
**Crate**: agent

| File | Lines | Focus |
|---|---|---|
| `hypervisor_tick.rs` | 82 | Probe result interpretation (CPUID anomaly, timing deviation). |
| `firmware_tick.rs` | 96 | MSR value validation, UEFI variable parsing. |
| `knowledge_graph/mod.rs` | 69 | Public helper surface. |
| `redis_reader.rs` | 66 | Consumer-group cursor logic, message ACK gating. |
| `incident_autodismiss.rs` | 29 | Dismiss rule matching. |
| `incident_honeypot_router.rs` | 29 | Router match arms. |
| `narrative_anomaly.rs` | 23 | Threshold evaluation. |
| `incident_ai_failure.rs` | 8 | Error classification. |
| `fail2ban.rs` | 4 | Single helper. |
| `narrative_incident_ingest.rs` | 31 | Text build from incident fields. |

### Batch 6 — agent main.rs pure helpers

**Branch**: `023-batch-6`
**Target**: ~40 tests
**Crate**: agent

Targets the 1,177 uncovered lines of `main.rs` by testing every pure helper there. Many are already present (`honeypot_runtime`, `is_pid_in_own_tree`, `adaptive_block_ttl_secs`, `append_blocked_ip`, `NarrativeAccumulator::*`, `incident_line`, etc.). Walk `grep -E '^pub\(crate\) fn |^fn '` in `main.rs` and ensure every pure helper has at least one test per branch.

### Batch 7 — agent knowledge graph ingestion

**Branch**: `023-batch-7`
**Target**: ~30 tests
**Crate**: agent

| File | Lines | Focus |
|---|---|---|
| `knowledge_graph/ingestion.rs` | 761 | Event → node type mapping (every event kind → correct `NodeType`). Edge creation rules. Entity extraction (IP/user/file/process from details). `ensure_ip`, `ensure_user`, `ensure_file` guards (caller sanitization — validate invalid input doesn't create garbage nodes). Dedup behavior across repeated events. |

### Batch 8 — agent neural_lifecycle + telegram formatting

**Branch**: `023-batch-8`
**Target**: ~30 tests
**Crate**: agent

| File | Lines | Focus |
|---|---|---|
| `neural_lifecycle.rs` | 423 | Training schedule (nightly 3 AM UTC), drift detection thresholds, model version gating, training input serialization. |
| `telegram.rs` | 1,053 | Message formatting functions (HTML escape, severity emoji, incident summary, button construction). Skip the HTTP client itself. |

### Batch 9 — agent other low-coverage

**Branch**: `023-batch-9`
**Target**: ~25 tests
**Crate**: agent

| File | Lines | Current | Focus |
|---|---|---|---|
| `honeypot_always_on.rs` | 193 | 5.18% | Listener bind address validation, service port mapping, shutdown signal handling logic. |
| `defender_brain.rs` | 243 | 31.28% | Feature vector construction, score classification, decision gate. |
| `threat_feeds.rs` | 70 | 15.71% | Feed URL list validation, IOC parsing per feed format. |
| `crowdsec.rs` | 71 | 5.63% | Sync result parsing, blocklist diff logic. |
| `slack.rs` | 112 | 15.18% | Block builder (severity → color, title format), webhook URL validation. |
| `mesh.rs` | 34 | 0% | Peer signature verification, signal construction. |
| `web_push.rs` | 84 | 23.81% | VAPID payload construction, subscription JSON parsing. |
| `abuseipdb.rs` | 69 | 33.33% | Category mapping per detector, confidence computation. |

### Batch 10 — sensor collector remainder

**Branch**: `023-batch-10`
**Target**: ~25 tests
**Crate**: sensor

| File | Lines | Current | Focus |
|---|---|---|---|
| `collectors/tcp_stream.rs` | 260 | 33.85% | Flow state transitions, HTTP/TLS fingerprint extraction from segments. |
| `collectors/kernel_integrity.rs` | 96 | 18.75% | Syscall-table diff, module inventory change detection. |
| `collectors/proc_maps.rs` | 139 | 8.63% | Parse `/proc/pid/maps` lines, RWX classification, anonymous mapping detection. |
| `collectors/fanotify_watch.rs` | 81 | 14.81% | Entropy calculation, ransomware burst detection threshold. |
| `detectors/stego_detect.rs` | 292 | 38.36% | Payload entropy check, stego signature matching. |

### Batch 11 — hypervisor + smm + shield closeout

**Branch**: `023-batch-11`
**Target**: ~25 tests
**Crates**: hypervisor, smm, shield

| File | Lines | Current | Focus |
|---|---|---|---|
| `hypervisor/src/main.rs` | 63 | 0% | Subcommand dispatch, report formatting. |
| `hypervisor/src/vmexit.rs` | 67 | 17.91% | VM-exit reason classification. |
| `hypervisor/src/cpuid.rs` | 81 | 45.68% | CPUID feature bit parsing, VM-provider signature matching. |
| `hypervisor/src/kvm.rs` | 68 | 55.88% | KVM module presence check predicate. |
| `smm/src/main.rs` | 96 | 0% | Probe runner dispatch. |
| `smm/src/smi.rs` | 21 | 0% | SMI count parsing. |
| `smm/src/spi.rs` | 30 | 20% | SPI flash hash comparison. |
| `smm/src/msr.rs` | 36 | 33% | MSR value classification. |
| `shield/src/telegram_notify.rs` | 54 | 0% | Escalation message construction. |
| `shield/src/origin_lockdown.rs` | 98 | 6.12% | Lockdown trigger evaluation. |
| `shield/src/cloudflare_failover.rs` | 48 | 33% | Failover trigger threshold, zone-id validation. |

## Summary table

| Batch | Crate | Files | Target tests | Est. coverage lift |
|---|---|---|---|---|
| 1 | ctl | 6 | ~35 | +0.7% |
| 2 | ctl | 4 | ~35 | +1.0% |
| 3 | ctl | 1 | ~30 | +2.0% |
| 4 | sensor | 7 | ~30 | +1.5% |
| 5 | agent | 10 | ~30 | +0.8% |
| 6 | agent | 1 | ~40 | +2.5% |
| 7 | agent | 1 | ~30 | +1.5% |
| 8 | agent | 2 | ~30 | +2.5% |
| 9 | agent | 8 | ~25 | +0.8% |
| 10 | sensor | 5 | ~25 | +1.2% |
| 11 | hypervisor/smm/shield | 11 | ~25 | +0.8% |
| **Total** | | **56 files** | **~335 tests** | **45% → ~65%** |

Combined with 019 (outstanding ~160 tests, +8%) and 022 (~135 tests, +4%), this path reaches **~77% project-wide**. Beyond 70% is stretch — diminishing returns vs the cost of mocking async/HTTP boundaries.

## Execution rules (same as 019 and 022)

1. **Branch from `development`** (NOT from another batch branch, NOT from `main`).
2. **`cargo clippy --workspace -- -D warnings`** must pass. CI rejects warnings.
3. **`cargo fmt --all`** before commit. CI checks formatting.
4. **`make test`** must pass. Don't merge a batch that fails tests.
5. **No behavior changes** to production code. Only:
   - Extracting pure functions (same pattern as `check_block_eligibility` / `is_valid_block_target` / `format_skill_outcome`).
   - Renaming for testability (rare — ask first).
6. **Every test has a comment** stating what code path it exercises and why it matters.
7. **No `unwrap()` in test setup** — use `expect("reason")` or `panic!("reason")`.
8. **No network, no root, no subprocess** in tests. If a function must call one, extract the pre-spawn logic and test that.
9. **Read existing tests first** — many files already have 1–5 tests. Don't duplicate; extend.
10. **PR title**: `test(<crate>): batch N — <description>`.
11. **PR body lists every file touched + test count delta.**
12. **One batch per PR.** Small, reviewable diffs.

## Acceptance criteria

- [ ] 11 batches merged.
- [ ] Codecov on `main` shows ≥65% overall (stretch 70%).
- [ ] Every file listed has `#[cfg(test)] mod tests` with ≥3 tests.
- [ ] Zero clippy warnings on `main`.
- [ ] `make test` green.
- [ ] No test requires network, root, or external services.
- [ ] Patch coverage ≥80% on every merged PR from this spec.

## Coordination with 019 and 022

- **019 (Gemini-owned per memory)**: batches 2–7 still open. If a file listed here is also listed in 019, **019 takes precedence** — this spec excludes it once 019's PR lands. Before starting a batch, re-check Codecov and skip files already covered.
- **022 (Dashboard)**: dashboard files are explicitly excluded from this spec. Batches 4–6 of 022 (`sensors.rs`, `live_feed.rs`, `actions.rs`, `agent_api.rs`, `intelligence.rs`, `sse.rs`, `push.rs`, `brain.rs`, `data_api.rs`) are the canonical targets for those files.
- **New bugs caught during test-writing**: open a separate PR with a commit per bug. Don't bundle with the coverage PR — reviewers need to see bug fixes distinctly.

## Out of scope

- HTTP handler integration tests (would require an axum test harness — separate infrastructure spec).
- eBPF integration tests (require privileged kernel — separate e2e spec).
- Real provider API tests (OpenAI, Anthropic, Cloudflare, AbuseIPDB, Telegram, Slack).
- End-to-end attack scenario tests (replay-qa already covers this).
- Property-based / fuzz testing (separate spec if justified).
- Benchmarks.

## Failure modes to watch

From the 3 coverage PRs already landed (spec 019 Batch 1 + PR #124), these patterns cause lint/CI failures:

| Pattern | How to avoid |
|---|---|
| `sort_by(|a,b| b.x.cmp(&a.x))` triggers `unnecessary_sort_by` on clippy 1.95. | Crate-level `#![allow(clippy::unnecessary_sort_by)]` is already set on `agent` and `ctl`. If you add it elsewhere, do the same. |
| `for item in &items { ... idx += 1 }` triggers `explicit_counter_loop`. | Use `for (idx, item) in (1usize..).zip(items.iter())`. |
| `cargo fmt` rewrites multi-line `assert!(… r#""#)` chains. | Run `cargo fmt` before every commit. |
| Clippy 1.95 introduces new lints periodically. | Run `cargo +1.95 clippy --workspace -- -D warnings` locally before pushing. |
| Tests that spawn subprocesses fail in CI. | Extract the arg-construction logic; test it; leave the spawn call alone. |

## References

- Codecov dashboard: `https://app.codecov.io/gh/InnerWarden/innerwarden` (main branch).
- Spec 019: `.specify/features/019-test-coverage-gaps/spec.md` (Gemini-owned batches 2–7).
- Spec 022: `.specify/features/022-dashboard-tests/spec.md` (dashboard batches 1–6).
- PR #124 (this PR, landing coverage wins for the invalid-IP cascade): `https://github.com/InnerWarden/innerwarden/pull/124`.
