# Feature Specification: Decomposition for Testability

**Feature Branch**: `026-decomposition-for-testability`
**Created**: 2026-04-17
**Status**: DRAFT
**Priority**: P1 (blocks spec 023 stretch goal of 65% project coverage)
**Depends on**: nothing. Prerequisite for the remaining ~10pp of project coverage.

## Why this spec exists

Codex ran the 11 batches of spec 023 and the result, measured on PR #125,
is **+272 tests (3102 → 3374) and patch coverage 72%**, but **project
coverage went from 45.14% to 43.65%** (and the 1.5pp drop is mostly
tarpaulin tooling change, not real regression — patch coverage 72% on
7,300 changed lines is net positive).

Why doesn't batch-level work lift project coverage? Because the biggest
uncovered files are so large that adding unit tests to a slice of them
only moves the file's coverage by 2–4pp. The project-coverage needle
follows those files by weight.

Ranked by product of `LoC × uncovered %`:

| File | LoC (wc) | Coverage | Uncovered LoC |
|---|---|---|---|
| `crates/agent/src/main.rs` | 5,710 | ~13% | ~4,970 |
| `crates/agent/src/telegram.rs` | 3,472 | ~33% | ~2,320 |
| `crates/agent/src/skills/builtin/honeypot/mod.rs` | 3,206 | ~17% | ~2,660 |
| `crates/ctl/src/harden.rs` | 2,612 | ~13% | ~2,270 |
| `crates/ctl/src/commands/ops.rs` | 2,144 | ~6% | ~2,015 |

These five files alone carry **~14,200 uncovered lines** — roughly 30%
of the entire workspace's uncovered surface. A focused decomposition
of the top three (15,000 LoC total) is the realistic path to 65%
project coverage.

Unit tests cannot reach that code today because:

* `main.rs` embeds orchestration (`process_incidents`,
  `process_telegram_approval`, fast-loop body, slow-loop body) alongside
  wiring. Extracting a free function returns you a 400-line closure that
  captures 40+ fields of `AgentState`; you can't invoke it without
  rebuilding the whole agent.
* `honeypot/mod.rs` is a state machine + banner generator + command
  parser + containment launcher + pcap handoff + audit writer, all in
  one file. Any slice you touch drags in the rest.
* `telegram.rs` mixes the HTTP client, rate limiter, escape helpers, and
  message-template builders. The pure template code is trapped behind
  `TelegramClient::send_*` methods that can't be invoked in a unit test
  because they construct an HTTP request.

Decomposition — moving code into submodules with narrow interfaces —
exposes that logic to `#[cfg(test)] mod tests` without changing any
runtime behavior.

## Non-negotiables

* **Zero behavior change in production.** Every function moved keeps
  identical signatures and side-effects. Verified by: existing tests
  stay green with no edits beyond import paths, `make replay-qa` passes,
  the prod sensor + agent deployed on the new binary matches the old
  one's output byte-for-byte over a 10-minute sample.
* **No new public API.** Extractions are `pub(crate)` or narrower. We do
  not expose internals to other crates as a side-effect of decomposition.
* **One file at a time, per PR.** No "big-bang restructure" PR. Reviewer
  reads a diff where 90% is moves and 10% is the new module boundary.
* **Tests grow in the same PR.** Each decomposition PR lands the split
  file AND the `#[cfg(test)] mod tests` for the new submodule(s). Project
  coverage must increase ≥5pp for the crate being touched, measured
  locally with `cargo tarpaulin` before opening the PR.

## Scope — three files, three PRs

### Phase A — `agent/src/main.rs` decomposition

**Target**: 5,710 LoC → ≤1,500 LoC of wiring, the rest in submodules.

Proposed modules (names negotiable, shapes aren't):

| New module | Extracts |
|---|---|
| `agent/src/loops/fast_loop.rs` | Body of the 2-second tick: read events from sqlite, dispatch to detectors, execute decisions. Currently ~800 LoC inline in `main`. |
| `agent/src/loops/slow_loop.rs` | Body of the 30-second tick: narrative, telemetry, data retention, correlation, baseline, attacker intel. ~600 LoC inline. |
| `agent/src/loops/boot.rs` | `main()`'s construction of `AgentState` — config load, sqlite open, AI provider creation, skill registry, mesh init, shield init. ~400 LoC. |
| `agent/src/process/incidents.rs` | `process_incidents` + its helpers (already part-extracted in `incident_*` modules; finish the job). ~400 LoC. |
| `agent/src/process/telegram_approval.rs` | `process_telegram_approval` + callback dispatch. ~200 LoC. |
| `agent/src/process/post_decision.rs` | Post-decision audit trail + correlation-boost logic currently inline. ~150 LoC. |
| Remaining `main.rs` | Argument parsing, signal handling, top-level `tokio::select!`. ≤800 LoC. |

Each new module gets at least three `#[cfg(test)]` tests that cover a
non-trivial branch of its logic. The orchestration modules
(`fast_loop`, `slow_loop`) need a minimal `AgentState` builder in
`tests::fixtures` so unit tests can invoke them with mocked dependencies.

**Acceptance**:
- `crates/agent/src/main.rs` ≤ 1,500 LoC.
- `cargo tarpaulin -p innerwarden-agent` reports ≥ +5pp on the agent
  crate vs pre-change baseline.
- `make replay-qa` passes unchanged.
- Diff of runtime output on prod sample: no new lines, no reordering.

### Phase B — `skills/builtin/honeypot/mod.rs` decomposition

**Target**: 3,206 LoC → submodules.

Proposed layout (honeypot subdir already exists with `ssh_interact.rs`,
`http_interact.rs`, `fake_shell.rs`, `custom_responses.rs`):

| New module | Extracts |
|---|---|
| `honeypot/session.rs` | Session lifecycle state machine (connect → auth → shell → cleanup). |
| `honeypot/banner.rs` | Service banner generation (SSH, HTTP, Telnet, custom). Pure functions. |
| `honeypot/containment.rs` | Namespace / jail / subprocess launching for the interactive handler. I/O-heavy but the command construction is pure. |
| `honeypot/pcap_handoff.rs` | tcpdump spawn + filter rotation logic. Command construction is pure. |
| `honeypot/audit.rs` | Session JSONL writer + rotation. |
| Remaining `mod.rs` | Skill trait impl + public entry points. ≤ 500 LoC. |

**Acceptance**:
- `mod.rs` ≤ 500 LoC.
- `cargo tarpaulin -p innerwarden-agent` reports ≥ +3pp on the agent
  crate vs post-Phase-A baseline.
- Zero change to honeypot session format (forensics JSONL byte-identical
  on a replayed session).

### Phase C — `agent/src/telegram.rs` decomposition

**Target**: 3,472 LoC → submodules.

Proposed layout:

| New module | Extracts |
|---|---|
| `telegram/client.rs` | `TelegramClient` struct + HTTP request/retry/rate-limit. No formatting. |
| `telegram/formatting.rs` | Message building, HTML escape, severity emoji, incident summary, keyboard construction. All pure. |
| `telegram/templates.rs` | Static message templates (onboarding, 2FA prompt, daily briefing). Pure. |
| `telegram/burst.rs` | `BurstTracker` and rate-limit helpers already close to isolated; finish the extraction. |
| Remaining `telegram.rs` | Module barrel + `TelegramProvider` wiring for `AgentState`. |

**Acceptance**:
- Pure formatting module ≥ 80% unit coverage.
- HTTP client module tested against a mock response (no real Telegram API).
- `cargo tarpaulin -p innerwarden-agent` reports ≥ +2pp on the agent
  crate vs post-Phase-B baseline.

## Sequencing

Three sequential PRs (A → B → C). Phase B can overlap with late Phase A
if separate contributors, but dependencies make serial the safer choice.
Total: **3 AI sessions, 3 PRs**.

## Acceptance criteria

* [ ] `main.rs` decomposed per Phase A.
* [ ] `honeypot/mod.rs` decomposed per Phase B.
* [ ] `telegram.rs` decomposed per Phase C.
* [ ] Project coverage (measured with `cargo tarpaulin 0.33 --workspace`
  after this spec plus spec 023's batches re-baselined): ≥ 58% (base for
  spec 023 stretch goal of 65% with future batches on the newly exposed
  modules).
* [ ] `make replay-qa` passes unchanged.
* [ ] `make test` passes, no test file edited beyond import paths or
  moved test modules.
* [ ] Production canary on the server (ubuntu@130.162.171.105): 10-min
  sample of agent output before vs after, `diff -u` clean.

## Non-goals

* Adding new behavior or new skills.
* Refactoring `ctl/harden.rs` or `ctl/commands/ops.rs`. Those are spec
  023 batch targets; they stay unit-test-only until a separate
  decomposition spec picks them up.
* Splitting dashboard HTTP handlers — that's spec 022's territory.
* Changing the agent's top-level binary interface, CLI flags, or config
  file shape.

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| Moving a function breaks a call site we missed | `cargo check --workspace` + `cargo clippy --workspace -- -D warnings` + `make test` on every commit, before opening the PR. |
| Submodule visibility too tight or too loose | Default to `pub(crate)`. Widen only when another module genuinely needs access. Reviewer checks the `pub` count in the diff. |
| Replay QA drift (output differs after refactor) | Run `scripts/replay_qa.sh` locally on both the old and new binary, diff the resulting `events-*.jsonl` + `incidents-*.jsonl`. Zero difference is the gate. |
| Test fixtures grow into a parallel state machine | Keep fixtures minimal — a single `fn test_agent_state_minimal() -> AgentState` with all-defaults. If a test needs more, it builds inline. No fixture hierarchy. |
| Agent boot sequence depends on hidden ordering that decomposition reveals | Add a boot-order unit test that constructs the state step by step and asserts the sqlite store exists before the dashboard starts, etc. Catches hidden coupling. |

## Prompt for the executing AI

```
You are executing spec 026 (decomposition for testability).

Repo: /Users/maiconesteves/github/_innerwarden/innerwarden
Branch from origin/main. One phase per PR: 026-phase-A, -B, -C.
PR base: main. PR title: refactor(agent): phase <X> decomposition for testability.

INEGOCIABLE:
- Zero behavior change. If a test that passed before fails after, you
  broke something — revert and re-attempt the split smaller.
- cargo +1.95 clippy --workspace -- -D warnings clean.
- cargo +1.95 fmt --all --check clean.
- make test green.
- make replay-qa green.
- Each PR lands the split + the new tests for the extracted modules.
- Agent crate coverage must rise by the per-phase target (A: +5pp,
  B: +3pp, C: +2pp) measured with cargo tarpaulin 0.33.

For each phase:
1. Read the current file end-to-end before touching anything.
2. Draft the target module tree on paper. Validate with the spec.
3. Do the moves in one commit, then add tests in a second commit.
4. Run tarpaulin locally. If the coverage target isn't met, add more
   tests until it is, in a third commit.
5. Open the PR.

PROHIBITED:
- Editing behavior while moving. If a bug is visible during the move,
  open a separate issue and keep moving.
- Introducing a new trait or abstraction "for future flexibility".
- Adding dependencies.
- Splitting below the module granularity proposed in the spec without
  justification in the PR body.

Start with Phase A (main.rs).
```

## References

* PR #125 result (the evidence that batches aren't enough): patch 72%,
  project drift −1.5pp (mostly tooling noise), +272 tests.
* Spec 023 (coverage closeout): the 11 batches that did everything
  unit-testable without decomposition.
* `crates/agent/src/main.rs:2740..2900`: `process_incidents` + call site
  for LLM — the single largest uncovered hot path.
* `crates/agent/src/skills/builtin/honeypot/mod.rs`: the 3,206-LoC state
  machine blocking coverage on the whole skills subsystem.
* `crates/agent/src/telegram.rs`: 3,472 LoC where pure template code is
  trapped behind HTTP client methods.
