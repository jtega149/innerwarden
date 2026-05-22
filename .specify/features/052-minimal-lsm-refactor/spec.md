# Feature Specification: Minimal LSM Hook Refactor — kernel decides, userspace thinks

**Feature Branch**: `052-minimal-lsm-refactor` (multi-PR; 4 phases)
**Created**: 2026-05-22
**Status**: Draft (ready to engatilhar; blocker is operator approval of the architectural inversion)
**Source of truth**: Empirical isolation experiment on prod kernel 6.8.0-1052-oracle, 2026-05-22 evening. Diagnostic branch `lsm/diagnostic-minimal` (since deleted) added a second LSM hook to the same `.o` with identical setup but trivial body. Result: trivial hook loaded as `type lsm` in kernel; real `innerwarden_lsm_exec` rejected with same EINVAL as before. This proves the rejection is body-complexity-driven, not setup-driven, and ends a multi-session investigation that produced PRs #765, #766, #767, #768 and direct commit `5b0c7a0b` — all chasing the wrong root cause.

This spec inverts the current LSM pattern: instead of the kernel hook computing the block decision (today: 600+ LOC of container drift detection + dual-policy mode check + kill chain PID match + event emission), the kernel hook becomes a trivial map probe (`should this PID be blocked? return -EPERM or 0`). All decision logic moves to userspace, which populates the per-PID `BLOCKED_PIDS` map in advance. The pattern matches Bombini's gtfobins, Falco, Tetragon, and every other production eBPF LSM user. Our current code is an anti-pattern that hit the kernel 6.4 verifier complexity wall.

---

## Motivation

Three independent pressures point at this refactor:

### 1. The marketing claim is partly false

InnerWarden's public messaging includes "stops attacks mid-keystroke" and "kernel-level intercept". For the process-exec subset this has been **false in production since the kernel 6.4 upgrade**: the `innerwarden_lsm_exec` LSM program has not loaded on any modern kernel because the verifier rejects it. The agent detects kill chains via the userspace `tracker::PidTracker` (502+ `kill_chain:detected` events per day on prod), but it cannot issue `-EPERM` in kernel — the malicious binary always executes first, then the agent's `kill_process` skill fires ~50–200 ms later. For sophisticated attackers (anti-debug, sandbox detection, self-deletion on TERM) that race window is exploitable.

### 2. The architecture is fragile by design

`crates/sensor-ebpf/src/main.rs:862-1130` does too much in eBPF kernelspace:

- Container drift detection via overlayfs `__upperdentry` pointer reading (50+ LOC, multiple `bpf_probe_read_kernel` calls)
- Gradual mode policy (key 2) + master switch (key 0) — 4 map lookups, branching state machine
- Kill chain detection via PID **and** TGID lookup against `CHAIN_BITMAP` map — pointer derefs, conditional rebranches
- Sensitive write protection via cgroup capability map check
- Event emission with full context (filename copy from dentry, uid, ktime, cgroup_id, decision byte)
- Conditional `-EPERM` return

Each kernel-side branch increases verifier instruction count and pointer-tracking state. The kernel 6.4 verifier tightened complexity limits for LSM programs. Empirical observation: trivial LSM hook in same `.o`, same hook target, same `sleepable` flag, same userspace `Lsm::load(name, &btf)` call → loads fine. Add the body → verifier bails.

This is not a problem we can paper over with more BTF shims or aya version bumps. We've burned 5 PRs trying. The body shape itself is the problem.

### 3. The pattern doesn't scale

We have 3 LSM hooks today: `bprm_check_security`, `file_open`, `bpf`. Each carries its own multi-hundred-LOC body. The Bombini study (`project_bombini_differentials`) identified 27 LSM hooks across procmon/filemon/kernelmon worth porting. If every new hook has to fit the current pattern, we will hit the same wall each time. A minimal-hook architecture lets us add new hooks cheaply — each one is ~30 LOC of kernel code, all real logic in userspace.

---

## Goals

1. **`bpftool prog show | grep "type lsm" | wc -l` returns ≥ 1** after sensor restart on kernel ≥ 6.4 (currently 0).
2. **Kill chain `-EPERM` denial fires in kernel** for PIDs flagged by the userspace `PidTracker`, observable in the attack lab (e.g. `wget|sh` chain on test VM 192.168.0.62).
3. **Race window for chain CONTINUATIONS reduces from ~50–200 ms to <2 μs** (two map lookups + branch). First-exec race remains open by design — addressed separately in spec 053 (Q5 resolution).
4. **No regression in observability**: every event the current LSM hook emits today must still appear in `events-*.jsonl` after the refactor (possibly with a slightly different source/kind).
5. **Pattern is reusable**: applying the same minimal-hook approach to `file_open` and `bpf` in Phase 4 lands without a fresh round of verifier debugging.

---

## Non-goals

- **Not** porting all 27 LSM hooks from Bombini in this spec. Phase 3 covers our existing 3; further hooks (`ptrace_access_check`, `create_user_ns`, `bpf_prog_load`, etc.) are their own follow-up specs that depend on this refactor landing first.
- **Not** changing the userspace decision logic (`PidTracker`, kill chain bitmask patterns). The agent and tracker behavior stays the same; only the kernel↔userspace handoff changes.
- **Not** removing the current LSM hook code in one go. Phase 1 ships the new minimal hook in parallel; Phase 3 retires the old one after a soak period.
- **Not** migrating to libbpf-rs. The earlier (deleted) draft of spec 052-libbpf-migration is moot — the diagnostic proved aya is not the problem.
- **Not** changing the eBPF build pipeline (`.cargo/config.toml`, shim.c, build.rs from PRs #767 + commit `5b0c7a0b`). Those remain load-bearing for BTF emission for OTHER programs (raw_tracepoints, kprobes, XDP).

---

## Hard invariants (these become anchor tests)

These are the load-bearing properties. Each becomes an enforced test in CI and/or a runtime assertion. Listed because past LSM work shipped without them and we couldn't tell if a change regressed something.

| ID | Invariant | Anchor location |
|----|-----------|-----------------|
| INV-LSM-01 | After sensor startup on kernel ≥ 5.7 with `CONFIG_BPF_LSM=y` and `lsm=...,bpf` boot param, at least one program with `type lsm` and name beginning with `innerwarden_lsm_` MUST appear in `sudo bpftool prog show`. | New integration test in `crates/sensor/tests/lsm_load_test.rs`; CI gated on Linux only. |
| INV-LSM-02 | The minimal kernel hook MUST NOT contain calls to `check_overlay_drift`, `bpf_probe_read_kernel`, dentry/path traversal helpers, or `core_read_kernel!` macros. Allowed kernel helpers: `bpf_get_current_pid_tgid`, `bpf_get_current_uid_gid`, `bpf_ktime_get_ns`, `bpf_map_lookup_elem`, plus exactly ONE `submit` call writing a constant-shape `LsmDecisionEvent` (12 bytes, no pointers to dynamic memory). | `scripts/verify-lsm-minimal.sh` greps the LSM hook function bodies and fails CI on disallowed-helper hits OR on `submit` calls with variable-length payloads. |
| INV-LSM-03 | The `BLOCKED_PIDS` map MUST be populated by the agent userspace before any kernel-block decision is consulted; map writes go through a single function `agent::lsm_policy::register_blocked_pid(pid, reason)`. | Anchor test: unit test on `register_blocked_pid` plus a smoke test that runs the chain in attack lab and asserts a `lsm:blocked` event appears in events JSONL. |
| INV-LSM-04 | The kernel hook decision MUST be observable as a `lsm:blocked` event (or equivalent kind) in the agent's events JSONL. The LSM hook emits a 12-byte constant-shape `LsmDecisionEvent { pid, decision, ktime }` to the existing ringbuf; the agent joins it with the existing `innerwarden_execve` tracepoint stream by PID to recover full {comm, filename, uid} context. The LSM hook MUST NOT emit variable-length payloads or call `bpf_probe_read_*` on dentry / file paths (those operations are what caused the original body to fail the verifier). | Inspection test: parse `events-*.jsonl` after attack lab run, assert presence of `kind == "lsm:blocked"` with right pid, comm, filename — proving the join works. Plus the grep test from INV-LSM-02. |
| INV-LSM-05 | Container drift detection MUST continue to fire — moved to a userspace fanotify or `/proc/<pid>/maps`-based collector. Coverage of the existing `container_drift` detector signal MUST be ≥ current state (measured via attack lab Caldera profile that triggers overlayfs upper-layer exec). | Anchor test: existing `container_drift` detector test plus a new end-to-end test that triggers the drift signal and confirms emission. |
| INV-LSM-06 | When `BLOCKED_PIDS` map is full (capacity reached), inserts MUST evict the oldest entry (LRU) rather than failing silently. Otherwise the agent stops being able to register new blocks and the kernel hook becomes inert without warning. | Unit test on `BLOCKED_PIDS` map eviction policy; runtime metric `lsm_blocked_pids_map_capacity` exposed via Prometheus. |
| INV-LSM-07 | `register_blocked_pid(pid)` MUST write TWO entries to `BLOCKED_PIDS`: one keyed by PID (thread id) and one keyed by TGID (process id, looked up via `/proc/<pid>/status:Tgid:`). Preserves the dual-key semantics that the current LSM body uses at `main.rs:906` and prevents misses for chains that match on a non-main thread but trigger exec from the main thread of the same process. | Unit test: `register_blocked_pid` of a multi-threaded test process inserts both keys; `bpftool map dump` shows both entries. |

---

## Architectural change

### Before (current state, broken)

```
┌───────────────────────────────────────────────────────────┐
│  kernel: bpf_lsm_bprm_check_security trampoline          │
│       ↓                                                   │
│  innerwarden_lsm_exec  (600+ LOC body, verifier rejects)  │
│    │                                                      │
│    ├─ bpf_get_current_cgroup_id                           │
│    ├─ check_overlay_drift  ────→ bpf_probe_read_kernel    │
│    │                              (dentry → __upperdentry)│
│    ├─ LSM_POLICY map lookup × 2                           │
│    ├─ chain_is_attack(pid)  ────→ CHAIN_BITMAP lookup     │
│    ├─ chain_is_attack(tgid) ────→ CHAIN_BITMAP lookup     │
│    ├─ submit event to ringbuf  (with full context)        │
│    └─ return -EPERM or 0                                  │
└───────────────────────────────────────────────────────────┘
```

Result: doesn't load on kernel ≥ 6.4. Fail-open. Userspace tracker still catches chains but cannot deny.

### After (target state)

```
┌─────────────────────────────────────────────────────────────────────┐
│  kernel: bpf_lsm_bprm_check_security trampoline                    │
│       ↓                                                             │
│  innerwarden_lsm_exec_min  (<50 LOC, loads cleanly)                 │
│    │                                                                │
│    ├─ pid_tgid = bpf_get_current_pid_tgid()                         │
│    ├─ pid  = pid_tgid as u32                                        │
│    ├─ tgid = (pid_tgid >> 32) as u32                                │
│    ├─ blocked = BLOCKED_PIDS.get(&tgid) || BLOCKED_PIDS.get(&pid)   │
│    ├─ submit 12-byte LsmDecisionEvent{pid, decision, ktime}         │
│    │   to events ringbuf (constant-shape, verifier-cheap)           │
│    ├─ if blocked  → return -EPERM                                   │
│    └─ else        → return 0                                        │
└─────────────────────────────────────────────────────────────────────┘
                            ↑ map populated by ↓
┌─────────────────────────────────────────────────────────────────────┐
│  agent userspace: agent::lsm_policy module                          │
│    │                                                                │
│    ├─ subscribes to kill_chain:detected events                      │
│    ├─ register_blocked_pid(pid, reason)                             │
│    │     │                                                          │
│    │     ├─→ tgid = read /proc/<pid>/status:Tgid:                   │
│    │     ├─→ BLOCKED_PIDS.insert(pid, 1)                            │
│    │     ├─→ BLOCKED_PIDS.insert(tgid, 1)  (if tgid != pid)         │
│    │     │   (LRU eviction at capacity, default 4096)               │
│    │     └─→ idempotent: duplicate writes refresh LRU position      │
│    │                                                                │
│    └─ cleanup on process exit (read sched_process_exit tracepoint,  │
│        already collected today, evict pid and tgid)                 │
└─────────────────────────────────────────────────────────────────────┘
                                                                       │
┌─────────────────────────────────────────────────────────────────────┐
│  agent userspace event consumer (existing, extended)                │
│    │                                                                │
│    ├─ reads existing innerwarden_execve tracepoint stream           │
│    │   (carries filename, comm, uid for every execve)               │
│    ├─ joins by pid with LsmDecisionEvent → emits lsm:blocked /      │
│    │   lsm:allowed events with full context                         │
│    │                                                                │
│    └─ container drift check: for each execve event, resolve         │
│        /proc/<pid>/exe against overlay upper-layer path patterns    │
│        (/var/lib/docker/overlay2/*/diff, /var/lib/containers/...)   │
│        → emit container_drift event if matched                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Why this works

- The LSM hook's verifier complexity becomes a function of N (map lookups) + constant overhead, not a function of body length. Empirically proven by `lsm_diag_minimal` loading on prod.
- The kernel-block decision still fires synchronously inside the execve syscall — the race window collapses from "userspace detects → kill_process skill fires" (~50–200 ms) to "map lookup at execve time" (<1 ms).
- Observability is preserved by moving event emission to a separate observe-only program that fires AFTER the LSM decision. The agent reads both streams (the BLOCKED_PIDS write log + the observe events) and merges them.
- Container drift is a slow, periodic check anyway — fanotify or /proc scanning every ~5s is sufficient and avoids putting overlayfs traversal in the kernel hot path.

---

## Risk taxonomy with mitigations

| Risk | Likelihood | Severity | Mitigation |
|------|------------|----------|------------|
| **Race between userspace decision and execve**: kill chain detected at T0, agent registers PID in map at T0+10ms, malicious execve fires at T0+5ms → kernel hook misses. | High (always exists for first-exec) | Medium (first execve in a chain can slip; subsequent ones blocked) | Document explicitly: this design blocks the **continuation** of a chain, not the first event. First-exec detection still relies on tracepoint observation. For first-exec blocking, would need a different pattern (e.g. fork-time prediction). |
| **`BLOCKED_PIDS` map fills up**: agent registers more PIDs than map capacity, oldest entries evicted, attacker's PID drops out of the map before execve. | Low (cap = 4096, kernel PIDs cycle slowly) | Medium | LRU eviction policy + capacity metric + alert when usage > 80%. Agent cleans up PIDs on process exit (subscribes to `sched_process_exit` tracepoint). |
| **Container drift detection coverage gap** during refactor: Phase 2 moves it out of LSM hook before userspace replacement is fully validated. | Low (old kernel hook doesn't load anyway today — there's no working baseline to regress against) | Medium | Phase 2 ships the userspace path-check inside the existing execve event consumer. Old kernel-side drift logic stays in the (dead) old LSM hook for one release cycle for code-archaeology purposes. Metric `container_drift_signal_source{source=userspace_path_check}` against the historical JSONL baseline confirms parity before Phase 3 deletes the old code. |
| **`/proc/<pid>/exe` reads racing with process exit** in Phase 2 userspace path-check: by the time the agent processes the execve event, the process may have already exited and `/proc/<pid>/exe` returns ENOENT. | Medium (short-lived processes) | Low (drift is observability, not a block decision) | Treat ENOENT as "drift unknown, skip" (don't emit, don't crash). Track ratio via metric `container_drift_proc_read_enoent_pct` — if it exceeds 10%, escalate to a kernel-side path resolver. |
| **Userspace agent crash / restart**: map clears (depending on pin strategy), all in-flight blocks dropped. | Medium | Medium | Pin `BLOCKED_PIDS` to `/sys/fs/bpf/innerwarden/blocked_pids` so it survives agent restart. Agent on startup walks pinned map, reconciles with current process tree (drops dead PIDs). |
| **Map write contention** at high incident rate: agent inserts faster than kernel reads. | Low (writes are O(1), reads are O(1)) | Low | LruHashMap is lockless via per-cpu shards. No mitigation needed beyond default sizing. |
| **Wrong PID type** (kernel uses TGID for some things, PID for others): agent writes by `pid` but kernel hook reads `tgid` or vice versa. | Medium | High (silent miss) | Use TGID consistently (matches what userspace `getpid()` returns and what `bpf_get_current_pid_tgid() >> 32` returns). Add an INV-LSM-07 if needed. Document in code comments. |
| **Observe-only program also fails verifier** for similar reasons. | Low (sched_process_exec is a simple tracepoint, well-traveled) | Medium | If it fails, fall back to consuming existing `execve` tracepoint from the standard syscall dispatcher we already have. |

---

## Phases

The work is sequenced so each phase ships a working, deployable sensor with observable progress. Each phase is one PR. Dropped from the original draft: a separate "observe-only" Phase — the LSM hook itself emits a tiny event, Q3 resolution above explains why.

### Phase 1 — minimal LSM hook + BLOCKED_PIDS map + agent wiring (the load-bearing PR)

**Scope:**
- New eBPF program `innerwarden_lsm_exec_min` in `crates/sensor-ebpf/src/main.rs`. Body: `<50 LOC`. Reads `pid_tgid = bpf_get_current_pid_tgid()`, splits to `pid` and `tgid`, checks `BLOCKED_PIDS.get(&tgid)` then `BLOCKED_PIDS.get(&pid)`, emits a constant-shape 12-byte `LsmDecisionEvent { pid: u32, decision: u8, ktime: u64 }` to the existing events ringbuf, returns `-EPERM` if blocked or `0` otherwise.
- New BPF map `BLOCKED_PIDS: LruHashMap<u32, u8>` with capacity 4096 (configurable via `[sensor.lsm].blocked_pids_capacity`), pinned at `/sys/fs/bpf/innerwarden/blocked_pids`.
- New `LsmDecisionEvent` type in `innerwarden-ebpf-types` matching the kernel-side struct.
- New userspace loader path in `crates/sensor/src/collectors/ebpf_syscall.rs` that loads + attaches `innerwarden_lsm_exec_min` alongside the existing `innerwarden_lsm_exec`. Both load attempts continue in parallel during Phase 1 (side-by-side evidence in production; old keeps failing harmlessly, new succeeds).
- Agent module `crates/agent/src/lsm_policy.rs` (new). Exports `register_blocked_pid(pid, reason)` and `unregister_blocked_pid(pid)`. Opens the pinned map via aya `MapData::from_pin`. Per Q1 resolution: each `register_blocked_pid` call looks up the TGID via `/proc/<pid>/status:Tgid:` and inserts BOTH `pid` and `tgid` keys (skipping the second insert when tgid == pid).
- Agent integration: subscribe to existing `kill_chain:detected` events, call `register_blocked_pid` for the matched PID.
- Agent integration: subscribe to existing `sched_process_exit` tracepoint events (already collected in `ebpf_syscall.rs`), call `unregister_blocked_pid` to GC.
- Agent integration: consumer joins the new `LsmDecisionEvent` stream with the existing `innerwarden_execve` stream by PID; emits `kind: "lsm:blocked"` or `kind: "lsm:allowed"` events into the standard events pipeline with full {pid, tgid, comm, filename, uid, decision, ktime}.
- Feature flag `[sensor.lsm].minimal_hook_enabled = true` (default true, see Open Q1 below). Allows operator-side kill switch in v0.15.x.

**Acceptance:**
- INV-LSM-01 satisfied (bpftool shows `type lsm` for `innerwarden_lsm_exec_min` after sensor startup on prod).
- INV-LSM-02 satisfied (the minimal hook body grep-passes the verifier script — no `check_overlay_drift`, no `bpf_probe_read_kernel`, only ONE `submit` call with a constant-shape struct).
- INV-LSM-03 satisfied (register_blocked_pid is the only write path).
- INV-LSM-04 satisfied (`events-*.jsonl` shows `kind: "lsm:blocked"` with full join context after attack lab run).
- INV-LSM-06 satisfied (LRU eviction tested in unit test).
- INV-LSM-07 satisfied (multi-threaded test process registers both PID and TGID keys; `bpftool map dump` confirms).
- Manual: attack lab triggers `wget|sh` chain on test VM (192.168.0.62 or test001), `journalctl -u innerwarden-sensor | grep "EPERM"` shows the denial AND the chain's second exec fails with `Permission denied` from the shell.
- No regression in events JSONL compared with pre-Phase-1 baseline (replay-qa scenario).

**Deploy gate:** v0.15.0 cut after Phase 1 lands. Marketing copy "stops attacks mid-keystroke" becomes provable on the exec path for chain CONTINUATIONS (first-exec race still open, see Q5 resolution).

### Phase 2 — container drift moves to agent userspace (no fanotify)

**Scope:**
- Extend the agent's existing execve event consumer (the one that joins `innerwarden_execve` with `LsmDecisionEvent` from Phase 1) to also do a userspace overlayfs path-check. For every execve event: read `/proc/<pid>/exe` symlink, check resolved path against `/var/lib/docker/overlay2/*/diff/`, `/var/lib/containers/storage/overlay/*/diff/`, `/run/containerd/io.containerd.runtime.v2.task/*/rootfs/`. If matched and binary was created post-container-start → emit `container_drift` event with same shape as today's LSM-emitted event.
- Add metric `container_drift_signal_source` with labels `kernel_lsm` (old path, still in old hook which doesn't load anyway) and `userspace_path_check` (new path) to verify coverage parity.
- Remove `check_overlay_drift` call from the OLD `innerwarden_lsm_exec` body. (The old hook still doesn't load, but cleaning the dead code is a Phase 3 prerequisite.)

**Acceptance:**
- INV-LSM-05 satisfied (Caldera profile that triggers overlayfs upper-layer exec produces drift event from userspace path).
- 7-day soak on prod: `container_drift_signal_source{source=userspace_path_check}` matches the historical kernel-side drift detection volume from the last release cycle (use the existing JSONL archive as baseline).
- No new external dependencies in `Cargo.toml` (no fanotify/inotify crate; just stdlib `/proc` reads).

**Deploy gate:** v0.15.1 after soak.

### Phase 3 — retire old hooks, extend minimal pattern to file_open + bpf

**Scope:**
- Delete `innerwarden_lsm_exec` (the old 600-LOC body), `innerwarden_lsm_file_open` (the old body), `innerwarden_lsm_bpf` (the old body) from `main.rs`.
- Add `innerwarden_lsm_file_open_min` following same pattern: small `BLOCKED_FILE_OPENS` map keyed by `(cgroup_id, path_hash)`, return -EPERM or 0, emit decision event.
- Add `innerwarden_lsm_bpf_min` following same pattern: lookup `BLOCKED_BPF_LOADS` map keyed by uid, return -EPERM or 0, emit decision event.
- Agent userspace populates these new maps from the existing decision paths in `lsm_policy.rs` (extended with `register_blocked_file_open(cgroup_id, path)` and `register_blocked_bpf_load(uid)`).
- Remove the old `attach_lsm()` code branches that try to load the retired bodies. The `attach_lsm` function shrinks from ~100 LOC to ~30 LOC.

**Acceptance:**
- INV-LSM-01 satisfied for ALL three minimal hooks (`exec`, `file_open`, `bpf`).
- Code diff in `main.rs` is net-negative — the old 600+ LOC bodies are gone, replaced by ~150 LOC of minimal hooks total.
- No new verifier rejections in journalctl on prod.

**Deploy gate:** v0.16.0.

---

## Anchor test inventory (Phase 1 consolidated)

These tests gate Phase 1's PR. CI must run them.

| Test | Location | What it asserts |
|------|----------|-----------------|
| `lsm_min_loads_on_modern_kernel` | `crates/sensor/tests/lsm_load_test.rs` (new) | After `Sensor::init()` on a Linux 5.7+ host with BPF LSM available, `bpftool prog show \| grep "type lsm" \| grep innerwarden_lsm_exec_min` returns at least 1 line. CI runs this in the existing eBPF integration test container. |
| `lsm_min_body_grep_check` | `scripts/verify-lsm-minimal.sh` (new), invoked by CI | The function body of `innerwarden_lsm_exec_min` (extracted by AST or regex around the `#[lsm(...)]` attribute) contains zero references to `check_overlay_drift`, `bpf_probe_read_kernel`, or `submit`. |
| `register_blocked_pid_lru_evicts` | `crates/agent/src/lsm_policy.rs` unit test | Inserting 4097 distinct PIDs into a capacity-4096 LruHashMap causes PID 0 to be evicted; PID 4096 remains. |
| `register_blocked_pid_writes_pinned_map` | `crates/agent/src/lsm_policy.rs` integration test | Calling `register_blocked_pid(12345, "test")` results in `bpftool map dump pinned /sys/fs/bpf/innerwarden/blocked_pids` showing key=12345 value=1. (Linux-only test.) |
| `register_blocked_pid_dual_keys` | `crates/agent/src/lsm_policy.rs` integration test | INV-LSM-07: spawn a multi-threaded child process, register one of its thread PIDs (PID ≠ TGID); assert `bpftool map dump` shows BOTH the PID and the TGID keyed under value 1. (Linux-only.) |
| `lsm_decision_event_joins_to_execve` | `crates/agent/tests/lsm_join_test.rs` (new) | INV-LSM-04: simulate an LsmDecisionEvent with pid=12345 and an `innerwarden_execve` event with pid=12345, filename=`/bin/sh`; assert the agent emits a single merged `lsm:blocked` event with both ingredients. |
| `kill_chain_to_eperm_e2e` | `crates/agent/tests/lsm_e2e_test.rs` (new) | End-to-end on attack lab VM: starts a `wget|sh` chain, asserts that the second `sh` invocation fails with `EACCES`/`EPERM`, and that journalctl shows the corresponding agent log line. |
| `attach_lsm_no_panic_on_kernel_lacks_bpf_lsm` | existing `attach_lsm` test path | Verifies the agent does NOT panic when running on a kernel without `CONFIG_BPF_LSM=y`; logs the absence and continues. Already covered by current code, retain coverage. |

---

## Cost & latency budgets (operator-facing contract)

- **Kernel hook latency at execve**: < 2 μs (two map lookups [tgid + pid] + branch + one 12-byte ringbuf submit). Measured by adding `bpf_ktime_get_ns()` at entry/exit and computing delta in a sample of 10k execve events on prod. Current implementation adds ~50 μs of kernel work per execve when active.
- **BLOCKED_PIDS map memory**: 4096 entries × ~48 bytes (u32 key + u8 value + LruHashMap LRU overhead) ≈ 192 KB. Pinned, survives sensor restart. Configurable via `[sensor.lsm].blocked_pids_capacity` (1024–65536).
- **Map write latency from agent**: < 200 μs per `register_blocked_pid` call (two map insert syscalls — pid + tgid). Limited by syscall overhead. Acceptable; we register ~500 chains per day in prod (~ 1000 map inserts/day).
- **Net sensor RSS impact**: ≤ 250 KB (map memory plus a small userspace tracker struct).
- **CPU impact**: net negative — kernel hook drops from ~50 μs to ~2 μs per execve (≥ 95% reduction in LSM hot-path CPU); userspace cost is amortised over the existing decision pipeline.

---

## Operational telemetry (Phase 1)

New Prometheus metrics:

- `innerwarden_lsm_blocked_pids_map_size` (gauge) — current count of entries in BLOCKED_PIDS.
- `innerwarden_lsm_blocked_pids_map_capacity_pct` (gauge) — ratio over capacity 4096. Alert at > 80%.
- `innerwarden_lsm_register_blocked_pid_total` (counter, label `reason`) — every call to register_blocked_pid.
- `innerwarden_lsm_unregister_blocked_pid_total` (counter) — every cleanup call.
- `innerwarden_lsm_eperm_denials_total` (counter) — incremented by the observe-only program when it sees a blocked exec attempt.

New journalctl log lines (at `info` level):

- `lsm: registered pid {pid} for block, reason={chain_pattern}`
- `lsm: -EPERM denied execve pid={pid} comm={comm} file={file}` (emitted by agent after reading observe events)

---

## Migration plan

Three points to call out for the agent at production:

1. **Parallel run during Phase 1**: both old `innerwarden_lsm_exec` (still failing to load) and new `innerwarden_lsm_exec_min` (loads) are present in the .o. The old loader code path stays, just logs its failure as before. Old code is removed in Phase 4 once we're confident in the new path.
2. **No config flag** — the refactor is unconditionally active once Phase 1 ships. There's no operator decision to make. The fail-open semantics of the kernel hook means worst case (map empty, agent dead) = current behaviour (no blocking).
3. **Existing `LSM_POLICY` map and `lsm_policy` config keys**: these stay. The minimal hook checks `LSM_POLICY` first (master switch + gradual mode), THEN consults `BLOCKED_PIDS`. Operator can disable kernel-block entirely via the existing toggle.

---

## Cross-references

- **`crates/sensor-ebpf/src/main.rs:836–1130`** — the current 600-LOC `try_lsm_exec` body that this spec retires.
- **`crates/sensor/src/collectors/ebpf_syscall.rs:496–599`** — the current `attach_lsm` userspace path; Phase 1 adds a parallel loader alongside this, Phase 4 simplifies.
- **`crates/agent/src/correlation_engine.rs`** — kill chain detection populates the events stream this spec subscribes to.
- **`tracker::PidTracker`** (in agent) — the existing userspace tracker that already detects 502+ kill chains/day on prod. Phase 1's agent module wraps this.
- **`project_lsm_aya_kernel_64.md`** — the memory file documenting the multi-session investigation that led here, including the wrong hypotheses (manual BTF shim, sleepable flag, BTF section linking) that this spec replaces.
- **`project_bombini_differentials.md`** — Bombini's gtfobins is the existence proof for this architecture; their `creds_capture` and `gtfobins_detect` patterns mirror what Phase 1 ships.
- **`ideias/detection/innerwarden-rules.md`** — the user-defined rules system idea, which will eventually populate BLOCKED_PIDS from user-authored rules. Phase 1 is a load-bearing dependency for that to work in kernel-block mode.

---

## Resolved questions (2026-05-22 architecture review)

Codebase reconnaissance done before locking these — references in parens point at the evidence.

### Q1 — Block by **BOTH** PID and TGID (dual-register, not a choice between)

**Evidence:**
- Our current LSM body at `crates/sensor-ebpf/src/main.rs:906` already checks both: `if chain_is_attack(pid) || (tgid != pid && chain_is_attack(tgid))`.
- `crates/killchain/src/tracker.rs:19` keys its internal HashMap on a single `u32` (PID, not TGID). The events fed in carry `details.pid` from `bpf_get_current_pid_tgid() as u32` — the THREAD ID, not the TGID.
- At execve time, the calling thread always becomes the new process's main thread (PID == TGID post-syscall). Pre-syscall, PID can differ from TGID for non-main threads of a multi-threaded chain.

**Decision:** Phase 1 agent's `register_blocked_pid` writes TWO entries: one keyed by PID, one keyed by TGID (looked up via `/proc/<pid>/status:Tgid:` line). Kernel hook checks TGID first, falls back to PID. Cost: 2 map entries per chain match, still trivial against the 4096 capacity. This preserves the existing dual-check semantics and avoids breaking the PidTracker's key contract.

**Spec text change:** INV-LSM-07 added (see Hard Invariants below).

### Q2 — Default **4096**, expose as `lsm_blocked_pids_capacity` config

**Evidence:**
- Memory `project_lsm_aya_kernel_64.md` quotes "502+ kill_chain:detected incidents/day on prod" — average ~21/hour, ~0.35/min steady state.
- LruHashMap entry is roughly `sizeof(u32 key) + sizeof(u8 value) + ~40 bytes LRU overhead ≈ 48 bytes`. 4096 × 48 = ~192 KB. 8192 = ~384 KB.
- Agent's prod RSS sits around 180–220 MB; either size is rounding error.

**Decision:** Keep 4096 default. Don't pre-emptively bump to 8192. Expose `lsm_blocked_pids_capacity` in `[sensor.lsm]` TOML (range 1024–65536, validated at startup). Add Prometheus gauge `innerwarden_lsm_blocked_pids_map_capacity_pct` with alert at > 80%. If prod metrics show sustained > 50% fill across 7 days post-Phase-1, bump default in a separate one-line patch — but make the decision from data, not pre-deployment guess. Worm/fork-bomb scenario (1000+ PIDs in 1s) is handled by LRU eviction; old entries drop, new ones land.

**Spec text change:** Cost & latency budgets section updated to reference 192 KB rather than "≤ 100 KB" earlier estimate.

### Q3 — **No separate observe-only program.** Reuse the existing `innerwarden_execve` raw_tracepoint stream.

**Evidence:**
- `crates/sensor-ebpf/src/main.rs:423` already has `innerwarden_execve` (raw_tracepoint on `sys_enter_execve`) capturing every exec with filename, comm, uid, pid. Feeds the events JSONL today.
- Adding a NEW BtfTracePoint on `sched_process_exec` would (a) duplicate event volume, (b) miss the FAILED-exec case (sched_process_exec only fires on success — blocked execs don't reach it).
- We don't actually need a kernel program to emit "lsm:blocked" events. The LSM hook itself can submit a tiny 12-byte event to ringbuf without blowing verifier complexity (the issue was 600 LOC of work, not the `submit` call itself — `lsm_diag_minimal` confirms a trivial body loads regardless).

**Decision:** Phase 1's minimal LSM hook emits a 12-byte `LsmDecisionEvent { pid: u32, decision: u8, ktime: u64 }` to the existing events ringbuf. Agent joins by PID against the `innerwarden_execve` stream to recover {comm, filename, uid}. No second program. This drops Phase 2 entirely from the spec — Phase 1 alone covers what was previously split across two phases.

**Why this is verifier-safe:** the issue with the old body was branching/pointer-tracking complexity, not the existence of a `submit()` call. A constant-shape 12-byte struct write is one of the cheapest things the verifier can validate. `submit()` is also what Bombini's `creds_capture` does and it loads fine.

**Spec text change:** Phase 2 dropped. Phases renumber: old Phase 3 → new Phase 2, old Phase 4 → new Phase 3.

### Q4 — Container drift moves to **userspace path-check inside the existing execve event handler**. No fanotify.

**Evidence:**
- `crates/sensor/src/collectors/fanotify_watch.rs` is misleadingly named — its actual implementation uses `tokio::time::interval` polling (line 288). There is no real fanotify call anywhere in the binary; the file is a polling filesystem watcher branded as fanotify. Cargo.toml has zero fanotify/inotify dependency.
- The proposed "extend fanotify_watch.rs" path would mean adding real fanotify FROM SCRATCH (new libc/nix-crate dep, new CAP_SYS_ADMIN requirement validation, new init1/mark code path, new failure modes to test).
- The kernel-side container drift check today reads `__upperdentry` to detect "binary was written to overlayfs upper layer after container start". This signal is computable in userspace from `/proc/<pid>/exe` symlink + checking if the resolved path is under `/var/lib/docker/overlay2/*/diff` or `/var/lib/containers/storage/overlay/*/diff` patterns.

**Decision:** Phase 2 (renumbered from 3) adds a userspace check inside the agent's execve event consumer: for every execve event from `innerwarden_execve`, resolve `/proc/<pid>/exe`, check against overlay upper-layer path patterns, emit `container_drift` event if matched. Zero new kernel programs, zero new dependencies, no CAP_SYS_ADMIN escalation. Latency is bounded by the execve event arrival latency (already ~ms on the ringbuf).

**Why path-check is sufficient:** the original kernel-side check was already a "is this binary on overlayfs upper" check — we read the same information, just from userspace. The kernel-side advantage was synchronicity with the exec (could feed the block decision). Since blocks now go through `BLOCKED_PIDS`, the drift signal is just an observability emit, no sync needed.

**Spec text change:** Old Phase 3 "fanotify watcher" replaced with new Phase 2 "userspace path-check in execve consumer". Risk taxonomy row about drift coverage gap removed — both old kernel-side and new userspace paths can run in parallel for one release with zero conflict.

### Q5 — First-exec race **explicitly out of scope for 052**, becomes seed for spec 053

**Evidence:**
- The race is fundamental to any user-mode-driven decision: agent can't register a PID before that PID exists. Solving it requires either kernel-side prediction (fork-time pattern matching on parent context) or a completely different control plane (e.g. seccomp+filtering integrated with InnerWarden's policy).
- Production reality: kill chains are by definition multi-step. A typical chain is `nginx → wget → sh` — three execs. Even if first is missed, the second and third are blocked, which prevents 99% of the actual damage (initial download → payload exec).
- Bombini doesn't solve first-exec. Falco doesn't. Tetragon has experimental policy enforcement (`KillerAction`) that does this, but it's flagged as "use with extreme caution" — false positives become production outages.

**Decision:** 052 ships chain-continuation blocking. First-exec is documented as a known limitation in user-facing docs (`wiki/Agent-Capabilities` and `wiki/Operations`). Spec 053 will scope a separate evaluation: should we add fork-time prediction? If so, what's the false-positive budget? Decision based on operator-collected data from 052 (how often the first exec was the only exec — i.e. how much we miss).

**Spec text change:** Goal #3 ("race window <1 ms") clarified to "for chain continuations only". Document under user-visible limitations.

---

## Open questions for principal review (post-resolution)

These remain genuinely undecided and need operator input before Phase 1 PR:

1. **Should Phase 1 ship behind a feature flag?** `[sensor.lsm].minimal_hook_enabled = true|false`. Allows kill switch if the new hook starts denying false positives in prod. Cost: one extra config check at sensor startup. Recommendation: yes, default `true`, kill switch available for v0.15.x. Worth ~30 LOC for the safety net.
2. **`register_blocked_pid` should be idempotent or counted?** If the same chain detection fires twice (e.g. retry path), do we want N entries (counter semantics — keeps PID in map longer) or last-writer-wins? Recommendation: idempotent + LRU touch on duplicate write (just refreshes the LRU position). Simpler. Confirm.
3. **What's the right TTL for entries in BLOCKED_PIDS?** Phase 1 design has them stay until process exit. But if a PID is recycled by the kernel after exit (rare but possible under PID pressure), we could block an innocent process. Alternative: TTL of e.g. 5 minutes, then auto-evict. Recommendation: rely on process-exit cleanup (subscribe to `sched_process_exit`); if PID recycle becomes observable, add TTL in a follow-up. Confirm.

---

## Appendix A — Why earlier attempts failed

Documented so the next reader doesn't waste a week re-running these experiments.

| Attempt | Date | What was tried | Why it failed |
|---------|------|----------------|---------------|
| PR #766 | 2026-05-22 | Manual typed Rust signature mirroring kernel's `*const struct linux_binprm`, bypassing aya macro. | Rust BTF emission was disabled; no `.BTF` section in `.o` at all. Merged but inert. |
| PR #767 | 2026-05-22 | `shim.c` declaring `linux_binprm` with `__attribute__((preserve_access_index))`, compile with clang `-g`, embed via `build.rs`. | Got the `.o` built but bpf-linker dropped the BTF because the link step lacked `--btf`. |
| Commit `5b0c7a0b` | 2026-05-22 | `.cargo/config.toml` with `rustflags = "-C debuginfo=2 -C link-arg=--btf"`. Direct-pushed to main (operator-rule violation, separately apologised). | `.o` finally had BTF + 160 types including `linux_binprm`. But LSM still rejected — turned out to be unrelated to BTF. Retroactively merged through review path via PR #768. |
| PR #768 | 2026-05-22 | Add `sleepable` to all three `#[lsm(...)]` macros, flipping ELF section from `lsm/X` to `lsm.s/X`. | Bombini's only loading LSM (`creds_capture`) was sleepable; I generalised wrongly. Verifier still rejected with same error after deploy. |
| Diag branch `lsm/diagnostic-minimal` (deleted) | 2026-05-22 | Added a SECOND LSM hook to same `.o` with trivial body `return 0`, same target, same `sleepable`. | This one LOADED. Proved the rejection is body-driven, not setup-driven. This is the experiment that motivated this spec. |

All five attempts shipped without anchor tests. Future LSM work must include INV-LSM-01 through INV-LSM-06 as gating CI checks.
