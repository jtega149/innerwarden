# Tasks: Real-Time Critical Detectors

**Input**: `.specify/features/011-realtime-critical-detectors/`

## Phase A: Infrastructure

- [ ] T001 Change `ingest()` return type in `ingestion.rs` from `()` to `Vec<Incident>` — returns incidents from critical triggers
- [ ] T002 Add `check_critical_triggers(&self, edge: &Edge, state: &mut GraphDetectorState, host: &str, now: DateTime) -> Vec<Incident>` to `graph.rs` — called inside `add_edge()`, dispatches to trigger functions
- [ ] T003 Update `main.rs` fast loop — collect trigger incidents from `graph.ingest(event)`, write to JSONL, ingest into graph as Incident nodes

**Checkpoint**: `ingest()` returns Vec<Incident>. Empty for now. No behavior change.

## Phase B: Trigger Functions

Each trigger function does 1-2 index lookups. No traversal.

- [ ] T004 [P] `trigger_reverse_shell(graph, edge, state, host, now)` — on RedirectedFd: check ConnectedTo(external). On ConnectedTo(external): check RedirectedFd. Cooldown 300s.
- [ ] T005 [P] `trigger_fileless(graph, edge, state, host, now)` — on MprotectExec or ConnectedTo(external): check CreatedMemfd + MprotectExec + ConnectedTo(external) all present within 60s. Cooldown 300s.
- [ ] T006 [P] `trigger_container_escape(graph, edge, state, host, now)` — on Read|Wrote to file: check if path in ESCAPE_PATHS. Cooldown 600s.
- [ ] T007 [P] `trigger_service_stop(graph, edge, state, host, now)` — on Executed by systemctl: check summary for "stop" + security service. Cooldown 300s.

**Checkpoint**: 4 triggers firing in real-time. 30s versions suppressed by shared cooldown.

## Phase C: Tests + Benchmark

- [ ] T008 Tests: trigger_reverse_shell (both trigger directions: RedirectedFd first, ConnectedTo first)
- [ ] T009 Tests: trigger_fileless (complete vs incomplete pattern)
- [ ] T010 Tests: trigger_container_escape (escape path vs normal path)
- [ ] T011 Tests: trigger_service_stop (security service vs normal service)
- [ ] T012 Tests: no duplicate from 30s tick (cooldown shared)
- [ ] T013 Benchmark: add_edge() before/after — must be <5% overhead

**Checkpoint**: All tests pass. Performance validated.

## Verification

| Test | Success Criteria |
|------|-----------------|
| Reverse shell trigger | Incident within <2s of completing edge |
| Fileless trigger | Incident within <2s |
| Container escape trigger | Incident within <2s |
| Service stop trigger | Incident within <2s |
| No duplicate | 30s tick suppressed by cooldown |
| Performance | add_edge() overhead <5% |
| `cargo test` | All pass |
