# Feature Specification: Real-Time Critical Detectors

**Feature Branch**: `011-realtime-critical-detectors`
**Created**: 2026-04-10
**Status**: Planned
**Input**: Phase 3 complete — 25 graph detectors running on 30s tick. 4 CRITICAL detectors (reverse_shell, fileless, container_escape, service_stop) need sub-second detection.

## Origin

Graph detectors run every 30s in the agent slow loop. For most detectors (port_scan, host_drift, credential_stuffing) this is fine — 30s latency is acceptable. But for 4 CRITICAL detectors, 30s is too slow:

- **Reverse shell**: attacker has a shell in 1s. 30s later the graph detects it. By then they've already run commands.
- **Fileless execution**: memfd_create + mprotect + outbound = complete in <5s. 30s detection misses the window.
- **Container escape**: docker.sock access → host compromise in seconds.
- **Service stop**: `systemctl stop innerwarden-sensor` — if we wait 30s, the sensor is already dead.

## Problem

The 30s tick is a batch processing model. For time-critical attacks, we need an event-driven model: detect the pattern **at the moment the completing edge is inserted** into the graph, not 30s later when the tick runs.

## Solution: Edge-Insert Triggers

When `add_edge()` is called in the graph, check if the new edge completes a critical pattern. This runs in the hot path (per-event), so it must be **O(1) or O(small constant)** — index lookups only, no graph traversal.

### Architecture

```
Sensor → Event → Agent fast loop → graph.ingest(event)
                                      → add_edge(process → ip, ConnectedTo)
                                        → check_critical_triggers(edge)
                                          → "process has RedirectedFd + ConnectedTo(external)?"
                                          → YES → emit Incident immediately
```

### Why This Is Safe

1. **O(1) checks**: Each trigger does 1-2 index lookups (outgoing edges of the source node). No BFS, no path traversal.
2. **Cooldown**: Same cooldown tracker as 30s detectors — no duplicate alerts.
3. **Hot path is already fast**: `add_edge()` currently does dedup check + append. Adding 4 `if` checks is negligible.
4. **Existing detectors still run**: The 30s tick versions remain as fallback. The trigger fires first, the tick version gets suppressed by cooldown.

---

## Detectors to Convert

### 1. Reverse Shell (currently `detect_reverse_shell`)

**Trigger edge**: `RedirectedFd` (fd 0, 1, or 2)
**Check**: Source process also has `ConnectedTo(external IP)` edge within 30s
**Pattern**: Process redirected stdin/stdout/stderr AND connected to external IP = reverse shell

**Current 30s version** (detectors.rs):
```
Process with RedirectedFd(fd 0,1,2) AND ConnectedTo(external) within 30s
```

**Trigger version**:
```
on add_edge(proc, proc, RedirectedFd):
  if proc has ConnectedTo(external) in last 30s → fire
  
on add_edge(proc, ip, ConnectedTo) where ip.is_external:
  if proc has RedirectedFd(fd 0,1,2) in last 30s → fire
```

### 2. Fileless Execution (currently `detect_fileless`)

**Trigger edge**: `MprotectExec` or `ConnectedTo(external)`
**Check**: Source process has `CreatedMemfd` AND `MprotectExec` AND `ConnectedTo(external)` within 60s
**Pattern**: memfd_create + mprotect(EXEC) + outbound connection = fileless malware

**Trigger version**:
```
on add_edge(proc, proc, MprotectExec):
  if proc has CreatedMemfd AND ConnectedTo(external) in last 60s → fire

on add_edge(proc, ip, ConnectedTo) where ip.is_external:
  if proc has CreatedMemfd AND MprotectExec in last 60s → fire
```

### 3. Container Escape (currently `detect_container_escape`)

**Trigger edge**: `Read` or `Wrote` to escape-path files
**Check**: Target file path is in escape paths list (/var/run/docker.sock, /proc/1/root, etc.)
**Pattern**: Any process accessing container escape paths

**Trigger version**:
```
on add_edge(proc, file, Read|Wrote):
  if file.path in ESCAPE_PATHS → fire
```

### 4. Service Stop (currently `detect_service_stop`)

**Trigger edge**: `Executed` by systemctl/service process
**Check**: Edge summary contains "stop" + security service name
**Pattern**: systemctl stopping a security service

**Trigger version**:
```
on add_edge(proc, file, Executed) where proc.comm == "systemctl":
  if edge.summary contains "stop" AND any SECURITY_SERVICE → fire
```

---

## User Scenarios & Testing

### User Story 1 — Sub-Second Reverse Shell Detection (Priority: P1)

**Independent Test**: Simulate reverse shell (netcat + fd redirect). Incident must appear within 2s, not 30s.

**Acceptance Scenarios**:

1. **Given** process with ConnectedTo(external), **When** RedirectedFd edge added, **Then** incident fires within event processing tick (<2s).
2. **Given** process with RedirectedFd, **When** ConnectedTo(external) edge added, **Then** incident fires within <2s.
3. **Given** reverse shell detected by trigger, **When** 30s tick runs, **Then** tick version suppressed by cooldown (no duplicate).
4. **Given** trigger fires, **When** next event for different process, **Then** no measurable latency impact on ingest.

### User Story 2 — Sub-Second Fileless Detection (Priority: P1)

**Acceptance Scenarios**:

1. **Given** process with CreatedMemfd + MprotectExec, **When** ConnectedTo(external) edge added, **Then** incident fires within <2s.
2. **Given** only CreatedMemfd (no mprotect or connect), **When** trigger checks, **Then** no incident (incomplete pattern).

### User Story 3 — Sub-Second Container Escape (Priority: P1)

**Acceptance Scenarios**:

1. **Given** any process, **When** Read edge to /var/run/docker.sock added, **Then** incident fires within <2s.
2. **Given** Read edge to /var/log/syslog (not an escape path), **When** trigger checks, **Then** no incident.

### User Story 4 — Sub-Second Service Stop (Priority: P1)

**Acceptance Scenarios**:

1. **Given** systemctl process, **When** Executed edge with "stop innerwarden" in summary, **Then** CRITICAL incident fires within <2s.
2. **Given** systemctl process with "start nginx" (not security service), **When** trigger checks, **Then** no incident.

### User Story 5 — Performance (Priority: P1)

**Independent Test**: Benchmark `add_edge()` before and after triggers. Must be <1% overhead.

**Acceptance Scenarios**:

1. **Given** 10,000 edges inserted, **When** benchmarked, **Then** trigger version is within 5% of baseline.
2. **Given** trigger fires, **When** cooldown prevents duplicate, **Then** zero additional work on repeated edges.

---

## Files to Modify

| File | Changes |
|------|---------|
| `knowledge_graph/graph.rs` | Add `check_critical_triggers()` call in `add_edge()`. Returns `Vec<Incident>`. |
| `knowledge_graph/detectors.rs` | Add `CriticalTrigger` functions: `trigger_reverse_shell()`, `trigger_fileless()`, `trigger_container_escape()`, `trigger_service_stop()`. Share cooldown tracker with 30s detectors. |
| `knowledge_graph/ingestion.rs` | Propagate trigger incidents from `ingest()` back to caller. Add return type `Vec<Incident>` to `ingest()`. |
| `main.rs` | Collect trigger incidents from `graph.ingest(event)` and write to JSONL + knowledge graph. |

## Risks

1. **Hot path performance**: Mitigated by O(1) checks. Benchmark before/after.
2. **False positives from partial patterns**: Mitigated by requiring ALL pattern components, not just the trigger edge.
3. **Race with 30s tick**: Mitigated by shared cooldown tracker — trigger fires first, tick gets suppressed.

## Verification

1. `cargo test` — all existing + new trigger tests pass
2. Benchmark: `add_edge()` overhead <5%
3. Simulate reverse shell on production → incident appears in <2s
4. Check 30s tick doesn't duplicate the trigger incident
