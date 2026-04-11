# Feature Specification: Knowledge Graph Full Connectivity

**Feature Branch**: `014-graph-full-connectivity`
**Created**: 2026-04-11
**Status**: Phase A + B complete (deployed 2026-04-11)
**Priority**: P1 (force multiplier — unlocks correlation, narrative, AI triage quality)
**Depends on**: 013-graph-single-source (Phase 7, complete)

## Completion Status

| Phase | Status | Result |
|-------|--------|--------|
| **A: tcp_stream → graph** | DONE | ConnectedTo edges populated from 247K tcp_stream events/day, deduped by (src,dst,port) |
| **B: eBPF typed events** | DONE (rebuild + filename fix) | Sensor was missing `--features ebpf` flag. After rebuild, file ingestors had path/filename mismatch — added field aliasing |
| **C: Cross-entity edges** | DONE | CorrelatedWith edges between incidents in same kill chain via correlation_engine |
| **D: Incident enrichment** | DONE | ingest_incident now extracts pid from evidence array, links Incident → Process |
| **Leftover: memory.* events** | DONE | anon_executable, rwx_memory, deleted_file_mapping → Read with memory_anomaly property |
| **Leftover: cgroup.* events** | DONE | memory_spike, cpu_abuse → Signaled with cgroup_event property |
| **Critical bug fix** | DONE | JSONL sink had 200MB/day cap silently dropping events. Bumped to 1GB |

## Final metrics (2026-04-11)

| Metric | Before (013) | After (014 complete) | Δ |
|--------|--------------|---------------------|---|
| Total edges | 12,559 | 33,456 | +166% |
| Process nodes | 411 | 4,470 | +988% |
| Active relations | 8 | 18 | +125% |
| SpawnedBy | 0 | 1,662 | ✅ |
| ConnectedTo | 0 | 692 | ✅ |
| Read | 0 | 2,126 | ✅ |
| Wrote | 0 | 4 | ✅ |
| RunAs | 0 | 3,539 | ✅ |
| RedirectedFd | 0 | 6,410 | ✅ |
| Memory anomaly | 0 | 62 | ✅ |
| Cgroup edges | 0 | 6 | ✅ |
| Incident→Process | 0 | 3 | ✅ |
| ListensOn | 0 | 4 | ✅ |
| MprotectExec | 0 | 40 | ✅ |
| TimingAnomaly | 0 | 30 | ✅ |

## Problem

The knowledge graph has 50+ relation types and ingestion code for 58 event kinds, but production shows **8 relation types used out of 50+**. Critical behavioral edges are completely missing:

| Relation | Production count | Expected |
|----------|-----------------|----------|
| SpawnedBy | 0 | thousands/day |
| ConnectedTo | 0 | thousands/day |
| Wrote/Read/Executed | 0 | thousands/day |
| PtraceAttached | 0 | rare but critical |
| EscalatedTo | 0 | should appear on privesc |
| InContainer | 0 | depends on container events |

**Root cause**: The sensor doesn't emit eBPF events as individual typed events (`process.exec`, `file.write_access`, `network.outbound_connect`). Instead:
- eBPF hooks fire → events aggregate into detector patterns → detectors emit incidents
- The raw syscall-level events never reach the agent as typed Events
- Only certain collectors (auth_log, http_capture, dns_capture, journald) emit typed Events that reach the graph

**Current event flow**:
```
eBPF hooks → collector (ebpf_syscall) → detectors → incidents (JSONL/Redis)
                                         ↓ NOT ↓
                                    typed Events → graph.ingest()
```

**What reaches graph.ingest()**:
- shell.command_exec (29,692/day) — from auditd collector
- http.request (5,101/day) — from http_capture
- dns.query (3,311/day) — from dns_capture
- kernel.bpf_program_loaded (624/day) — from kernel_integrity
- sudo.command (395/day) — from auth_log
- ssh.login_* (282/day) — from auth_log
- network.snapshot (857/day) — from net_snapshot
- tcp_stream.* (344,302/day) — NOT mapped to graph (no ingest handler)

**What DOESN'T reach graph.ingest()**:
- process.exec, process.clone — eBPF execve/clone hooks exist, events not emitted
- network.outbound_connect — eBPF connect hook exists, events not emitted
- file.write_access, file.read_access, file.delete — eBPF openat hook exists, events not emitted
- process.ptrace_attach — eBPF ptrace hook exists, events not emitted

## Solution

Three phases, each independently valuable:

---

### Phase A: Map tcp_stream events to graph edges (1 day, high ROI)

The sensor already produces 344K tcp_stream events/day. These carry IP, port, and connection metadata but have no graph ingest handler.

**Add to ingestion.rs**:
```rust
"tcp_stream.flow" => self.ingest_tcp_flow(event),
"tcp_stream.ssh" => self.ingest_tcp_ssh(event),
"tcp_stream.http" => self.ingest_tcp_http(event),
"tcp_stream.smb" => self.ingest_tcp_smb(event),
```

**tcp_stream.flow details**: `{ src_ip, dst_ip, dst_port, proto, bytes_out, bytes_in, duration_ms }`

**Edges created**:
- Ip →(ConnectedTo)→ Ip (with port, bytes, duration as edge properties)
- Ip →(ScannedPort)→ Port (for short-lived connections to new ports)

**Volume control**: tcp_stream.flow is high-volume (261K/day). Deduplicate by (src_ip, dst_ip, dst_port) pair — update existing edge with cumulative bytes/count instead of creating new edges.

**Impact**: Immediately populates ConnectedTo with real network topology. Enables "show me all IPs this attacker talked to" queries.

---

### Phase B: Emit typed events from eBPF collector (3-4 days, core)

The eBPF collector (`ebpf_syscall.rs`) currently processes raw syscall data and feeds detectors, but doesn't emit structured Events for non-detector consumption.

**Modify `crates/sensor/src/collectors/ebpf_syscall.rs`**:

For each eBPF hook that fires, emit a typed Event in addition to feeding detectors:

| eBPF hook | Event kind to emit | Key fields |
|-----------|-------------------|------------|
| execve | `process.exec` | pid, ppid, comm, exe, uid, container_id |
| clone | `process.clone` | child_pid, parent_pid, comm, uid |
| connect | `network.outbound_connect` | pid, dst_ip, dst_port, proto, container_id |
| openat (write) | `file.write_access` | pid, path, comm, uid, flags |
| openat (read) | `file.read_access` | pid, path, comm, uid |
| unlink | `file.delete` | pid, path, comm, uid |
| rename | `file.rename` | pid, oldname, newname |
| ptrace | `process.ptrace_attach` | pid, target_pid, request |
| setuid | `privilege.setuid` | pid, uid, new_uid, comm |
| mount | `filesystem.mount` | pid, path, fs_type, device |
| kill | `process.signal` | pid, target_pid, signal |
| memfd_create | `process.memfd_create` | pid, filename |
| mprotect | `memory.mprotect_exec` | pid, prot, addr |
| accept | `network.accept` | pid, src_ip, dst_port |
| listen/bind | `network.listen` | pid, port, proto |
| io_uring_* | `io_uring.create/submit` | pid, entries, opcode |

**Volume control**: eBPF hooks fire for EVERY syscall. Must filter:
1. **Allowlist internal processes**: skip innerwarden-sensor, innerwarden-agent, systemd, sshd (configurable)
2. **Rate limit per event kind**: max N events/second per kind (configurable, default 100/s)
3. **Dedup within window**: same (pid, path) or (pid, dst_ip) within 5s → update, don't create new event
4. **Severity gate**: only emit events with severity >= configured threshold (default: all for graph, high for JSONL sink)

**Sensor config addition** (`config.toml`):
```toml
[sensor.graph_events]
enabled = true
rate_limit_per_kind = 100   # max events/s per kind
dedup_window_secs = 5
skip_comms = ["innerwarden-sensor", "innerwarden-agent", "systemd-*", "sshd"]
```

**Impact**: Full behavioral graph. Process trees, network connections, file access patterns all visible.

---

### Phase C: Enrich graph with cross-entity edges (1 day)

Once Phases A and B populate nodes, add derived edges that connect entities across types:

1. **Process →(InContainer)→ Container**: When process has container_id in exec event, add InContainer edge. Currently the field exists in events but no edge is created.

2. **Incident →(CorrelatedWith)→ Incident**: The correlation engine (`correlation_engine.rs`) detects multi-stage attacks (CL-001 to CL-043). Currently creates new incidents. Should ALSO create CorrelatedWith edges between the constituent incidents.

3. **Ip →(MemberOf)→ Campaign**: Campaign detection (`attacker_intel.rs`) clusters IPs by DNA. Should create MemberOf edges in the graph.

4. **File →(DownloadedFrom)→ Ip**: Already ingested from `file.extracted_from_network` but could also be derived from process trees: if `curl` connects to IP then writes file → File →(DownloadedFrom)→ Ip.

5. **User →(EscalatedTo)→ User**: When sudo.command shows user A running as user B, create User →(EscalatedTo)→ User edge (currently only Process →(SudoAs)→ User exists).

---

### Phase D: Incident entity enrichment (0.5 day)

Currently `Incident →(TriggeredBy)→ Ip` only connects to IP entities. Many incidents have process context:

- `ssh_bruteforce` → should link to `sshd` process node
- `reverse_shell` → should link to the spawned shell process
- `crypto_miner` → should link to the miner process

**Modify `ingestion.rs:ingest_incident()`**: When incident has PID in evidence JSON, find or create Process node and add `TriggeredBy` edge.

---

## Priority and Sequencing

| Phase | Effort | Impact | New edges/day (est.) |
|-------|--------|--------|---------------------|
| **A: tcp_stream → graph** | 1 day | Network topology visible | ~50K (deduped) |
| **B: eBPF → typed events** | 3-4 days | Full behavioral graph | ~100K (rate-limited) |
| **C: Cross-entity edges** | 1 day | Campaign + correlation visible | ~500 |
| **D: Incident enrichment** | 0.5 day | Richer incident context | ~2K |

**Total**: ~6 days. Phase A is quick win, Phase B is the core.

**Recommended order**: A → B → D → C

## Memory Impact

Current graph: ~5MB (2939 nodes, 16K edges). With full connectivity:
- Phase A adds ~5K unique IP pairs/day → ~10K new edges → +2MB
- Phase B adds ~50K process/file/network nodes → +20MB, ~100K edges → +30MB
- Total estimated: ~60MB (well within 512MB memory limit)

Graph already has `enforce_memory_limit()` with configurable cap. Existing cleanup/compaction handles overflow.

## Verification

After Phase A:
```
ConnectedTo edges > 0
"Show all IPs connected to attacker X" returns results
```

After Phase B:
```
SpawnedBy edges > 0 (process trees)
Wrote/Read edges > 0 (file access)
ConnectedTo from Process > 0 (who connected where)
"Reconstruct attack: from SSH login to data exfil" shows full chain
```

After Phase C:
```
CorrelatedWith edges between kill-chain incidents
MemberOf edges for campaign clusters
```

## What This Unlocks

1. **Attack narratives**: "User logged in from IP → spawned bash → wrote to /tmp/x → connected to C2 → exfiltrated data"
2. **AI triage context**: AI sees the full graph around an incident, not just the incident title
3. **Kill chain visualization**: Dashboard can render attack chains as connected graphs
4. **Anomaly detection**: Graph-based anomaly detection (unseen process→IP pairs, new file access patterns)
5. **Threat hunting**: "Show me all processes that connected to external IPs in the last hour"
