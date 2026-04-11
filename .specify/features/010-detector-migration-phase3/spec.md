# Feature Specification: Knowledge Graph Phase 3 — Detector Migration

**Feature Branch**: `010-detector-migration-phase3`
**Created**: 2026-04-10
**Status**: Planned
**Input**: `ideias/knowledge-graph-implementation-plan.md` Phase 3. Today: 8/57 detectors on graph (~14%). Target: 80%.

## Origin

The knowledge graph engine (Phase 1) and dashboard (Phase 2) are complete. 8 graph detectors run in parallel with 49 sensor detectors. The graph detectors proved faster (30s tick vs per-event), more context-aware (cross-entity correlation), and lower false-positive rate (structural queries vs pattern matching).

Production data (2026-04-10, single server):
- 1,335 incidents/day across 15 active detectors
- `host_drift` alone: 823 incidents (62% of all incidents, mostly false positives from admin activity)
- `proto_anomaly`: 205 incidents (15%)
- Combined top 3 detectors: 90% of incident volume

The graph can dramatically reduce noise by correlating events across entities before triggering incidents, instead of firing on each individual event.

## Problem

1. **Dual running wastes resources**: Same detection running in sensor (per-event) AND graph (per-tick). CPU spent twice.
2. **No dedup mechanism**: Sensor and graph may fire for the same attack → duplicate incidents.
3. **High FP rate on per-event detectors**: `host_drift` fires 823 times because each process execution is checked independently. Graph could aggregate: "admin ran 50 commands in 2 minutes → 1 incident, not 50".
4. **43 correlation rules run as per-event pattern matching**: These are fundamentally graph queries (multi-stage attack paths across entities) but implemented as sliding window state machines.

## Goals

- Migrate detectors from sensor per-event matching to graph structural queries where beneficial.
- Reduce incident volume by 30%+ through aggregation and correlation.
- Keep sensor-only detectors that can't benefit from graph (signatures, baselines, ML).
- No false negatives: every migrated detector must detect at least what the sensor version detected.
- Parallel running during migration: both versions fire, compare results, then disable sensor version.

## Non-Goals

- Eliminating JSONL (Phase 6, separate effort)
- GNN/ML on graph (Phase 5, separate effort)
- Modifying the sensor crate (all changes in agent)

---

## Architecture

### Current Flow (per-event)
```
Sensor → Event JSONL → Agent reads → Per-event detector → Incident
```

### Target Flow (graph-based)
```
Sensor → Event JSONL → Agent reads → Graph ingestion → Graph detector (30s tick) → Incident
```

### Hybrid (during migration)
```
Sensor → Event → Agent:
  ├── Graph ingestion (always)
  ├── Sensor detector (being phased out)
  └── Graph detector (new, parallel)
       └── Compare results weekly → Disable sensor version when graph proves reliable
```

---

## Detector Classification

### Already Done (8 detectors) ✅
threat_intel, lateral_movement, process_tree_anomaly, reverse_shell, fileless, discovery_burst, persistence (crontab + systemd + ssh_key), data_exfil

### Phase 3A — Easy Migrations (10 detectors)
Single graph query, no new node types needed. Expected: ~200 fewer incidents/day.

| Detector | Graph Query | Why Easy |
|----------|------------|----------|
| `kernel_module_load` | Process→Executed(insmod/modprobe) | Single edge lookup |
| `user_creation` | New User node appears with privilege edges | Node creation trigger |
| `service_stop` | Process→Executed(systemctl stop *security*) | Edge to service name |
| `container_escape` | Process→Read(/var/run/docker.sock) OR Process→Read(/proc/1/*) | File path pattern |
| `docker_anomaly` | Container node restart count in window | Container state tracking |
| `crypto_miner` | Process→ConnectedTo(mining pool IP) + high CPU cgroup | IP lookup + cgroup |
| `user_agent_scanner` | Ip→RequestedHttp with scanner UA patterns | HTTP edge property |
| `log_tampering` | Non-standard Process→Wrote(/var/log/*) | File path + process allowlist |
| `cgroup_abuse` | Process with high CPU cgroup events | Aggregate cgroup events |
| `c2_callback` | Process→ConnectedTo(external) with beacon pattern (periodic, fixed interval) | Edge timestamp analysis |

### Phase 3B — Medium Migrations (8 detectors)
Need aggregation logic or minor graph schema additions. Expected: ~100 fewer incidents/day.

| Detector | Challenge | Graph Approach |
|----------|----------|----------------|
| `host_drift` | Needs process execution baseline | Aggregate Process→Executed edges, compare vs known binaries |
| `proto_anomaly` | Needs connection pattern analysis | Aggregate Ip→ConnectedTo edges by port/proto, spike detection |
| `port_scan` | Multi-target aggregation | Count distinct Port nodes per source Ip in window |
| `network_sniffing` | Tool fingerprinting | Process→Executed(tcpdump/tshark/wireshark) + CAP_NET_RAW |
| `dns_tunneling` | DNS entropy analysis | Aggregate Domain nodes, entropy of labels |
| `credential_stuffing` | Multi-user SSH failures | Aggregate Ip→FailedAuth→User, count distinct users |
| `sudo_abuse` | Command burst detection | User→Executed with sudo in window, count threshold |
| `sensitive_write` | File path classification | Process→Wrote→File(is_sensitive), exclude trusted processes |

### Phase 3C — Keep on Sensor (8 detectors)
Fundamentally per-event, statistical, or signature-based. Cannot benefit from graph.

| Detector | Reason |
|----------|--------|
| `ssh_bruteforce` | Per-IP sliding window counter. Graph adds no context. |
| `execution_guard` | Structural command risk scoring (ML). Not a graph query. |
| `ransomware` | Per-file entropy + write rate. Filesystem-level, not entity-level. |
| `rootkit` | Kernel state consistency (timing, hidden PIDs). Low-level introspection. |
| `integrity_alert` | Hash baseline comparison. Per-file, not structural. |
| `sigma_rule` | Log field pattern matching. Per-event by definition. |
| `yara_scan` | Binary signature matching. Per-file content analysis. |
| `web_shell` | File hash + HTTP body + entropy. Hybrid per-event analysis. |

### Correlation Rules (43 → Graph Paths)
The 43 correlation rules (`CL-001` to `CL-043`) are multi-stage attack chains currently implemented as sliding window state machines in `correlation_engine.rs`. These are **natural graph queries**: "find path from Recon node to Exfil node through this IP within 1800s".

Migration approach: convert each rule to a `detect_correlation_*` function that queries the graph for the stage pattern. Priority: the 10 most impactful rules (CL-001 to CL-010).

---

## User Scenarios & Testing

### User Story 1 — Phase 3A Easy Detectors (Priority: P1)

Migrate 10 easy detectors to graph. Each must detect at least what the sensor version detects.

**Independent Test**: Run both versions in parallel for 24h. Compare: graph version must have ≥95% recall (no missed detections) and ≤50% of sensor's false positive rate.

**Acceptance Scenarios**:

1. **Given** insmod execution, **When** graph tick runs, **Then** `graph_kernel_module` incident fires within 30s.
2. **Given** new user created with sudo group, **When** graph tick runs, **Then** `graph_user_creation` incident fires.
3. **Given** `systemctl stop innerwarden-sensor`, **When** graph tick runs, **Then** `graph_service_stop` incident fires with CRITICAL severity.
4. **Given** process reading /var/run/docker.sock, **When** graph tick runs, **Then** `graph_container_escape` incident fires.
5. **Given** mining pool connection sustained 60s, **When** graph tick runs, **Then** `graph_crypto_miner` incident fires.
6. **Given** all 10 graph detectors running in parallel with sensor, **When** 24h passes, **Then** graph catches ≥95% of sensor detections with ≤50% FP rate.

---

### User Story 2 — Host Drift Aggregation (Priority: P1)

The single most impactful migration. 823 incidents/day → should be ~20 aggregated incidents.

**Independent Test**: With graph `detect_host_drift`, production generates <50 host_drift incidents in 24h (vs 823 today). No real drift missed.

**Acceptance Scenarios**:

1. **Given** admin running 50 commands in 2 minutes, **When** graph tick runs, **Then** 1 aggregated incident "host_drift: 50 unusual executions by ubuntu" instead of 50 separate incidents.
2. **Given** unknown binary `/tmp/payload` executed, **When** graph tick runs, **Then** incident fires immediately (not aggregated — unknown binary is always reported).
3. **Given** known system binary (apt, dpkg, logrotate) executed, **When** graph tick runs, **Then** no incident (process is in system allowlist).

---

### User Story 3 — Proto Anomaly Aggregation (Priority: P2)

205 incidents/day → should be ~30 aggregated.

**Independent Test**: Graph version generates <50 proto_anomaly incidents in 24h.

**Acceptance Scenarios**:

1. **Given** 20 malformed SSH from same IP in 5 minutes, **When** graph tick runs, **Then** 1 incident with count=20, not 20 incidents.
2. **Given** new unique malformed SSH from new IP, **When** graph tick runs, **Then** incident fires for the new IP.

---

### User Story 4 — Correlation Rules as Graph Paths (Priority: P2)

Convert top 10 correlation rules to graph path queries.

**Independent Test**: `cargo test` includes test for each correlation rule with mock graph data.

**Acceptance Scenarios**:

1. **Given** port_scan from IP X + ssh_bruteforce from X + data_exfil from X within 1800s, **When** graph correlation runs, **Then** CL-002 "Recon→Exfil" fires as CRITICAL multi-stage incident.
2. **Given** only port_scan (no follow-up), **When** graph correlation runs, **Then** no multi-stage incident fires.

---

### User Story 5 — Dedup Sensor vs Graph (Priority: P1)

When both sensor and graph detect the same event, only one incident should be visible.

**Independent Test**: With parallel running, incident count does not increase vs sensor-only baseline.

**Acceptance Scenarios**:

1. **Given** threat_intel match on IP, **When** both sensor and graph fire, **Then** only 1 incident appears (graph takes priority, sensor version suppressed).
2. **Given** graph detector disabled for a type, **When** sensor fires, **Then** sensor incident appears normally (graceful fallback).

---

## Implementation Plan

### Phase 3A (Week 1-2): Easy Detectors
10 new `detect_*` functions in `detectors.rs`. Each follows the existing pattern:
- Query graph for specific node/edge pattern
- Check cooldown tracker
- Return `Vec<GraphIncident>` if found

### Phase 3B (Week 3-4): Medium Detectors
8 detectors needing aggregation. Add:
- `detect_host_drift_aggregated()` — count Process→Executed edges per user per tick, fire if unusual count or unknown binary
- `detect_proto_anomaly_aggregated()` — count anomalous Ip→ConnectedTo edges per source IP, fire once per IP per window
- Others follow same aggregation pattern

### Phase 3C: Correlation Rules (Week 5-6)
Convert CL-001 to CL-010 to `detect_correlation_*` functions. Each:
- Queries graph for multi-hop path matching the rule stages
- Uses entity matching (same IP/User across stages)
- Respects time window from rule spec

### Phase 3D: Dedup + Disable (Week 6)
- Add `is_graph_detected` flag to incidents
- When graph fires, check if sensor already fired for same entity+detector in window → suppress duplicate
- After 1 week of parallel running with ≥95% recall, disable sensor version per detector

---

## Files to Modify

| File | Changes |
|------|---------|
| `crates/agent/src/knowledge_graph/detectors.rs` | Add 18+ new `detect_*` functions |
| `crates/agent/src/knowledge_graph/types.rs` | Possibly add new Relation variants for aggregation |
| `crates/agent/src/knowledge_graph/graph.rs` | Add aggregation query helpers (count edges by type in window) |
| `crates/agent/src/main.rs` | Wire new detectors into slow loop, add dedup logic |
| `crates/agent/src/correlation_engine.rs` | Eventually replace sliding window with graph queries |

## Risks

1. **False negatives during migration**: Mitigated by parallel running. Never disable sensor version without 1 week of comparison data.
2. **Graph memory growth**: More detectors querying the graph may slow ticks. Mitigated by 50MB memory cap and LRU pruning.
3. **30s detection delay**: Graph detectors run every 30s vs per-event. For time-critical detectors (reverse_shell, fileless), keep sensor version as primary with graph as enrichment.

## Verification

1. `cargo test -p innerwarden-agent` — all existing + new detector tests pass
2. Deploy to production with parallel running (both sensor + graph)
3. After 24h: compare incident counts — graph should match sensor ≥95%
4. After 1 week: disable sensor versions for validated detectors
5. Monitor FP rate — graph should have ≤50% of sensor FP rate

## Metrics to Track

- Incidents/day per detector (before vs after)
- Detection latency (time from event to incident)
- False positive rate (allowlisted/ignored incidents as % of total)
- Graph tick duration (must stay <500ms)
- Memory usage (must stay <50MB)
