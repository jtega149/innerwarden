# Feature Specification: Knowledge Graph Phase 2 — Complete

**Feature Branch**: `009-knowledge-graph-phase2`
**Created**: 2026-04-10
**Status**: Planned
**Input**: Phase 2 from `ideias/knowledge-graph-implementation-plan.md`. Core graph engine (Phase 1) is complete. Dashboard graph tab exists with basic visualization. Missing: 4 API endpoints, search, edge click, export PNG, incident mini-graph.

## Origin

Phase 2 was partially implemented: `/api/graph/stats`, `/api/graph/view`, `/api/graph/neighborhood` exist. Cytoscape.js integration works. But 4 planned endpoints were never added, and several UI features are missing.

## What EXISTS

- `GET /api/graph/stats` — GraphMetrics JSON
- `GET /api/graph/view` — Full graph as Cytoscape.js elements (capped at 500 nodes)
- `GET /api/graph/neighborhood?type=ip&value=X&depth=Y` — Subgraph by entity
- Graph tab in dashboard with Cytoscape.js, node colors, filters, click handler
- Backend has all query methods: `path_between`, `timeline`, `threat_intel_hits`, `descendants`, `ancestors`, `find_by_*`

## What's MISSING

### 2.1 API Endpoints (4 missing)

| Endpoint | Query Method Exists | Status |
|----------|-------------------|--------|
| `GET /api/graph/path?from=N&to=N` | `graph.path_between()` | Missing endpoint |
| `GET /api/graph/process-tree/:pid` | `graph.descendants()` + `graph.ancestors()` | Missing endpoint |
| `GET /api/graph/timeline/:node_id` | `graph.timeline()` | Missing endpoint |
| `GET /api/graph/threats` | `graph.threat_intel_hits()` | Missing endpoint |

### 2.2 Dashboard UI (missing features)

| Feature | Status |
|---------|--------|
| Click edge: tooltip with timestamp + details | Missing |
| Search: by IP, PID, domain, filename | Missing |
| Timeframe filter (1h/6h/24h) | Missing |
| Export PNG | Missing |

### 2.3 Incident Graph Context

| Feature | Status |
|---------|--------|
| Mini-graph in journey detail | Removed (was there, removed in UX redesign) |
| `neighborhood(incident_node, depth=2)` inline | Missing |

---

## User Scenarios & Testing

### User Story 1 — Path Between Nodes (Priority: P2)

Operator asks "how is this IP connected to this process?" — finds the shortest path.

**Independent Test**: `curl /api/graph/path?from=42&to=99` returns array of edges.

**Acceptance Scenarios**:

1. **Given** connected nodes A and B, **When** `/api/graph/path?from=A&to=B` called, **Then** returns ordered edge array from A to B.
2. **Given** disconnected nodes, **When** called, **Then** returns empty array.
3. **Given** depth > 10, **When** called, **Then** caps at max_depth=10.

---

### User Story 2 — Process Tree (Priority: P2)

Operator investigates suspicious process — sees full parent/child tree.

**Independent Test**: `curl /api/graph/process-tree/1234` returns ancestors + descendants as Cytoscape elements.

**Acceptance Scenarios**:

1. **Given** PID 1234 with parent chain sshd→bash→wget, **When** called, **Then** returns tree with all 3 processes + edges.
2. **Given** unknown PID, **When** called, **Then** returns empty elements.

---

### User Story 3 — Node Timeline (Priority: P1)

Operator clicks a node — sees chronological timeline of all edges (connections, reads, writes, spawns).

**Independent Test**: `curl /api/graph/timeline/42` returns edges sorted by timestamp.

**Acceptance Scenarios**:

1. **Given** IP node with 5 edges, **When** called, **Then** returns 5 edges sorted oldest→newest.
2. **Given** node with no edges, **When** called, **Then** returns empty array.

---

### User Story 4 — Threat Intel Hits (Priority: P1)

Dashboard shows all process→IP connections where IP has threat intel datasets.

**Independent Test**: `curl /api/graph/threats` returns array of `{process, ip, dataset}` tuples.

**Acceptance Scenarios**:

1. **Given** process connecting to known malicious IP, **When** called, **Then** returns the connection with dataset name.
2. **Given** no threat intel matches, **When** called, **Then** returns empty array.

---

### User Story 5 — Graph Search (Priority: P1)

Operator types IP/domain/PID in search box — graph highlights matching node.

**Acceptance Scenarios**:

1. **Given** search "192.168.1.1", **When** typed in search box, **Then** graph centers on that IP node and highlights it.
2. **Given** search "bash", **When** typed, **Then** highlights all Process nodes with comm="bash".
3. **Given** no match, **When** typed, **Then** shows "No match found".

---

### User Story 6 — Edge Tooltip (Priority: P3)

Clicking an edge shows timestamp, relation type, event source, and summary.

**Acceptance Scenarios**:

1. **Given** edge ConnectedTo between Process and Ip, **When** clicked, **Then** tooltip shows: relation, timestamp, event_kind, summary.

---

### User Story 7 — Export PNG (Priority: P3)

Operator exports current graph view as PNG for reports.

**Acceptance Scenarios**:

1. **Given** graph rendered, **When** "Export PNG" clicked, **Then** downloads PNG file of current view.

---

## Scope

**Backend files to modify:**
- `crates/agent/src/dashboard/mod.rs` — add 4 routes
- `crates/agent/src/dashboard/intelligence.rs` — add 4 handler functions (they use existing graph query methods)

**Frontend file to modify:**
- `crates/agent/src/dashboard/frontend/js/graph.js` — search, edge tooltip, export PNG

**No new dependencies.** All backend query methods already exist in `graph.rs`.

## Verification

1. `cargo test -p innerwarden-agent` — passes
2. `curl /api/graph/path?from=1&to=2` — returns edges
3. `curl /api/graph/process-tree/1234` — returns tree
4. `curl /api/graph/timeline/42` — returns sorted edges
5. `curl /api/graph/threats` — returns threat intel connections
6. Browser: type IP in graph search → node highlights
7. Browser: click edge → tooltip appears
8. Browser: Export PNG → file downloads
