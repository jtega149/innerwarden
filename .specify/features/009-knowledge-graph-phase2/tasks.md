# Tasks: Knowledge Graph Phase 2 — Complete

**Input**: `.specify/features/009-knowledge-graph-phase2/`

## Phase A: Backend — Missing API Endpoints

All 4 query methods already exist in `graph.rs`. Just need handlers + routes.

- [ ] T001 [P] [US1] Add `GET /api/graph/path?from=N&to=N&max_depth=10` handler in `intelligence.rs` — calls `graph.path_between()`, returns Cytoscape edges JSON
- [ ] T002 [P] [US2] Add `GET /api/graph/process-tree/:pid` handler in `intelligence.rs` — calls `graph.ancestors()` + `graph.descendants()`, builds Cytoscape elements JSON
- [ ] T003 [P] [US3] Add `GET /api/graph/timeline/:node_id` handler in `intelligence.rs` — calls `graph.timeline()`, returns sorted edges with properties
- [ ] T004 [P] [US4] Add `GET /api/graph/threats` handler in `intelligence.rs` — calls `graph.threat_intel_hits()`, returns `[{process_label, ip, dataset}]`
- [ ] T005 [US1-4] Add 4 routes in `mod.rs` for the new endpoints

**Checkpoint**: `cargo test` passes. All 4 endpoints return data via curl.

## Phase B: Frontend — Graph UI Enhancements

- [ ] T006 [US5] Add search box to graph tab in `index.html` — input field in graph toolbar
- [ ] T007 [US5] Add `searchGraph(query)` function in `graph.js` — find node by IP/comm/domain/PID, center + highlight
- [ ] T008 [US6] Add edge click handler in `graph.js` — `cy.on('tap', 'edge', ...)` showing tooltip with relation, timestamp, event_kind
- [ ] T009 [US7] Add "Export PNG" button to graph toolbar in `index.html`
- [ ] T010 [US7] Add `exportGraphPng()` function in `graph.js` — uses `cy.png()` + download blob

**Checkpoint**: Browser: search works, edge click shows tooltip, PNG exports.

## Verification

| US | Test |
|----|------|
| US1 | `curl /api/graph/path?from=1&to=2` |
| US2 | `curl /api/graph/process-tree/1234` |
| US3 | `curl /api/graph/timeline/42` |
| US4 | `curl /api/graph/threats` |
| US5 | Browser: type IP in search → node highlights |
| US6 | Browser: click edge → tooltip |
| US7 | Browser: Export PNG → file downloads |
