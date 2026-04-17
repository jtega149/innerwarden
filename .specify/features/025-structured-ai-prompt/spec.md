# Feature Specification: Structured AI Prompt (subgraph as JSON)

**Feature Branch**: `025-structured-ai-prompt`
**Created**: 2026-04-17
**Status**: DRAFT
**Priority**: P1 (direct +20 pp accuracy on the decision layer — measured)
**Depends on**: nothing
**Related**: 024 (regression safety net — the scenario suite that would have caught the original bug)

## Origin

Operator reported on 2026-04-17 that the honeypot on port 2222 auto-blocked
an attacker (45.156.128.82) instead of letting the listener collect intel.
The deterministic pre-LLM gates had already matched AbuseIPDB 100/100 →
`block_ip` was applied. We investigated whether an LLM-driven decision path
would have done better if the prompt carried the graph as **structured
subgraph** instead of the current **prose narrative** produced by
`graph.attack_narrative(node, depth=3)`.

## Evidence (from `innerwarden-test/ai-grounding/results/run-baseline.csv`)

15 cases (10 real from prod + 5 adversarial simulations), 4 models ×
3 prompt formats, 180 total calls. Format definitions live at
`innerwarden-test/ai-grounding/prompts/formats.py`:

* **A** = current prod: incident JSON + graph rendered as prose
* **B** = incident JSON + graph as structured nodes/edges JSON
* **C** = B + model must cite `subgraph.nodes[].id` in `evidence_refs`

Headline table:

| model | format | action accuracy | hallucinated target | p50 latency |
|---|---|---|---|---|
| qwen2.5:3b (**prod today**) | A | **53%** | **47%** | 1.9 s |
| qwen2.5:3b | B | **73%** | 7% | 2.3 s |
| qwen2.5:3b | C | 73% | 20% | 3.8 s |
| qwen2.5:1.5b | A | 73% | 13% | 1.1 s |
| qwen2.5:1.5b | **B** | **73%** | **0%** | **1.3 s** |
| qwen2.5:1.5b | C | 67% | 0% | 2.0 s |
| phi3:3.8b | any | ≤53% | 20-33% | 2.5-5 s |
| qwen3.5:4b | any | parse-fail 47-80% | — | 95-120 s |

Three hypotheses from the README had measurable thresholds:

* ✅ **H3** (structured JSON beats prose by ≥10 pp): qwen2.5:3b A → B went
  53% → 73%. **+20 pp accuracy**. Target hallucination dropped 47% → 7%.
* ✅ **H2** (smaller model + B matches bigger model + A): qwen2.5:1.5b + B
  matches qwen2.5:3b + A on accuracy (both 73%) and **beats it** on
  hallucination (0% vs 47%) with 30% lower latency.
* ❌ **H1** (mandatory grounding reduces hallucination ≥20 pp): grounding
  (format C) hurts accuracy. Models became overcautious, citing `ignore`
  when other actions were right. qwen2.5:1.5b R-10 went `monitor` (correct
  enough) in B → `ignore` (wrong) in C.

Case-level confirmation of the original operator complaint: on **R-10**
(honeypot hit, port 2222), qwen2.5:3b chose `block_ip` with format A
(prose) and `honeypot` with formats B and C. **The bug is in the prompt
format, not in the model.**

Another strong signal — the three real cases R-01/R-02/R-03 were the
assistant's own diagnostic commands (`journalctl | grep`, `sqlite3 SELECT`,
`python3 -c "import json…"`) classified as data exfil. Only qwen2.5:1.5b
got all three right (`ignore`). The bigger qwen2.5:3b suggested `monitor`
(wrong but safer than block). phi3 variously picked `block_ip`,
`suspend_user`, `kill_process` — actively dangerous.

## Problem

Today's prompt (`crates/agent/src/ai/openai.rs:246` `build_prompt`) serialises:

* incident as JSON ✓
* recent events as JSON ✓
* related incidents as JSON ✓
* available skills as JSON ✓
* IP reputation as one-line prose ✓ (small, fine)
* IP geo as one-line prose ✓ (small, fine)
* **graph context as multi-paragraph prose** (returned by
  `graph.attack_narrative(node, depth=3)`) ✗

The prose graph wastes tokens, hides entity IDs, and forces the LLM to
re-derive structure from natural language. That's the 53% → 73% accuracy
gap measured above.

## Goals

* Replace the prose graph section with a structured JSON subgraph in the
  prompt sent to every LLM provider.
* Preserve the existing `attack_narrative` code path as a fallback (used
  by dashboards and monthly reports — not changing those).
* Keep the output schema unchanged (`action`, `target`, `confidence`,
  `reason`). No `evidence_refs` — the experiment showed it hurts.
* Re-run the benchmark after implementation; accuracy on qwen2.5:3b must
  land ≥70% on the same 15-case dataset.

## Non-goals

* Mandatory grounding / `evidence_refs`. Measured as harmful; explicitly
  excluded from this spec.
* Switching AI provider / model in production. A separate opt-in experiment
  may propose qwen2.5:1.5b later — this spec only changes prompt shape.
* Dashboard narrative changes. `attack_narrative` stays, still used by
  the dashboard's `investigation` and `threat_report`.
* Conversational interface / natural-language query over the graph.
* Pattern discovery / APT attribution via LLM. Out of scope forever.

## Scope — files touched

| File | Change |
|---|---|
| `crates/agent/src/knowledge_graph/graph.rs` | new method `attack_subgraph_json(center, depth) -> serde_json::Value` returning `{nodes, edges}`. Does not replace `attack_narrative`. |
| `crates/agent/src/ai/mod.rs` | `DecisionContext` gains an optional `graph_subgraph: Option<serde_json::Value>` field alongside the existing `graph_context: Option<String>`. Both optional so the transition can happen in one commit without breaking existing call sites. |
| `crates/agent/src/main.rs` | at the `graph_context` call site (~line 2815), populate both `graph_context` (backward compat) and the new `graph_subgraph` from the same center node. Zero additional graph reads. |
| `crates/agent/src/ai/openai.rs` | `build_prompt` prefers `graph_subgraph` when present and serialises it as JSON; falls back to the prose `graph_context` when absent. Shared path used by `ollama.rs`. |
| `crates/agent/src/ai/anthropic.rs` | same change as openai.rs, separate `build_prompt` function. |
| `crates/agent/src/ai/ollama.rs` | no change — reuses `openai::build_prompt_pub`. |

## Acceptance criteria

* [ ] `DecisionContext::graph_subgraph` field exists and is populated in
  the production decision path (main.rs).
* [ ] `build_prompt` for OpenAI, Anthropic, and (via openai) Ollama all
  emit `GRAPH_SUBGRAPH:` as JSON when the field is present.
* [ ] `attack_narrative` unchanged; dashboards and reports still work.
* [ ] Unit tests cover: subgraph serialisation shape; prompt contains the
  JSON block; fallback to prose when subgraph is None.
* [ ] The AI grounding benchmark (`innerwarden-test/ai-grounding/`) is
  re-run with the updated prompt builder wired into a new `Format D`
  runner. Accuracy on qwen2.5:3b on the same 15 cases ≥ 70%.
* [ ] `make test` + `make check` clean.
* [ ] No measurable latency regression in prod (p50 of AI decisions over
  24h within ±15% of pre-change baseline).

## Implementation phases

### Phase A — shape change (half a session)

1. Add `attack_subgraph_json` to `knowledge_graph/graph.rs`. Traverses the
   same neighbourhood as `attack_narrative` (BFS from centre, same depth),
   emits `{nodes: [{id, type, ...}], edges: [{from, to, type}]}`.
2. Add `graph_subgraph: Option<serde_json::Value>` to `DecisionContext`
   in `ai/mod.rs`.
3. Populate it at the main.rs call site alongside the existing prose.
4. Tests: new `attack_subgraph_json` unit tests (~8 cases covering empty
   centre, depth=0, depth=3, node types, entity propagation).

### Phase B — prompt wiring (half a session)

1. Update `build_prompt` in `openai.rs`: if `graph_subgraph.is_some()`,
   render as `GRAPH_SUBGRAPH:\n<json>`. Else fall back to the existing
   prose `GRAPH_CONTEXT:` block.
2. Same change in `anthropic.rs`.
3. Tests: prompt contains JSON when subgraph set; falls back to prose
   when None; both providers produce matching shape.

### Phase C — benchmark re-run (0.3 session)

1. Add `format_d` to `innerwarden-test/ai-grounding/prompts/formats.py`:
   prompt identical to the new production `build_prompt` output shape.
2. Run matrix with `--formats D` + existing A/B/C for comparison.
3. Commit the resulting `run-after-025.csv` next to `run-baseline.csv`.

### Phase D — production deploy (0.3 session)

1. Ship on a feature flag `[ai] use_structured_subgraph = true` (default
   true for new installs, false for existing to allow 48h comparison).
2. After 48h clean on prod: flip default to true, schedule flag removal
   in the next minor release.

## Risks

| Risk | Mitigation |
|---|---|
| Subgraph JSON explodes prompt size on large neighbourhoods (50+ nodes) | Cap nodes at 40 in `attack_subgraph_json` with a truncation note. Prose fallback available via flag. |
| Ollama local models trip on JSON embedded in a larger prompt | Benchmark (Phase C) catches this — re-run on qwen2.5:3b + qwen2.5:1.5b; accept if both ≥70%. |
| Provider-specific JSON mode conflicts with existing schema enforcement | Keep our JSON inside a labelled section (`GRAPH_SUBGRAPH:`), not in a `response_format` field. The output schema of the LLM reply stays the same. |
| Dashboard depends on `graph_context` prose ending up in decision audit | Audit stores the prose separately (spec 016); `graph_subgraph` is prompt-only, never persisted. |
| Benchmarks stop being representative after prod traffic drifts | Spec 024 Phase A will make this regression-proof — once its scenario suite lands, coverage over the same cases runs on every PR. |

## Out of scope (explicit)

* Any evidence-citation / grounding requirement on the LLM output.
* Any change to `attack_narrative` or the downstream narrative consumers.
* Any change to the output schema expected from the LLM.
* Replacing or upgrading the production model. Left for a separate probe
  once this lands and the accuracy bar is hit.
* Re-engineering the deterministic pre-LLM gates
  (`incident_obvious`, `abuseipdb_autoblock`, `crowdsec_autoblock`,
  `honeypot_router`). Those still run first.

## Prompt for the executing AI

```
You are executing spec 025. Read the spec end-to-end before writing code.

Branch from origin/main as `025-structured-ai-prompt`. One PR, not four.
Phases A → B → C → D, each one commit with clear message.

Inegociable:
- cargo +1.95 clippy --workspace -- -D warnings clean
- cargo +1.95 fmt --all --check clean
- make test green
- make check green
- zero changes to attack_narrative; new attack_subgraph_json alongside
- no evidence_refs anywhere
- no output-schema change
- no provider/model change

Benchmark re-run lives in innerwarden-test/ai-grounding/ (not this repo).
Produce the run-after-025.csv locally and attach to the PR description,
then point to the accuracy delta vs run-baseline.csv.

Acceptance: qwen2.5:3b on the 15 benchmark cases ≥ 70% action_match.

Ship it.
```

## References

* Experiment scaffold: `innerwarden-test/ai-grounding/`
* Baseline CSV: `innerwarden-test/ai-grounding/results/run-baseline.csv`
* Prompt format definitions: `innerwarden-test/ai-grounding/prompts/formats.py`
* Current prompt builder: `crates/agent/src/ai/openai.rs:246` (`build_prompt`)
* Current graph narrative: `crates/agent/src/knowledge_graph/graph.rs::attack_narrative`
* Decision context: `crates/agent/src/ai/mod.rs::DecisionContext`
* Original complaint thread (2026-04-17): operator question about honeypot hit on port 2222
  being auto-blocked by AbuseIPDB gate; follow-up investigation showed qwen2.5:3b in
  format A chose `block_ip` but in format B chose `honeypot` on the same incident.
