use std::path::Path;

use anyhow::Result;
use tracing::{info, warn};

use crate::{correlation_engine, AgentState};

/// Ingest newly written incidents and update narrative/correlation state.
pub(crate) fn ingest_new_incidents(
    data_dir: &Path,
    _today: &str,
    state: &mut AgentState,
) -> Result<()> {
    // Read new incidents from SQLite store
    let new_incidents: Vec<innerwarden_core::incident::Incident> =
        if let Some(ref sq) = state.sqlite_store {
            let cursor_key = "narrative_incidents";
            let cval = sq.get_agent_cursor(cursor_key).unwrap_or(0);
            match sq.incidents_since(cval, 5000) {
                Ok(rows) if !rows.is_empty() => {
                    let max_id = rows.last().unwrap().0;
                    let entries: Vec<_> = rows.into_iter().map(|(_, inc)| inc).collect();
                    let _ = sq.set_agent_cursor(cursor_key, max_id);
                    entries
                }
                _ => Vec::new(),
            }
        } else {
            warn!("sqlite_store not available — cannot read narrative incidents");
            return Ok(());
        };
    let _ = data_dir; // silence unused warning
    if !new_incidents.is_empty() {
        state.narrative_acc.ingest_incidents(&new_incidents);

        // Feed incidents into cross-layer correlation engine
        for incident in &new_incidents {
            let corr_event = correlation_engine::CorrelationEngine::classify_incident(incident);
            state.correlation_engine.observe(corr_event);
        }

        // Check for completed attack chains
        let chains = state.correlation_engine.drain_completed();
        for chain in &chains {
            info!(
                chain_id = %chain.chain_id,
                rule = %chain.rule_id,
                name = %chain.rule_name,
                stages = chain.stages_matched,
                layers = chain.layers_involved.len(),
                confidence = chain.confidence,
                "cross-layer attack chain detected: {}",
                chain.summary
            );

            // Phase 014-C: Create a synthetic Incident node for this chain and
            // ingest it into the graph. The incident carries all entities from the
            // chain events, so the existing incident ingestion creates TriggeredBy
            // edges automatically. Multiple events in a chain that share entities
            // now have a single "parent" incident in the graph, queryable via
            // /api/incidents, /api/journey, and graph traversal.
            //
            // Previously we tried to link existing incidents via CorrelatedWith,
            // but for pure event-driven chains (CL-008 file.read + outbound) there
            // are no existing incidents to link — the chain is the incident.
            {
                let host = chain
                    .events
                    .first()
                    .and_then(|_| state.knowledge_graph.read().ok())
                    .and_then(|g| {
                        g.system_node()
                            .and_then(|id| g.get_node(id))
                            .map(|n| n.label())
                    })
                    .unwrap_or_else(|| "unknown".to_string());

                // Deduplicate entities across all chain events
                let mut entity_map: std::collections::BTreeMap<
                    (String, String),
                    innerwarden_core::entities::EntityRef,
                > = std::collections::BTreeMap::new();
                for ev in &chain.events {
                    for e in &ev.entities {
                        entity_map
                            .entry((format!("{:?}", e.r#type), e.value.clone()))
                            .or_insert_with(|| e.clone());
                    }
                }
                let entities: Vec<innerwarden_core::entities::EntityRef> =
                    entity_map.into_values().collect();

                if !entities.is_empty() {
                    let chain_incident = innerwarden_core::incident::Incident {
                        ts: chain.last_ts,
                        host,
                        incident_id: format!(
                            "cross_layer_chain:{}:{}",
                            chain.rule_id.to_lowercase(),
                            chain.chain_id
                        ),
                        severity: chain.severity.clone(),
                        title: format!(
                            "Cross-layer chain: {} ({} stages)",
                            chain.rule_name, chain.stages_matched
                        ),
                        summary: chain.summary.clone(),
                        evidence: serde_json::json!({
                            "chain_id": chain.chain_id,
                            "rule_id": chain.rule_id,
                            "stages": chain.stages_matched,
                            "stages_total": chain.stages_total,
                            "confidence": chain.confidence,
                            "layers": format!("{:?}", chain.layers_involved),
                        }),
                        recommended_checks: vec![],
                        tags: vec!["cross_layer_chain".to_string(), chain.rule_id.clone()],
                        entities,
                    };

                    // Ingest into graph (creates Incident node + TriggeredBy edges
                    // to each entity). The incident_enrichment path (Phase 014-D)
                    // handles any pid info; for chain incidents there is none.
                    {
                        let mut graph = state.knowledge_graph.write().unwrap();
                        graph.ingest_incident(&chain_incident);
                    }
                    info!(
                        chain_id = %chain.chain_id,
                        entities = chain_incident.entities.len(),
                        "chain incident ingested into graph"
                    );
                }
            }

            // Evaluate chain-triggered playbooks
            for incident in &new_incidents {
                if let Some(exec) = state
                    .playbook_engine
                    .evaluate_chain(&chain.rule_id, incident)
                {
                    info!(
                        playbook = %exec.playbook_id,
                        chain = %chain.rule_id,
                        steps = exec.steps.len(),
                        "chain-triggered playbook: {}",
                        exec.playbook_name
                    );
                }
            }
        }

        // Persist detected chains to JSON for dashboard
        if !chains.is_empty() {
            let chains_path = data_dir.join("attack-chains.json");
            let mut existing: Vec<serde_json::Value> = std::fs::read_to_string(&chains_path)
                .ok()
                .and_then(|s| serde_json::from_str(&s).ok())
                .unwrap_or_default();
            for chain in &chains {
                if let Ok(val) = serde_json::to_value(chain) {
                    existing.push(val);
                }
            }
            // Keep last 100 chains
            if existing.len() > 100 {
                existing = existing.split_off(existing.len() - 100);
            }
            let _ = std::fs::write(
                &chains_path,
                serde_json::to_string(&existing).unwrap_or_default(),
            );
        }

        // Check for multi-low elevation
        if let Some(chain) = state.correlation_engine.check_multi_low_elevation() {
            info!(
                chain_id = %chain.chain_id,
                "multi-low severity elevation: {}",
                chain.summary
            );
        }
    }

    Ok(())
}
