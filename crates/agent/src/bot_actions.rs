use std::path::Path;

use tracing::{debug, info, warn};

use crate::{
    append_honeypot_marker_event, append_trust_rule, config, decisions, execute_decision,
    honeypot_runtime, skills, telegram, AgentState,
};

/// Handle Telegram action callbacks that execute responder skills.
/// Returns true when a callback was matched and handled.
pub(crate) async fn handle_telegram_action_callback(
    result: &telegram::ApprovalResult,
    data_dir: &Path,
    cfg: &config::AgentConfig,
    state: &mut AgentState,
) -> bool {
    // Spec 005 Phase 7: any operator tap — regardless of the chosen action —
    // clears the pending feedback entry and resets the ignore tally for the
    // underlying (detector, entity_type) key. This keeps the tracker
    // responsive to renewed operator engagement after a previous stretch of
    // ignores had demoted the class.
    {
        let action_label = if result.chosen_action.is_empty() {
            if result.approved {
                "approve"
            } else {
                "deny"
            }
        } else {
            result.chosen_action.as_str()
        };
        if let Some(ev) = state.feedback_tracker.on_operator_action(
            &result.incident_id,
            action_label,
            chrono::Utc::now(),
        ) {
            if let Err(e) = crate::notification_pipeline::feedback_store::append(data_dir, &ev) {
                tracing::warn!("feedback action persist failed: {e:#}");
            }
        }
    }

    // Quick-block sentinel: "quick:block:<ip>" - initiated from the inline keyboard on T.1 alerts
    if let Some(ip) = result.incident_id.strip_prefix("__quick_block__:") {
        let ip = ip.to_string();
        let operator = result.operator_name.clone();
        info!(ip = %ip, operator = %operator, "Telegram quick-block received");

        if !cfg.responder.enabled {
            tg_reply(
                state,
                "⚠️ Responder is disabled. Enable it in agent.toml to allow blocking.\n\
                 Run: <code>innerwarden configure responder</code>"
                    .to_string(),
            );
            return true;
        }

        let skill_id = format!("block-ip-{}", cfg.responder.block_backend);
        if !cfg.responder.allowed_skills.contains(&skill_id) {
            tg_reply(
                state,
                format!(
                    "⚠️ Skill <code>{skill_id}</code> is not in allowed_skills. \
                     Add it to agent.toml under [responder] allowed_skills."
                ),
            );
            return true;
        }

        let skill = state.skill_registry.get(&skill_id).or_else(|| {
            state
                .skill_registry
                .block_skill_for_backend(&cfg.responder.block_backend)
        });

        let Some(skill) = skill else {
            tg_reply(
                state,
                format!("⚠️ Skill <code>{skill_id}</code> not found in registry."),
            );
            return true;
        };

        // Build a minimal incident for the skill context
        let host = std::env::var("HOSTNAME")
            .or_else(|_| std::fs::read_to_string("/etc/hostname").map(|s| s.trim().to_string()))
            .unwrap_or_else(|_| "unknown".to_string());
        let inc = {
            use innerwarden_core::event::Severity;
            innerwarden_core::incident::Incident {
                ts: chrono::Utc::now(),
                host: host.clone(),
                incident_id: format!("telegram:quick_block:{ip}"),
                severity: Severity::High,
                title: format!("Quick block of {ip} via Telegram"),
                summary: format!("Telegram operator requested immediate block of {ip}"),
                evidence: serde_json::json!({}),
                recommended_checks: vec![],
                tags: vec!["telegram".to_string(), "manual".to_string()],
                entities: vec![innerwarden_core::entities::EntityRef::ip(ip.clone())],
            }
        };

        let ctx = skills::SkillContext {
            incident: inc.clone(),
            target_ip: Some(ip.clone()),
            target_user: None,
            target_container: None,
            duration_secs: None,
            host: inc.host.clone(),
            data_dir: data_dir.to_path_buf(),
            honeypot: honeypot_runtime(cfg),
            ai_provider: state.ai_router.any_llm(),
        };

        // 2026-05-10 (skill_gate): even operator-driven Telegram quick-blocks
        // route through `skill_gate::gate_block_ip`. Stops an accidental
        // tap from putting a `trusted_ips` IP or a Cloudflare CDN edge
        // into the firewall just because the operator clicked the inline
        // button on the wrong alert.
        let exec_result = match crate::skill_gate::gate_block_ip(&ip, &cfg.allowlist.trusted_ips) {
            Ok(gate) => {
                crate::skill_gate::execute_block_skill_gated(
                    skill,
                    &ctx,
                    cfg.responder.dry_run,
                    &gate,
                )
                .await
            }
            Err(refusal) => {
                warn!(
                    ip = %ip,
                    skill_id = %skill_id,
                    reason = %refusal,
                    "Telegram quick-block refused by gate (allowlist / safelist / shape)"
                );
                skills::SkillResult {
                    success: false,
                    message: format!("{refusal}"),
                }
            }
        };

        if exec_result.success {
            state.blocklist.insert(ip.clone());
        }

        // Audit trail
        if let Some(writer) = &mut state.decision_writer {
            let provider = "telegram".to_string();
            let entry = decisions::DecisionEntry {
                ts: chrono::Utc::now(),
                incident_id: inc.incident_id.clone(),
                host: inc.host.clone(),
                ai_provider: provider,
                action_type: "block_ip".to_string(),
                target_ip: Some(ip.clone()),
                target_user: None,
                skill_id: Some(skill_id.clone()),
                confidence: 1.0,
                auto_executed: true,
                dry_run: cfg.responder.dry_run,
                reason: "Quick block requested by Telegram operator".to_string(),
                estimated_threat: "manual".to_string(),
                execution_result: exec_result.message.clone(),
                prev_hash: None,
                decision_layer: Some("manual_operator".to_string()),
            };
            if let Err(e) = writer.write(&entry) {
                warn!("failed to write quick-block decision entry: {e:#}");
            }
        }

        let reply = if cfg.responder.dry_run {
            format!(
                "🧪 Simulated - would've dropped {ip} at the firewall. Enable live mode to make it real."
            )
        } else if exec_result.success {
            format!("🛡 Threat actor {ip} neutralized - dropped at the firewall. They won't pivot from there.")
        } else {
            format!("❌ Failed to contain {ip}: {}", exec_result.message)
        };
        tg_reply(state, reply);
        return true;
    }

    // Honeypot operator-in-the-loop: "hpot:{action}:{ip}" via send_honeypot_suggestion
    if let Some(ip) = result.incident_id.strip_prefix("__hpot__:") {
        let ip = ip.to_string();
        let operator = result.operator_name.clone();
        let chosen = result.chosen_action.as_str();
        info!(ip = %ip, operator = %operator, action = %chosen, "Telegram honeypot choice received");

        let Some(choice) = state.pending_honeypot_choices.remove(&ip) else {
            info!(
                ip = %ip,
                "Telegram honeypot choice for unknown or expired IP"
            );
            tg_reply(
                state,
                format!(
                    "⏳ That choice for {ip} expired or was already handled. If the threat is still active, it'll show up again."
                ),
            );
            return true;
        };

        let host = choice.incident.host.clone();
        let provider_label = "operator:telegram".to_string();

        match chosen {
            "honeypot" => {
                // Build SkillContext and execute the honeypot skill
                if let Some(skill) = state.skill_registry.get("honeypot") {
                    let mut runtime = honeypot_runtime(cfg);
                    let skill_ai = state.ai_router.any_llm();
                    runtime.ai_provider = skill_ai.clone();
                    let ctx = skills::SkillContext {
                        incident: choice.incident.clone(),
                        target_ip: Some(ip.clone()),
                        target_user: None,
                        target_container: None,
                        duration_secs: None,
                        host: host.clone(),
                        data_dir: data_dir.to_path_buf(),
                        honeypot: runtime.clone(),
                        ai_provider: skill_ai,
                    };
                    let exec_result = skill.execute(&ctx, cfg.responder.dry_run).await;
                    let msg = if exec_result.success {
                        match append_honeypot_marker_event(
                            data_dir,
                            &choice.incident,
                            &ip,
                            cfg.responder.dry_run,
                            &runtime,
                        )
                        .await
                        {
                            Ok(path) => format!(
                                "{} | honeypot marker written to {}",
                                exec_result.message,
                                path.display()
                            ),
                            Err(e) => {
                                warn!("failed to write honeypot marker: {e:#}");
                                exec_result.message.clone()
                            }
                        }
                    } else {
                        exec_result.message.clone()
                    };
                    if let Some(writer) = &mut state.decision_writer {
                        let entry = decisions::DecisionEntry {
                            ts: chrono::Utc::now(),
                            incident_id: choice.incident_id.clone(),
                            host: host.clone(),
                            ai_provider: provider_label,
                            action_type: "honeypot".to_string(),
                            target_ip: Some(ip.clone()),
                            target_user: None,
                            skill_id: Some("honeypot".to_string()),
                            confidence: 1.0,
                            auto_executed: true,
                            dry_run: cfg.responder.dry_run,
                            reason: "Telegram operator chose honeypot".to_string(),
                            estimated_threat: "high".to_string(),
                            execution_result: msg.clone(),
                            prev_hash: None,
                            decision_layer: Some("manual_operator".to_string()),
                        };
                        if let Err(e) = writer.write(&entry) {
                            warn!("failed to write honeypot decision entry: {e:#}");
                        }
                    }
                    let reply = if cfg.responder.dry_run {
                        format!(
                            "🧪 Dry run - {ip} would be sent to the honeypot. Enable live mode to execute for real."
                        )
                    } else if exec_result.success {
                        format!("🍯 {ip} sent to honeypot. Now let's see what they try to do.")
                    } else {
                        format!(
                            "❌ Failed to activate honeypot for {ip}: {}",
                            exec_result.message
                        )
                    };
                    tg_reply(state, reply);
                } else {
                    tg_reply(state, format!("⚠️ Honeypot skill not available for {ip}."));
                }
            }
            "block" => {
                // Execute block_ip skill
                let skill_id = format!("block-ip-{}", cfg.responder.block_backend);
                let skill = state.skill_registry.get(&skill_id).or_else(|| {
                    state
                        .skill_registry
                        .block_skill_for_backend(&cfg.responder.block_backend)
                });
                if let Some(skill) = skill {
                    let ctx = skills::SkillContext {
                        incident: choice.incident.clone(),
                        target_ip: Some(ip.clone()),
                        target_user: None,
                        target_container: None,
                        duration_secs: None,
                        host: host.clone(),
                        data_dir: data_dir.to_path_buf(),
                        honeypot: honeypot_runtime(cfg),
                        ai_provider: state.ai_router.any_llm(),
                    };
                    // 2026-05-10 (skill_gate): operator-driven block from
                    // the honeypot suggestion flow also routes through
                    // the gate. Same rationale as the quick-block above:
                    // an inline-keyboard tap on the wrong IP must not
                    // bypass the operator's `trusted_ips` allowlist or
                    // the cloud-provider safelist.
                    let exec_result =
                        match crate::skill_gate::gate_block_ip(&ip, &cfg.allowlist.trusted_ips) {
                            Ok(gate) => {
                                crate::skill_gate::execute_block_skill_gated(
                                    skill,
                                    &ctx,
                                    cfg.responder.dry_run,
                                    &gate,
                                )
                                .await
                            }
                            Err(refusal) => {
                                warn!(
                                    ip = %ip,
                                    skill_id = %skill_id,
                                    reason = %refusal,
                                    "Telegram operator-honeypot block refused by gate"
                                );
                                skills::SkillResult {
                                    success: false,
                                    message: format!("{refusal}"),
                                }
                            }
                        };
                    if exec_result.success {
                        state.blocklist.insert(ip.clone());
                    }
                    if let Some(writer) = &mut state.decision_writer {
                        let entry = decisions::DecisionEntry {
                            ts: chrono::Utc::now(),
                            incident_id: choice.incident_id.clone(),
                            host: host.clone(),
                            ai_provider: provider_label,
                            action_type: "block_ip".to_string(),
                            target_ip: Some(ip.clone()),
                            target_user: None,
                            skill_id: Some(skill_id.clone()),
                            confidence: 1.0,
                            auto_executed: true,
                            dry_run: cfg.responder.dry_run,
                            reason: "Telegram operator chose block".to_string(),
                            estimated_threat: "high".to_string(),
                            execution_result: exec_result.message.clone(),
                            prev_hash: None,
                            decision_layer: Some("manual_operator".to_string()),
                        };
                        if let Err(e) = writer.write(&entry) {
                            warn!("failed to write honeypot-block decision entry: {e:#}");
                        }
                    }
                    let reply = if cfg.responder.dry_run {
                        format!("🧪 Dry run - {ip} would be blocked in the firewall.")
                    } else if exec_result.success {
                        format!("🛡 {ip} blocked in the firewall. Done with this one.")
                    } else {
                        format!("❌ Failed to block {ip}: {}", exec_result.message)
                    };
                    tg_reply(state, reply);
                } else {
                    tg_reply(state, format!("⚠️ Block skill not available for {ip}."));
                }
            }
            "monitor" => {
                if let Some(writer) = &mut state.decision_writer {
                    let entry = decisions::DecisionEntry {
                        ts: chrono::Utc::now(),
                        incident_id: choice.incident_id.clone(),
                        host: host.clone(),
                        ai_provider: provider_label,
                        action_type: "monitor".to_string(),
                        target_ip: Some(ip.clone()),
                        target_user: None,
                        skill_id: None,
                        confidence: 1.0,
                        auto_executed: false,
                        dry_run: cfg.responder.dry_run,
                        reason: "Telegram operator chose monitor".to_string(),
                        estimated_threat: "medium".to_string(),
                        execution_result: "monitoring: no active action taken".to_string(),
                        prev_hash: None,
                        decision_layer: Some("manual_operator".to_string()),
                    };
                    if let Err(e) = writer.write(&entry) {
                        warn!("failed to write monitor decision entry: {e:#}");
                    }
                }
                tg_reply(
                    state,
                    format!("👁 Silent monitoring active on {ip} - collecting intel."),
                );
            }
            _ => {
                // "ignore" or anything else
                if let Some(writer) = &mut state.decision_writer {
                    let entry = decisions::DecisionEntry {
                        ts: chrono::Utc::now(),
                        incident_id: choice.incident_id.clone(),
                        host: host.clone(),
                        ai_provider: provider_label,
                        action_type: "ignore".to_string(),
                        target_ip: Some(ip.clone()),
                        target_user: None,
                        skill_id: None,
                        confidence: 1.0,
                        auto_executed: false,
                        dry_run: cfg.responder.dry_run,
                        reason: "Telegram operator chose ignore".to_string(),
                        estimated_threat: "low".to_string(),
                        execution_result: "ignored by operator".to_string(),
                        prev_hash: None,
                        decision_layer: Some("manual_operator".to_string()),
                    };
                    if let Err(e) = writer.write(&entry) {
                        warn!("failed to write ignore decision entry: {e:#}");
                    }
                }
                tg_reply(
                    state,
                    format!("👍 Anotado. {ip} marcado como falso positivo. Mantendo olho aberto."),
                );
            }
        }

        // Spec 062 Phase 6a: the operator's honeypot/block/monitor/ignore
        // choice is a gold training label.
        if cfg.learning.emit_labels {
            let sample = crate::warden_labels::build_sample(
                chrono::Utc::now(),
                &choice.incident.host,
                &choice.incident_id,
                crate::learned_suppression::detector_of(&choice.incident_id),
                Some(ip.as_str()),
                &choice.incident.severity,
                label_verdict(chosen),
                crate::warden_labels::LabelSource::TelegramHoneypot,
                &choice.incident.summary,
            );
            crate::warden_labels::append_label(data_dir, &sample, chrono::Utc::now());
        }

        return true;
    }

    // Spec 062 Phase 3: needs_review operator decision via send_needs_review_request.
    // sentinel: "__review__:{incident_id}". The operator tapped Block / Ignore /
    // Dismiss on a needs_review notification. We resolve the incident from the
    // store, run the chosen terminal action, and write a NEW decision row — that
    // becomes the incident's most-recent decision so the Phase 2 timeout sweep
    // (which keys off the latest decision being `needs_review`) stops treating it
    // as pending.
    if let Some(incident_id) = result.incident_id.strip_prefix("__review__:") {
        let incident_id = incident_id.to_string();
        let chosen = result.chosen_action.clone();
        let operator = result.operator_name.clone();
        info!(
            incident_id = %incident_id,
            operator = %operator,
            action = %chosen,
            "Telegram needs_review decision received"
        );

        let Some(incident) = state
            .sqlite_store
            .as_ref()
            .and_then(|s| s.get_incident(&incident_id).ok().flatten())
        else {
            tg_reply(
                state,
                format!(
                    "⏳ Couldn't find incident {incident_id} - it may have been pruned. Nothing to do."
                ),
            );
            return true;
        };

        let host = incident.host.clone();
        let ip = incident
            .entities
            .iter()
            .find(|e| e.r#type == innerwarden_core::entities::EntityType::Ip)
            .map(|e| e.value.clone());
        let provider_label = format!("telegram:{operator}");
        let now = chrono::Utc::now();

        // Resolve the terminal action. `block` runs the gated firewall skill;
        // `ignore`/`dismiss` are bookkeeping-only. Each path yields the audit
        // tuple (action_type, skill_id, target_ip, auto_executed, exec_result,
        // reply) written once below.
        #[allow(clippy::type_complexity)]
        let (action_type, skill_id, target_ip, auto_executed, exec_result, reply): (
            &str,
            Option<String>,
            Option<String>,
            bool,
            String,
            String,
        ) = match chosen.as_str() {
            "block" => {
                if let Some(ip) = ip.clone() {
                    let skill_id = format!("block-ip-{}", cfg.responder.block_backend);
                    let skill = state.skill_registry.get(&skill_id).or_else(|| {
                        state
                            .skill_registry
                            .block_skill_for_backend(&cfg.responder.block_backend)
                    });
                    if let Some(skill) = skill {
                        let ctx = skills::SkillContext {
                            incident: incident.clone(),
                            target_ip: Some(ip.clone()),
                            target_user: None,
                            target_container: None,
                            duration_secs: None,
                            host: host.clone(),
                            data_dir: data_dir.to_path_buf(),
                            honeypot: honeypot_runtime(cfg),
                            ai_provider: state.ai_router.any_llm(),
                        };
                        // 2026-05-10 skill_gate: operator-driven needs_review
                        // blocks route through the same allowlist / cloud-safelist
                        // gate as every other block path. A wrong tap must not
                        // firewall a trusted_ips IP or a CDN edge.
                        let exec =
                            match crate::skill_gate::gate_block_ip(&ip, &cfg.allowlist.trusted_ips)
                            {
                                Ok(gate) => {
                                    crate::skill_gate::execute_block_skill_gated(
                                        skill,
                                        &ctx,
                                        cfg.responder.dry_run,
                                        &gate,
                                    )
                                    .await
                                }
                                Err(refusal) => {
                                    warn!(
                                        ip = %ip,
                                        skill_id = %skill_id,
                                        reason = %refusal,
                                        "Telegram needs_review block refused by gate"
                                    );
                                    skills::SkillResult {
                                        success: false,
                                        message: format!("{refusal}"),
                                    }
                                }
                            };
                        if exec.success {
                            state.blocklist.insert(ip.clone());
                        }
                        let reply = if cfg.responder.dry_run {
                            format!("🧪 Dry run - {ip} would be blocked in the firewall.")
                        } else if exec.success {
                            format!("🛡 {ip} blocked. This review is closed.")
                        } else {
                            format!("❌ Failed to block {ip}: {}", exec.message)
                        };
                        (
                            "block_ip",
                            Some(skill_id),
                            Some(ip.clone()),
                            true,
                            exec.message,
                            reply,
                        )
                    } else {
                        (
                            "block_ip",
                            None,
                            Some(ip.clone()),
                            false,
                            "block skill not available".to_string(),
                            format!("⚠️ Block skill not available for {ip}."),
                        )
                    }
                } else {
                    // No IP to block — degrade to dismiss rather than a no-op.
                    (
                        "dismiss",
                        None,
                        None,
                        false,
                        "no IP on incident; dismissed".to_string(),
                        format!("⚠️ No IP on {incident_id} - can't block. Dismissed instead."),
                    )
                }
            }
            "ignore" => (
                "ignore",
                None,
                ip.clone(),
                false,
                "ignored by operator".to_string(),
                format!("🙈 {incident_id} ignored. Logged as a non-threat, keeping an eye out."),
            ),
            _ => (
                "dismiss",
                None,
                ip.clone(),
                false,
                "dismissed by operator".to_string(),
                format!("🗑 {incident_id} dismissed. Won't surface it again."),
            ),
        };

        // Terminal decision row (JSONL + SQLite mirror). Being the most-recent
        // decision is what excludes this incident from the Phase 2 sweep.
        if let Some(writer) = state.decision_writer.as_mut() {
            let entry = decisions::DecisionEntry {
                ts: now,
                incident_id: incident_id.clone(),
                host: host.clone(),
                ai_provider: provider_label,
                action_type: action_type.to_string(),
                target_ip: target_ip.clone(),
                target_user: None,
                skill_id,
                confidence: 1.0,
                auto_executed,
                dry_run: cfg.responder.dry_run,
                reason: format!("Telegram operator resolved needs_review via {action_type}"),
                estimated_threat: "manual".to_string(),
                execution_result: exec_result,
                prev_hash: None,
                decision_layer: Some("manual_operator".to_string()),
            };
            if let Err(e) = writer.write(&entry) {
                warn!("failed to write needs_review decision entry: {e:#}");
            }
        }

        // Label the in-memory graph in place so graph-derived dashboard views
        // reflect the resolution without waiting for a rebuild.
        {
            let mut graph = state.knowledge_graph.write().unwrap();
            graph.ingest_decision(
                &incident_id,
                action_type,
                target_ip.as_deref(),
                1.0,
                &format!("operator {operator} resolved needs_review: {action_type}"),
                auto_executed,
                now,
            );
        }

        // Spec 062 Phase 6a: an operator resolving a needs_review from the
        // phone is a gold training label. Persist it to the warden corpus.
        if cfg.learning.emit_labels {
            let sample = crate::warden_labels::build_sample(
                now,
                &host,
                &incident_id,
                crate::learned_suppression::detector_of(&incident_id),
                target_ip.as_deref(),
                &incident.severity,
                label_verdict(action_type),
                crate::warden_labels::LabelSource::TelegramReview,
                &incident.summary,
            );
            crate::warden_labels::append_label(data_dir, &sample, now);
        }

        tg_reply(state, reply);
        return true;
    }

    false
}

/// Map a decision `action_type` to the warden-corpus verdict vocabulary
/// (`block` | `ignore` | `dismiss` | `monitor` | `honeypot` | `suppress`).
/// `block_ip` collapses to `block`; everything else passes through.
fn label_verdict(action_type: &str) -> &str {
    match action_type {
        "block_ip" => "block",
        other => other,
    }
}

/// Handle standard pending confirmations (approve/reject/always) that come from
/// Telegram inline approval buttons.
/// Returns true when a pending confirmation entry was found and processed.
pub(crate) async fn handle_pending_confirmation(
    result: &telegram::ApprovalResult,
    data_dir: &Path,
    cfg: &config::AgentConfig,
    state: &mut AgentState,
) -> bool {
    let Some((pending, decision, incident)) =
        state.pending_confirmations.remove(&result.incident_id)
    else {
        debug!(
            incident_id = %result.incident_id,
            "Telegram approval for unknown or expired incident - ignoring"
        );
        return false;
    };

    // If "Always" - save trust rule before executing
    if result.always {
        info!(
            detector = %pending.detector,
            action = %pending.action_name,
            operator = %result.operator_name,
            "operator added trust rule via Telegram"
        );
        append_trust_rule(
            data_dir,
            &mut state.trust_rules,
            &pending.detector,
            &pending.action_name,
        );
    }

    // Acknowledge in Telegram: remove inline keyboard and add follow-up message
    let tg = state.telegram_client.clone();
    if let Some(ref tg) = tg {
        let _ = tg
            .resolve_confirmation(
                pending.telegram_message_id,
                result.approved,
                result.always,
                &result.operator_name,
            )
            .await;
    }

    let (exec_result, _cf_pushed) = if result.approved {
        info!(
            incident_id = %result.incident_id,
            operator = %result.operator_name,
            always = result.always,
            "operator approved action via Telegram"
        );
        execute_decision(&decision, &incident, data_dir, cfg, state).await
    } else {
        info!(
            incident_id = %result.incident_id,
            operator = %result.operator_name,
            "operator rejected action via Telegram"
        );
        (
            format!("rejected by operator {}", result.operator_name),
            false,
        )
    };

    // Audit trail with ai_provider = "telegram:<operator>"
    if let Some(writer) = &mut state.decision_writer {
        let provider = format!("telegram:{}", result.operator_name);
        let mut entry = decisions::build_entry(
            &incident.incident_id,
            &incident.host,
            &provider,
            &decision,
            cfg.responder.dry_run,
            &exec_result,
        );
        // PR17: override the auto-derived layer — `telegram:<op>` provider
        // does not match the AI-router pattern, but the decision is
        // operator-driven by definition.
        entry.decision_layer = Some("manual_operator".to_string());
        if let Err(e) = writer.write(&entry) {
            warn!("failed to write Telegram decision entry: {e:#}");
        }
    }

    true
}

fn tg_reply(state: &AgentState, text: impl Into<String>) {
    if let Some(ref tg) = state.telegram_client {
        let tg = tg.clone();
        let text = text.into();
        tokio::spawn(async move {
            let _ = tg.send_text_message(&text).await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn approval(id: &str, chosen_action: &str) -> telegram::ApprovalResult {
        telegram::ApprovalResult {
            incident_id: id.to_string(),
            approved: true,
            operator_name: "operator".to_string(),
            always: false,
            chosen_action: chosen_action.to_string(),
        }
    }

    #[tokio::test]
    async fn quick_block_returns_warning_when_responder_disabled() {
        let dir = TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let cfg = config::AgentConfig::default();
        let handled = handle_telegram_action_callback(
            &approval("__quick_block__:198.51.100.42", ""),
            dir.path(),
            &cfg,
            &mut state,
        )
        .await;
        assert!(handled);
    }

    #[tokio::test]
    async fn quick_block_uses_skill_and_updates_blocklist_when_allowed() {
        let dir = TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let mut cfg = config::AgentConfig::default();
        cfg.responder.enabled = true;
        cfg.responder.dry_run = true;
        cfg.responder.block_backend = "ufw".to_string();
        cfg.responder.allowed_skills = vec!["block-ip-ufw".to_string()];
        let handled = handle_telegram_action_callback(
            &approval("__quick_block__:203.0.113.45", ""),
            dir.path(),
            &cfg,
            &mut state,
        )
        .await;

        assert!(handled);
        assert!(state.blocklist.contains("203.0.113.45"));
    }

    #[tokio::test]
    async fn quick_block_returns_warning_when_skill_not_allowed() {
        let dir = TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let mut cfg = config::AgentConfig::default();
        cfg.responder.enabled = true;
        cfg.responder.block_backend = "ufw".to_string();
        cfg.responder.allowed_skills = Vec::new();

        let handled = handle_telegram_action_callback(
            &approval("__quick_block__:203.0.113.46", ""),
            dir.path(),
            &cfg,
            &mut state,
        )
        .await;

        assert!(handled);
        assert!(!state.blocklist.contains("203.0.113.46"));
    }

    #[tokio::test]
    async fn honeypot_callback_monitor_path_consumes_pending_choice() {
        let dir = TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let cfg = config::AgentConfig::default();
        state.pending_honeypot_choices.insert(
            "198.51.100.55".to_string(),
            crate::PendingHoneypotChoice {
                ip: "198.51.100.55".to_string(),
                incident_id: "inc-hpot-1".to_string(),
                incident: crate::tests::test_incident("198.51.100.55"),
                expires_at: chrono::Utc::now() + chrono::Duration::minutes(5),
            },
        );

        let handled = handle_telegram_action_callback(
            &approval("__hpot__:198.51.100.55", "monitor"),
            dir.path(),
            &cfg,
            &mut state,
        )
        .await;

        assert!(handled);
        assert!(!state.pending_honeypot_choices.contains_key("198.51.100.55"));
    }

    #[tokio::test]
    async fn honeypot_callback_returns_warning_for_unknown_choice() {
        let dir = TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let cfg = config::AgentConfig::default();

        let handled = handle_telegram_action_callback(
            &approval("__hpot__:198.51.100.56", "monitor"),
            dir.path(),
            &cfg,
            &mut state,
        )
        .await;

        assert!(handled);
        assert!(!state.pending_honeypot_choices.contains_key("198.51.100.56"));
    }

    #[tokio::test]
    async fn honeypot_callback_ignore_path_consumes_pending_choice() {
        let dir = TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let cfg = config::AgentConfig::default();
        state.pending_honeypot_choices.insert(
            "198.51.100.57".to_string(),
            crate::PendingHoneypotChoice {
                ip: "198.51.100.57".to_string(),
                incident_id: "inc-hpot-ignore".to_string(),
                incident: crate::tests::test_incident("198.51.100.57"),
                expires_at: chrono::Utc::now() + chrono::Duration::minutes(5),
            },
        );

        let handled = handle_telegram_action_callback(
            &approval("__hpot__:198.51.100.57", "ignore"),
            dir.path(),
            &cfg,
            &mut state,
        )
        .await;

        assert!(handled);
        assert!(!state.pending_honeypot_choices.contains_key("198.51.100.57"));
    }

    // -----------------------------------------------------------------------
    // Spec 062 Phase 3 — needs_review operator decision handler
    // -----------------------------------------------------------------------

    fn today_str() -> String {
        chrono::Local::now()
            .date_naive()
            .format("%Y-%m-%d")
            .to_string()
    }

    #[tokio::test]
    async fn needs_review_dismiss_resolves_and_writes_decision() {
        let dir = TempDir::new().expect("tempdir");
        let store = crate::tests::test_sqlite_store(dir.path());
        let inc = crate::tests::test_incident("203.0.113.70");
        crate::tests::insert_test_incident(&store, &inc);
        let mut state = crate::tests::triage_test_state(dir.path());
        state.sqlite_store = Some(store);
        let cfg = config::AgentConfig::default();

        let id = format!("__review__:{}", inc.incident_id);
        let handled = handle_telegram_action_callback(
            &approval(&id, "dismiss"),
            dir.path(),
            &cfg,
            &mut state,
        )
        .await;

        assert!(handled);
        // A terminal decision row was written — this is what excludes the
        // incident from the Phase 2 needs_review timeout sweep.
        assert!(
            decisions::count_decisions_for_date(dir.path(), &today_str()) >= 1,
            "dismiss must write a terminal decision row"
        );
    }

    #[tokio::test]
    async fn needs_review_unknown_incident_replies_without_decision() {
        let dir = TempDir::new().expect("tempdir");
        let store = crate::tests::test_sqlite_store(dir.path());
        let mut state = crate::tests::triage_test_state(dir.path());
        state.sqlite_store = Some(store);
        let cfg = config::AgentConfig::default();

        let handled = handle_telegram_action_callback(
            &approval("__review__:does-not-exist", "dismiss"),
            dir.path(),
            &cfg,
            &mut state,
        )
        .await;

        assert!(handled, "the sentinel is still consumed");
        assert_eq!(
            decisions::count_decisions_for_date(dir.path(), &today_str()),
            0,
            "no incident -> no decision row written"
        );
    }

    #[tokio::test]
    async fn needs_review_block_updates_blocklist() {
        let dir = TempDir::new().expect("tempdir");
        let store = crate::tests::test_sqlite_store(dir.path());
        let inc = crate::tests::test_incident("203.0.113.71");
        crate::tests::insert_test_incident(&store, &inc);
        let mut state = crate::tests::triage_test_state(dir.path());
        state.sqlite_store = Some(store);
        let mut cfg = config::AgentConfig::default();
        cfg.responder.dry_run = true;
        cfg.responder.block_backend = "ufw".to_string();

        let id = format!("__review__:{}", inc.incident_id);
        let handled =
            handle_telegram_action_callback(&approval(&id, "block"), dir.path(), &cfg, &mut state)
                .await;

        assert!(handled);
        assert!(
            state.blocklist.contains("203.0.113.71"),
            "operator block via needs_review must update the blocklist"
        );
    }

    #[tokio::test]
    async fn pending_confirmation_reject_writes_trust_rule_when_always_set() {
        let dir = TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let cfg = config::AgentConfig::default();
        state.pending_confirmations.insert(
            "inc-approve-1".to_string(),
            (
                telegram::PendingConfirmation {
                    incident_id: "inc-approve-1".to_string(),
                    telegram_message_id: 10,
                    action_description: "block ip".to_string(),
                    created_at: chrono::Utc::now(),
                    expires_at: chrono::Utc::now() + chrono::Duration::minutes(5),
                    detector: "ssh_bruteforce".to_string(),
                    action_name: "block_ip".to_string(),
                },
                crate::ai::AiDecision::ignore("rejected in test"),
                crate::tests::test_incident("203.0.113.200"),
            ),
        );
        let result = telegram::ApprovalResult {
            incident_id: "inc-approve-1".to_string(),
            approved: false,
            operator_name: "operator".to_string(),
            always: true,
            chosen_action: String::new(),
        };

        let handled = handle_pending_confirmation(&result, dir.path(), &cfg, &mut state).await;

        assert!(handled);
        assert!(state.trust_rules.contains("ssh_bruteforce:block_ip"));
    }

    #[tokio::test]
    async fn pending_confirmation_returns_false_for_unknown_incident() {
        let dir = TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let cfg = config::AgentConfig::default();
        let result = telegram::ApprovalResult {
            incident_id: "missing".to_string(),
            approved: true,
            operator_name: "operator".to_string(),
            always: false,
            chosen_action: String::new(),
        };

        let handled = handle_pending_confirmation(&result, dir.path(), &cfg, &mut state).await;
        assert!(!handled);
    }
}
