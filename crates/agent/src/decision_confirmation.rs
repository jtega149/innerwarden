use crate::{ai, config, telegram, AgentState};

/// Execute operator confirmation flow:
/// Telegram approval request first, then webhook fallback when configured.
pub(crate) async fn execute_request_confirmation(
    summary: &str,
    decision: &ai::AiDecision,
    incident: &innerwarden_core::incident::Incident,
    cfg: &config::AgentConfig,
    state: &mut AgentState,
) -> (String, bool) {
    // T.2 - send inline keyboard approval request via Telegram when enabled.
    let tg = state.telegram_client.clone();
    let req_detector = crate::agent_context::incident_detector(&incident.incident_id).to_string();
    let req_action = decision.action.name();
    if let Some(tg) = tg {
        let ttl = cfg.telegram.approval_ttl_secs;
        match tg
            .send_confirmation_request(incident, summary, req_action, decision.confidence, ttl)
            .await
        {
            Ok(msg_id) => {
                let now = chrono::Utc::now();
                let pending = telegram::PendingConfirmation {
                    incident_id: incident.incident_id.clone(),
                    telegram_message_id: msg_id,
                    action_description: summary.to_string(),
                    created_at: now,
                    expires_at: now + chrono::Duration::seconds(ttl as i64),
                    detector: req_detector,
                    action_name: req_action.to_string(),
                };
                state.pending_confirmations.insert(
                    incident.incident_id.clone(),
                    (pending, decision.clone(), incident.clone()),
                );
                return (
                    "pending: operator confirmation requested via Telegram".to_string(),
                    false,
                );
            }
            Err(e) => {
                tracing::warn!("Telegram confirmation request failed: {e:#}");
            }
        }
    }

    // Fallback: webhook notification when Telegram is not configured.
    if cfg.webhook.enabled && !cfg.webhook.url.is_empty() {
        let payload = serde_json::json!({
            "type": "confirmation_required",
            "incident_id": incident.incident_id,
            "summary": summary,
            "decision_reason": decision.reason,
        });
        let client = reqwest::Client::new();
        match client.post(&cfg.webhook.url).json(&payload).send().await {
            Ok(_) => ("confirmation request sent via webhook".to_string(), false),
            Err(e) => (format!("confirmation webhook failed: {e}"), false),
        }
    } else {
        (
            "confirmation requested (no Telegram or webhook configured)".to_string(),
            false,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn test_decision() -> ai::AiDecision {
        ai::AiDecision {
            action: ai::AiAction::RequestConfirmation {
                summary: "Need operator approval".to_string(),
            },
            confidence: 0.8,
            auto_execute: false,
            reason: "sensitive action".to_string(),
            alternatives: vec!["monitor".to_string()],
            estimated_threat: "high".to_string(),
        }
    }

    #[tokio::test]
    async fn returns_local_pending_message_without_telegram_or_webhook() {
        let dir = TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let cfg = config::AgentConfig::default();
        let incident = crate::tests::test_incident("203.0.113.10");

        let (status, pushed) = execute_request_confirmation(
            "please confirm",
            &test_decision(),
            &incident,
            &cfg,
            &mut state,
        )
        .await;

        assert_eq!(
            status,
            "confirmation requested (no Telegram or webhook configured)"
        );
        assert!(!pushed);
        assert!(state.pending_confirmations.is_empty());
    }

    #[tokio::test]
    async fn webhook_fallback_reports_success() {
        let dir = TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let mut cfg = config::AgentConfig::default();

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind listener");
        let addr = listener.local_addr().expect("local addr");
        cfg.webhook.enabled = true;
        cfg.webhook.url = format!("http://{addr}/confirm");

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            let mut buf = [0_u8; 4096];
            let _ = socket.read(&mut buf).await;
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .await
                .expect("write response");
        });

        let incident = crate::tests::test_incident("203.0.113.11");
        let (status, pushed) = execute_request_confirmation(
            "confirm via webhook",
            &test_decision(),
            &incident,
            &cfg,
            &mut state,
        )
        .await;

        server.await.expect("server task");
        assert_eq!(status, "confirmation request sent via webhook");
        assert!(!pushed);
    }

    #[tokio::test]
    async fn webhook_fallback_reports_error() {
        let dir = TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let mut cfg = config::AgentConfig::default();
        cfg.webhook.enabled = true;
        // Port 9 should fail quickly on localhost when no listener is present.
        cfg.webhook.url = "http://127.0.0.1:9/confirm".to_string();
        let incident = crate::tests::test_incident("203.0.113.12");

        let (status, pushed) = execute_request_confirmation(
            "confirm via broken webhook",
            &test_decision(),
            &incident,
            &cfg,
            &mut state,
        )
        .await;

        assert!(status.starts_with("confirmation webhook failed:"));
        assert!(!pushed);
    }
}
