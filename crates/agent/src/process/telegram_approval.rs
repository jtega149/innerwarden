use std::path::Path;

use crate::{
    bot_actions::{handle_pending_confirmation, handle_telegram_action_callback},
    bot_commands::handle_telegram_bot_command,
    bot_helpers, config, telegram, AgentState,
};

// ---------------------------------------------------------------------------
// Telegram T.2 approval handler
// ---------------------------------------------------------------------------

/// Process a single operator approval result received from the Telegram polling task.
/// Resolves and executes (or discards) the pending confirmation, writes an audit entry,
/// and informs the operator via Telegram of the outcome.
pub(crate) async fn process_telegram_approval(
    result: telegram::ApprovalResult,
    data_dir: &Path,
    cfg: &config::AgentConfig,
    state: &mut AgentState,
) {
    // 2FA: intercept TOTP code responses before any other handler
    if bot_helpers::handle_totp_response(&result, data_dir, cfg, state) {
        return;
    }

    if handle_telegram_bot_command(&result, data_dir, cfg, state).await {
        return;
    }

    if bot_helpers::handle_telegram_triage_action(&result, data_dir, cfg, state) {
        return;
    }

    if handle_telegram_action_callback(&result, data_dir, cfg, state).await {
        return;
    }

    let _ = handle_pending_confirmation(&result, data_dir, cfg, state).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn process_telegram_approval_handles_totp_cancel_first() {
        let dir = TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let operator = "alice";
        state.two_factor_state.set_pending(
            operator,
            crate::two_factor::PendingAction {
                action_type: crate::two_factor::PendingActionType::AllowlistIp(
                    "198.51.100.99".to_string(),
                ),
                operator: operator.to_string(),
                created_at: chrono::Utc::now(),
                expires_at: chrono::Utc::now() + chrono::Duration::minutes(5),
                method: crate::two_factor::TwoFactorMethod::Totp,
            },
        );
        let cfg = config::AgentConfig::default();
        let result = telegram::ApprovalResult {
            incident_id: "/cancel".to_string(),
            approved: true,
            operator_name: operator.to_string(),
            always: false,
            chosen_action: String::new(),
        };

        process_telegram_approval(result, dir.path(), &cfg, &mut state).await;
        assert!(
            state.two_factor_state.take_pending(operator).is_none(),
            "pending 2FA action should be cancelled"
        );
    }

    #[tokio::test]
    async fn process_telegram_approval_routes_bot_command_before_confirmation() {
        let dir = TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let cfg = config::AgentConfig::default();
        let result = telegram::ApprovalResult {
            incident_id: "/status".to_string(),
            approved: true,
            operator_name: "operator".to_string(),
            always: false,
            chosen_action: String::new(),
        };

        process_telegram_approval(result, dir.path(), &cfg, &mut state).await;
        assert!(
            state.pending_confirmations.is_empty(),
            "bot command path should not mutate pending confirmations"
        );
    }

    #[tokio::test]
    async fn process_telegram_approval_falls_through_without_handlers() {
        let dir = TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let cfg = config::AgentConfig::default();
        let result = telegram::ApprovalResult {
            incident_id: "not-a-command".to_string(),
            approved: false,
            operator_name: "operator".to_string(),
            always: false,
            chosen_action: String::new(),
        };

        process_telegram_approval(result, dir.path(), &cfg, &mut state).await;
        assert!(state.pending_confirmations.is_empty());
    }
}
