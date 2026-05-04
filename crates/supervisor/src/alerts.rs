//! Telegram notification sender.
//!
//! Token + chat id are passed in by the caller (typically from environment
//! variables or a CLI flag). When either is absent, all `send_*` calls are
//! silent no-ops - operators who do not configure Telegram simply do not
//! receive alerts; nothing in the supervisor loop fails because of it.
//!
//! Hostname is read from `/etc/hostname` once at construction so the alert
//! payload identifies which host produced it. `send_telegram` swallows network
//! failures (logs a warn) - alert delivery is best-effort by design.

use serde::Serialize;
use tracing::{info, warn};

pub struct Alerter {
    telegram_token: Option<String>,
    telegram_chat_id: Option<String>,
    hostname: String,
}

impl Alerter {
    pub fn new(telegram_token: Option<String>, telegram_chat_id: Option<String>) -> Self {
        let hostname = std::fs::read_to_string("/etc/hostname")
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| "unknown".into());
        Self {
            telegram_token,
            telegram_chat_id,
            hostname,
        }
    }

    pub fn agent_restarted(&self, old_pid: u32, new_pid: u32, reason: &str) {
        let msg = format!(
            "\u{1f6a8} *InnerWarden Supervisor*\nHost: `{}`\nAgent restarted: PID {} \u{2192} {}\nReason: {}",
            self.hostname, old_pid, new_pid, reason
        );
        self.send_telegram(&msg);
    }

    pub fn restart_failed(&self, pid: u32, error: &str) {
        let msg = format!(
            "\u{2757} *InnerWarden Supervisor CRITICAL*\nHost: `{}`\nAgent PID {} died but restart FAILED\nError: {}",
            self.hostname, pid, error
        );
        self.send_telegram(&msg);
    }

    pub fn integrity_violation(&self, detail: &str) {
        let msg = format!(
            "\u{1f6d1} *InnerWarden INTEGRITY VIOLATION*\nHost: `{}`\n{}",
            self.hostname, detail
        );
        self.send_telegram(&msg);
    }

    fn send_telegram(&self, message: &str) {
        let (Some(token), Some(chat_id)) = (&self.telegram_token, &self.telegram_chat_id) else {
            return;
        };
        let url = format!("https://api.telegram.org/bot{}/sendMessage", token);
        #[derive(Serialize)]
        struct Body<'a> {
            chat_id: &'a str,
            text: &'a str,
            parse_mode: &'a str,
        }
        let body = Body {
            chat_id,
            text: message,
            parse_mode: "Markdown",
        };
        match ureq::post(&url).send_json(&body) {
            Ok(_) => info!("telegram alert sent"),
            Err(e) => warn!("telegram alert failed: {}", e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_token_or_chat_id_is_silent_noop() {
        // No tokens configured: send_telegram returns immediately, no panic,
        // no network attempt. The public `agent_restarted` etc just delegate
        // to send_telegram; cover them via a direct call here.
        let alerter = Alerter {
            telegram_token: None,
            telegram_chat_id: Some("chat".into()),
            hostname: "test".into(),
        };
        alerter.agent_restarted(1, 2, "test");
        alerter.restart_failed(1, "test");
        alerter.integrity_violation("test");
    }
}
