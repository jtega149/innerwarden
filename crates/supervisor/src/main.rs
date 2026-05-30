//! `innerwarden-supervisor` binary - OSS process supervisor for the
//! innerwarden-agent. See the crate-level docs in `lib.rs` for what it does.
//!
//! Telegram credentials are read from `INNERWARDEN_TELEGRAM_TOKEN` and
//! `INNERWARDEN_TELEGRAM_CHAT_ID`. When either is absent the supervisor still
//! runs; alerts become silent no-ops.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use innerwarden_supervisor::{Supervisor, SupervisorConfig};

#[derive(Parser, Debug)]
#[command(name = "innerwarden-supervisor")]
#[command(about = "Process supervisor for innerwarden-agent")]
struct Cli {
    /// Path to the agent binary to monitor and restart.
    #[arg(long, default_value = "/usr/local/bin/innerwarden-agent")]
    agent_binary: PathBuf,

    /// Argument to pass to the agent on every (re)start. Repeat the flag for
    /// each argument: `--agent-arg --config --agent-arg /etc/innerwarden/agent.toml`.
    #[arg(long = "agent-arg", allow_hyphen_values = true)]
    agent_args: Vec<String>,

    /// Agent API base URL for the periodic health probe (HTTPS by default;
    /// the agent serves TLS, and loopback cert verification is auto-skipped).
    // HTTPS: the agent serves its dashboard/API over TLS by default (a
    // self-signed cert on a fresh install). The health checker auto-skips
    // cert verification for loopback HTTPS (see health.rs AUDIT-005). An
    // `http://` default here would hit the TLS listener with a plaintext
    // request, fail every probe, and the supervisor would SIGKILL a
    // perfectly healthy agent in a loop. Verified live on test001
    // 2026-05-30: /livez returns 200 on https, connection-refused on http.
    #[arg(long, default_value = "https://127.0.0.1:8787")]
    agent_api: String,

    /// Health check interval in seconds.
    #[arg(long, default_value_t = 30)]
    health_interval: u64,

    /// Maximum restarts allowed per rolling hour before the supervisor halts.
    #[arg(long, default_value_t = 10)]
    max_restarts_per_hour: u32,

    /// Log level passed to the tracing subscriber when `RUST_LOG` is unset.
    #[arg(long, default_value = "info")]
    log_level: String,
}

fn env_filter_for(log_level: &str) -> tracing_subscriber::EnvFilter {
    tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(log_level))
}

fn build_supervisor_config(
    cli: Cli,
    telegram_token: Option<String>,
    telegram_chat_id: Option<String>,
) -> SupervisorConfig {
    let config = SupervisorConfig::new(cli.agent_binary)
        .with_args(cli.agent_args)
        .with_health(cli.agent_api, Duration::from_secs(cli.health_interval))
        .with_max_restarts_per_hour(cli.max_restarts_per_hour);

    match (telegram_token, telegram_chat_id) {
        (Some(token), Some(chat_id)) if !token.is_empty() && !chat_id.is_empty() => {
            config.with_telegram(token, chat_id)
        }
        _ => config,
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter(env_filter_for(&cli.log_level))
        .init();

    tracing::info!(
        "innerwarden-supervisor v{} starting",
        env!("CARGO_PKG_VERSION")
    );

    let config = build_supervisor_config(
        cli,
        std::env::var("INNERWARDEN_TELEGRAM_TOKEN").ok(),
        std::env::var("INNERWARDEN_TELEGRAM_CHAT_ID").ok(),
    );

    Supervisor::new(config)
        .context("supervisor pre-flight check failed")?
        .run()
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn cli_uses_operator_friendly_defaults() {
        let cli = Cli::try_parse_from(["innerwarden-supervisor"]).expect("defaults should parse");

        assert_eq!(
            cli.agent_binary,
            PathBuf::from("/usr/local/bin/innerwarden-agent")
        );
        assert!(cli.agent_args.is_empty());
        assert_eq!(cli.agent_api, "https://127.0.0.1:8787");
        assert_eq!(cli.health_interval, 30);
        assert_eq!(cli.max_restarts_per_hour, 10);
        assert_eq!(cli.log_level, "info");
    }

    #[test]
    fn cli_accepts_repeated_agent_args_with_hyphen_values() {
        let cli = Cli::try_parse_from([
            "innerwarden-supervisor",
            "--agent-binary",
            "/opt/innerwarden-agent",
            "--agent-arg",
            "--config",
            "--agent-arg",
            "/etc/innerwarden/agent.toml",
            "--agent-api",
            "https://127.0.0.1:9443",
            "--health-interval",
            "5",
            "--max-restarts-per-hour",
            "3",
            "--log-level",
            "debug",
        ])
        .expect("custom CLI should parse");

        assert_eq!(cli.agent_binary, PathBuf::from("/opt/innerwarden-agent"));
        assert_eq!(
            cli.agent_args,
            vec!["--config", "/etc/innerwarden/agent.toml"]
        );
        assert_eq!(cli.agent_api, "https://127.0.0.1:9443");
        assert_eq!(cli.health_interval, 5);
        assert_eq!(cli.max_restarts_per_hour, 3);
        assert_eq!(cli.log_level, "debug");
    }

    #[test]
    fn build_config_maps_cli_fields_into_supervisor_config() {
        let cli = Cli::try_parse_from([
            "innerwarden-supervisor",
            "--agent-binary",
            "/bin/agent",
            "--agent-arg",
            "--config",
            "--agent-api",
            "https://localhost:8787",
            "--health-interval",
            "45",
            "--max-restarts-per-hour",
            "7",
        ])
        .expect("CLI should parse");

        let config = build_supervisor_config(cli, None, None);

        assert_eq!(config.agent_binary, PathBuf::from("/bin/agent"));
        assert_eq!(config.agent_args, vec!["--config"]);
        assert_eq!(config.agent_api, "https://localhost:8787");
        assert_eq!(config.health_interval, Duration::from_secs(45));
        assert_eq!(config.max_restarts_per_hour, 7);
        assert!(config.telegram_token.is_none());
        assert!(config.telegram_chat_id.is_none());
    }

    #[test]
    fn build_config_requires_both_non_empty_telegram_values() {
        let with_both = build_supervisor_config(
            Cli::try_parse_from(["innerwarden-supervisor"]).expect("CLI should parse"),
            Some("token".to_string()),
            Some("chat".to_string()),
        );
        assert_eq!(with_both.telegram_token.as_deref(), Some("token"));
        assert_eq!(with_both.telegram_chat_id.as_deref(), Some("chat"));

        let missing_chat = build_supervisor_config(
            Cli::try_parse_from(["innerwarden-supervisor"]).expect("CLI should parse"),
            Some("token".to_string()),
            None,
        );
        assert!(missing_chat.telegram_token.is_none());
        assert!(missing_chat.telegram_chat_id.is_none());

        let empty_token = build_supervisor_config(
            Cli::try_parse_from(["innerwarden-supervisor"]).expect("CLI should parse"),
            Some(String::new()),
            Some("chat".to_string()),
        );
        assert!(empty_token.telegram_token.is_none());
        assert!(empty_token.telegram_chat_id.is_none());
    }

    #[test]
    fn env_filter_falls_back_to_cli_log_level() {
        let filter = env_filter_for("warn");
        assert_eq!(filter.to_string(), "warn");
    }
}
