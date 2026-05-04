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

    /// Agent HTTP API base URL for the periodic health probe.
    #[arg(long, default_value = "http://127.0.0.1:8787")]
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

fn main() -> Result<()> {
    let cli = Cli::parse();

    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&cli.log_level));
    tracing_subscriber::fmt().with_env_filter(env_filter).init();

    tracing::info!(
        "innerwarden-supervisor v{} starting",
        env!("CARGO_PKG_VERSION")
    );

    let config = SupervisorConfig::new(cli.agent_binary)
        .with_args(cli.agent_args)
        .with_health(cli.agent_api, Duration::from_secs(cli.health_interval))
        .with_max_restarts_per_hour(cli.max_restarts_per_hour);

    let config = match (
        std::env::var("INNERWARDEN_TELEGRAM_TOKEN").ok(),
        std::env::var("INNERWARDEN_TELEGRAM_CHAT_ID").ok(),
    ) {
        (Some(token), Some(chat_id)) if !token.is_empty() && !chat_id.is_empty() => {
            config.with_telegram(token, chat_id)
        }
        _ => config,
    };

    Supervisor::new(config)
        .context("supervisor pre-flight check failed")?
        .run()
}
