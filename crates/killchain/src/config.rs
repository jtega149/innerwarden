//! Configuration via CLI args.

use clap::Parser;

#[derive(Parser, Debug, Clone)]
#[command(
    name = "innerwarden-killchain",
    about = "Kill chain detection service for Inner Warden"
)]
pub struct Config {
    /// Redis URL
    #[arg(long, default_value = "redis://127.0.0.1:6379")]
    pub redis_url: String,

    /// Redis events stream name
    #[arg(long, default_value = "innerwarden:events")]
    pub events_stream: String,

    /// Redis incidents stream name
    #[arg(long, default_value = "innerwarden:incidents")]
    pub incidents_stream: String,

    /// Minimum proximity score to emit pre-chain warning (0.0-1.0)
    #[arg(long, default_value = "0.6")]
    pub pre_chain_threshold: f32,

    /// Session timeout in seconds (cleanup stale PIDs)
    #[arg(long, default_value = "60")]
    pub session_timeout_secs: i64,

    /// Log level
    #[arg(long, default_value = "info")]
    pub log_level: String,
}
