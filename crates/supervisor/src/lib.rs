//! Process supervisor for `innerwarden-agent`.
//!
//! Detects agent death via `kill(pid, 0)` polling at 100 ms, respawns within
//! ~200 ms, rate-limits restarts to N/hour, runs a periodic HTTP health check
//! against the agent's `/metrics` endpoint and force-kills the agent when it
//! becomes unresponsive (next tick respawns it). Optionally posts Telegram
//! alerts on every restart and on integrity-style failures escalated by a
//! [`RestartHook`].
//!
//! # Where this fits
//!
//! `Restart=always` in a systemd unit recovers from crashes too, but does not
//! report restarts anywhere actionable, has no per-application health probe,
//! and gives no programmatic way to refuse a restart when the agent binary on
//! disk has been swapped. This crate is the layer that closes those gaps for
//! the open-source distribution. Anti-tamper concerns (process stealth,
//! SHA-256 integrity gating, namespace isolation) live in a separate proprietary
//! supervisor that wraps this one via [`RestartHook`].
//!
//! # Anatomy
//!
//! ```text
//!     Supervisor::run()
//!       ├── ctrlc handler installed
//!       ├── ensure_not_symlink(agent_binary)
//!       ├── hook.before_spawn()           // hook returning Err refuses the spawn
//!       ├── Monitor::spawn_agent()        // first child
//!       └── loop {
//!             if !is_alive(pid)           // 100 ms poll
//!                 → hook.before_spawn()
//!                 → Monitor::restart_agent() // rate-limited, alerts on outcome
//!             every health_interval:
//!                 HealthChecker::check()  // HTTP /metrics, kill -9 after 3 fails
//!           }
//! ```

mod alerts;
mod health;
mod hook;
mod monitor;
mod symlink;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use tracing::{error, info, warn};

pub use alerts::Alerter;
pub use health::HealthChecker;
pub use hook::{NoopHook, RestartHook};
pub use monitor::Monitor;
pub use symlink::ensure_not_symlink;

/// Caller-supplied configuration for [`Supervisor`].
///
/// Build via [`SupervisorConfig::new`] + the `with_*` setters. The defaults
/// match what the OSS agent ships with: a local dashboard at `127.0.0.1:8787`,
/// 30 s health probe interval, and 10 restarts per rolling hour.
#[derive(Debug, Clone)]
pub struct SupervisorConfig {
    pub agent_binary: std::path::PathBuf,
    pub agent_args: Vec<String>,
    pub agent_api: String,
    pub health_interval: Duration,
    pub max_restarts_per_hour: u32,
    pub telegram_token: Option<String>,
    pub telegram_chat_id: Option<String>,
}

impl SupervisorConfig {
    pub fn new<P: Into<std::path::PathBuf>>(agent_binary: P) -> Self {
        Self {
            agent_binary: agent_binary.into(),
            agent_args: Vec::new(),
            agent_api: "http://127.0.0.1:8787".into(),
            health_interval: Duration::from_secs(30),
            max_restarts_per_hour: 10,
            telegram_token: None,
            telegram_chat_id: None,
        }
    }

    pub fn with_args(mut self, args: Vec<String>) -> Self {
        self.agent_args = args;
        self
    }

    pub fn with_health(mut self, api: impl Into<String>, interval: Duration) -> Self {
        self.agent_api = api.into();
        self.health_interval = interval;
        self
    }

    pub fn with_max_restarts_per_hour(mut self, n: u32) -> Self {
        self.max_restarts_per_hour = n;
        self
    }

    pub fn with_telegram(mut self, token: String, chat_id: String) -> Self {
        self.telegram_token = Some(token);
        self.telegram_chat_id = Some(chat_id);
        self
    }
}

/// Top-level supervisor. Owns the [`Monitor`], [`HealthChecker`], and
/// [`Alerter`], plus an optional [`RestartHook`] (defaults to [`NoopHook`]).
pub struct Supervisor {
    config: SupervisorConfig,
    hook: Box<dyn RestartHook>,
}

impl Supervisor {
    /// Validate the agent binary path (rejects symlinks) and prepare a
    /// supervisor that will spawn it on `run()`.
    pub fn new(config: SupervisorConfig) -> Result<Self> {
        ensure_not_symlink(&config.agent_binary)
            .context("agent binary path failed pre-spawn validation")?;
        Ok(Self {
            config,
            hook: Box::new(NoopHook),
        })
    }

    /// Replace the default [`NoopHook`] with a caller-supplied implementation.
    /// The proprietary watchdog uses this to inject SHA-256 integrity checks
    /// in front of every spawn.
    pub fn with_hook(mut self, hook: Box<dyn RestartHook>) -> Self {
        self.hook = hook;
        self
    }

    /// Install a SIGTERM/SIGINT handler, spawn the agent, then run the
    /// supervision loop until a signal arrives or an unrecoverable condition
    /// (binary tampered, restart-rate exceeded) is reached.
    pub fn run(self) -> Result<()> {
        let Self { config, hook } = self;

        let mut monitor = Monitor::new(
            config.agent_binary.clone(),
            config.agent_args.clone(),
            config.max_restarts_per_hour,
        );

        let alerter = Alerter::new(
            config.telegram_token.clone(),
            config.telegram_chat_id.clone(),
        );
        let mut health = HealthChecker::new(&config.agent_api);

        // Initial spawn: hook may refuse (e.g. paid integrity check).
        hook.before_spawn()
            .context("initial spawn refused by RestartHook")?;
        let initial_pid = monitor.spawn_agent()?;
        info!(pid = initial_pid, "monitoring agent - supervisor active");

        let running = Arc::new(AtomicBool::new(true));
        {
            let r = Arc::clone(&running);
            let _ = ctrlc::set_handler(move || {
                r.store(false, Ordering::Relaxed);
            });
        }

        let mut last_health = Instant::now();

        while running.load(Ordering::Relaxed) {
            if !monitor.is_alive() {
                let old_pid = monitor.agent_pid().unwrap_or(0);
                warn!(pid = old_pid, "agent died - attempting restart");

                if let Err(e) = hook.before_spawn() {
                    let msg = format!("{:#}", e);
                    error!("CRITICAL: hook refused restart: {}", msg);
                    alerter.restart_failed(old_pid, &msg);
                    if msg.contains("TAMPERED") {
                        alerter.integrity_violation(&msg);
                        error!("hook reported integrity violation - supervisor halting");
                        break;
                    }
                    std::thread::sleep(Duration::from_secs(5));
                } else {
                    match monitor.restart_agent() {
                        Ok(new_pid) => {
                            info!(old_pid, new_pid, "agent restarted successfully");
                            alerter.agent_restarted(old_pid, new_pid, "process exited");
                        }
                        Err(e) => {
                            let msg = format!("{:#}", e);
                            error!("CRITICAL: restart failed: {}", msg);
                            alerter.restart_failed(old_pid, &msg);
                            if msg.contains("rate limit") {
                                error!("restart rate limit exceeded - supervisor halting");
                                break;
                            }
                            std::thread::sleep(Duration::from_secs(5));
                        }
                    }
                }
            }

            if last_health.elapsed() >= config.health_interval {
                if let Err(e) = health.check() {
                    warn!("health check failed: {:#}", e);
                    if let Some(pid) = monitor.agent_pid() {
                        warn!(pid, "killing unresponsive agent");
                        let _ = nix::sys::signal::kill(
                            nix::unistd::Pid::from_raw(pid as i32),
                            nix::sys::signal::Signal::SIGKILL,
                        );
                    }
                }
                last_health = Instant::now();
            }

            std::thread::sleep(Duration::from_millis(100));
        }

        info!("supervisor shutting down gracefully");
        Ok(())
    }
}
