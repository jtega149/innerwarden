//! Process spawning, liveness polling, and rate-limited restart.
//!
//! Liveness is checked via `kill(pid, 0)` because that path works regardless
//! of whether the supervisor is the parent (it is, after `spawn_agent`) or an
//! attached observer (`attach`). The 100 ms poll cadence sets the upper bound
//! on time-to-detect, and the spawn cost is sub-millisecond, so end-to-end
//! restart latency stays under ~200 ms.
//!
//! Rate limiting uses a sliding 1-hour window of restart timestamps. When the
//! window exceeds the configured cap, the next restart returns an error
//! containing `"rate limit"` - the supervisor inspects the message and halts
//! the loop. This is intentional: a hot restart loop usually means the agent
//! has a deterministic fault that another restart will not fix.

use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use nix::sys::signal;
use nix::unistd::Pid;
use tracing::info;

use crate::symlink::ensure_not_symlink;

pub struct Monitor {
    agent_binary: PathBuf,
    agent_args: Vec<String>,
    agent_pid: Option<u32>,
    agent_child: Option<std::process::Child>,
    restart_times: Vec<Instant>,
    max_restarts_per_hour: u32,
}

impl Monitor {
    pub fn new(agent_binary: PathBuf, agent_args: Vec<String>, max_restarts_per_hour: u32) -> Self {
        Self {
            agent_binary,
            agent_args,
            agent_pid: None,
            agent_child: None,
            restart_times: Vec::new(),
            max_restarts_per_hour,
        }
    }

    /// Spawn the agent. Re-checks the symlink invariant every time so an
    /// attacker who introduces a symlink mid-uptime is caught on next restart.
    pub fn spawn_agent(&mut self) -> Result<u32> {
        ensure_not_symlink(&self.agent_binary).context("pre-spawn symlink check")?;

        info!(
            binary = %self.agent_binary.display(),
            args = ?self.agent_args,
            "spawning agent"
        );

        let child = Command::new(&self.agent_binary)
            .args(&self.agent_args)
            .spawn()
            .with_context(|| format!("spawn {}", self.agent_binary.display()))?;

        let pid = child.id();
        self.agent_pid = Some(pid);
        self.agent_child = Some(child);
        info!(pid, "agent spawned");
        Ok(pid)
    }

    /// Attach to an already-running agent by PID (no parent-child relationship).
    pub fn attach(&mut self, pid: u32) -> Result<()> {
        if !Self::pid_alive(pid) {
            bail!("process {} does not exist", pid);
        }
        self.agent_pid = Some(pid);
        info!(pid, "attached to running agent");
        Ok(())
    }

    pub fn is_alive(&self) -> bool {
        self.agent_pid.is_some_and(Self::pid_alive)
    }

    pub fn agent_pid(&self) -> Option<u32> {
        self.agent_pid
    }

    pub fn restart_count_last_hour(&self) -> usize {
        self.restart_times.len()
    }

    /// Reap the previous child, enforce the rate limit, then re-spawn.
    pub fn restart_agent(&mut self) -> Result<u32> {
        if let Some(ref mut child) = self.agent_child {
            let _ = child.wait();
        }
        self.agent_child = None;

        self.prune_old_restarts();
        if self.restart_times.len() >= self.max_restarts_per_hour as usize {
            bail!(
                "restart rate limit: {} in last hour (max {}). Manual intervention needed.",
                self.restart_times.len(),
                self.max_restarts_per_hour
            );
        }

        let pid = self.spawn_agent()?;
        self.restart_times.push(Instant::now());
        Ok(pid)
    }

    fn pid_alive(pid: u32) -> bool {
        signal::kill(Pid::from_raw(pid as i32), None).is_ok()
    }

    fn prune_old_restarts(&mut self) {
        let cutoff = Instant::now() - Duration::from_secs(3600);
        self.restart_times.retain(|t| *t > cutoff);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_limit_blocks_further_restarts() {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("nonexistent-bin");
        let mut monitor = Monitor::new(bin, vec![], 3);
        for _ in 0..3 {
            monitor.restart_times.push(Instant::now());
        }
        let err = monitor.restart_agent().unwrap_err();
        assert!(format!("{:#}", err).contains("rate limit"));
    }

    #[test]
    fn prune_drops_restarts_older_than_one_hour() {
        let dir = tempfile::tempdir().unwrap();
        let mut monitor = Monitor::new(dir.path().join("x"), vec![], 10);
        let stale = Instant::now() - Duration::from_secs(7200);
        let fresh = Instant::now() - Duration::from_secs(60);
        monitor.restart_times = vec![stale, fresh];
        monitor.prune_old_restarts();
        assert_eq!(monitor.restart_times.len(), 1);
    }

    #[test]
    fn pid_alive_returns_false_for_unused_pid() {
        // 2^31 - 1 is virtually never a live PID on Linux/macOS.
        assert!(!Monitor::pid_alive(2_147_483_647));
    }

    #[test]
    fn spawn_rejects_symlink_on_agent_binary() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        let link = dir.path().join("link");
        std::fs::write(&real, b"#!/bin/sh\nexit 0\n").unwrap();
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let mut monitor = Monitor::new(link, vec![], 10);
        let err = monitor.spawn_agent().unwrap_err();
        assert!(format!("{:#}", err).contains("symlink"));
    }
}
