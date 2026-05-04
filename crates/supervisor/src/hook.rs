//! Extension point for callers that want to gate spawns on extra checks.
//!
//! The free supervisor performs a symlink rejection on the agent binary at
//! [`Supervisor::new`](crate::Supervisor::new) time - that is the entire
//! tamper surface it covers. Callers that need stronger guarantees (SHA-256
//! integrity hashing, signature verification, TPM attestation) implement
//! [`RestartHook`] and inject it via
//! [`Supervisor::with_hook`](crate::Supervisor::with_hook).
//!
//! Hook contract:
//!
//! - `before_spawn` runs immediately before EVERY spawn (initial + every
//!   restart). Returning `Err` refuses the spawn.
//! - If the error message contains the literal string `"TAMPERED"`, the
//!   supervisor halts the loop and emits an integrity-violation alert. Use
//!   this only when continuing to attempt restart would be unsafe.
//! - Any other error is treated as transient: the supervisor logs, alerts,
//!   sleeps 5 s, and tries again on the next tick.

use anyhow::Result;

/// Pre-spawn check the supervisor consults before launching the agent.
pub trait RestartHook: Send + Sync {
    fn before_spawn(&self) -> Result<()>;
}

/// Default no-op hook used when the caller does not supply one.
pub struct NoopHook;

impl RestartHook for NoopHook {
    fn before_spawn(&self) -> Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noop_hook_always_allows() {
        assert!(NoopHook.before_spawn().is_ok());
    }

    struct AlwaysRefuse;
    impl RestartHook for AlwaysRefuse {
        fn before_spawn(&self) -> Result<()> {
            anyhow::bail!("synthetic refusal")
        }
    }

    #[test]
    fn custom_hook_can_refuse() {
        assert!(AlwaysRefuse.before_spawn().is_err());
    }
}
