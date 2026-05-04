//! Sync HTTP health check against the agent's `/metrics` endpoint.
//!
//! Three consecutive failures are required before [`HealthChecker::check`]
//! returns `Err` - the supervisor reacts by SIGKILLing the agent, which the
//! spawn loop notices on the next 100 ms tick. The 5 s per-request timeout
//! prevents a hung connection from stalling the supervisor itself.
//!
//! `ureq` is used instead of an async client because the supervisor is
//! deliberately tokio-free (small RSS, fewer transitive deps).

use anyhow::{bail, Result};
use tracing::{debug, warn};

pub struct HealthChecker {
    agent_api: String,
    consecutive_failures: u32,
    max_failures: u32,
}

impl HealthChecker {
    pub fn new(agent_api: &str) -> Self {
        Self {
            agent_api: agent_api.trim_end_matches('/').to_string(),
            consecutive_failures: 0,
            max_failures: 3,
        }
    }

    /// Probe `<agent_api>/metrics`. Returns `Err` only after `max_failures`
    /// consecutive non-2xx or transport errors.
    pub fn check(&mut self) -> Result<()> {
        let url = format!("{}/metrics", self.agent_api);
        let agent = ureq::Agent::new_with_config(
            ureq::config::Config::builder()
                .timeout_global(Some(std::time::Duration::from_secs(5)))
                .build(),
        );
        match agent.get(&url).call() {
            Ok(resp) if resp.status().is_success() => {
                if self.consecutive_failures > 0 {
                    debug!(
                        "agent health recovered after {} failures",
                        self.consecutive_failures
                    );
                }
                self.consecutive_failures = 0;
                Ok(())
            }
            Ok(resp) => {
                self.consecutive_failures += 1;
                warn!(
                    status = resp.status().as_u16(),
                    failures = self.consecutive_failures,
                    "agent health check returned non-200"
                );
                self.maybe_fail()
            }
            Err(e) => {
                self.consecutive_failures += 1;
                warn!(
                    error = %e,
                    failures = self.consecutive_failures,
                    "agent health check failed"
                );
                self.maybe_fail()
            }
        }
    }

    pub fn consecutive_failures(&self) -> u32 {
        self.consecutive_failures
    }

    fn maybe_fail(&self) -> Result<()> {
        if self.consecutive_failures >= self.max_failures {
            bail!(
                "agent unresponsive: {} consecutive health check failures",
                self.consecutive_failures
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trims_trailing_slash_from_api_url() {
        let h = HealthChecker::new("http://127.0.0.1:8787/");
        assert_eq!(h.agent_api, "http://127.0.0.1:8787");
    }

    #[test]
    fn maybe_fail_returns_ok_below_threshold() {
        let h = HealthChecker {
            agent_api: "x".into(),
            consecutive_failures: 2,
            max_failures: 3,
        };
        assert!(h.maybe_fail().is_ok());
    }

    #[test]
    fn maybe_fail_returns_err_at_threshold() {
        let h = HealthChecker {
            agent_api: "x".into(),
            consecutive_failures: 3,
            max_failures: 3,
        };
        let err = h.maybe_fail().unwrap_err();
        assert!(format!("{:#}", err).contains("3 consecutive"));
    }

    #[test]
    fn check_against_unreachable_endpoint_increments_failure_count() {
        // Bind to an OS-assigned port, then drop the listener so the address
        // is guaranteed-unused for the duration of the test.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let mut h = HealthChecker::new(&format!("http://{}", addr));
        // First two failures should not bubble; third should.
        let _ = h.check();
        let _ = h.check();
        let result = h.check();
        assert!(result.is_err());
        assert_eq!(h.consecutive_failures(), 3);
    }
}
