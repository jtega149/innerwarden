//! Host posture snapshot — what controls are already hardened.
//!
//! Spec 044 (`/.specify/features/044-posture-aware-alerting/spec.md`).
//!
//! The agent's severity downgrade engine (Phase 3, not yet implemented)
//! reads this snapshot to answer "would this attack have actually
//! worked given the host's current configuration". A SSH password
//! bruteforce against a host with `PasswordAuthentication no` hits the
//! sshd wall before reaching the kernel — the attempt is informational,
//! not a high-severity threat.
//!
//! **Cadence**: snapshot is taken at agent boot and refreshed every
//! 10 min by the slow loop (Phase 2.2). Operator changes (e.g. flipping
//! `PasswordAuthentication` for a debug session) are picked up within
//! one refresh window.
//!
//! **Source of truth**: each probe shells out to the canonical tool for
//! its surface (`sshd -T` for sshd, `ss -ltnp` for listeners, etc.)
//! rather than re-parsing config files. `sshd -T` already handles
//! `Include` directives, `Match` blocks, and effective defaults — much
//! safer than re-implementing that parser. If the canonical tool is
//! missing or fails, the probe records a `probe_failed` state and
//! the downgrade engine treats the surface as "permissive" (no
//! downgrade — bias toward keeping the alert).
//!
//! **What is NOT here**:
//!
//! - User account inventory (UIDs, names, login vs nologin shells) —
//!   `EnvironmentProfile` already covers this with bootstrap-once
//!   semantics. The downgrade engine reads both files.
//! - Active responses / dynamic blocklist — that is Decision state, not
//!   posture.
//! - Misconfiguration warnings — `innerwarden scan` / `innerwarden
//!   harden` own the "is this hardened enough" judgment. Posture is a
//!   read-only view.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tracing::{info, warn};

pub(crate) mod downgrade;
pub(crate) mod firewall;
pub(crate) mod services;
pub(crate) mod sshd;
pub(crate) mod sudo;

#[cfg(test)]
mod tests;

/// Top-level snapshot of host posture facts the severity engine cares about.
///
/// Each sub-struct carries a `probe_state` field describing whether the
/// underlying tool ran successfully, was missing, or failed — so the
/// downgrade engine can distinguish "we know SSH is hardened" from "we
/// have no idea, fall back to permissive".
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HostPosture {
    pub sshd: sshd::SshdPosture,
    pub services: services::ServicesPosture,
    pub sudo: sudo::SudoPosture,
    pub firewall: firewall::FirewallPosture,
    /// When this snapshot was taken (UTC). Used by the downgrade engine
    /// to refuse demotion when the snapshot is stale beyond a threshold.
    pub captured_at: chrono::DateTime<chrono::Utc>,
}

impl HostPosture {
    /// Take a fresh snapshot by running every probe.
    ///
    /// Probes never panic and never fail the snapshot as a whole — each
    /// records its own `probe_state` and the snapshot always returns.
    pub fn take_snapshot() -> Self {
        Self {
            sshd: sshd::probe_sshd(),
            services: services::probe_services(),
            sudo: sudo::probe_sudo(),
            firewall: firewall::probe_firewall(),
            captured_at: chrono::Utc::now(),
        }
    }

    /// Age of the snapshot in seconds. The slow loop refresh cadence
    /// is 10 min; the downgrade engine treats anything older than ~30
    /// min as stale and refuses to demote based on it.
    #[allow(dead_code)]
    pub fn age_seconds(&self) -> i64 {
        (chrono::Utc::now() - self.captured_at).num_seconds()
    }
}

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

/// Path to the posture snapshot JSON file. Sibling to
/// `environment-profile.json` under `data_dir`.
pub fn posture_path(data_dir: &Path) -> PathBuf {
    data_dir.join("posture.json")
}

/// Write the snapshot to disk via temp-file + rename so a crash mid-write
/// does not leave a half-written file the dashboard would choke on.
/// Mirrors the pattern in `capped_log::write_atomic`.
pub fn save(data_dir: &Path, posture: &HostPosture) -> std::io::Result<()> {
    let path = posture_path(data_dir);
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    if !parent.exists() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = parent.join(format!("posture.{}.tmp", std::process::id()));
    let bytes = serde_json::to_vec_pretty(posture)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    std::fs::write(&tmp, &bytes)?;
    match std::fs::rename(&tmp, &path) {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
    }
}

/// Load a previously-saved snapshot. Returns `None` when the file is
/// missing or unparseable — callers should re-snapshot in that case.
#[allow(dead_code)] // Used by `innerwarden get posture` (Phase 2.3) and tests.
pub fn load(data_dir: &Path) -> Option<HostPosture> {
    let path = posture_path(data_dir);
    let content = std::fs::read_to_string(&path).ok()?;
    match serde_json::from_str::<HostPosture>(&content) {
        Ok(p) => Some(p),
        Err(e) => {
            warn!(path = %path.display(), error = %e, "failed to parse posture.json");
            None
        }
    }
}

/// Take a fresh snapshot, log a one-line summary, and persist. Called
/// at boot (Phase 2 wiring) and from the slow loop refresh tick (Phase
/// 2.2). Errors are logged but not propagated — posture is best-effort.
pub fn refresh_and_save(data_dir: &Path) -> HostPosture {
    let posture = HostPosture::take_snapshot();
    info!(
        sshd_probe = %posture.sshd.probe_state.label(),
        password_auth = ?posture.sshd.password_authentication,
        permit_root_login = ?posture.sshd.permit_root_login,
        services_probe = %posture.services.probe_state.label(),
        listener_count = posture.services.listeners.len(),
        sudo_probe = %posture.sudo.probe_state.label(),
        sudo_members = posture.sudo.sudo_group_members.len(),
        firewall_probe = %posture.firewall.probe_state.label(),
        firewall_default = ?posture.firewall.default_policy,
        firewall_allowed_count = posture.firewall.allowed_tcp_ports.len(),
        "host posture snapshot"
    );
    if let Err(e) = save(data_dir, &posture) {
        warn!(error = %e, "failed to save posture.json");
    }
    posture
}
