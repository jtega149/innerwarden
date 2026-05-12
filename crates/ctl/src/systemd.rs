//! Thin wrappers around systemctl for service lifecycle management.

use std::process::Command;

use anyhow::{bail, Context, Result};

fn restart_service_with<F>(unit: &str, dry_run: bool, mut run: F) -> Result<()>
where
    F: FnMut(&str, &[String]) -> std::io::Result<std::process::Output>,
{
    if dry_run {
        return Ok(());
    }
    let args = vec!["restart".to_string(), unit.to_string()];
    let out = run("systemctl", &args)
        .with_context(|| format!("failed to run systemctl restart {unit}"))?;

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        bail!("systemctl restart {unit} failed: {stderr}");
    }
    Ok(())
}

/// Restart a systemd service unit.
/// In dry_run mode, prints the command without executing.
pub fn restart_service(unit: &str, dry_run: bool) -> Result<()> {
    restart_service_with(unit, dry_run, |program, args| {
        Command::new(program).args(args).output()
    })
}

fn restart_launchd_with<F>(label: &str, dry_run: bool, mut run: F) -> Result<()>
where
    F: FnMut(&str, &[String]) -> std::io::Result<std::process::Output>,
{
    if dry_run {
        return Ok(());
    }
    let target = format!("system/{label}");
    let args = vec!["kickstart".to_string(), "-k".to_string(), target];
    let out = run("launchctl", &args)
        .with_context(|| format!("failed to run launchctl kickstart -k system/{label}"))?;

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        bail!("launchctl kickstart system/{label} failed: {stderr}");
    }
    Ok(())
}

/// Restart a launchd service (macOS).
/// In dry_run mode, prints the command without executing.
pub fn restart_launchd(label: &str, dry_run: bool) -> Result<()> {
    restart_launchd_with(label, dry_run, |program, args| {
        Command::new(program).args(args).output()
    })
}

/// Result of querying a systemd service's runtime status.
///
/// Bug 2 / Bug 8 (2026-05-06 prod observation): the prior
/// `is_service_active(unit) -> bool` API conflated three distinct
/// states into one boolean — `false` for "service is dead", `false`
/// for "systemctl could not query the bus", and `false` for "command
/// not found / non-Linux host". When the operator ran `innerwarden
/// doctor` over an SSH non-login session that did not export
/// `XDG_RUNTIME_DIR`, `systemctl is-active` exited non-zero with
/// stderr `Failed to connect to bus: No data available` even though
/// the agent was alive (telemetry-freshness check confirmed it).
/// Doctor's Services section reported "is not running" while Agent
/// health reported "active - last write 5s ago" in the same output.
///
/// Splitting `Active` from `Inactive` from `Unknown` lets callers do
/// the right thing in each case: `Inactive` is a real finding,
/// `Unknown` is a "could not determine" that should defer to a
/// secondary check (telemetry-freshness in doctor, agent presence in
/// harden) instead of producing a false-positive operator alarm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceStatus {
    /// `systemctl is-active` returned `active`.
    Active,
    /// `systemctl is-active` returned `inactive` / `failed` / `deactivating`.
    Inactive,
    /// Could not determine. Bus unreachable, systemctl absent (macOS or
    /// non-systemd Linux), or stdout shape unrecognised. Caller must
    /// fall back to a secondary signal.
    Unknown,
}

/// Query the systemd status of `unit`.
///
/// stderr is intentionally swallowed — see Bug 1 (2026-05-06): the
/// `Failed to connect to bus` line leaked through to the user's
/// terminal when doctor ran over a session that lacked `DBUS_SESSION_BUS_ADDRESS`.
pub fn service_status(unit: &str) -> ServiceStatus {
    let out = Command::new("systemctl").args(["is-active", unit]).output();
    let out = match out {
        Ok(o) => o,
        Err(_) => return ServiceStatus::Unknown,
    };
    classify_systemctl_is_active(&out.stdout, out.status.success())
}

/// Pure helper: map `systemctl is-active` raw stdout + success bit to
/// a `ServiceStatus`. Split out from `service_status` so tests do not
/// need to spawn `systemctl`.
pub(crate) fn classify_systemctl_is_active(stdout: &[u8], success: bool) -> ServiceStatus {
    let stdout = String::from_utf8_lossy(stdout);
    let line = stdout.trim();
    match line {
        "active" => ServiceStatus::Active,
        "inactive" | "failed" | "deactivating" | "activating" => ServiceStatus::Inactive,
        // "unknown" is what systemctl prints on bus failure on some
        // distros; pair it with the success bit (false) to be sure
        // we are not misreading a genuinely inactive unit named
        // "unknown" by some quirk.
        _ => {
            if success && !line.is_empty() {
                // Unrecognised but-success shape: treat as Inactive
                // conservatively (better to suggest "start" than to
                // claim we could not determine when stdout was
                // produced normally). This branch should be unreachable
                // in practice — systemctl's documented active values
                // are a closed set.
                ServiceStatus::Inactive
            } else {
                ServiceStatus::Unknown
            }
        }
    }
}

/// Returns true if a service is currently active (running).
///
/// Backward-compat wrapper. Returns `true` only for the `Active`
/// branch — `Unknown` is treated as `false` here. New call sites
/// should prefer `service_status` so they can distinguish the
/// "could not determine" case.
pub fn is_service_active(unit: &str) -> bool {
    matches!(service_status(unit), ServiceStatus::Active)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shell_output(script: &str) -> std::io::Result<std::process::Output> {
        Command::new("sh").arg("-c").arg(script).output()
    }

    #[test]
    fn restart_in_dry_run_does_not_error() {
        // Should succeed without actually calling systemctl
        assert!(restart_service("innerwarden-agent", true).is_ok());
    }

    #[test]
    fn restart_launchd_in_dry_run_does_not_error() {
        assert!(restart_launchd("com.innerwarden.agent", true).is_ok());
    }

    #[test]
    fn restart_service_with_accepts_success_and_reports_stderr_on_failure() {
        assert!(
            restart_service_with("innerwarden-agent", false, |_program, _args| {
                shell_output("exit 0")
            })
            .is_ok()
        );

        let err = restart_service_with("innerwarden-agent", false, |_program, _args| {
            shell_output("printf service-down >&2; exit 1")
        })
        .expect_err("failed systemctl should surface stderr");
        assert!(err.to_string().contains("service-down"));
    }

    #[test]
    fn restart_launchd_with_covers_dry_run_success_and_failure_paths() {
        assert!(
            restart_launchd_with("com.innerwarden.agent", true, |_program, _args| {
                shell_output("exit 1")
            })
            .is_ok()
        );
        assert!(
            restart_launchd_with("com.innerwarden.agent", false, |_program, _args| {
                shell_output("exit 0")
            })
            .is_ok()
        );

        let err = restart_launchd_with("com.innerwarden.agent", false, |_program, _args| {
            shell_output("printf launchd-down >&2; exit 1")
        })
        .expect_err("launchctl failure should be reported");
        assert!(err.to_string().contains("launchd-down"));
    }

    /// Bug 2 anchor (2026-05-06): "active" stdout maps to Active.
    #[test]
    fn classify_systemctl_is_active_active_maps_to_active() {
        let s = classify_systemctl_is_active(b"active\n", true);
        assert_eq!(s, ServiceStatus::Active);
    }

    /// Bug 2 anchor: "inactive" stdout maps to Inactive even if the
    /// command exited non-zero (systemctl returns 3 for inactive).
    #[test]
    fn classify_systemctl_is_active_inactive_maps_to_inactive() {
        let s = classify_systemctl_is_active(b"inactive\n", false);
        assert_eq!(s, ServiceStatus::Inactive);
    }

    /// Bug 2 anchor: "failed" maps to Inactive (the unit ran but is
    /// dead — the operator should still see this as "service is down").
    #[test]
    fn classify_systemctl_is_active_failed_maps_to_inactive() {
        let s = classify_systemctl_is_active(b"failed\n", false);
        assert_eq!(s, ServiceStatus::Inactive);
    }

    /// Bug 2 anchor: "activating" / "deactivating" map to Inactive
    /// (we cannot serve traffic during transitions).
    #[test]
    fn classify_systemctl_is_active_transitional_maps_to_inactive() {
        let s = classify_systemctl_is_active(b"activating\n", false);
        assert_eq!(s, ServiceStatus::Inactive);
        let s = classify_systemctl_is_active(b"deactivating\n", false);
        assert_eq!(s, ServiceStatus::Inactive);
    }

    /// Bug 2 anchor (the headline case): "unknown" stdout + non-zero
    /// exit (the bus-failure shape) maps to Unknown — NOT Inactive.
    /// This is the difference between "doctor confidently reports the
    /// agent is down" (false positive) and "doctor defers to the
    /// freshness check below" (correct).
    #[test]
    fn classify_systemctl_is_active_bus_failure_maps_to_unknown() {
        let s = classify_systemctl_is_active(b"unknown\n", false);
        assert_eq!(s, ServiceStatus::Unknown);
    }

    /// Bug 1/2 anchor: empty stdout + non-zero exit (the "Failed to
    /// connect to bus" shape on some distros where stdout is empty
    /// and stderr has the message) also maps to Unknown.
    #[test]
    fn classify_systemctl_is_active_empty_stdout_maps_to_unknown() {
        let s = classify_systemctl_is_active(b"", false);
        assert_eq!(s, ServiceStatus::Unknown);
    }

    /// Pin the public alias so a future refactor that drops the
    /// `is_service_active(&str) -> bool` shim does not silently break
    /// every backward-compat caller.
    #[test]
    fn is_service_active_is_true_only_for_active() {
        assert!(matches!(
            classify_systemctl_is_active(b"active\n", true),
            ServiceStatus::Active
        ));
        assert!(!matches!(
            classify_systemctl_is_active(b"inactive\n", false),
            ServiceStatus::Active
        ));
        assert!(!matches!(
            classify_systemctl_is_active(b"unknown\n", false),
            ServiceStatus::Active
        ));
    }
}
