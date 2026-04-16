//! Shared target validator for firewall skills (ufw/iptables/nftables/pf).
//!
//! Each firewall skill must reject malformed strings before invoking the
//! corresponding CLI, otherwise ufw/iptables/nftables returns
//! `ERROR: Bad source address` on add — often after partially accepting the
//! rule — and the response lifecycle ends up with a zombie "Active" entry
//! that can never be reverted. That is the root cause of the
//! orphaned-response dashboard alert.
//!
//! This module also exposes a pure `format_skill_outcome` helper so each
//! skill's success/failure classification can be unit-tested without having
//! to spawn the real CLI subprocess.

use crate::skills::SkillResult;
use std::process::Output;

/// Convert a `std::process::Output` from spawning a firewall CLI into a
/// `SkillResult`. Kept pure (no tracing side effects) so the three branches
/// (exit success, exit failure, spawn error) can be tested in isolation.
/// `tool` is the human-readable label used in the result message
/// (`ufw`, `iptables`, `nftables`, `pf`). `ip` is the target.
pub(super) fn format_skill_outcome(
    tool: &str,
    ip: &str,
    spawn_result: std::io::Result<Output>,
) -> SkillResult {
    match spawn_result {
        Ok(out) if out.status.success() => SkillResult {
            success: true,
            message: format!("Blocked {ip} via {tool}"),
        },
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr).to_string();
            SkillResult {
                success: false,
                message: format!("{tool} block failed for {ip}: {stderr}"),
            }
        }
        Err(e) => SkillResult {
            success: false,
            message: format!("failed to run {tool}: {e}"),
        },
    }
}

/// Returns true if `s` is a single IPv4/IPv6 address, or a valid CIDR
/// (`<ip>/<prefix>`) that `ufw`, `iptables -s`, `nftables ip saddr`, and
/// `pfctl` all accept.
///
/// Rejects: empty strings, octet-out-of-range ("129.950.5.0"), short IPv4
/// forms ("137.274.6"), garbage ("not-an-ip"), CIDR with invalid IP part,
/// CIDR with prefix out of range, CIDR with non-numeric prefix.
pub(super) fn is_valid_firewall_target(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    match s.split_once('/') {
        Some((ip_part, prefix_part)) => match (
            ip_part.parse::<std::net::IpAddr>(),
            prefix_part.parse::<u8>(),
        ) {
            (Ok(std::net::IpAddr::V4(_)), Ok(p)) => p <= 32,
            (Ok(std::net::IpAddr::V6(_)), Ok(p)) => p <= 128,
            _ => false,
        },
        None => s.parse::<std::net::IpAddr>().is_ok(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── format_skill_outcome ─────────────────────────────────────────────

    fn ok_exit() -> Output {
        use std::os::unix::process::ExitStatusExt;
        Output {
            status: std::process::ExitStatus::from_raw(0),
            stdout: Vec::new(),
            stderr: Vec::new(),
        }
    }

    fn fail_exit(stderr: &str) -> Output {
        use std::os::unix::process::ExitStatusExt;
        Output {
            // exit code 1 shifted into the wait-status raw layout
            status: std::process::ExitStatus::from_raw(1 << 8),
            stdout: Vec::new(),
            stderr: stderr.as_bytes().to_vec(),
        }
    }

    #[test]
    fn format_outcome_success() {
        let r = format_skill_outcome("ufw", "1.2.3.4", Ok(ok_exit()));
        assert!(r.success);
        assert_eq!(r.message, "Blocked 1.2.3.4 via ufw");
    }

    #[test]
    fn format_outcome_nonzero_exit_includes_stderr() {
        let r = format_skill_outcome("ufw", "1.2.3.4", Ok(fail_exit("ERROR: Bad source address")));
        assert!(!r.success);
        assert!(r.message.contains("ufw block failed for 1.2.3.4"));
        assert!(r.message.contains("ERROR: Bad source address"));
    }

    #[test]
    fn format_outcome_spawn_error() {
        let e = std::io::Error::new(std::io::ErrorKind::NotFound, "no such file");
        let r = format_skill_outcome("iptables", "1.2.3.4", Err(e));
        assert!(!r.success);
        assert!(r.message.contains("failed to run iptables"));
        assert!(r.message.contains("no such file"));
    }

    #[test]
    fn format_outcome_stderr_with_non_utf8_bytes_is_handled() {
        use std::os::unix::process::ExitStatusExt;
        let out = Output {
            status: std::process::ExitStatus::from_raw(1 << 8),
            stdout: Vec::new(),
            stderr: vec![0xff, 0xfe, 0x00], // invalid UTF-8
        };
        let r = format_skill_outcome("nftables", "2001:db8::1", Ok(out));
        assert!(!r.success);
        assert!(r.message.contains("nftables block failed for 2001:db8::1"));
    }

    #[test]
    fn format_outcome_covers_all_tools() {
        for tool in ["ufw", "iptables", "nftables", "pf"] {
            let r = format_skill_outcome(tool, "10.0.0.0/8", Ok(ok_exit()));
            assert!(r.success);
            assert!(r.message.contains(tool));
        }
    }

    // ── is_valid_firewall_target ─────────────────────────────────────────

    #[test]
    fn accepts_plain_ipv4_ipv6() {
        assert!(is_valid_firewall_target("1.2.3.4"));
        assert!(is_valid_firewall_target("255.255.255.255"));
        assert!(is_valid_firewall_target("0.0.0.0"));
        assert!(is_valid_firewall_target("::1"));
        assert!(is_valid_firewall_target("2001:db8::1"));
    }

    #[test]
    fn accepts_valid_cidrs() {
        assert!(is_valid_firewall_target("10.0.0.0/8"));
        assert!(is_valid_firewall_target("192.168.0.0/16"));
        assert!(is_valid_firewall_target("136.216.0.0/16"));
        assert!(is_valid_firewall_target("192.168.1.1/32"));
        assert!(is_valid_firewall_target("::/0"));
        assert!(is_valid_firewall_target("2001:db8::/32"));
        assert!(is_valid_firewall_target("fe80::/10"));
    }

    #[test]
    fn rejects_empty_and_garbage() {
        assert!(!is_valid_firewall_target(""));
        assert!(!is_valid_firewall_target(" "));
        assert!(!is_valid_firewall_target("not-an-ip"));
        assert!(!is_valid_firewall_target("/"));
        assert!(!is_valid_firewall_target("/16"));
    }

    #[test]
    fn rejects_out_of_range_octets() {
        // Exact samples from the production incident.
        for bad in [
            "129.950.5.0",
            "129.525.8.0",
            "130.890.9.0",
            "130.932.0.0",
            "130.806.3.0",
            "130.806.1.17",
            "129.491.8.0",
            "129.952.2.0",
            "129.950.5.15",
            "129.950.5.5",
        ] {
            assert!(!is_valid_firewall_target(bad), "'{bad}' must be rejected");
        }
    }

    #[test]
    fn rejects_malformed_ipv4() {
        assert!(!is_valid_firewall_target("137.274.6")); // 3 octets
        assert!(!is_valid_firewall_target("1.2.3"));
        assert!(!is_valid_firewall_target("1.2.3.4.5"));
    }

    #[test]
    fn rejects_invalid_cidr() {
        assert!(!is_valid_firewall_target("129.950.5.0/24"));
        assert!(!is_valid_firewall_target("10.0.0.0/33"));
        assert!(!is_valid_firewall_target("2001:db8::/129"));
        assert!(!is_valid_firewall_target("10.0.0.0/"));
        assert!(!is_valid_firewall_target("10.0.0.0/-1"));
        assert!(!is_valid_firewall_target("10.0.0.0/abc"));
    }
}
