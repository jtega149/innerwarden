//! Banner + bind + interaction-mode helpers extracted from session.rs.
//!
//! These are pure functions the session state machine asks for when deciding
//! what bytes to send on the first connection (SSH / HTTP) and how to
//! classify the listener configuration. They are in their own module so unit
//! tests can exercise every branch without constructing a full session or
//! touching the filesystem.

use std::net::IpAddr;

pub(super) const SSH_BANNER: &[u8] = b"SSH-2.0-OpenSSH_9.2p1 Ubuntu-4ubuntu0.5\r\n";
pub(super) const HTTP_BANNER: &[u8] =
    b"HTTP/1.1 302 Found\r\nLocation: /login\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

/// Resolve the first-response banner for a honeypot service name.
///
/// Accepts case-insensitive `"ssh"` and `"http"`. Any other value is an
/// explicit error — the session code then rejects the config rather than
/// sending a blank banner that would leak "no service here".
pub(super) fn banner_for_service(service: &str) -> Result<&'static [u8], String> {
    match service.to_ascii_lowercase().as_str() {
        "ssh" => Ok(SSH_BANNER),
        "http" => Ok(HTTP_BANNER),
        other => Err(format!(
            "unsupported service '{other}' (supported: ssh, http)"
        )),
    }
}

/// Returns true when `bind_addr` parses as a loopback IP (127.0.0.0/8 or
/// [::1]). Used to decide whether the honeypot is exposed publicly or
/// only to the host — informs containment policy.
pub(super) fn is_loopback_bind(bind_addr: &str) -> bool {
    bind_addr
        .parse::<IpAddr>()
        .map(|ip| ip.is_loopback())
        .unwrap_or(false)
}

/// Normalise the isolation profile string. Unknown values map to the
/// stricter option so a typo in config never weakens sandboxing.
pub(super) fn normalize_isolation_profile(profile: &str) -> &'static str {
    if profile.eq_ignore_ascii_case("standard") {
        "standard"
    } else {
        "strict_local"
    }
}

/// Normalise the interaction level (banner / medium / llm_shell). Anything
/// not recognised collapses to `"banner"` — the least interactive mode.
pub(crate) fn normalize_interaction(level: &str) -> String {
    if level.eq_ignore_ascii_case("medium") {
        "medium".to_string()
    } else if level.eq_ignore_ascii_case("llm_shell") {
        "llm_shell".to_string()
    } else {
        "banner".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn banner_ssh_and_http_resolve_ok() {
        assert_eq!(banner_for_service("ssh").unwrap(), SSH_BANNER);
        assert_eq!(banner_for_service("http").unwrap(), HTTP_BANNER);
    }

    #[test]
    fn banner_is_case_insensitive() {
        assert_eq!(banner_for_service("SSH").unwrap(), SSH_BANNER);
        assert_eq!(banner_for_service("Http").unwrap(), HTTP_BANNER);
    }

    #[test]
    fn banner_rejects_unknown_service() {
        let err = banner_for_service("ftp").unwrap_err();
        assert!(err.contains("ftp"));
        assert!(err.contains("supported"));
    }

    #[test]
    fn banner_rejects_empty_service() {
        assert!(banner_for_service("").is_err());
    }

    #[test]
    fn loopback_detection_v4_and_v6() {
        assert!(is_loopback_bind("127.0.0.1"));
        assert!(is_loopback_bind("127.5.5.5"));
        assert!(is_loopback_bind("::1"));
        assert!(!is_loopback_bind("0.0.0.0"));
        assert!(!is_loopback_bind("192.168.1.1"));
    }

    #[test]
    fn loopback_detection_rejects_malformed() {
        assert!(!is_loopback_bind("not-an-ip"));
        assert!(!is_loopback_bind(""));
        assert!(!is_loopback_bind("127.0.0.1:22"));
    }

    #[test]
    fn isolation_profile_defaults_to_strict_on_unknown() {
        assert_eq!(normalize_isolation_profile("standard"), "standard");
        assert_eq!(normalize_isolation_profile("Standard"), "standard");
        assert_eq!(normalize_isolation_profile("strict_local"), "strict_local");
        assert_eq!(normalize_isolation_profile("weird"), "strict_local");
        assert_eq!(normalize_isolation_profile(""), "strict_local");
    }

    #[test]
    fn interaction_levels_are_normalized() {
        assert_eq!(normalize_interaction("medium"), "medium");
        assert_eq!(normalize_interaction("MEDIUM"), "medium");
        assert_eq!(normalize_interaction("llm_shell"), "llm_shell");
        assert_eq!(normalize_interaction("LLM_Shell"), "llm_shell");
        assert_eq!(normalize_interaction("banner"), "banner");
        assert_eq!(normalize_interaction("typo"), "banner");
        assert_eq!(normalize_interaction(""), "banner");
    }
}
