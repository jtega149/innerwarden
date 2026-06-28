//! Listening services / open ports probe.
//!
//! Runs `ss -ltnp` (TCP) and `ss -lunp` (UDP), parses the listener
//! lines, and emits one record per `(proto, addr, port, comm, pid)`
//! tuple.
//!
//! The downgrade engine reads this to answer "is anyone actually
//! listening on the port the attacker probed?". A `web_scan`
//! probe against a port with no listener is unreachable and gets
//! demoted; a probe against a real listener stays at original
//! severity.
//!
//! `ss -p` requires CAP_NET_ADMIN to show the process column. The
//! agent runs with that capability on prod (the systemd unit grants
//! it); when missing, the probe still gets the port + addr but the
//! `comm` column shows `?`. The downgrade decision works on port
//! presence alone, so the comm column is informational.

use serde::{Deserialize, Serialize};
use std::process::Command;

use super::sshd::ProbeState;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ServicesPosture {
    pub probe_state: ProbeState,
    pub listeners: Vec<Listener>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Listener {
    pub proto: Proto,
    /// Bound port. Multiple listeners on the same port (different
    /// addresses or v4/v6 split) appear as separate entries.
    pub port: u16,
    /// Bound address as it appeared in `ss` output (`0.0.0.0`,
    /// `127.0.0.1`, `::`, `[::1]`, etc.). Useful for the dashboard;
    /// the downgrade engine only consults the port.
    pub addr: String,
    /// Comm of the process that owns the socket. `?` when `ss -p` did
    /// not have permission to read it. Empty in the rare case of an
    /// orphan socket (kernel-owned).
    #[serde(default)]
    pub comm: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Proto {
    Tcp,
    Udp,
}

impl ServicesPosture {
    /// True when at least one listener is bound to `port` regardless
    /// of address or proto. The downgrade engine uses this to refuse
    /// demotion of `web_scan` against a port that does have a
    /// listener (real exposure surface).
    #[allow(dead_code)]
    pub fn has_listener_on_port(&self, port: u16) -> bool {
        self.probe_state == ProbeState::Ok && self.listeners.iter().any(|l| l.port == port)
    }
}

/// Probe via `ss -ltnp` + `ss -lunp`. Returns a combined posture.
/// Each `ss` invocation is independent; one failing does not fail the
/// other — the snapshot reports per-proto coverage.
pub fn probe_services() -> ServicesPosture {
    let mut listeners = Vec::new();
    let mut errors: Vec<String> = Vec::new();
    let mut tcp_ok = false;
    let mut udp_ok = false;

    match run_ss(&["-Hltnp"]) {
        Ok(out) => {
            listeners.extend(parse_ss_dump(&out, Proto::Tcp));
            tcp_ok = true;
        }
        Err(e) => errors.push(format!("ss tcp: {e}")),
    }
    match run_ss(&["-Hlunp"]) {
        Ok(out) => {
            listeners.extend(parse_ss_dump(&out, Proto::Udp));
            udp_ok = true;
        }
        Err(e) => errors.push(format!("ss udp: {e}")),
    }

    let probe_state = match (tcp_ok, udp_ok) {
        (false, false) => ProbeState::Unavailable,
        (true, true) => ProbeState::Ok,
        // Partial coverage — call it Ok but record the error so the
        // dashboard can show a "udp probe missing" hint. The downgrade
        // engine does not distinguish full from partial coverage.
        _ => ProbeState::Ok,
    };
    let error = if errors.is_empty() {
        None
    } else {
        Some(errors.join("; "))
    };

    ServicesPosture {
        probe_state,
        listeners,
        error,
    }
}

fn run_ss(argv: &[&str]) -> Result<String, String> {
    let candidates: [&str; 2] = ["ss", "/usr/bin/ss"];
    let mut last_err = String::from("ss binary not found");
    for bin in candidates {
        let output = match Command::new(bin).args(argv).output() {
            Ok(o) => o,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => {
                last_err = format!("{bin} {argv:?}: {e}");
                continue;
            }
        };
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            last_err = if stderr.is_empty() {
                format!("{bin} exited with status {}", output.status)
            } else {
                stderr
            };
            continue;
        }
        return Ok(String::from_utf8_lossy(&output.stdout).to_string());
    }
    Err(last_err)
}

/// Parse the no-header (`-H`) output of `ss -lt(u)np`.
///
/// One line per listener. Format (simplified, columns aligned by
/// whitespace):
/// ```text
/// LISTEN 0  128  0.0.0.0:22  0.0.0.0:*  users:(("sshd",pid=1234,fd=4))
/// LISTEN 0  100  [::]:22     [::]:*     users:(("sshd",pid=1234,fd=5))
/// UNCONN 0  0    127.0.0.53%lo:53  0.0.0.0:*  users:(("systemd-resolve",pid=999,fd=14))
/// ```
///
/// The address column is split on the LAST `:` because IPv6 forms
/// like `[::1]:22` use `:` inside brackets too. Anything we cannot
/// parse cleanly is silently dropped — better to under-report than
/// to fabricate.
pub(crate) fn parse_ss_dump(dump: &str, proto: Proto) -> Vec<Listener> {
    let mut out = Vec::new();
    for line in dump.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let cols: Vec<&str> = trimmed.split_whitespace().collect();
        // Need at least: state, recv-q, send-q, local-addr, peer-addr.
        // Process column may be absent on permission-restricted runs.
        if cols.len() < 5 {
            continue;
        }
        let local = cols[3];
        let (addr, port) = match split_addr_port(local) {
            Some(parts) => parts,
            None => continue,
        };
        let comm = cols
            .get(5)
            .and_then(|s| extract_comm(s))
            .unwrap_or_else(|| "?".to_string());
        out.push(Listener {
            proto,
            port,
            addr,
            comm,
        });
    }
    out
}

/// Split `addr:port` honouring IPv6 brackets and zone IDs.
///
/// Inputs we accept:
/// - `0.0.0.0:22` → ("0.0.0.0", 22)
/// - `127.0.0.1:8787` → ("127.0.0.1", 8787)
/// - `[::]:22` → ("[::]", 22)
/// - `[::1]:8787` → ("[::1]", 8787)
/// - `127.0.0.53%lo:53` → ("127.0.0.53%lo", 53) (zone-id IPv4, rare but real)
/// - `*:53` → ("*", 53)
fn split_addr_port(s: &str) -> Option<(String, u16)> {
    let last_colon = s.rfind(':')?;
    let addr = &s[..last_colon];
    let port_str = &s[last_colon + 1..];
    let port = port_str.parse::<u16>().ok()?;
    Some((addr.to_string(), port))
}

/// Pull the comm out of `users:(("sshd",pid=1234,fd=4))`. Returns
/// `None` if the column is the literal `users:(...)` placeholder
/// from a permission-denied run.
fn extract_comm(s: &str) -> Option<String> {
    // Cheapest path: locate the first `(("` and the matching closing `"`.
    let open = s.find("((\"")?;
    let rest = &s[open + 3..];
    let close = rest.find('"')?;
    Some(rest[..close].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr_port(addr: &str, port: u16) -> Option<(String, u16)> {
        Some((addr.to_string(), port))
    }

    #[test]
    fn parse_ss_dump_parses_known_good_tcp_snippet() {
        let dump = "\
LISTEN 0      128        127.0.0.1:22        0.0.0.0:*    users:((\"sshd\",pid=1234,fd=3))
LISTEN 0      4096         0.0.0.0:8787      0.0.0.0:*    users:((\"innerwarden-age\",pid=4321,fd=45))
";

        let listeners = parse_ss_dump(dump, Proto::Tcp);

        assert_eq!(
            listeners,
            vec![
                Listener {
                    proto: Proto::Tcp,
                    port: 22,
                    addr: "127.0.0.1".to_string(),
                    comm: "sshd".to_string(),
                },
                Listener {
                    proto: Proto::Tcp,
                    port: 8787,
                    addr: "0.0.0.0".to_string(),
                    comm: "innerwarden-age".to_string(),
                },
            ]
        );
    }

    #[test]
    fn parse_ss_dump_empty_input_returns_empty_vec() {
        assert!(parse_ss_dump("", Proto::Tcp).is_empty());
        assert!(parse_ss_dump("   \n\t\n", Proto::Udp).is_empty());
    }

    #[test]
    fn parse_ss_dump_skips_header_line() {
        let dump = "\
State  Recv-Q Send-Q Local Address:Port  Peer Address:Port Process
LISTEN 0      128        127.0.0.1:22    0.0.0.0:*         users:((\"sshd\",pid=1234,fd=3))
";

        let listeners = parse_ss_dump(dump, Proto::Tcp);

        assert_eq!(listeners.len(), 1);
        assert_eq!(listeners[0].addr, "127.0.0.1");
        assert_eq!(listeners[0].port, 22);
    }

    #[test]
    fn parse_ss_dump_handles_ipv6_bind_address() {
        let dump = "\
LISTEN 0      128             [::]:443          [::]:*    users:((\"nginx\",pid=99,fd=8))
";

        let listeners = parse_ss_dump(dump, Proto::Tcp);

        assert_eq!(
            listeners,
            vec![Listener {
                proto: Proto::Tcp,
                port: 443,
                addr: "[::]".to_string(),
                comm: "nginx".to_string(),
            }]
        );
    }

    #[test]
    fn parse_ss_dump_accepts_udp_unconn_zone_id() {
        let dump = "\
UNCONN 0      0          127.0.0.53%lo:53     0.0.0.0:*    users:((\"systemd-resolve\",pid=999,fd=14))
";

        let listeners = parse_ss_dump(dump, Proto::Udp);

        assert_eq!(
            listeners,
            vec![Listener {
                proto: Proto::Udp,
                port: 53,
                addr: "127.0.0.53%lo".to_string(),
                comm: "systemd-resolve".to_string(),
            }]
        );
    }

    #[test]
    fn parse_ss_dump_defaults_missing_process_column_to_question_mark() {
        let dump = "\
LISTEN 0      128          0.0.0.0:22        0.0.0.0:*
";

        let listeners = parse_ss_dump(dump, Proto::Tcp);

        assert_eq!(
            listeners,
            vec![Listener {
                proto: Proto::Tcp,
                port: 22,
                addr: "0.0.0.0".to_string(),
                comm: "?".to_string(),
            }]
        );
    }

    #[test]
    fn parse_ss_dump_skips_unparseable_local_address() {
        let dump = "\
LISTEN 0      128          not-an-addr        0.0.0.0:*    users:((\"bad\",pid=1,fd=1))
LISTEN 0      128          0.0.0.0:22         0.0.0.0:*    users:((\"sshd\",pid=1234,fd=3))
";

        let listeners = parse_ss_dump(dump, Proto::Tcp);

        assert_eq!(listeners.len(), 1);
        assert_eq!(listeners[0].comm, "sshd");
    }

    #[test]
    fn split_addr_port_parses_ipv4_address() {
        assert_eq!(split_addr_port("127.0.0.1:22"), addr_port("127.0.0.1", 22));
    }

    #[test]
    fn split_addr_port_parses_ipv6_address_without_losing_brackets() {
        assert_eq!(split_addr_port("[::1]:80"), addr_port("[::1]", 80));
    }

    #[test]
    fn split_addr_port_parses_wildcard_listener() {
        assert_eq!(split_addr_port("*:53"), addr_port("*", 53));
    }

    #[test]
    fn split_addr_port_returns_none_without_port_separator() {
        assert_eq!(split_addr_port("not-an-addr"), None);
    }

    #[test]
    fn split_addr_port_returns_none_for_non_numeric_port() {
        assert_eq!(split_addr_port("127.0.0.1:not-a-port"), None);
    }

    #[test]
    fn extract_comm_parses_ss_users_field() {
        assert_eq!(
            extract_comm("users:((\"sshd\",pid=1234,fd=3))"),
            Some("sshd".to_string())
        );
    }

    #[test]
    fn extract_comm_returns_none_without_users_field() {
        assert_eq!(extract_comm("timer:(\"sshd\",pid=1234,fd=3)"), None);
    }

    #[test]
    fn extract_comm_returns_none_for_malformed_quotes() {
        assert_eq!(extract_comm("users:((\"sshd,pid=1234,fd=3))"), None);
    }
}
