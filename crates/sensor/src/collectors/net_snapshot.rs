//! Process network snapshot collector.
//!
//! Periodically scans /proc/net/tcp{,6} and maps each socket to its owning
//! PID via /proc/[pid]/fd. Emits a snapshot of all active TCP connections
//! with process context.
//!
//! This provides STATE visibility ("who is connected to whom RIGHT NOW")
//! complementing eBPF's EVENT visibility ("someone just connected").
//!
//! When an incident fires, the agent can query the latest snapshot to know
//! exactly which process is talking to the C2 server.

use std::collections::HashMap;

use chrono::Utc;
use innerwarden_core::event::{Event, Severity};
use tokio::sync::mpsc;
use tracing::{debug, info};

/// A single TCP connection with process ownership.
#[derive(Debug, Clone)]
struct SocketEntry {
    local_addr: String,
    local_port: u16,
    remote_addr: String,
    remote_port: u16,
    state: &'static str,
    inode: u64,
    pid: Option<u32>,
    comm: Option<String>,
}

/// TCP connection states from /proc/net/tcp.
fn tcp_state(hex: &str) -> &'static str {
    match hex {
        "01" => "ESTABLISHED",
        "02" => "SYN_SENT",
        "03" => "SYN_RECV",
        "04" => "FIN_WAIT1",
        "05" => "FIN_WAIT2",
        "06" => "TIME_WAIT",
        "07" => "CLOSE",
        "08" => "CLOSE_WAIT",
        "09" => "LAST_ACK",
        "0A" => "LISTEN",
        "0B" => "CLOSING",
        _ => "UNKNOWN",
    }
}

/// Parse /proc/net/tcp into socket entries.
fn parse_proc_net_tcp(content: &str) -> Vec<SocketEntry> {
    let mut entries = Vec::new();

    for line in content.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 10 {
            continue;
        }

        let local = fields[1];
        let remote = fields[2];
        let state_hex = fields[3];
        let inode: u64 = fields[9].parse().unwrap_or(0);

        let (local_addr, local_port) = parse_hex_addr(local);
        let (remote_addr, remote_port) = parse_hex_addr(remote);

        entries.push(SocketEntry {
            local_addr,
            local_port,
            remote_addr,
            remote_port,
            state: tcp_state(state_hex),
            inode,
            pid: None,
            comm: None,
        });
    }

    entries
}

/// Parse hex address:port from /proc/net/tcp format.
/// Format: "0100007F:0050" = 127.0.0.1:80
fn parse_hex_addr(s: &str) -> (String, u16) {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 2 {
        return ("0.0.0.0".into(), 0);
    }

    let addr_hex = parts[0];
    let port = u16::from_str_radix(parts[1], 16).unwrap_or(0);

    // IPv4: 4 bytes in little-endian hex
    if addr_hex.len() == 8 {
        let n = u32::from_str_radix(addr_hex, 16).unwrap_or(0);
        let addr = format!(
            "{}.{}.{}.{}",
            n & 0xff,
            (n >> 8) & 0xff,
            (n >> 16) & 0xff,
            (n >> 24) & 0xff
        );
        (addr, port)
    } else {
        // IPv6: simplified
        (format!("ipv6:{}", addr_hex), port)
    }
}

/// Build a map of socket inode -> (pid, comm) by scanning /proc/[pid]/fd.
fn build_inode_pid_map() -> HashMap<u64, (u32, String)> {
    let mut map = HashMap::new();

    let Ok(proc_dir) = std::fs::read_dir("/proc") else {
        return map;
    };

    for entry in proc_dir.flatten() {
        let name = entry.file_name();
        let pid_str = name.to_string_lossy();
        let Ok(pid) = pid_str.parse::<u32>() else {
            continue;
        };

        let fd_dir = format!("/proc/{pid}/fd");
        let Ok(fds) = std::fs::read_dir(&fd_dir) else {
            continue;
        };

        let comm = std::fs::read_to_string(format!("/proc/{pid}/comm"))
            .map(|s| s.trim().to_string())
            .unwrap_or_default();

        for fd_entry in fds.flatten() {
            if let Ok(link) = std::fs::read_link(fd_entry.path()) {
                let link_str = link.to_string_lossy();
                if link_str.starts_with("socket:[") {
                    if let Some(inode_str) = link_str
                        .strip_prefix("socket:[")
                        .and_then(|s| s.strip_suffix(']'))
                    {
                        if let Ok(inode) = inode_str.parse::<u64>() {
                            map.insert(inode, (pid, comm.clone()));
                        }
                    }
                }
            }
        }
    }

    map
}

/// Run the network snapshot collector.
pub async fn run(tx: mpsc::Sender<Event>, host_id: String, interval_secs: u64) {
    info!("net_snapshot: starting (interval: {interval_secs}s)");

    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(interval_secs)).await;

        let now = Utc::now();

        // Parse /proc/net/tcp
        let tcp_content = match std::fs::read_to_string("/proc/net/tcp") {
            Ok(c) => c,
            Err(e) => {
                debug!("net_snapshot: cannot read /proc/net/tcp: {e}");
                continue;
            }
        };

        let mut entries = parse_proc_net_tcp(&tcp_content);

        // Also parse tcp6
        if let Ok(tcp6) = std::fs::read_to_string("/proc/net/tcp6") {
            entries.extend(parse_proc_net_tcp(&tcp6));
        }

        // Resolve PID ownership
        let inode_map = build_inode_pid_map();
        for entry in &mut entries {
            if let Some((pid, comm)) = inode_map.get(&entry.inode) {
                entry.pid = Some(*pid);
                entry.comm = Some(comm.clone());
            }
        }

        // Filter to interesting connections (skip loopback, TIME_WAIT)
        let interesting: Vec<&SocketEntry> = entries
            .iter()
            .filter(|e| e.state == "ESTABLISHED" || e.state == "LISTEN" || e.state == "SYN_SENT")
            .filter(|e| e.remote_addr != "0.0.0.0" || e.state == "LISTEN")
            .filter(|e| !e.local_addr.starts_with("127.") || e.state == "LISTEN")
            .collect();

        let established: Vec<serde_json::Value> = interesting
            .iter()
            .filter(|e| e.state == "ESTABLISHED")
            .map(|e| {
                serde_json::json!({
                    "pid": e.pid,
                    "comm": e.comm,
                    "local": format!("{}:{}", e.local_addr, e.local_port),
                    "remote": format!("{}:{}", e.remote_addr, e.remote_port),
                    "state": e.state,
                })
            })
            .collect();

        let listening: Vec<serde_json::Value> = interesting
            .iter()
            .filter(|e| e.state == "LISTEN")
            .map(|e| {
                serde_json::json!({
                    "pid": e.pid,
                    "comm": e.comm,
                    "addr": format!("{}:{}", e.local_addr, e.local_port),
                })
            })
            .collect();

        let event = Event {
            ts: now,
            host: host_id.clone(),
            source: "net_snapshot".into(),
            kind: "network.snapshot".into(),
            severity: Severity::Debug,
            summary: format!(
                "Network snapshot: {} established, {} listening",
                established.len(),
                listening.len()
            ),
            details: serde_json::json!({
                "established": established,
                "listening": listening,
                "established_count": established.len(),
                "listening_count": listening.len(),
            }),
            tags: vec!["snapshot".into(), "network".into()],
            entities: Vec::new(),
        };

        let _ = tx.send(event).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_hex_addr_ipv4() {
        // 0100007F:0050 = 127.0.0.1:80
        let (addr, port) = parse_hex_addr("0100007F:0050");
        assert_eq!(addr, "127.0.0.1");
        assert_eq!(port, 80);
    }

    #[test]
    fn test_parse_proc_net_tcp() {
        let content = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
   0: 0100007F:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0\n\
   1: 0100007F:1F90 0100007F:C35A 01 00000000:00000000 00:00000000 00000000  1000        0 67890 1 0000000000000000 100 0 0 10 0\n";

        let entries = parse_proc_net_tcp(content);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].state, "LISTEN");
        assert_eq!(entries[0].local_port, 80);
        assert_eq!(entries[0].inode, 12345);
        assert_eq!(entries[1].state, "ESTABLISHED");
    }

    #[test]
    fn test_tcp_state() {
        assert_eq!(tcp_state("01"), "ESTABLISHED");
        assert_eq!(tcp_state("0A"), "LISTEN");
        assert_eq!(tcp_state("06"), "TIME_WAIT");
        assert_eq!(tcp_state("FF"), "UNKNOWN");
    }
}
