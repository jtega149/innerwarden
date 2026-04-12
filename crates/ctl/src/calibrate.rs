//! `innerwarden system calibrate` — discover host inventory for FP reduction.
//!
//! Scans the current system to discover:
//! - Local interface IPs
//! - Listening TCP ports and their owning processes
//! - Running services (systemd units in active state)
//! - Active outbound connections and their destinations
//!
//! Outputs a report the operator can review and optionally paste into
//! `[calibration]` in the sensor config to suppress known-good FPs.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::Result;

/// Entry point for `innerwarden system calibrate`.
pub fn cmd_calibrate() -> Result<()> {
    println!("╔══════════════════════════════════════════════════════╗");
    println!("║          InnerWarden — Host Calibration             ║");
    println!("╚══════════════════════════════════════════════════════╝");
    println!();

    // 1. Own IPs
    let own_ips = discover_ips();
    println!("🔹 Local interface IPs ({}):", own_ips.len());
    for ip in &own_ips {
        println!("   {ip}");
    }
    println!();

    // 2. Listening ports
    let listeners = discover_listeners();
    println!("🔹 Listening TCP ports ({}):", listeners.len());
    for (port, procs) in &listeners {
        let proc_str = procs.iter().cloned().collect::<Vec<_>>().join(", ");
        println!("   :{port:<6} ({proc_str})");
    }
    println!();

    // 3. Running services
    let services = discover_services();
    println!("🔹 Active services ({}):", services.len());
    for svc in &services {
        println!("   {svc}");
    }
    println!();

    // 4. Outbound connections
    let outbound = discover_outbound();
    println!("🔹 Active outbound destinations ({}):", outbound.len());
    for (dst, procs) in &outbound {
        let proc_str = procs.iter().cloned().collect::<Vec<_>>().join(", ");
        println!("   {dst:<40} ({proc_str})");
    }
    println!();

    // 5. Suggested config
    println!("───────────────────────────────────────────────────────");
    println!("Suggested [calibration] for sensor config.toml:");
    println!();
    println!("[calibration]");
    let svc_names: Vec<_> = services
        .iter()
        .filter(|s| !s.contains("innerwarden"))
        .map(|s| format!("\"{}\"", s.trim_end_matches(".service")))
        .collect();
    println!("expected_services = [{}]", svc_names.join(", "));

    // Extract just the IP (without port) for the config suggestion
    let out_ips: BTreeSet<_> = outbound
        .keys()
        .filter_map(|d| d.rsplit(':').nth(1)) // "1.2.3.4:443" → "1.2.3.4"
        .filter(|ip| !ip.starts_with("127.") && !ip.starts_with("10.") && !ip.starts_with("172."))
        .collect();
    let out_names: Vec<_> = out_ips.iter().map(|ip| format!("\"{ip}\"")).collect();
    println!("expected_outbound = [{}]", out_names.join(", "));
    println!();
    println!("Review the above and paste into /etc/innerwarden/config.toml");
    println!("Only approved entries will be used — nothing is applied automatically.");

    Ok(())
}

/// Discover local interface IPs from /proc/net/fib_trie.
fn discover_ips() -> BTreeSet<String> {
    let mut ips = BTreeSet::new();
    let Ok(content) = std::fs::read_to_string("/proc/net/fib_trie") else {
        return ips;
    };
    let lines: Vec<&str> = content.lines().collect();
    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if let Some(ip_str) = trimmed.strip_prefix("|-- ") {
            if i + 1 < lines.len()
                && lines[i + 1].trim().contains("/32 host LOCAL")
                && !ip_str.starts_with("127.")
            {
                ips.insert(ip_str.to_string());
            }
        }
    }
    ips
}

/// Discover listening TCP ports and their owning processes.
fn discover_listeners() -> BTreeMap<u16, BTreeSet<String>> {
    let mut result: BTreeMap<u16, BTreeSet<String>> = BTreeMap::new();

    // Try ss first (more info), fall back to /proc/net/tcp
    if let Ok(output) = std::process::Command::new("ss")
        .args(["-tlnp"])
        .output()
    {
        let text = String::from_utf8_lossy(&output.stdout);
        for line in text.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 5 {
                continue;
            }
            // Local address:port is in column 3
            if let Some(port_str) = parts[3].rsplit(':').next() {
                if let Ok(port) = port_str.parse::<u16>() {
                    // Process info in last column: users:(("sshd",pid=1234,...))
                    let proc_name = parts
                        .last()
                        .and_then(|s| {
                            s.split('"').nth(1).map(|n| n.to_string())
                        })
                        .unwrap_or_else(|| "?".to_string());
                    result.entry(port).or_default().insert(proc_name);
                }
            }
        }
    }

    if result.is_empty() {
        // Fallback: parse /proc/net/tcp
        for path in &["/proc/net/tcp", "/proc/net/tcp6"] {
            let Ok(content) = std::fs::read_to_string(path) else {
                continue;
            };
            for line in content.lines().skip(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() < 4 || parts[3] != "0A" {
                    continue;
                }
                if let Some(port_hex) = parts[1].split(':').nth(1) {
                    if let Ok(port) = u16::from_str_radix(port_hex, 16) {
                        if port > 0 {
                            result.entry(port).or_default().insert("?".to_string());
                        }
                    }
                }
            }
        }
    }

    result
}

/// Discover running systemd services.
fn discover_services() -> BTreeSet<String> {
    let mut services = BTreeSet::new();
    if let Ok(output) = std::process::Command::new("systemctl")
        .args(["list-units", "--type=service", "--state=running", "--no-legend", "--plain"])
        .output()
    {
        let text = String::from_utf8_lossy(&output.stdout);
        for line in text.lines() {
            if let Some(name) = line.split_whitespace().next() {
                if !name.is_empty() {
                    services.insert(name.to_string());
                }
            }
        }
    }
    services
}

/// Discover active outbound connections and their destination IPs/domains.
fn discover_outbound() -> BTreeMap<String, BTreeSet<String>> {
    let mut result: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();

    if let Ok(output) = std::process::Command::new("ss")
        .args(["-tnp", "state", "established"])
        .output()
    {
        let text = String::from_utf8_lossy(&output.stdout);
        for line in text.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            // Format: Recv-Q Send-Q LocalAddr:Port PeerAddr:Port [Process]
            if parts.len() < 5 {
                continue;
            }
            let peer = parts[4].to_string();
            // Skip localhost connections
            if peer.starts_with("127.") || peer.starts_with("[::1]") {
                continue;
            }
            // Process info is in column 5+ (if running as root with -p)
            let proc_name = if parts.len() > 5 {
                parts[5..]
                    .join(" ")
                    .split('"')
                    .nth(1)
                    .map(|n| n.to_string())
                    .unwrap_or_else(|| "?".to_string())
            } else {
                "?".to_string()
            };
            result.entry(peer).or_default().insert(proc_name);
        }
    }

    result
}
