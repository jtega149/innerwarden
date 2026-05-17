use std::io::{IsTerminal, Write};
use std::time::Duration;

use anyhow::Result;
use dialoguer::theme::ColorfulTheme;
use dialoguer::MultiSelect;

use crate::{AgentCommand, Cli};

/// Resolve the dashboard URL from agent config or default.
///
/// Default scheme is HTTPS: the agent's `--dashboard` flag enables a
/// self-signed TLS cert at startup ("dashboard HTTPS started" in the log),
/// so probing http:// returns "Connection refused" and the setup wizard
/// prints the misleading "Dashboard not reachable".
///
/// Parsing rules:
///   1. Top-level `dashboard_bind = "..."` wins.
///   2. Inside `[dashboard]` (or `[dashboard.*]` subsections), an exact
///      `bind = "..."` wins.
///   3. Everything else is ignored. Crucially: a `bind_addr` inside
///      `[honeypot]` must NOT be picked up — the old `starts_with("bind")`
///      check captured that and produced URLs like `http://127.0.0.1` with
///      no port.
///   4. Fully-qualified `http://` or `https://` URLs are honored as-is.
///   5. If the bound address has no `:port` suffix, default to `:8787`.
///   6. `bind` set to a wildcard (`0.0.0.0` / `[::]`) is rewritten to
///      `127.0.0.1` so the CLI talks to itself, not whatever's listening on
///      the public interface.
pub(crate) fn resolve_dashboard_url(cli: &Cli) -> String {
    const DEFAULT: &str = "https://127.0.0.1:8787";

    let Ok(content) = std::fs::read_to_string(&cli.agent_config) else {
        return DEFAULT.to_string();
    };

    let mut current_section = String::new();
    let mut dashboard_bind: Option<String> = None;

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        if let Some(rest) = trimmed.strip_prefix('[').and_then(|r| r.strip_suffix(']')) {
            current_section = rest.trim().to_string();
            continue;
        }

        let Some(eq) = trimmed.find('=') else {
            continue;
        };
        let key = trimmed[..eq].trim();
        let raw_value = trimmed[eq + 1..].trim();
        // Strip inline comments and surrounding quotes.
        let value_no_comment = raw_value.split('#').next().unwrap_or("").trim();
        let value = value_no_comment.trim_matches('"').trim_matches('\'');

        if value.is_empty() {
            continue;
        }

        // Rule 1: top-level dashboard_bind.
        if key == "dashboard_bind" && current_section.is_empty() {
            dashboard_bind = Some(value.to_string());
            break;
        }

        // Rule 2: bind inside [dashboard] (or [dashboard.something]).
        if key == "bind"
            && (current_section == "dashboard" || current_section.starts_with("dashboard."))
        {
            dashboard_bind = Some(value.to_string());
            break;
        }
    }

    let Some(mut addr) = dashboard_bind else {
        return DEFAULT.to_string();
    };

    if addr.starts_with("http://") || addr.starts_with("https://") {
        return addr;
    }

    // Rewrite wildcards: the CLI calls localhost, not the public bind.
    if let Some(rest) = addr.strip_prefix("0.0.0.0") {
        addr = format!("127.0.0.1{rest}");
    } else if let Some(rest) = addr.strip_prefix("[::]") {
        addr = format!("127.0.0.1{rest}");
    } else if addr == "*" {
        addr = "127.0.0.1:8787".to_string();
    }

    // If no :port suffix, add the default.
    let has_port = if addr.starts_with('[') {
        // IPv6 literal: [::1]:8787 — port follows the closing bracket.
        addr.split_once(']')
            .is_some_and(|(_, rest)| rest.starts_with(':'))
    } else {
        addr.contains(':')
    };
    if !has_port {
        addr = format!("{addr}:8787");
    }

    format!("https://{addr}")
}

pub(crate) fn dashboard_api_agent(url: &str) -> ureq::Agent {
    let mut builder = ureq::Agent::config_builder().timeout_global(Some(Duration::from_secs(5)));
    if is_loopback_dashboard_url(url) {
        // The local dashboard uses a self-signed certificate. Keep the relaxed
        // TLS policy scoped to loopback URLs only.
        builder = builder.tls_config(
            ureq::tls::TlsConfig::builder()
                .disable_verification(true)
                .build(),
        );
    }
    let config = builder.build();
    config.into()
}

fn is_loopback_dashboard_url(url: &str) -> bool {
    let authority = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url)
        .split('/')
        .next()
        .unwrap_or("");

    let host = if let Some(rest) = authority.strip_prefix('[') {
        rest.split_once(']').map(|(host, _)| host).unwrap_or(rest)
    } else {
        authority.split(':').next().unwrap_or(authority)
    };

    matches!(host, "127.0.0.1" | "localhost" | "::1")
}

pub(crate) fn parse_selection_indices(input: &str, max: usize) -> Option<Vec<usize>> {
    let trimmed = input.trim();
    if trimmed.is_empty() || max == 0 {
        return None;
    }
    if trimmed.eq_ignore_ascii_case("all") {
        return Some((1..=max).collect());
    }

    let mut indexes = Vec::new();
    for part in trimmed.split(',') {
        let idx: usize = part.trim().parse().ok()?;
        if idx == 0 || idx > max {
            return None;
        }
        if !indexes.contains(&idx) {
            indexes.push(idx);
        }
    }
    if indexes.is_empty() {
        None
    } else {
        Some(indexes)
    }
}

#[derive(Debug, PartialEq, Eq)]
enum InstallCommandOutcome {
    Success,
    Exit(Option<i32>),
    SpawnError(String),
    NotRunnable,
}

fn run_install_command(cmd: &str) -> InstallCommandOutcome {
    let parts: Vec<&str> = cmd.split_whitespace().collect();
    if parts.len() < 2 {
        return InstallCommandOutcome::NotRunnable;
    }

    match std::process::Command::new(parts[0])
        .args(&parts[1..])
        .status()
    {
        Ok(status) if status.success() => InstallCommandOutcome::Success,
        Ok(status) => InstallCommandOutcome::Exit(status.code()),
        Err(err) => InstallCommandOutcome::SpawnError(err.to_string()),
    }
}

fn report_install_outcome(agent_name: &str, cmd: &str, outcome: InstallCommandOutcome) {
    match outcome {
        InstallCommandOutcome::Success => {
            println!("  \x1b[32m✓\x1b[0m {agent_name} installed");
            println!("  \x1b[32m✓\x1b[0m Connected to InnerWarden (agent-guard active)");
            println!("  \x1b[32m✓\x1b[0m Protection: warn mode (alerts you, doesn't block)");
            println!();
            println!(
                "  Your agent is ready. Start it with: {}",
                agent_name.to_lowercase()
            );
            println!();
            println!(
                "  \x1b[2m💡 Tip: run 'innerwarden agent status' to see what your agent is doing\x1b[0m"
            );
        }
        InstallCommandOutcome::Exit(code) => {
            eprintln!("  \x1b[31m✗\x1b[0m Installation failed (exit code {code:?})",);
        }
        InstallCommandOutcome::SpawnError(err) => {
            eprintln!("  \x1b[31m✗\x1b[0m Failed to run installer: {err}");
            eprintln!("  Try installing manually: {cmd}");
        }
        InstallCommandOutcome::NotRunnable => {}
    }
}

pub(crate) fn cmd_agent(cli: &Cli, command: Option<&AgentCommand>) -> Result<()> {
    use innerwarden_agent_guard::signatures::{Kind, SignatureIndex, KNOWN};

    match command {
        None => {
            // Interactive menu
            println!();
            println!("  \x1b[1;36m🤖 InnerWarden Agent Guard\x1b[0m");
            println!();
            println!("  \x1b[1mWhat do you want to do?\x1b[0m");
            println!();
            println!("  1. Install a new agent        (OpenClaw, ZeroClaw, others)");
            println!("  2. Scan for existing agents   (find agents already running)");
            println!("  3. View connected agents      (see what's being protected)");
            println!("  4. List available agents       (see what we support)");
            println!();
            println!("  Or use directly:");
            println!("    innerwarden agent add <name>");
            println!("    innerwarden agent scan");
            println!("    innerwarden agent status");
            println!();
            Ok(())
        }

        Some(AgentCommand::List) => {
            println!();
            println!("  \x1b[1;36m🤖 Available Agents\x1b[0m");
            println!();
            println!("  \x1b[1mInstallable agents\x1b[0m (innerwarden agent add <name>):");
            println!("  {:<16} {:<20} DESCRIPTION", "NAME", "VENDOR");
            println!("  {}", "─".repeat(60));
            for sig in KNOWN.iter().filter(|s| s.kind == Kind::Agent) {
                println!(
                    "  {:<16} {:<20} {}",
                    sig.name.to_lowercase(),
                    sig.vendor,
                    match sig.name {
                        "OpenClaw" => "Autonomous AI assistant with persistent memory",
                        "ZeroClaw" => "Ultra-lightweight Rust AI agent (5MB RAM)",
                        _ => "",
                    }
                );
            }
            println!();
            println!("  \x1b[1mAuto-detected tools\x1b[0m (monitored when running):");
            println!("  {:<16} {:<12} VENDOR", "NAME", "INTEGRATION");
            println!("  {}", "─".repeat(50));
            for sig in KNOWN.iter().filter(|s| s.kind == Kind::Tool) {
                let integ = format!("{:?}", sig.integration).to_lowercase();
                println!("  {:<16} {:<12} {}", sig.name, integ, sig.vendor);
            }
            println!();
            println!("  \x1b[1mAuto-detected runtimes\x1b[0m (API monitored):");
            println!("  {:<16} VENDOR", "NAME");
            println!("  {}", "─".repeat(36));
            for sig in KNOWN.iter().filter(|s| s.kind == Kind::Runtime) {
                println!("  {:<16} {}", sig.name, sig.vendor);
            }
            println!();
            println!("  \x1b[2m💡 Agents: install + full protection");
            println!("  💡 Tools: auto-detected, connect for full MCP protection");
            println!("  💡 Runtimes: auto-detected, API traffic monitored\x1b[0m");
            println!();
            Ok(())
        }

        Some(AgentCommand::Add { name }) => {
            let agents: Vec<_> = SignatureIndex::installable_agents();

            match name {
                None => {
                    println!();
                    println!("  \x1b[1;36m🤖 Install an Agent\x1b[0m");
                    println!();
                    println!("  Available agents:");
                    println!();
                    for sig in &agents {
                        let desc = match sig.name {
                            "OpenClaw" => "Autonomous AI assistant with persistent memory",
                            "ZeroClaw" => "Ultra-lightweight Rust AI agent (5MB RAM)",
                            _ => "",
                        };
                        println!("  \x1b[1m{:<16}\x1b[0m {}", sig.name.to_lowercase(), desc);
                        if let Some(cmd) = sig.install_cmd {
                            println!("  {:<16} install: {}", "", cmd);
                        }
                        println!();
                    }
                    println!("  Usage: innerwarden agent add <name>");
                    println!();
                    Ok(())
                }
                Some(agent_name) => {
                    let lower = agent_name.to_lowercase();
                    let sig = agents.iter().find(|s| s.name.to_lowercase() == lower);

                    match sig {
                        Some(sig) => {
                            println!();
                            println!("  Installing {}...", sig.name);

                            if let Some(cmd) = sig.install_cmd {
                                println!("  Running: {cmd}");
                                report_install_outcome(sig.name, cmd, run_install_command(cmd));
                            }
                            println!();
                            Ok(())
                        }
                        None => {
                            eprintln!("  Unknown agent: {agent_name}");
                            eprintln!();
                            eprintln!("  Available agents:");
                            for a in &agents {
                                eprintln!("    {}", a.name.to_lowercase());
                            }
                            eprintln!();
                            eprintln!("  Run 'innerwarden agent list' to see all supported agents and tools.");
                            Ok(())
                        }
                    }
                }
            }
        }

        Some(AgentCommand::Scan) => {
            use innerwarden_agent_guard::detect;

            println!();
            println!("  Scanning for running agents...");
            println!();

            let index = SignatureIndex::new();
            let found = detect::scan_processes(&index);

            if found.is_empty() {
                println!("  No known agents or tools detected.");
                println!();
                println!("  To install an agent: innerwarden agent add <name>");
                println!("  See supported names: innerwarden agent list");
                println!("  To connect detected agents: innerwarden agent connect");
            } else {
                println!(
                    "  {:<6} {:<8} {:<16} {:<10} STATUS",
                    "FOUND", "PID", "NAME", "TYPE"
                );
                println!("  {}", "─".repeat(56));
                for (i, agent) in found.iter().enumerate() {
                    let kind = if agent.integration == "official" {
                        "agent"
                    } else {
                        "tool"
                    };
                    println!(
                        "  {:<6} {:<8} {:<16} {:<10} not connected",
                        i + 1,
                        agent.pid,
                        agent.name,
                        kind
                    );
                }
                println!();
                println!("  Connect with: innerwarden agent connect");
            }
            println!();
            Ok(())
        }

        Some(AgentCommand::Status) => {
            println!();
            println!("  \x1b[1;36m🤖 Agent Guard Status\x1b[0m");
            println!();
            println!("  Agent guard is enabled. Checking dashboard API...");
            println!();

            // Wave 2026-05-17 fix: the dashboard speaks HTTPS only —
            // `axum_server::bind_rustls` is the default since spec 037
            // when a self-signed cert lands in /var/lib/innerwarden at
            // first boot. The previous implementation shelled out to
            //   curl -s http://localhost:8787/api/agent/security-context
            // which returns "connection refused" against HTTPS and
            // printed the misleading "Dashboard not reachable (is
            // innerwarden-agent running?)" — exactly what the
            // operator saw on Oracle prod right after the agent
            // connect succeeded over the SAME dashboard.
            //
            // Reuse the dashboard_api_agent + resolve_dashboard_url
            // helpers that `connect` / `disconnect` use: HTTPS,
            // self-signed cert allowed on loopback, short timeout.
            let dashboard_url = resolve_dashboard_url(cli);
            let url = format!("{dashboard_url}/api/agent/security-context");
            match dashboard_api_agent(&url).get(&url).call() {
                Ok(resp) => {
                    let body: serde_json::Value = resp.into_body().read_json().unwrap_or_default();
                    let level = body["threat_level"].as_str().unwrap_or("unknown");
                    let incidents = body["active_incidents_today"].as_u64().unwrap_or(0);
                    let blocks = body["recent_blocks_today"].as_u64().unwrap_or(0);
                    println!("  Server threat level: {level}");
                    println!("  Incidents today:     {incidents}");
                    println!("  IPs blocked today:   {blocks}");
                }
                Err(e) => {
                    println!("  \x1b[33m⚠\x1b[0m  Dashboard not reachable at {url} ({e:#})");
                    println!(
                        "       Is innerwarden-agent running? sudo systemctl status innerwarden-agent"
                    );
                }
            }

            // Scan for running agents/tools
            let index = SignatureIndex::new();
            let found = innerwarden_agent_guard::detect::scan_processes(&index);

            if !found.is_empty() {
                println!();
                println!("  \x1b[1mDetected processes:\x1b[0m");
                println!("  {:<16} {:<8} {:<12} INTEGRATION", "NAME", "PID", "TYPE");
                println!("  {}", "─".repeat(48));
                for agent in &found {
                    println!(
                        "  {:<16} {:<8} {:<12} {}",
                        agent.name, agent.pid, agent.comm, agent.integration
                    );
                }
            } else {
                println!();
                println!("  No agents or tools detected.");
                println!("  Install one with: innerwarden agent add <name>");
                println!("  See options: innerwarden agent list");
            }
            println!();
            Ok(())
        }

        Some(AgentCommand::Connect { pid, name, label }) => {
            println!();
            let index = SignatureIndex::new();

            let selected_pids: Vec<u32> = if let Some(pid) = *pid {
                vec![pid]
            } else {
                let found = innerwarden_agent_guard::detect::scan_processes(&index);
                if found.is_empty() {
                    println!("  No known agent process detected.");
                    println!("  Run one first, then use: innerwarden agent connect");
                    println!("  Or install one with: innerwarden agent add <name>");
                    println!("  See options: innerwarden agent list");
                    println!();
                    return Ok(());
                }

                let candidates: Vec<_> = if let Some(filter) = name.as_deref() {
                    let filter_lc = filter.to_lowercase();
                    let matches: Vec<_> = found
                        .iter()
                        .filter(|a| {
                            a.name.to_lowercase().contains(&filter_lc)
                                || a.comm.to_lowercase().contains(&filter_lc)
                        })
                        .collect();
                    if matches.is_empty() {
                        println!("  No running agent matched '{filter}'.");
                        println!("  Running detections:");
                        for agent in &found {
                            println!(
                                "    - {} (pid {}, comm {}, integration {})",
                                agent.name, agent.pid, agent.comm, agent.integration
                            );
                        }
                        println!();
                        return Ok(());
                    }
                    matches
                } else {
                    found.iter().collect()
                };

                if candidates.len() == 1 {
                    println!(
                        "  Auto-detected: {} (pid {})",
                        candidates[0].name, candidates[0].pid
                    );
                    vec![candidates[0].pid]
                } else {
                    // Wave 2026-05-17 UX: present an arrow-key + space-bar
                    // picker via dialoguer::MultiSelect when stdin is a
                    // TTY, instead of asking the operator to type
                    // "1,3,5" into a numbered table. The numeric path
                    // is retained as a fallback for non-TTY contexts
                    // (CI, redirected stdin, automated scripts) so
                    // pipelines that depend on the typed-index syntax
                    // do not break.
                    let labels: Vec<String> = candidates
                        .iter()
                        .map(|a| format!("{:<16} pid {:<7}  [{}]", a.name, a.pid, a.integration))
                        .collect();

                    let selected_indexes: Vec<usize> = if std::io::stdin().is_terminal() {
                        println!("  Detected agents:");
                        println!();
                        match MultiSelect::with_theme(&ColorfulTheme::default())
                            .with_prompt("  ↑/↓ to move, space to select, enter to connect")
                            .items(&labels)
                            .interact_opt()
                        {
                            Ok(Some(sel)) if !sel.is_empty() => sel,
                            Ok(_) => {
                                println!("  Cancelled.");
                                println!();
                                return Ok(());
                            }
                            Err(err) => {
                                eprintln!("  Picker failed: {err:#}");
                                println!();
                                return Ok(());
                            }
                        }
                    } else {
                        // Non-TTY fallback: keep the existing numbered
                        // table + "1,3 or all" prompt so scripted
                        // callers and CI pipelines that pipe input
                        // into the command still work.
                        println!("  Detected agents:");
                        println!("  {:<4} {:<8} {:<16} TYPE", "NO.", "PID", "NAME");
                        println!("  {}", "─".repeat(48));
                        for (i, agent) in candidates.iter().enumerate() {
                            println!(
                                "  {:<4} {:<8} {:<16} {}",
                                i + 1,
                                agent.pid,
                                agent.name,
                                agent.integration
                            );
                        }
                        println!();
                        print!("  Select one or more (ex: 1,3) or 'all' [Enter to cancel]: ");
                        std::io::stdout().flush()?;
                        let mut input = String::new();
                        std::io::stdin().read_line(&mut input)?;
                        let trimmed = input.trim();
                        if trimmed.is_empty() {
                            println!("  Cancelled.");
                            println!();
                            return Ok(());
                        }
                        let Some(indexes) = parse_selection_indices(trimmed, candidates.len())
                        else {
                            println!("  Invalid selection '{trimmed}'.");
                            println!();
                            return Ok(());
                        };
                        // `parse_selection_indices` returns 1-based;
                        // normalize to 0-based for the unified path.
                        indexes.into_iter().map(|i| i - 1).collect()
                    };

                    selected_indexes
                        .into_iter()
                        .map(|idx| candidates[idx].pid)
                        .collect()
                }
            };

            let dashboard_url = resolve_dashboard_url(cli);
            let mut connected = 0usize;

            for selected_pid in selected_pids {
                // Read /proc/<pid>/comm to identify
                let comm_path = format!("/proc/{selected_pid}/comm");
                let comm = std::fs::read_to_string(&comm_path)
                    .map(|s| s.trim().to_string())
                    .unwrap_or_else(|_| "unknown".to_string());

                let name = if let Some(sig) = index.identify(&comm) {
                    sig.name.to_string()
                } else {
                    comm.clone()
                };

                println!("  Connecting {name} (pid {selected_pid})...");

                // Call agent-guard API to register
                let payload = serde_json::json!({
                    "name": name,
                    "pid": selected_pid,
                    "label": label.as_deref().unwrap_or(""),
                });

                let url = format!("{dashboard_url}/api/agent-guard/connect");
                match dashboard_api_agent(&url).post(&url).send_json(&payload) {
                    Ok(resp) => {
                        // Wave 2026-05-17: respect the `connected: false`
                        // flag in the server response body. The
                        // `/api/agent-guard/connect` endpoint returns
                        // HTTP 200 in BOTH success and structured-error
                        // paths (e.g. duplicate-pid), so a raw `Ok(resp)`
                        // doesn't tell us whether the agent was actually
                        // registered. Previously the CLI printed
                        //   ✓ <name> (pid <n>) connected as unknown
                        // for every duplicate-pid call — operator
                        // thought it succeeded when the server had
                        // refused. Read the body, branch on the flag,
                        // surface the `error` string on failure.
                        let body: serde_json::Value =
                            resp.into_body().read_json().unwrap_or_default();
                        let connected_flag = body
                            .get("connected")
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false);
                        if !connected_flag {
                            let reason = body.get("error").and_then(|v| v.as_str()).unwrap_or(
                                "server returned connected=false without an error string",
                            );
                            println!(
                                "  \x1b[33m!\x1b[0m {name} (pid {selected_pid}) NOT registered — {reason}"
                            );
                            // Don't bump `connected` and don't fall
                            // through to the offline-queue path —
                            // server is reachable, it just declined.
                            continue;
                        }
                        let agent_id = body
                            .get("agent_id")
                            .and_then(|v| v.as_str())
                            .unwrap_or("unknown");
                        println!(
                            "  \x1b[32m✓\x1b[0m {name} (pid {selected_pid}) connected as {agent_id}"
                        );
                        connected += 1;
                    }
                    Err(e) => {
                        // Fallback: write to persistence file for agent to pick up on restart
                        let path = cli.data_dir.join("agent-connections.jsonl");
                        if let Ok(mut f) = std::fs::OpenOptions::new()
                            .create(true)
                            .append(true)
                            .open(&path)
                        {
                            use std::io::Write;
                            let entry = serde_json::json!({
                                "ts": chrono::Utc::now().to_rfc3339(),
                                "action": "connect",
                                "name": name,
                                "pid": selected_pid,
                                "label": label,
                            });
                            let _ = writeln!(f, "{}", entry);
                        }
                        println!(
                            "  \x1b[33m!\x1b[0m Dashboard not reachable ({e:#}), saved for next agent restart"
                        );
                    }
                }
            }

            if let Some(lbl) = label {
                println!("  Label: {lbl}");
            }
            if connected > 1 {
                println!("  Connected {connected} agents.");
            }
            println!();
            println!("  \x1b[2mView status: innerwarden agent status\x1b[0m");
            println!();
            Ok(())
        }

        Some(AgentCommand::Disconnect { id }) => {
            println!();
            let dashboard_url = resolve_dashboard_url(cli);
            let payload = serde_json::json!({ "agent_id": id });
            let url = format!("{dashboard_url}/api/agent-guard/disconnect");

            match dashboard_api_agent(&url).post(&url).send_json(&payload) {
                Ok(_) => {
                    println!("  \x1b[32m✓\x1b[0m Agent {id} disconnected");
                }
                Err(e) => {
                    println!("  \x1b[33m!\x1b[0m Dashboard not reachable ({e:#})");
                }
            }
            println!();
            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------
// ATT&CK Navigator layer generation
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use std::io::{ErrorKind, Read, Write};
    use std::net::TcpListener;
    use std::thread;
    use std::time::{Duration, Instant};
    use tempfile::TempDir;

    fn test_cli(temp: &TempDir) -> Cli {
        let mut cli = Cli::parse_from(["innerwarden", "replay"]);
        cli.sensor_config = temp.path().join("sensor.toml");
        cli.agent_config = temp.path().join("agent.toml");
        cli.data_dir = temp.path().join("data");
        cli.dry_run = true;
        std::fs::create_dir_all(&cli.data_dir).expect("test should create data dir");
        cli
    }

    #[cfg(unix)]
    fn write_executable(temp: &TempDir, name: &str, body: &str) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt;

        let path = temp.path().join(name);
        std::fs::write(&path, body).expect("test should write fake executable");
        let mut perms = std::fs::metadata(&path)
            .expect("fake executable metadata")
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&path, perms).expect("test should chmod fake executable");
        path
    }

    fn start_one_shot_json_server(
        response_body: &'static str,
    ) -> (String, thread::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("test should bind local server");
        let addr = listener.local_addr().expect("test should read local addr");
        listener
            .set_nonblocking(true)
            .expect("test should make listener nonblocking");
        let handle = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(5);
            let (mut stream, _) = loop {
                match listener.accept() {
                    Ok(pair) => break pair,
                    Err(err)
                        if err.kind() == ErrorKind::WouldBlock && Instant::now() < deadline =>
                    {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(err) if err.kind() == ErrorKind::WouldBlock => {
                        panic!("test server timed out waiting for dashboard request");
                    }
                    Err(err) => panic!("test should accept request: {err}"),
                }
            };
            let mut buf = [0_u8; 4096];
            let n = stream.read(&mut buf).expect("test should read request");
            let request = String::from_utf8_lossy(&buf[..n]).to_string();
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response_body.len(),
                response_body
            );
            stream
                .write_all(response.as_bytes())
                .expect("test should write response");
            request
        });
        (addr.to_string(), handle)
    }

    #[test]
    fn resolve_dashboard_url_defaults_when_config_is_missing() {
        // Default scheme is HTTPS — the agent starts a self-signed TLS
        // listener whenever --dashboard is passed (the install.sh systemd
        // unit always passes it). Probing http:// returned a misleading
        // "Connection refused" during setup and made the wizard print
        // "Dashboard not reachable" even when the dashboard was up.
        let temp = TempDir::new().expect("test should create temp dir");
        let cli = test_cli(&temp);
        let url = resolve_dashboard_url(&cli);
        assert_eq!(url, "https://127.0.0.1:8787");
    }

    #[test]
    fn resolve_dashboard_url_reads_bind_from_dashboard_section() {
        // bind inside [dashboard] is honoured; 0.0.0.0 is rewritten to
        // 127.0.0.1 because the CLI talks to localhost, not whatever's
        // listening on the public bind.
        let temp = TempDir::new().expect("test should create temp dir");
        let cli = test_cli(&temp);
        std::fs::write(
            &cli.agent_config,
            r#"[dashboard]
bind = "0.0.0.0:9999"
"#,
        )
        .expect("test should write agent config");
        let url = resolve_dashboard_url(&cli);
        assert_eq!(url, "https://127.0.0.1:9999");
    }

    #[test]
    fn resolve_dashboard_url_reads_top_level_dashboard_bind_and_ignores_empty_values() {
        // dashboard_bind only wins at the top level (rule 1). An empty
        // value inside [dashboard] is skipped and the next entry is used.
        let temp = TempDir::new().expect("test should create temp dir");
        let cli = test_cli(&temp);
        std::fs::write(
            &cli.agent_config,
            r#"dashboard_bind = "127.0.0.1:8788"

[dashboard]
bind = ""
"#,
        )
        .expect("test should write agent config");

        let url = resolve_dashboard_url(&cli);
        assert_eq!(url, "https://127.0.0.1:8788");
    }

    #[test]
    fn resolve_dashboard_url_ignores_honeypot_bind_addr() {
        // Regression for the v0.13.4-rc.1 bug where `bind_addr` inside
        // [honeypot] was picked up as the dashboard address because the
        // parser used `starts_with("bind")`. That produced URLs like
        // `http://127.0.0.1` (no port) and broke the reachability probe.
        let temp = TempDir::new().expect("test should create temp dir");
        let cli = test_cli(&temp);
        std::fs::write(
            &cli.agent_config,
            r#"[honeypot]
mode = "demo"
bind_addr = "127.0.0.1"
port = 2222
"#,
        )
        .expect("test should write agent config");
        let url = resolve_dashboard_url(&cli);
        assert_eq!(url, "https://127.0.0.1:8787");
    }

    #[test]
    fn resolve_dashboard_url_appends_default_port_when_missing() {
        let temp = TempDir::new().expect("test should create temp dir");
        let cli = test_cli(&temp);
        std::fs::write(
            &cli.agent_config,
            r#"[dashboard]
bind = "127.0.0.1"
"#,
        )
        .expect("test should write agent config");
        let url = resolve_dashboard_url(&cli);
        assert_eq!(url, "https://127.0.0.1:8787");
    }

    #[test]
    fn resolve_dashboard_url_ipv6_wildcard_rewrites_to_loopback() {
        let temp = TempDir::new().expect("test should create temp dir");
        let cli = test_cli(&temp);
        std::fs::write(
            &cli.agent_config,
            r#"[dashboard]
bind = "[::]:8787"
"#,
        )
        .expect("test should write agent config");
        let url = resolve_dashboard_url(&cli);
        assert_eq!(url, "https://127.0.0.1:8787");
    }

    #[test]
    fn parse_selection_indices_handles_all_dedup_and_invalid_cases() {
        assert_eq!(parse_selection_indices("all", 3), Some(vec![1, 2, 3]));
        assert_eq!(parse_selection_indices(" ALL ", 2), Some(vec![1, 2]));
        assert_eq!(parse_selection_indices("1,2,2,3", 3), Some(vec![1, 2, 3]));
        assert_eq!(parse_selection_indices("", 3), None);
        assert_eq!(parse_selection_indices("all", 0), None);
        assert_eq!(parse_selection_indices("0", 3), None);
        assert_eq!(parse_selection_indices("4", 3), None);
        assert_eq!(parse_selection_indices("x", 3), None);
    }

    #[test]
    fn cmd_agent_menu_and_list_return_ok() {
        let temp = TempDir::new().expect("test should create temp dir");
        let cli = test_cli(&temp);
        assert!(cmd_agent(&cli, None).is_ok());
        assert!(cmd_agent(&cli, Some(&AgentCommand::List)).is_ok());
    }

    #[test]
    fn cmd_agent_add_without_name_and_unknown_name_return_ok() {
        let temp = TempDir::new().expect("test should create temp dir");
        let cli = test_cli(&temp);
        assert!(cmd_agent(&cli, Some(&AgentCommand::Add { name: None })).is_ok());
        assert!(cmd_agent(
            &cli,
            Some(&AgentCommand::Add {
                name: Some("definitely-unknown-agent".to_string()),
            }),
        )
        .is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn run_install_command_reports_success_failure_spawn_error_and_short_command() {
        let temp = TempDir::new().expect("test should create temp dir");
        let ok = write_executable(&temp, "ok-installer", "#!/bin/sh\nexit 0\n");
        let fail = write_executable(&temp, "fail-installer", "#!/bin/sh\nexit 7\n");

        assert_eq!(
            run_install_command(&format!("{} --unit", ok.display())),
            InstallCommandOutcome::Success
        );
        assert_eq!(
            run_install_command(&format!("{} --unit", fail.display())),
            InstallCommandOutcome::Exit(Some(7))
        );
        assert!(matches!(
            run_install_command(&format!("{}/missing --unit", temp.path().display())),
            InstallCommandOutcome::SpawnError(_)
        ));
        assert_eq!(
            run_install_command("single-word"),
            InstallCommandOutcome::NotRunnable
        );
    }

    #[test]
    fn report_install_outcome_covers_all_status_variants() {
        report_install_outcome(
            "OpenClaw",
            "npm install -g @anthropic-ai/openclaw",
            InstallCommandOutcome::Success,
        );
        report_install_outcome(
            "OpenClaw",
            "npm install -g @anthropic-ai/openclaw",
            InstallCommandOutcome::Exit(Some(7)),
        );
        report_install_outcome(
            "OpenClaw",
            "npm install -g @anthropic-ai/openclaw",
            InstallCommandOutcome::SpawnError("missing npm".to_string()),
        );
        report_install_outcome(
            "OpenClaw",
            "npm install -g @anthropic-ai/openclaw",
            InstallCommandOutcome::NotRunnable,
        );
    }

    #[test]
    fn cmd_agent_scan_and_status_are_non_fatal_without_services() {
        let temp = TempDir::new().expect("test should create temp dir");
        let cli = test_cli(&temp);
        assert!(cmd_agent(&cli, Some(&AgentCommand::Scan)).is_ok());
        assert!(cmd_agent(&cli, Some(&AgentCommand::Status)).is_ok());
    }

    #[test]
    fn cmd_agent_connect_with_pid_falls_back_to_local_queue_when_dashboard_unreachable() {
        let temp = TempDir::new().expect("test should create temp dir");
        let cli = test_cli(&temp);
        std::fs::write(
            &cli.agent_config,
            r#"[dashboard]
bind = "http://127.0.0.1:1"
"#,
        )
        .expect("test should write agent config");

        assert!(cmd_agent(
            &cli,
            Some(&AgentCommand::Connect {
                pid: Some(std::process::id()),
                name: None,
                label: Some("unit".to_string()),
            }),
        )
        .is_ok());

        let queue_path = cli.data_dir.join("agent-connections.jsonl");
        let queued = std::fs::read_to_string(queue_path).expect("connect should queue fallback");
        assert!(queued.contains("\"action\":\"connect\""));
    }

    #[test]
    fn cmd_agent_connect_with_pid_uses_dashboard_when_reachable() {
        let temp = TempDir::new().expect("test should create temp dir");
        let cli = test_cli(&temp);
        let (addr, handle) = start_one_shot_json_server(r#"{"agent_id":"ag-test"}"#);
        std::fs::write(
            &cli.agent_config,
            format!("[dashboard]\nbind = \"http://{addr}\"\n"),
        )
        .expect("test should write agent config");

        assert!(cmd_agent(
            &cli,
            Some(&AgentCommand::Connect {
                pid: Some(std::process::id()),
                name: None,
                label: None,
            }),
        )
        .is_ok());

        let request = handle.join().expect("server thread should finish");
        assert!(request.contains("POST /api/agent-guard/connect"));
        assert!(!cli.data_dir.join("agent-connections.jsonl").exists());
    }

    #[test]
    fn cmd_agent_disconnect_is_non_fatal_when_dashboard_unreachable() {
        let temp = TempDir::new().expect("test should create temp dir");
        let cli = test_cli(&temp);
        std::fs::write(
            &cli.agent_config,
            r#"[dashboard]
bind = "http://127.0.0.1:1"
"#,
        )
        .expect("test should write agent config");

        assert!(cmd_agent(
            &cli,
            Some(&AgentCommand::Disconnect {
                id: "ag-0001".to_string(),
            }),
        )
        .is_ok());
    }

    #[test]
    fn cmd_agent_disconnect_posts_to_dashboard_when_reachable() {
        let temp = TempDir::new().expect("test should create temp dir");
        let cli = test_cli(&temp);
        let (addr, handle) = start_one_shot_json_server(r#"{}"#);
        std::fs::write(
            &cli.agent_config,
            format!("[dashboard]\nbind = \"http://{addr}\"\n"),
        )
        .expect("test should write agent config");

        assert!(cmd_agent(
            &cli,
            Some(&AgentCommand::Disconnect {
                id: "ag-0001".to_string(),
            }),
        )
        .is_ok());

        let request = handle.join().expect("server thread should finish");
        assert!(request.contains("POST /api/agent-guard/disconnect"));
    }
}
