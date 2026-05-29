//! Spec 056 Phase 3a: stateless virtual skill implementations.
//!
//! Phase 2 recognised the seven virtual skills but returned
//! [`StepStatus::Deferred`] for all of them. This module implements the
//! four that need nothing beyond what [`RegistryStepExecutor`] already
//! carries (registry, trusted_ips, dry_run, host, data_dir, base
//! incident):
//!
//! - `wait` — pause via [`tokio::time::sleep`] before the next step.
//! - `emit_metric` — bump a process-global named counter
//!   ([`crate::telemetry::emit_counter`]) so operators can measure
//!   playbook hit-rate per host.
//! - `block_subnet` — block a whole CIDR by enumerating its host
//!   addresses and routing **each one** through the same
//!   [`crate::skill_gate`] floor + `block-ip-xdp` backend a single
//!   `block_ip_*` step uses. Bounded so a wide prefix cannot flood the
//!   XDP map.
//! - `open_ticket` — POST to a ticketing system (jira / github /
//!   generic_webhook). Templating (`{trigger.X}` / `${env:VAR}`) already
//!   ran on the args before dispatch, so secrets arrive resolved.
//!
//! The three state-coupled skills (`route_alert`, `capture_pcap`,
//! `set_tag`) still return `Deferred` here; Phase 3b wires them once the
//! executor can reach the agent's notification / pcap / attacker-intel
//! subsystems.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use tracing::{info, warn};

use super::executor::{RegistryStepExecutor, StepRunResult, StepStatus};
use crate::{skill_gate, skills};

/// Hard cap on how many host addresses `block_subnet` will enumerate.
/// A `/24` (256 addresses) is the widest IPv4 subnet a single step may
/// block; a `/120` is the IPv6 equivalent. Anything broader is refused
/// so a fat-fingered `prefix_len: 8` cannot push 16M keys into the XDP
/// map. Operators who genuinely need a wider block stage multiple steps.
const MAX_SUBNET_HOSTS: u32 = 256;

impl RegistryStepExecutor<'_> {
    /// Dispatch a Phase-3a virtual skill. Returns `Deferred` for the
    /// Phase-3b skills so a playbook using them still loads and the rest
    /// of its steps run.
    pub(super) async fn dispatch_virtual(
        &self,
        skill: &str,
        args: &serde_yaml::Value,
        primary_ip: Option<&str>,
    ) -> StepRunResult {
        match skill {
            "wait" => run_wait(args).await,
            "emit_metric" => run_emit_metric(args),
            "block_subnet" => self.run_block_subnet(args, primary_ip).await,
            "open_ticket" => run_open_ticket(args).await,
            // Phase 3b: needs &mut AgentState subsystems.
            "route_alert" | "capture_pcap" | "set_tag" => StepRunResult {
                status: StepStatus::Deferred,
                message: format!("virtual skill '{skill}' lands in Phase 3b"),
            },
            other => StepRunResult {
                status: StepStatus::Failed,
                message: format!("unknown virtual skill '{other}'"),
            },
        }
    }

    /// `block_subnet`: derive the CIDR from the primary IP + `prefix_len`,
    /// then gate + block each host address through the existing
    /// `block-ip-xdp` skill. Gating per host (not per network address)
    /// means a cloud-safelisted or operator-trusted IP inside the range
    /// is skipped rather than blocked — the safety floor holds at subnet
    /// granularity exactly as it does for a single block.
    async fn run_block_subnet(
        &self,
        args: &serde_yaml::Value,
        primary_ip: Option<&str>,
    ) -> StepRunResult {
        let arg_ip = args.get("target_ip").and_then(|v| v.as_str());
        let Some(base_ip) = arg_ip.or(primary_ip) else {
            return StepRunResult {
                status: StepStatus::Failed,
                message: "block_subnet: no target IP in incident or args".to_string(),
            };
        };
        let Ok(ip) = base_ip.parse::<IpAddr>() else {
            return StepRunResult {
                status: StepStatus::Failed,
                message: format!("block_subnet: '{base_ip}' is not a valid IP"),
            };
        };

        let hosts = match enumerate_subnet(
            ip,
            args.get("prefix_len").and_then(serde_yaml::Value::as_u64),
        ) {
            Ok(h) => h,
            Err(msg) => {
                return StepRunResult {
                    status: StepStatus::Failed,
                    message: format!("block_subnet: {msg}"),
                }
            }
        };

        let Some(skill) = self.registry.get("block-ip-xdp") else {
            return StepRunResult {
                status: StepStatus::Failed,
                message: "block_subnet: block-ip-xdp skill not registered".to_string(),
            };
        };

        let duration_secs = args
            .get("ttl_secs")
            .and_then(serde_yaml::Value::as_u64)
            .or_else(|| {
                args.get("duration_secs")
                    .and_then(serde_yaml::Value::as_u64)
            });

        let (mut blocked, mut gated, mut failed) = (0u32, 0u32, 0u32);
        let mut first_failure: Option<String> = None;
        for host in &hosts {
            let host_s = host.to_string();
            match skill_gate::gate_block_ip(&host_s, self.trusted_ips) {
                Ok(gate) => {
                    let ctx = skills::SkillContext {
                        incident: self.base_incident.clone(),
                        target_ip: Some(host_s.clone()),
                        target_user: None,
                        target_container: None,
                        duration_secs,
                        host: self.host.clone(),
                        data_dir: self.data_dir.clone(),
                        honeypot: self.honeypot.clone(),
                        ai_provider: self.ai_provider.clone(),
                    };
                    let r = skill_gate::execute_block_skill_gated(skill, &ctx, self.dry_run, &gate)
                        .await;
                    if r.success {
                        blocked += 1;
                    } else {
                        failed += 1;
                        first_failure.get_or_insert(r.message);
                    }
                }
                Err(_) => gated += 1,
            }
        }

        // A failed XDP insert (e.g. map missing) is a hard failure so the
        // step's retry / on_error policy applies. An all-gated subnet is a
        // legitimate no-op (every host was trusted / cloud-safelisted).
        if failed > 0 {
            StepRunResult {
                status: StepStatus::Failed,
                message: format!(
                    "block_subnet {base_ip}: {blocked} blocked, {gated} gated, {failed} failed (first: {})",
                    first_failure.unwrap_or_default()
                ),
            }
        } else {
            StepRunResult {
                status: StepStatus::Success,
                message: format!(
                    "block_subnet {base_ip}: {blocked} blocked, {gated} gated out of {} hosts",
                    hosts.len()
                ),
            }
        }
    }
}

/// Expand `ip`'s enclosing CIDR (default `/24` v4, `/120` v6) into its
/// host addresses, refusing prefixes wider than [`MAX_SUBNET_HOSTS`].
fn enumerate_subnet(ip: IpAddr, prefix_len: Option<u64>) -> Result<Vec<IpAddr>, String> {
    match ip {
        IpAddr::V4(v4) => {
            let p = prefix_len.unwrap_or(24);
            if p > 32 {
                return Err(format!("prefix_len {p} out of range for IPv4 (max 32)"));
            }
            let host_bits = 32 - p as u32;
            if host_bits >= 32 || (1u64 << host_bits) > MAX_SUBNET_HOSTS as u64 {
                return Err(format!(
                    "prefix_len {p} too wide (> {MAX_SUBNET_HOSTS} hosts); narrow it"
                ));
            }
            let mask: u32 = if p == 0 { 0 } else { u32::MAX << host_bits };
            let base = u32::from(v4) & mask;
            let count = 1u32 << host_bits;
            Ok((0..count)
                .map(|i| IpAddr::V4(Ipv4Addr::from(base + i)))
                .collect())
        }
        IpAddr::V6(v6) => {
            let p = prefix_len.unwrap_or(120);
            if p > 128 {
                return Err(format!("prefix_len {p} out of range for IPv6 (max 128)"));
            }
            let host_bits = 128 - p as u32;
            if host_bits >= 128 || (1u128 << host_bits) > MAX_SUBNET_HOSTS as u128 {
                return Err(format!(
                    "prefix_len {p} too wide (> {MAX_SUBNET_HOSTS} hosts); narrow it"
                ));
            }
            let mask: u128 = if p == 0 { 0 } else { u128::MAX << host_bits };
            let base = u128::from(v6) & mask;
            let count = 1u128 << host_bits;
            Ok((0..count)
                .map(|i| IpAddr::V6(Ipv6Addr::from(base + i)))
                .collect())
        }
    }
}

/// `wait`: sleep for `secs` (or `ms`). The executor already wraps every
/// dispatch in `tokio::time::timeout(leaf.timeout_secs)`, so a `wait`
/// longer than the step's `timeout_secs` (default 30) is killed and
/// marked failed — operators must raise `timeout_secs` for long pauses.
/// Capped at one hour regardless so a typo cannot hang a step until the
/// timeout fires.
async fn run_wait(args: &serde_yaml::Value) -> StepRunResult {
    let ms = match wait_ms_from_args(args) {
        Ok(ms) => ms,
        Err(msg) => {
            return StepRunResult {
                status: StepStatus::Failed,
                message: msg,
            }
        }
    };
    tokio::time::sleep(Duration::from_millis(ms)).await;
    StepRunResult {
        status: StepStatus::Success,
        message: format!("waited {ms}ms"),
    }
}

/// Resolve + clamp the wait duration from args. Pure so the cap is
/// unit-testable without actually sleeping (a test that exercised the
/// clamp through `run_wait` would block for the full hour).
fn wait_ms_from_args(args: &serde_yaml::Value) -> Result<u64, String> {
    const MAX_MS: u64 = 3_600_000;
    let ms = match (
        args.get("ms").and_then(serde_yaml::Value::as_u64),
        args.get("secs")
            .or_else(|| args.get("seconds"))
            .or_else(|| args.get("duration_secs"))
            .and_then(serde_yaml::Value::as_u64),
    ) {
        (Some(ms), _) => ms,
        (None, Some(secs)) => secs.saturating_mul(1000),
        (None, None) => return Err("wait: missing 'secs' or 'ms' argument".to_string()),
    };
    Ok(ms.min(MAX_MS))
}

/// `emit_metric`: bump a process-global named counter. `name` is
/// required; `value` (alias `by`) defaults to 1.
fn run_emit_metric(args: &serde_yaml::Value) -> StepRunResult {
    let Some(name) = args.get("name").and_then(|v| v.as_str()) else {
        return StepRunResult {
            status: StepStatus::Failed,
            message: "emit_metric: missing 'name' argument".to_string(),
        };
    };
    if name.is_empty() {
        return StepRunResult {
            status: StepStatus::Failed,
            message: "emit_metric: 'name' is empty".to_string(),
        };
    }
    let by = args
        .get("value")
        .or_else(|| args.get("by"))
        .and_then(serde_yaml::Value::as_u64)
        .unwrap_or(1);
    let total = crate::telemetry::emit_counter(name, by);
    info!(metric = name, by, total, "playbook emit_metric");
    StepRunResult {
        status: StepStatus::Success,
        message: format!("metric {name} += {by} (total {total})"),
    }
}

/// `open_ticket`: POST to a ticketing backend. Args are already
/// interpolated, so `${env:JIRA_TOKEN}` and `{trigger.X}` arrive as
/// resolved strings.
async fn run_open_ticket(args: &serde_yaml::Value) -> StepRunResult {
    let system = args
        .get("system")
        .or_else(|| args.get("adapter"))
        .and_then(|v| v.as_str())
        .unwrap_or("generic_webhook");
    let timeout_secs = args
        .get("timeout_secs")
        .and_then(serde_yaml::Value::as_u64)
        .unwrap_or(15)
        .clamp(1, 120);
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(timeout_secs))
        .user_agent("innerwarden-playbook")
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            return StepRunResult {
                status: StepStatus::Failed,
                message: format!("open_ticket: http client build failed: {e}"),
            }
        }
    };

    match system {
        "generic_webhook" => open_ticket_generic(&client, args).await,
        "jira" => open_ticket_jira(&client, args).await,
        "github" => open_ticket_github(&client, args).await,
        other => StepRunResult {
            status: StepStatus::Failed,
            message: format!("open_ticket: unknown system '{other}' (jira|github|generic_webhook)"),
        },
    }
}

fn str_arg<'a>(args: &'a serde_yaml::Value, key: &str) -> Option<&'a str> {
    args.get(key)
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
}

/// Map a finished HTTP request to a step result. `2xx` is success;
/// anything else (including transport errors) is a hard failure so the
/// step's retry / on_error policy applies.
fn http_result(system: &str, resp: reqwest::Result<reqwest::Response>) -> StepRunResult {
    match resp {
        Ok(r) => {
            let status = r.status();
            if status.is_success() {
                StepRunResult {
                    status: StepStatus::Success,
                    message: format!("open_ticket {system}: HTTP {}", status.as_u16()),
                }
            } else {
                StepRunResult {
                    status: StepStatus::Failed,
                    message: format!("open_ticket {system}: HTTP {}", status.as_u16()),
                }
            }
        }
        Err(e) => StepRunResult {
            status: StepStatus::Failed,
            message: format!("open_ticket {system}: request failed: {e}"),
        },
    }
}

async fn open_ticket_generic(client: &reqwest::Client, args: &serde_yaml::Value) -> StepRunResult {
    let Some(url) = str_arg(args, "url") else {
        return StepRunResult {
            status: StepStatus::Failed,
            message: "open_ticket generic_webhook: missing 'url'".to_string(),
        };
    };
    let body = args
        .get("body")
        .map(|v| serde_json::to_value(v).unwrap_or(serde_json::Value::Null))
        .unwrap_or(serde_json::Value::Null);
    let mut req = client.post(url).json(&body);
    if let Some(serde_yaml::Value::Mapping(headers)) = args.get("headers") {
        for (k, v) in headers {
            if let (Some(k), Some(v)) = (k.as_str(), v.as_str()) {
                req = req.header(k, v);
            }
        }
    }
    http_result("generic_webhook", req.send().await)
}

async fn open_ticket_jira(client: &reqwest::Client, args: &serde_yaml::Value) -> StepRunResult {
    let Some(base_url) = str_arg(args, "base_url") else {
        return StepRunResult {
            status: StepStatus::Failed,
            message: "open_ticket jira: missing 'base_url'".to_string(),
        };
    };
    let Some(project) = str_arg(args, "project") else {
        return StepRunResult {
            status: StepStatus::Failed,
            message: "open_ticket jira: missing 'project'".to_string(),
        };
    };
    let Some(token) = str_arg(args, "token") else {
        return StepRunResult {
            status: StepStatus::Failed,
            message: "open_ticket jira: missing 'token' (set via ${env:JIRA_TOKEN})".to_string(),
        };
    };
    let summary = str_arg(args, "summary")
        .or_else(|| str_arg(args, "title"))
        .unwrap_or("InnerWarden incident");
    let description = str_arg(args, "description").unwrap_or("");
    let issue_type = str_arg(args, "issue_type").unwrap_or("Task");

    let payload = serde_json::json!({
        "fields": {
            "project": { "key": project },
            "summary": summary,
            "description": description,
            "issuetype": { "name": issue_type },
        }
    });
    let url = format!("{}/rest/api/2/issue", base_url.trim_end_matches('/'));
    // Jira Cloud uses Basic (email:token); Server/DC uses Bearer. `email`
    // present -> Basic, else Bearer.
    let mut req = client.post(&url).json(&payload);
    req = match str_arg(args, "email") {
        Some(email) => req.basic_auth(email, Some(token)),
        None => req.bearer_auth(token),
    };
    http_result("jira", req.send().await)
}

async fn open_ticket_github(client: &reqwest::Client, args: &serde_yaml::Value) -> StepRunResult {
    let Some(repo) = str_arg(args, "repo") else {
        return StepRunResult {
            status: StepStatus::Failed,
            message: "open_ticket github: missing 'repo' (owner/name)".to_string(),
        };
    };
    let Some(title) = str_arg(args, "title") else {
        return StepRunResult {
            status: StepStatus::Failed,
            message: "open_ticket github: missing 'title'".to_string(),
        };
    };
    let Some(token) = str_arg(args, "token") else {
        return StepRunResult {
            status: StepStatus::Failed,
            message: "open_ticket github: missing 'token' (set via ${env:GITHUB_TOKEN})"
                .to_string(),
        };
    };
    let body = str_arg(args, "body").unwrap_or("");
    let mut payload = serde_json::json!({ "title": title, "body": body });
    if let Some(serde_yaml::Value::Sequence(labels)) = args.get("labels") {
        let labels: Vec<String> = labels
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect();
        if !labels.is_empty() {
            payload["labels"] = serde_json::json!(labels);
        }
    }
    // `api_base` lets tests point at a mock server; defaults to GitHub.
    let api_base = str_arg(args, "api_base").unwrap_or("https://api.github.com");
    let url = format!("{}/repos/{repo}/issues", api_base.trim_end_matches('/'));
    let req = client
        .post(&url)
        .bearer_auth(token)
        .header("Accept", "application/vnd.github+json");
    let r = http_result("github", req.send().await);
    if r.status == StepStatus::Failed {
        warn!(repo, "open_ticket github: issue creation failed");
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- enumerate_subnet ----------------------------------------------

    #[test]
    fn enumerate_v4_default_24_is_256_hosts() {
        let hosts = enumerate_subnet("203.0.113.42".parse().unwrap(), None).unwrap();
        assert_eq!(hosts.len(), 256);
        assert_eq!(hosts[0].to_string(), "203.0.113.0");
        assert_eq!(hosts[255].to_string(), "203.0.113.255");
    }

    #[test]
    fn enumerate_v4_single_host_32() {
        let hosts = enumerate_subnet("203.0.113.42".parse().unwrap(), Some(32)).unwrap();
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].to_string(), "203.0.113.42");
    }

    #[test]
    fn enumerate_v4_too_wide_refused() {
        let err = enumerate_subnet("10.0.0.1".parse().unwrap(), Some(8)).unwrap_err();
        assert!(err.contains("too wide"), "got: {err}");
        let err2 = enumerate_subnet("10.0.0.1".parse().unwrap(), Some(23)).unwrap_err();
        assert!(err2.contains("too wide"), "got: {err2}");
    }

    #[test]
    fn enumerate_v4_out_of_range_refused() {
        let err = enumerate_subnet("10.0.0.1".parse().unwrap(), Some(33)).unwrap_err();
        assert!(err.contains("out of range"), "got: {err}");
    }

    #[test]
    fn enumerate_v6_default_120() {
        let hosts = enumerate_subnet("2001:db8::ff".parse().unwrap(), None).unwrap();
        assert_eq!(hosts.len(), 256);
        assert_eq!(hosts[0].to_string(), "2001:db8::");
    }

    #[test]
    fn enumerate_v6_too_wide_refused() {
        let err = enumerate_subnet("2001:db8::1".parse().unwrap(), Some(64)).unwrap_err();
        assert!(err.contains("too wide"), "got: {err}");
    }

    // ---- wait -----------------------------------------------------------

    #[tokio::test]
    async fn wait_ms_succeeds() {
        let mut m = serde_yaml::Mapping::new();
        m.insert(
            serde_yaml::Value::String("ms".to_string()),
            serde_yaml::Value::Number(5.into()),
        );
        let r = run_wait(&serde_yaml::Value::Mapping(m)).await;
        assert_eq!(r.status, StepStatus::Success);
        assert!(r.message.contains("5ms"), "got: {}", r.message);
    }

    #[test]
    fn wait_ms_clamped_to_one_hour() {
        // Exercise the cap on the PURE helper so the test never actually
        // sleeps the clamped hour (run_wait would block the suite).
        let mut m = serde_yaml::Mapping::new();
        m.insert(
            serde_yaml::Value::String("ms".to_string()),
            serde_yaml::Value::Number(9_999_999_999u64.into()),
        );
        assert_eq!(
            wait_ms_from_args(&serde_yaml::Value::Mapping(m)).unwrap(),
            3_600_000
        );
    }

    #[test]
    fn wait_secs_converts_to_ms() {
        let mut m = serde_yaml::Mapping::new();
        m.insert(
            serde_yaml::Value::String("secs".to_string()),
            serde_yaml::Value::Number(2.into()),
        );
        assert_eq!(
            wait_ms_from_args(&serde_yaml::Value::Mapping(m)).unwrap(),
            2000
        );
    }

    #[test]
    fn wait_missing_arg_errors() {
        let err = wait_ms_from_args(&serde_yaml::Value::Null).unwrap_err();
        assert!(err.contains("missing"), "got: {err}");
    }

    #[tokio::test]
    async fn wait_missing_arg_fails() {
        let r = run_wait(&serde_yaml::Value::Null).await;
        assert_eq!(r.status, StepStatus::Failed);
        assert!(r.message.contains("missing"), "got: {}", r.message);
    }

    // ---- emit_metric ----------------------------------------------------

    #[test]
    fn emit_metric_increments_named_counter() {
        let name = "test.emit_metric.counter.alpha";
        let before = crate::telemetry::playbook_metric_value(name);
        let mut m = serde_yaml::Mapping::new();
        m.insert(
            serde_yaml::Value::String("name".to_string()),
            serde_yaml::Value::String(name.to_string()),
        );
        m.insert(
            serde_yaml::Value::String("value".to_string()),
            serde_yaml::Value::Number(3.into()),
        );
        let r = run_emit_metric(&serde_yaml::Value::Mapping(m));
        assert_eq!(r.status, StepStatus::Success);
        assert_eq!(
            crate::telemetry::playbook_metric_value(name),
            before + 3,
            "counter must advance by the supplied value"
        );
    }

    #[test]
    fn emit_metric_defaults_to_one() {
        let name = "test.emit_metric.counter.beta";
        let mut m = serde_yaml::Mapping::new();
        m.insert(
            serde_yaml::Value::String("name".to_string()),
            serde_yaml::Value::String(name.to_string()),
        );
        let r = run_emit_metric(&serde_yaml::Value::Mapping(m));
        assert_eq!(r.status, StepStatus::Success);
        assert_eq!(crate::telemetry::playbook_metric_value(name), 1);
    }

    #[test]
    fn emit_metric_missing_name_fails() {
        let r = run_emit_metric(&serde_yaml::Value::Null);
        assert_eq!(r.status, StepStatus::Failed);
        assert!(r.message.contains("missing 'name'"), "got: {}", r.message);
    }

    // ---- open_ticket ----------------------------------------------------

    fn yaml(pairs: &[(&str, &str)]) -> serde_yaml::Value {
        let mut m = serde_yaml::Mapping::new();
        for (k, v) in pairs {
            m.insert(
                serde_yaml::Value::String(k.to_string()),
                serde_yaml::Value::String(v.to_string()),
            );
        }
        serde_yaml::Value::Mapping(m)
    }

    #[tokio::test]
    async fn open_ticket_generic_webhook_success() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("POST", "/hook")
            .with_status(200)
            .create_async()
            .await;
        let args = yaml(&[
            ("system", "generic_webhook"),
            ("url", &format!("{}/hook", server.url())),
        ]);
        let r = run_open_ticket(&args).await;
        mock.assert_async().await;
        assert_eq!(r.status, StepStatus::Success, "got: {}", r.message);
    }

    #[tokio::test]
    async fn open_ticket_generic_webhook_server_error_fails() {
        let mut server = mockito::Server::new_async().await;
        let _mock = server
            .mock("POST", "/hook")
            .with_status(500)
            .create_async()
            .await;
        let args = yaml(&[
            ("system", "generic_webhook"),
            ("url", &format!("{}/hook", server.url())),
        ]);
        let r = run_open_ticket(&args).await;
        assert_eq!(r.status, StepStatus::Failed);
        assert!(r.message.contains("500"), "got: {}", r.message);
    }

    #[tokio::test]
    async fn open_ticket_generic_webhook_missing_url_fails() {
        let args = yaml(&[("system", "generic_webhook")]);
        let r = run_open_ticket(&args).await;
        assert_eq!(r.status, StepStatus::Failed);
        assert!(r.message.contains("missing 'url'"), "got: {}", r.message);
    }

    #[tokio::test]
    async fn open_ticket_jira_success_basic_auth() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("POST", "/rest/api/2/issue")
            .match_header(
                "authorization",
                mockito::Matcher::Regex("Basic .*".to_string()),
            )
            .with_status(201)
            .create_async()
            .await;
        let args = yaml(&[
            ("system", "jira"),
            ("base_url", &server.url()),
            ("project", "SOC"),
            ("token", "secret-token"),
            ("email", "soc@example.com"),
            ("summary", "test"),
        ]);
        let r = run_open_ticket(&args).await;
        mock.assert_async().await;
        assert_eq!(r.status, StepStatus::Success, "got: {}", r.message);
    }

    #[tokio::test]
    async fn open_ticket_jira_missing_token_fails_without_network() {
        let args = yaml(&[
            ("system", "jira"),
            ("base_url", "http://127.0.0.1:1"),
            ("project", "SOC"),
        ]);
        let r = run_open_ticket(&args).await;
        assert_eq!(r.status, StepStatus::Failed);
        assert!(r.message.contains("missing 'token'"), "got: {}", r.message);
    }

    #[tokio::test]
    async fn open_ticket_github_success() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("POST", "/repos/acme/soc/issues")
            .match_header("authorization", "Bearer gh-token")
            .with_status(201)
            .create_async()
            .await;
        let args = yaml(&[
            ("system", "github"),
            ("repo", "acme/soc"),
            ("title", "intrusion"),
            ("token", "gh-token"),
            ("api_base", &server.url()),
        ]);
        let r = run_open_ticket(&args).await;
        mock.assert_async().await;
        assert_eq!(r.status, StepStatus::Success, "got: {}", r.message);
    }

    #[tokio::test]
    async fn open_ticket_github_missing_token_fails() {
        let args = yaml(&[("system", "github"), ("repo", "acme/soc"), ("title", "x")]);
        let r = run_open_ticket(&args).await;
        assert_eq!(r.status, StepStatus::Failed);
        assert!(r.message.contains("missing 'token'"), "got: {}", r.message);
    }

    #[tokio::test]
    async fn open_ticket_unknown_system_fails() {
        let args = yaml(&[("system", "servicenow")]);
        let r = run_open_ticket(&args).await;
        assert_eq!(r.status, StepStatus::Failed);
        assert!(r.message.contains("unknown system"), "got: {}", r.message);
    }

    #[tokio::test]
    async fn open_ticket_network_error_is_failure() {
        // Port 1 is unbindable for a normal service -> transport error.
        let args = yaml(&[
            ("system", "generic_webhook"),
            ("url", "http://127.0.0.1:1/hook"),
            ("timeout_secs", "1"),
        ]);
        let r = run_open_ticket(&args).await;
        assert_eq!(r.status, StepStatus::Failed);
        assert!(r.message.contains("request failed"), "got: {}", r.message);
    }

    #[tokio::test]
    async fn open_ticket_jira_bearer_auth_when_no_email() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("POST", "/rest/api/2/issue")
            .match_header("authorization", "Bearer dc-token")
            .with_status(201)
            .create_async()
            .await;
        let args = yaml(&[
            ("system", "jira"),
            ("base_url", &server.url()),
            ("project", "SOC"),
            ("token", "dc-token"),
        ]);
        let r = run_open_ticket(&args).await;
        mock.assert_async().await;
        assert_eq!(r.status, StepStatus::Success, "got: {}", r.message);
    }

    #[tokio::test]
    async fn open_ticket_jira_missing_base_url_fails() {
        let args = yaml(&[("system", "jira"), ("project", "SOC"), ("token", "t")]);
        let r = run_open_ticket(&args).await;
        assert_eq!(r.status, StepStatus::Failed);
        assert!(r.message.contains("base_url"), "got: {}", r.message);
    }

    #[tokio::test]
    async fn open_ticket_jira_missing_project_fails() {
        let args = yaml(&[("system", "jira"), ("base_url", "http://x"), ("token", "t")]);
        let r = run_open_ticket(&args).await;
        assert_eq!(r.status, StepStatus::Failed);
        assert!(r.message.contains("project"), "got: {}", r.message);
    }

    #[tokio::test]
    async fn open_ticket_github_with_labels_and_body() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("POST", "/repos/acme/soc/issues")
            .with_status(201)
            .create_async()
            .await;
        let mut m = serde_yaml::Mapping::new();
        for (k, v) in [
            ("system", "github"),
            ("repo", "acme/soc"),
            ("title", "intrusion"),
            ("body", "details here"),
            ("token", "gh-token"),
            ("api_base", &server.url()),
        ] {
            m.insert(
                serde_yaml::Value::String(k.to_string()),
                serde_yaml::Value::String(v.to_string()),
            );
        }
        m.insert(
            serde_yaml::Value::String("labels".to_string()),
            serde_yaml::Value::Sequence(vec![
                serde_yaml::Value::String("security".to_string()),
                serde_yaml::Value::String("p1".to_string()),
            ]),
        );
        let r = run_open_ticket(&serde_yaml::Value::Mapping(m)).await;
        mock.assert_async().await;
        assert_eq!(r.status, StepStatus::Success, "got: {}", r.message);
    }

    #[tokio::test]
    async fn open_ticket_github_missing_repo_fails() {
        let args = yaml(&[("system", "github"), ("title", "x"), ("token", "t")]);
        let r = run_open_ticket(&args).await;
        assert_eq!(r.status, StepStatus::Failed);
        assert!(r.message.contains("missing 'repo'"), "got: {}", r.message);
    }

    #[tokio::test]
    async fn open_ticket_github_missing_title_fails() {
        let args = yaml(&[("system", "github"), ("repo", "a/b"), ("token", "t")]);
        let r = run_open_ticket(&args).await;
        assert_eq!(r.status, StepStatus::Failed);
        assert!(r.message.contains("missing 'title'"), "got: {}", r.message);
    }

    // ---- block_subnet (via a real RegistryStepExecutor, dry-run) --------

    fn exec_with<'a>(
        reg: &'a skills::SkillRegistry,
        trusted: &'a [String],
        ip: &str,
    ) -> RegistryStepExecutor<'a> {
        RegistryStepExecutor {
            registry: reg,
            trusted_ips: trusted,
            dry_run: true,
            host: "h".to_string(),
            data_dir: std::env::temp_dir(),
            base_incident: crate::tests::test_incident(ip),
            honeypot: skills::HoneypotRuntimeConfig::default(),
            ai_provider: None,
        }
    }

    fn subnet_args(prefix_len: u64) -> serde_yaml::Value {
        let mut m = serde_yaml::Mapping::new();
        m.insert(
            serde_yaml::Value::String("prefix_len".to_string()),
            serde_yaml::Value::Number(prefix_len.into()),
        );
        serde_yaml::Value::Mapping(m)
    }

    #[tokio::test]
    async fn block_subnet_blocks_clean_hosts_in_dry_run() {
        let reg = skills::SkillRegistry::default_builtin();
        let exec = exec_with(&reg, &[], "198.51.100.5");
        // /30 = 4 clean hosts -> all pass the gate -> 4 dry-run blocks.
        let r = exec
            .run_block_subnet(&subnet_args(30), Some("198.51.100.5"))
            .await;
        assert_eq!(r.status, StepStatus::Success, "got: {}", r.message);
        assert!(r.message.contains("4 blocked"), "got: {}", r.message);
    }

    #[tokio::test]
    async fn block_subnet_all_gated_is_success_noop() {
        let reg = skills::SkillRegistry::default_builtin();
        let trusted = vec!["203.0.113.0/24".to_string()];
        let exec = exec_with(&reg, &trusted, "203.0.113.5");
        let r = exec
            .run_block_subnet(&subnet_args(30), Some("203.0.113.5"))
            .await;
        assert_eq!(r.status, StepStatus::Success, "got: {}", r.message);
        assert!(r.message.contains("0 blocked"), "got: {}", r.message);
        assert!(r.message.contains("4 gated"), "got: {}", r.message);
    }

    #[tokio::test]
    async fn block_subnet_no_target_ip_fails() {
        let reg = skills::SkillRegistry::default_builtin();
        let exec = exec_with(&reg, &[], "198.51.100.5");
        let r = exec.run_block_subnet(&serde_yaml::Value::Null, None).await;
        assert_eq!(r.status, StepStatus::Failed);
        assert!(r.message.contains("no target IP"), "got: {}", r.message);
    }

    #[tokio::test]
    async fn block_subnet_invalid_ip_fails() {
        let reg = skills::SkillRegistry::default_builtin();
        let exec = exec_with(&reg, &[], "198.51.100.5");
        let mut m = serde_yaml::Mapping::new();
        m.insert(
            serde_yaml::Value::String("target_ip".to_string()),
            serde_yaml::Value::String("not-an-ip".to_string()),
        );
        let r = exec
            .run_block_subnet(&serde_yaml::Value::Mapping(m), None)
            .await;
        assert_eq!(r.status, StepStatus::Failed);
        assert!(r.message.contains("not a valid IP"), "got: {}", r.message);
    }

    #[tokio::test]
    async fn block_subnet_too_wide_prefix_fails() {
        let reg = skills::SkillRegistry::default_builtin();
        let exec = exec_with(&reg, &[], "10.0.0.5");
        let r = exec
            .run_block_subnet(&subnet_args(8), Some("10.0.0.5"))
            .await;
        assert_eq!(r.status, StepStatus::Failed);
        assert!(r.message.contains("too wide"), "got: {}", r.message);
    }

    #[tokio::test]
    async fn block_subnet_missing_backend_skill_fails() {
        let reg = skills::SkillRegistry::empty();
        let exec = exec_with(&reg, &[], "198.51.100.5");
        let r = exec
            .run_block_subnet(&subnet_args(32), Some("198.51.100.5"))
            .await;
        assert_eq!(r.status, StepStatus::Failed);
        assert!(
            r.message.contains("block-ip-xdp skill not registered"),
            "got: {}",
            r.message
        );
    }

    // ---- dispatch_virtual routing --------------------------------------

    #[tokio::test]
    async fn dispatch_virtual_routes_each_skill() {
        let reg = skills::SkillRegistry::default_builtin();
        let exec = exec_with(&reg, &[], "198.51.100.5");

        // wait
        let mut w = serde_yaml::Mapping::new();
        w.insert(
            serde_yaml::Value::String("ms".to_string()),
            serde_yaml::Value::Number(1.into()),
        );
        assert_eq!(
            exec.dispatch_virtual("wait", &serde_yaml::Value::Mapping(w), None)
                .await
                .status,
            StepStatus::Success
        );

        // emit_metric
        let mut em = serde_yaml::Mapping::new();
        em.insert(
            serde_yaml::Value::String("name".to_string()),
            serde_yaml::Value::String("test.dispatch.metric".to_string()),
        );
        assert_eq!(
            exec.dispatch_virtual("emit_metric", &serde_yaml::Value::Mapping(em), None)
                .await
                .status,
            StepStatus::Success
        );

        // block_subnet
        assert_eq!(
            exec.dispatch_virtual("block_subnet", &subnet_args(32), Some("198.51.100.5"))
                .await
                .status,
            StepStatus::Success
        );

        // Phase 3b skills -> Deferred
        for s in ["route_alert", "capture_pcap", "set_tag"] {
            let r = exec
                .dispatch_virtual(s, &serde_yaml::Value::Null, None)
                .await;
            assert_eq!(r.status, StepStatus::Deferred, "{s} should defer");
            assert!(r.message.contains("Phase 3b"), "got: {}", r.message);
        }

        // unknown virtual skill -> Failed
        let r = exec
            .dispatch_virtual("nope", &serde_yaml::Value::Null, None)
            .await;
        assert_eq!(r.status, StepStatus::Failed);
        assert!(
            r.message.contains("unknown virtual skill"),
            "got: {}",
            r.message
        );
    }
}
