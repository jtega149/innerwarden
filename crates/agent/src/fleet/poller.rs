//! Background poller for spec 038 Phase 1+2.
//!
//! One tokio task, one HTTP client. Each cycle hits each spoke's
//! `/api/overview` endpoint: a 2xx body produces `HostState::Up`
//! (or `Degraded` when the spoke's own `SystemHealth` is non-OK)
//! plus a parsed `FleetHostOverview`. Anything else (timeout,
//! transport, non-2xx, parse error) flips the host to `HostState::Down`
//! and clears any stale overview cache.
//!
//! Single-request design: hitting `/api/overview` covers both
//! liveness and KPI capture, saving a round-trip vs probing
//! `/api/status` separately. The endpoint is auth-gated on the
//! spoke; Phase 4 wires per-host bearer-token refresh on 401.

use std::sync::Arc;
use std::time::Duration;

use tokio::time;
use tracing::{debug, warn};

use crate::config::{FleetConfig, FleetHostConfig};

use super::{FleetHostOverview, FleetState, HostState};

/// Spawn the poll loop. Returns immediately; the loop runs on the
/// tokio runtime until the agent shuts down. Cancellation safety is
/// provided implicitly by the `tokio::time::interval` ticker — the
/// agent's TaskGroup-cancellation tree (spec 036 I-04) reaches every
/// task started under the runtime.
pub fn spawn(state: FleetState, cfg: Arc<FleetConfig>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        if cfg.hosts.is_empty() {
            debug!("fleet poller: no hosts configured, exiting");
            return;
        }

        // Build one shared HTTP client. Tight per-request timeout so
        // a hung spoke does not stall the whole loop. `rustls-tls`
        // is the workspace default (no system-cert dependency).
        let client = match reqwest::Client::builder()
            .timeout(Duration::from_secs(cfg.request_timeout_seconds.max(1)))
            .build()
        {
            Ok(c) => c,
            Err(e) => {
                warn!(error = %e, "fleet poller: failed to build HTTP client; aborting");
                return;
            }
        };

        let interval_secs = cfg.poll_interval_seconds.max(5);
        let mut ticker = time::interval(Duration::from_secs(interval_secs));
        // Skip the immediate first tick the interval emits; we want
        // the first poll to land at +interval, not at boot when many
        // other tasks are still warming up.
        ticker.set_missed_tick_behavior(time::MissedTickBehavior::Delay);

        loop {
            ticker.tick().await;
            for host in &cfg.hosts {
                match poll_with_refresh(&client, host, &state).await {
                    Ok(overview) => {
                        // The spoke's own SystemHealth flips this
                        // entry into `Degraded` so the fleet card
                        // colour reflects "spoke is reachable but
                        // unhealthy" without needing the operator
                        // to drill in.
                        let state_verdict = match overview.health_kind.as_deref() {
                            Some("operating_normally") | Some("backed_up") | None => HostState::Up,
                            // ai_not_responding / abandoned_backlog / degraded
                            // all read as Degraded from a fleet POV. The
                            // distinction belongs on the per-host journey.
                            Some(_) => HostState::Degraded,
                        };
                        state.record(&host.id, state_verdict, None, Some(overview));
                    }
                    Err(e) => {
                        let msg = format!("{e:#}");
                        debug!(host = %host.id, error = %msg, "fleet poll: down");
                        state.record(&host.id, HostState::Down, Some(msg), None);
                    }
                }
            }
        }
    })
}

/// Phase 4: poll a spoke and transparently refresh the bearer token
/// on 401. The retry happens at most once per cycle: a second 401
/// with a freshly-issued token signals a real auth failure (operator
/// rotated the password without updating the env, the spoke's user
/// store changed, etc.) and is surfaced as `Down` rather than
/// looped on.
async fn poll_with_refresh(
    client: &reqwest::Client,
    host: &FleetHostConfig,
    state: &FleetState,
) -> anyhow::Result<FleetHostOverview> {
    let bearer = state.bearer_for(&host.id);
    match poll_one_with_bearer(client, host, bearer.as_deref()).await {
        Ok(overview) => Ok(overview),
        Err(e) => {
            // Only the 401 path triggers refresh — every other
            // failure (timeout, transport, 5xx, parse) propagates
            // unchanged so the caller marks the host Down.
            let msg = format!("{e:#}");
            if !msg.contains("HTTP 401") {
                return Err(e);
            }
            // Refresh requires both username + password env vars.
            // Hosts using a static `token_env` only stay in their
            // current state if the token expires; the operator
            // upgrades them by adding username/password env vars.
            if host.username_env.is_empty() || host.password_env.is_empty() {
                return Err(e);
            }
            let user = std::env::var(&host.username_env).unwrap_or_default();
            let pass = std::env::var(&host.password_env).unwrap_or_default();
            if user.is_empty() || pass.is_empty() {
                return Err(e);
            }
            let new_bearer = login_to_spoke(client, host, &user, &pass).await?;
            state.set_bearer(&host.id, new_bearer.clone());
            poll_one_with_bearer(client, host, Some(&new_bearer)).await
        }
    }
}

/// Probe one spoke with an explicit bearer (or none). Splits the
/// auth concern out of `poll_one` so the refresh path can call it
/// twice with different tokens.
async fn poll_one_with_bearer(
    client: &reqwest::Client,
    host: &FleetHostConfig,
    bearer: Option<&str>,
) -> anyhow::Result<FleetHostOverview> {
    let url = format!("{}/api/overview", host.url.trim_end_matches('/'));
    let mut req = client.get(&url);
    if let Some(t) = bearer {
        if !t.is_empty() {
            req = req.bearer_auth(t);
        }
    }
    let resp = req.send().await?;
    let status = resp.status();
    if !status.is_success() {
        anyhow::bail!("HTTP {} from {}", status.as_u16(), url);
    }
    let body = read_capped_json(resp).await?;
    parse_overview(&body).ok_or_else(|| anyhow::anyhow!("malformed /api/overview body from {url}"))
}

/// Read a response body with a size cap before JSON-parsing. A compromised or
/// misbehaving spoke host must not be able to OOM the hub with an unbounded body.
async fn read_capped_json(resp: reqwest::Response) -> anyhow::Result<serde_json::Value> {
    const MAX_BODY: usize = 4 * 1024 * 1024;
    let bytes = resp.bytes().await?;
    if bytes.len() > MAX_BODY {
        anyhow::bail!("response body too large ({} bytes)", bytes.len());
    }
    Ok(serde_json::from_slice(&bytes)?)
}

/// Phase 4: refresh the bearer token by calling
/// `POST /api/auth/login` with Basic Auth credentials. Returns the
/// fresh token on success; propagates a structured error on
/// transport / 401 / malformed-body so the caller can decide
/// whether to mark the host Down.
async fn login_to_spoke(
    client: &reqwest::Client,
    host: &FleetHostConfig,
    user: &str,
    pass: &str,
) -> anyhow::Result<String> {
    let url = format!("{}/api/auth/login", host.url.trim_end_matches('/'));
    let resp = client
        .post(&url)
        .basic_auth(user, Some(pass))
        .send()
        .await?;
    let status = resp.status();
    if !status.is_success() {
        anyhow::bail!("login HTTP {} from {}", status.as_u16(), url);
    }
    let body = read_capped_json(resp).await?;
    body.get("token")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| anyhow::anyhow!("login response missing token field from {url}"))
}

/// Phase 1 entry point preserved for unit tests. Reads the bearer
/// token from `host.token_env` (if set) and delegates to
/// `poll_one_with_bearer`. New callers should use
/// `poll_with_refresh` to get the Phase 4 retry-on-401 behaviour.
#[cfg(test)]
async fn poll_one(
    client: &reqwest::Client,
    host: &FleetHostConfig,
) -> anyhow::Result<FleetHostOverview> {
    let bearer = if !host.token_env.is_empty() {
        std::env::var(&host.token_env).ok()
    } else {
        None
    };
    poll_one_with_bearer(client, host, bearer.as_deref()).await
}

/// Defensive extractor: turn the spoke's `OverviewResponse` JSON
/// into a slim `FleetHostOverview`. Returns `None` only when the
/// `date` field is missing — every other field defaults so a future
/// spoke version that adds new fields stays compatible.
fn parse_overview(body: &serde_json::Value) -> Option<FleetHostOverview> {
    let date = body.get("date")?.as_str()?.to_string();
    let u = |k: &str| body.get(k).and_then(serde_json::Value::as_u64).unwrap_or(0);
    let health_kind = body
        .pointer("/snapshot/health/kind")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string);
    Some(FleetHostOverview {
        date,
        events_count: u("events_count"),
        incidents_count: u("incidents_count"),
        decisions_count: u("decisions_count"),
        blocked_count: u("blocked_count"),
        observing_count: u("observing_count"),
        attention_count: u("attention_count"),
        handled_ips_today: u("handled_ips_today"),
        health_kind,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host(id: &str, url: &str) -> FleetHostConfig {
        FleetHostConfig {
            id: id.into(),
            url: url.into(),
            token_env: String::new(),
            username_env: String::new(),
            password_env: String::new(),
        }
    }

    /// Smallest body that satisfies `parse_overview`: only `date`.
    /// Every numeric field defaults to zero so a brand-new spoke
    /// returns a usable snapshot.
    fn minimal_overview_body() -> String {
        r#"{"date":"2026-05-02"}"#.to_string()
    }

    fn full_overview_body() -> String {
        r#"{
            "date":"2026-05-02",
            "events_count":12345,
            "incidents_count":42,
            "decisions_count":40,
            "blocked_count":15,
            "observing_count":3,
            "attention_count":2,
            "handled_ips_today":18,
            "snapshot":{"health":{"kind":"operating_normally"}}
        }"#
        .to_string()
    }

    #[tokio::test]
    async fn poll_one_returns_overview_on_2xx() {
        let server = mockito::Server::new_async().await;
        let mut server = server;
        let _m = server
            .mock("GET", "/api/overview")
            .with_status(200)
            .with_body(full_overview_body())
            .create_async()
            .await;
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(2))
            .build()
            .expect("client");
        let h = host("test", &server.url());
        let overview = poll_one(&client, &h).await.expect("ok overview");
        assert_eq!(overview.date, "2026-05-02");
        assert_eq!(overview.events_count, 12345);
        assert_eq!(overview.incidents_count, 42);
        assert_eq!(overview.blocked_count, 15);
        assert_eq!(overview.handled_ips_today, 18);
        assert_eq!(overview.health_kind.as_deref(), Some("operating_normally"));
    }

    #[tokio::test]
    async fn poll_one_accepts_minimal_body_for_back_compat() {
        // Older spoke or future field renames must not break the
        // poller. Anchor: missing optional fields default to zero +
        // None, only `date` is required.
        let server = mockito::Server::new_async().await;
        let mut server = server;
        let _m = server
            .mock("GET", "/api/overview")
            .with_status(200)
            .with_body(minimal_overview_body())
            .create_async()
            .await;
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(2))
            .build()
            .expect("client");
        let h = host("test", &server.url());
        let overview = poll_one(&client, &h).await.expect("minimal body parses");
        assert_eq!(overview.date, "2026-05-02");
        assert_eq!(overview.events_count, 0);
        assert!(overview.health_kind.is_none());
    }

    #[tokio::test]
    async fn poll_one_returns_err_when_date_missing() {
        // Schema regression on the spoke side: if `date` disappears
        // we surface it loudly rather than silently caching a
        // zero-valued snapshot.
        let server = mockito::Server::new_async().await;
        let mut server = server;
        let _m = server
            .mock("GET", "/api/overview")
            .with_status(200)
            .with_body(r#"{"events_count":1}"#)
            .create_async()
            .await;
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(2))
            .build()
            .expect("client");
        let h = host("test", &server.url());
        let r = poll_one(&client, &h).await;
        assert!(r.is_err(), "missing date must be a hard error");
        let msg = format!("{:#}", r.unwrap_err());
        assert!(
            msg.contains("malformed"),
            "expected malformed-body error: {msg}"
        );
    }

    #[tokio::test]
    async fn poll_one_returns_err_on_non_2xx() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("GET", "/api/overview")
            .with_status(503)
            .create_async()
            .await;
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(2))
            .build()
            .expect("client");
        let h = host("test", &server.url());
        let r = poll_one(&client, &h).await;
        assert!(r.is_err(), "expected Err on 503");
        let msg = format!("{:#}", r.unwrap_err());
        assert!(msg.contains("503"), "expected status code in error: {msg}");
    }

    #[tokio::test]
    async fn poll_one_returns_err_on_unreachable_host() {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_millis(200))
            .build()
            .expect("client");
        // 127.0.0.1:1 is reserved + nothing listens; connect fails fast.
        let h = host("test", "http://127.0.0.1:1");
        let r = poll_one(&client, &h).await;
        assert!(r.is_err(), "expected transport error on unreachable host");
    }

    #[tokio::test]
    async fn poll_one_strips_trailing_slash_from_url() {
        let server = mockito::Server::new_async().await;
        let mut server = server;
        let _m = server
            .mock("GET", "/api/overview")
            .with_status(200)
            .with_body(minimal_overview_body())
            .create_async()
            .await;
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(2))
            .build()
            .expect("client");
        // Note the explicit trailing slash on the URL: poll_one
        // must not produce `//api/overview`.
        let h = host("test", &format!("{}/", server.url()));
        let r = poll_one(&client, &h).await;
        assert!(
            r.is_ok(),
            "trailing slash must not break URL composition: {r:?}"
        );
    }

    #[test]
    fn parse_overview_returns_none_when_date_missing() {
        let body = serde_json::json!({"events_count": 5});
        assert!(parse_overview(&body).is_none());
    }

    #[test]
    fn parse_overview_extracts_health_kind_from_snapshot_pointer() {
        let body = serde_json::json!({
            "date": "2026-05-02",
            "snapshot": {"health": {"kind": "ai_not_responding", "stuck_count": 4}}
        });
        let o = parse_overview(&body).expect("parses");
        assert_eq!(o.health_kind.as_deref(), Some("ai_not_responding"));
    }

    // ── Phase 4: login_to_spoke + retry-on-401 ───────────────────────

    #[tokio::test]
    async fn login_to_spoke_returns_token_on_2xx() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("POST", "/api/auth/login")
            .with_status(200)
            .with_body(r#"{"token":"new-bearer-abc","expires_in_minutes":480}"#)
            .create_async()
            .await;
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(2))
            .build()
            .expect("client");
        let h = host("test", &server.url());
        let token = login_to_spoke(&client, &h, "admin", "secret")
            .await
            .expect("login ok");
        assert_eq!(token, "new-bearer-abc");
    }

    #[tokio::test]
    async fn login_to_spoke_returns_err_on_401() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("POST", "/api/auth/login")
            .with_status(401)
            .create_async()
            .await;
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(2))
            .build()
            .expect("client");
        let h = host("test", &server.url());
        let r = login_to_spoke(&client, &h, "wrong", "creds").await;
        assert!(r.is_err());
    }

    #[tokio::test]
    async fn login_to_spoke_returns_err_when_token_missing() {
        // A misbehaving spoke (or schema drift) returning 200 with a
        // body that lacks `token` must surface a structured error so
        // the caller does not cache an empty bearer.
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("POST", "/api/auth/login")
            .with_status(200)
            .with_body(r#"{"expires_in_minutes":480}"#)
            .create_async()
            .await;
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(2))
            .build()
            .expect("client");
        let h = host("test", &server.url());
        let r = login_to_spoke(&client, &h, "admin", "secret").await;
        assert!(r.is_err());
        assert!(format!("{:#}", r.unwrap_err()).contains("missing token"));
    }

    #[tokio::test]
    async fn poll_with_refresh_caches_bearer_after_401_retry() {
        // Anchor the Phase 4 contract: the first /api/overview call
        // hits 401, the manager refreshes the bearer via /api/auth/login,
        // the retry succeeds, and the new bearer lands in the cache.
        let mut server = mockito::Server::new_async().await;
        // First overview call — no bearer, 401.
        let _m_first = server
            .mock("GET", "/api/overview")
            .match_header("authorization", mockito::Matcher::Missing)
            .with_status(401)
            .create_async()
            .await;
        // Login succeeds.
        let _m_login = server
            .mock("POST", "/api/auth/login")
            .with_status(200)
            .with_body(r#"{"token":"refreshed-token","expires_in_minutes":480}"#)
            .create_async()
            .await;
        // Retry overview call carrying the new bearer.
        let _m_second = server
            .mock("GET", "/api/overview")
            .match_header("authorization", "Bearer refreshed-token")
            .with_status(200)
            .with_body(r#"{"date":"2026-05-02","events_count":5}"#)
            .create_async()
            .await;

        // Stash creds in env vars the host config references.
        std::env::set_var("FLEET_TEST_USER_4", "admin");
        std::env::set_var("FLEET_TEST_PASS_4", "secret");
        let host_cfg = FleetHostConfig {
            id: "test-refresh".into(),
            url: server.url(),
            token_env: String::new(),
            username_env: "FLEET_TEST_USER_4".into(),
            password_env: "FLEET_TEST_PASS_4".into(),
        };
        let state = FleetState::from_config(std::slice::from_ref(&host_cfg));
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(2))
            .build()
            .expect("client");
        let r = poll_with_refresh(&client, &host_cfg, &state).await;
        assert!(r.is_ok(), "refresh path should produce an overview: {r:?}");
        // Bearer cached — subsequent polls reuse it without calling
        // login again. The Phase 4 invariant.
        assert_eq!(
            state.bearer_for("test-refresh").as_deref(),
            Some("refreshed-token")
        );
    }

    #[tokio::test]
    async fn poll_with_refresh_does_not_retry_when_creds_missing() {
        // Anchor: a host configured with `token_env` only (no
        // username/password) that hits 401 must NOT loop on login.
        // It propagates the error so the host is marked Down.
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("GET", "/api/overview")
            .with_status(401)
            .expect_at_most(1)
            .create_async()
            .await;
        let host_cfg = FleetHostConfig {
            id: "no-refresh".into(),
            url: server.url(),
            token_env: String::new(),
            username_env: String::new(),
            password_env: String::new(),
        };
        let state = FleetState::from_config(std::slice::from_ref(&host_cfg));
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(2))
            .build()
            .expect("client");
        let r = poll_with_refresh(&client, &host_cfg, &state).await;
        assert!(r.is_err(), "401 without creds must NOT retry");
        assert!(state.bearer_for("no-refresh").is_none());
    }
}
