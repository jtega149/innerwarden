// Cloudflare IP Access Rules integration
// When innerwarden blocks an IP, optionally push the block to Cloudflare's edge
// so the IP is blocked at the CDN level before it reaches the host.
//
// API: POST https://api.cloudflare.com/client/v4/zones/{zone_id}/firewall/access_rules/rules
// Docs: https://developers.cloudflare.com/api/operations/ip-access-rules-for-a-zone-create-an-ip-access-rules
//
// Configuration in agent.toml:
//   [cloudflare]
//   enabled = true
//   zone_id = "abc123..."       # from Cloudflare dashboard
//   api_token = ""              # or CLOUDFLARE_API_TOKEN env var
//   auto_push_blocks = true     # push to Cloudflare when block_ip executes
//   block_notes_prefix = "innerwarden"  # prefix for note in Cloudflare rules

use serde::Deserialize;
use serde_json::json;
use tracing::{debug, warn};

// ---------------------------------------------------------------------------
// API response types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct CloudflareResponse {
    success: bool,
    #[serde(default)]
    result: Option<CloudflareResult>,
    #[serde(default)]
    errors: Vec<CloudflareError>,
}

#[derive(Debug, Deserialize)]
struct CloudflareResult {
    id: String,
}

#[derive(Debug, Deserialize)]
struct CloudflareError {
    code: i64,
    #[allow(dead_code)]
    message: String,
}

/// Cloudflare API error code for "an access rule with this configuration
/// already exists" — the IP is already blocked at the edge, so from the
/// agent's perspective the push succeeded idempotently.
/// https://developers.cloudflare.com/fundamentals/api/reference/errors/
const CF_ERROR_DUPLICATE: i64 = 10009;

// ---------------------------------------------------------------------------
// CloudflareClient
// ---------------------------------------------------------------------------

/// Pushes IP block decisions to Cloudflare's edge via the IP Access Rules API.
///
/// Fail-silent: any network error, non-2xx response, or parse failure is logged
/// with `warn!` and the method returns `None`. Cloudflare being unavailable
/// must never stop the agent from processing events (fail-open policy).
pub struct CloudflareClient {
    zone_id: String,
    api_token: String,
    http: reqwest::Client,
    /// Prefix used in Cloudflare rule notes (e.g., "innerwarden")
    notes_prefix: String,
}

impl CloudflareClient {
    /// Create a new client. The HTTP client is configured with an 8-second timeout.
    #[allow(dead_code)]
    pub fn new(zone_id: impl Into<String>, api_token: impl Into<String>) -> Self {
        Self::with_prefix(zone_id, api_token, "innerwarden")
    }

    /// Create a new client with a custom notes prefix.
    pub fn with_prefix(
        zone_id: impl Into<String>,
        api_token: impl Into<String>,
        notes_prefix: impl Into<String>,
    ) -> Self {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(8))
            .build()
            .unwrap_or_default();
        Self {
            zone_id: zone_id.into(),
            api_token: api_token.into(),
            http,
            notes_prefix: notes_prefix.into(),
        }
    }

    /// Returns `true` when both `zone_id` and `api_token` are non-empty.
    pub fn is_configured(&self) -> bool {
        !self.zone_id.is_empty() && !self.api_token.is_empty()
    }

    /// Push an IP block to Cloudflare's edge via IP Access Rules.
    ///
    /// Returns the Cloudflare rule ID on success, or `None` on any error.
    /// The method is fail-silent - errors are logged with `warn!` and swallowed.
    pub async fn push_block(&self, ip: &str, reason: &str) -> Option<String> {
        if !self.is_configured() {
            warn!("Cloudflare push_block called but client is not configured");
            return None;
        }

        let url = format!(
            "https://api.cloudflare.com/client/v4/zones/{}/firewall/access_rules/rules",
            self.zone_id
        );

        let notes = format!("{}: {}", self.notes_prefix, reason);
        let body = json!({
            "mode": "block",
            "configuration": {
                "target": "ip",
                "value": ip
            },
            "notes": notes
        });

        let resp = match self
            .http
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.api_token))
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                warn!(ip, error = %e, "Cloudflare push_block: HTTP request failed");
                return None;
            }
        };

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body_text = resp.text().await.unwrap_or_default();
            if classify_non_2xx_as_duplicate(&body_text) {
                debug!(
                    ip,
                    status, "Cloudflare push_block: IP already blocked (duplicate rule)"
                );
                return None;
            }
            warn!(
                ip,
                status,
                body = body_text.chars().take(200).collect::<String>(),
                "Cloudflare push_block: non-2xx response"
            );
            return None;
        }

        let cf_resp: CloudflareResponse = match resp.json().await {
            Ok(v) => v,
            Err(e) => {
                warn!(ip, error = %e, "Cloudflare push_block: failed to parse response");
                return None;
            }
        };

        if !cf_resp.success {
            if cf_resp.errors.iter().any(|e| e.code == CF_ERROR_DUPLICATE) {
                debug!(
                    ip,
                    "Cloudflare push_block: IP already blocked (duplicate rule)"
                );
                return None;
            }
            warn!(ip, "Cloudflare push_block: API returned success=false");
            return None;
        }

        cf_resp.result.map(|r| r.id)
    }
}

/// Returns true when the response body indicates the block rule already
/// exists for this IP. Used on non-2xx responses, where Cloudflare reports
/// the duplicate as a `400` with a typed error body.
fn classify_non_2xx_as_duplicate(body: &str) -> bool {
    // Cheap path: look for the numeric code without full deserialization, so
    // malformed or unexpected bodies still hit the regular warn path.
    if let Ok(parsed) = serde_json::from_str::<CloudflareResponse>(body) {
        return parsed.errors.iter().any(|e| e.code == CF_ERROR_DUPLICATE);
    }
    false
}

// ---------------------------------------------------------------------------
// Helper: resolve API token
// ---------------------------------------------------------------------------

/// Resolve the Cloudflare API token.
///
/// Config value takes precedence; falls back to the `CLOUDFLARE_API_TOKEN`
/// environment variable when the config value is empty.
pub fn resolve_api_token(config_token: &str) -> String {
    if !config_token.is_empty() {
        return config_token.to_string();
    }
    std::env::var("CLOUDFLARE_API_TOKEN").unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_configured_when_both_set() {
        let client = CloudflareClient::new("zone123", "token456");
        assert!(client.is_configured());
    }

    #[test]
    fn not_configured_when_zone_empty() {
        let client = CloudflareClient::new("", "token456");
        assert!(!client.is_configured());
    }

    #[test]
    fn not_configured_when_token_empty() {
        let client = CloudflareClient::new("zone123", "");
        assert!(!client.is_configured());
    }

    #[test]
    fn resolve_api_token_prefers_config() {
        // Even if the env var is set, the config value must win.
        // We set a non-empty config value and verify it is returned as-is.
        let token = resolve_api_token("config-token-abc");
        assert_eq!(token, "config-token-abc");
    }

    #[test]
    fn block_notes_format() {
        let prefix = "innerwarden";
        let reason = "SSH brute-force from 1.2.3.4";
        let notes = format!("{}: {}", prefix, reason);
        assert_eq!(notes, "innerwarden: SSH brute-force from 1.2.3.4");
    }

    #[test]
    fn resolve_api_token_falls_back_to_env_when_config_empty() {
        // Remove env var to ensure a clean state, then check empty config
        // yields empty string (env not set in unit test environment by default).
        std::env::remove_var("CLOUDFLARE_API_TOKEN");
        let token = resolve_api_token("");
        assert_eq!(token, "");
    }

    // ── Duplicate rule (error 10009) classification ─────────────────────────

    #[test]
    fn classify_duplicate_detects_error_10009() {
        // Verbatim shape returned by Cloudflare when a firewall access rule
        // for the same IP already exists.
        let body = r#"{
            "result": null,
            "success": false,
            "errors": [
                {"code": 10009, "message": "firewallaccessrules.api.duplicate_of_existing"}
            ],
            "messages": []
        }"#;
        assert!(classify_non_2xx_as_duplicate(body));
    }

    #[test]
    fn classify_duplicate_ignores_other_errors() {
        let body = r#"{
            "result": null,
            "success": false,
            "errors": [{"code": 10000, "message": "authentication error"}]
        }"#;
        assert!(!classify_non_2xx_as_duplicate(body));
    }

    #[test]
    fn classify_duplicate_ignores_empty_errors() {
        assert!(!classify_non_2xx_as_duplicate(
            r#"{"success": false, "errors": []}"#
        ));
    }

    #[test]
    fn classify_duplicate_ignores_malformed_body() {
        assert!(!classify_non_2xx_as_duplicate("not json at all"));
        assert!(!classify_non_2xx_as_duplicate(""));
    }

    #[test]
    fn classify_duplicate_picks_matching_code_among_many() {
        let body = r#"{
            "success": false,
            "errors": [
                {"code": 1001, "message": "other"},
                {"code": 10009, "message": "dup"}
            ]
        }"#;
        assert!(classify_non_2xx_as_duplicate(body));
    }

    #[test]
    fn cloudflare_response_deserializes_with_errors_array() {
        let body = r#"{
            "success": false,
            "errors": [{"code": 10009, "message": "dup"}]
        }"#;
        let parsed: CloudflareResponse = serde_json::from_str(body).unwrap();
        assert!(!parsed.success);
        assert!(parsed.result.is_none());
        assert_eq!(parsed.errors.len(), 1);
        assert_eq!(parsed.errors[0].code, CF_ERROR_DUPLICATE);
    }

    #[test]
    fn cloudflare_response_deserializes_success_without_errors_field() {
        // Successful creation response has no `errors` key at all — default
        // handling must produce an empty vec so the deserializer succeeds.
        let body = r#"{
            "success": true,
            "result": {"id": "abc123"}
        }"#;
        let parsed: CloudflareResponse = serde_json::from_str(body).unwrap();
        assert!(parsed.success);
        assert_eq!(parsed.result.unwrap().id, "abc123");
        assert!(parsed.errors.is_empty());
    }
}
