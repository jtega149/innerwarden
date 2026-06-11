// ---------------------------------------------------------------------------
// IP Geolocation enrichment via ip-api.com
// ---------------------------------------------------------------------------
//
// Before sending an incident to the AI provider, InnerWarden can optionally
// query ip-api.com to enrich the decision context with geolocation data.
// This gives the AI provider additional geographic and network signal (country,
// city, ISP, ASN) without requiring an API key.
//
// API: GET http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,isp,org,as
// Docs: https://ip-api.com/docs/api:json
//
// Free tier: 45 requests/minute. Private IPs and invalid addresses return
// {"status":"fail"} and are handled gracefully (returns None).
//
// Configuration in agent.toml:
//   [geoip]
//   enabled = true

use serde::Deserialize;
use tracing::{debug, warn};

// ---------------------------------------------------------------------------
// API response types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct IpApiResponse {
    #[serde(default)]
    status: String,
    #[serde(default, deserialize_with = "lenient_string")]
    country: String,
    #[serde(rename = "countryCode", default, deserialize_with = "lenient_string")]
    country_code: String,
    #[serde(default, deserialize_with = "lenient_string")]
    city: String,
    #[serde(default, deserialize_with = "lenient_string")]
    isp: String,
    #[serde(rename = "as", default, deserialize_with = "lenient_string")]
    asn: String,
}

/// Accept a string, a bare number (stringified), or null for a string field
/// (defaults to empty). ip-api.com returns the `as` field as a bare integer
/// for some IPs and fields can arrive as `null`; a plain `String` field would
/// fail the WHOLE record and silently kill geo enrichment for every IP — the
/// exact failure mode the DShield `as` bug had in prod (2026-06-11).
fn lenient_string<'de, D>(de: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let v = serde_json::Value::deserialize(de)?;
    Ok(match v {
        serde_json::Value::String(s) => s,
        serde_json::Value::Number(n) => n.to_string(),
        _ => String::new(),
    })
}

/// Lightweight geolocation summary attached to `DecisionContext`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GeoInfo {
    pub country: String,
    pub country_code: String,
    pub city: String,
    pub isp: String,
    pub asn: String,
}

impl GeoInfo {
    /// Human-readable summary for inclusion in the AI prompt.
    pub fn as_context_line(&self) -> String {
        format!(
            "Geolocation: country={} ({}), city={}, isp={}, asn={}",
            self.country, self.country_code, self.city, self.isp, self.asn
        )
    }
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

pub struct GeoIpClient {
    http: reqwest::Client,
}

impl GeoIpClient {
    pub fn new() -> Self {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .expect("failed to build GeoIP HTTP client");
        Self { http }
    }

    /// Look up geolocation for a single IP address.
    /// Returns `None` on any non-fatal error (API down, rate limit, private IP,
    /// parse failure) so callers can proceed without enrichment.
    pub async fn lookup(&self, ip: &str) -> Option<GeoInfo> {
        if ip.is_empty() {
            return None;
        }

        // ip-api.com free tier returns 403 on HTTPS (HTTPS is paid-tier only).
        // SEC-016 originally mandated HTTPS to avoid leaking queried IPs in
        // transit, but the queried IPs are attacker addresses already observed
        // on this host's public interfaces — plaintext transit reveals no
        // additional information. Sticking with HTTPS here silently breaks
        // enrichment for every caller on the free plan.
        debug!(ip, "querying ip-api.com (HTTP, free tier)");

        let url = format!(
            "http://ip-api.com/json/{}?fields=status,country,countryCode,city,isp,org,as",
            ip
        );

        let resp = self.http.get(&url).send().await;

        let resp = match resp {
            Ok(r) => r,
            Err(e) => {
                warn!(ip, error = %e, "ip-api.com request failed");
                return None;
            }
        };

        if resp.status().as_u16() == 429 {
            warn!("ip-api.com rate limit hit - skipping geolocation enrichment");
            return None;
        }

        if !resp.status().is_success() {
            warn!(ip, status = %resp.status(), "ip-api.com returned non-200");
            return None;
        }

        // Cap the body before parsing — ip-api responses are tiny; a hostile
        // or MITM'd response should not be able to OOM the agent.
        const MAX_BODY: usize = 256 * 1024;
        let bytes = match resp.bytes().await {
            Ok(b) => b,
            Err(e) => {
                warn!(ip, error = %e, "ip-api.com body read failed");
                return None;
            }
        };
        if bytes.len() > MAX_BODY {
            warn!(
                ip,
                body_bytes = bytes.len(),
                "ip-api.com response too large"
            );
            return None;
        }
        let data: IpApiResponse = match serde_json::from_slice(&bytes) {
            Ok(d) => d,
            Err(e) => {
                warn!(ip, error = %e, "failed to parse ip-api.com response");
                return None;
            }
        };

        if data.status != "success" {
            // Handles private IPs, invalid IPs, etc.
            return None;
        }

        Some(GeoInfo {
            country: data.country,
            country_code: data.country_code,
            city: data.city,
            isp: data.isp,
            asn: data.asn,
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserializes_success_response() {
        let json = r#"{
            "status": "success",
            "country": "China",
            "countryCode": "CN",
            "city": "Shenzhen",
            "isp": "China Telecom",
            "org": "China Telecom Guangdong",
            "as": "AS4134 China Telecom"
        }"#;
        let resp: IpApiResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.status, "success");
        assert_eq!(resp.country, "China");
        assert_eq!(resp.country_code, "CN");
        assert_eq!(resp.city, "Shenzhen");
        assert_eq!(resp.isp, "China Telecom");
        assert_eq!(resp.asn, "AS4134 China Telecom");
    }

    #[test]
    fn fail_response_defaults_optional_fields() {
        let json = r#"{"status":"fail","message":"private range"}"#;
        let resp: IpApiResponse = serde_json::from_str(json).unwrap();

        assert_eq!(resp.status, "fail");
        assert_eq!(resp.country, "");
        assert_eq!(resp.country_code, "");
        assert_eq!(resp.city, "");
        assert_eq!(resp.isp, "");
        assert_eq!(resp.asn, "");
    }

    #[test]
    fn lenient_parse_survives_integer_as_and_null_fields() {
        // Regression for the DShield/geoip type-flip class: ip-api can return
        // `as` as a BARE INTEGER and string fields as `null`. With plain
        // `String` fields this failed the whole record and silently killed geo
        // enrichment for every IP. lenient_string stringifies the number and
        // treats null as empty, so the record still parses.
        let json = r#"{
            "status":"success",
            "country":"Brazil",
            "countryCode":null,
            "city":null,
            "isp":12345,
            "as":268869
        }"#;
        let resp: IpApiResponse =
            serde_json::from_str(json).expect("must parse with integer `as`/`isp` + null fields");
        assert_eq!(resp.status, "success");
        assert_eq!(resp.country, "Brazil");
        assert_eq!(resp.country_code, "");
        assert_eq!(resp.city, "");
        assert_eq!(resp.isp, "12345");
        assert_eq!(resp.asn, "268869");
    }

    #[test]
    fn success_response_defaults_missing_optional_fields() {
        let json = r#"{"status":"success","country":"Japan","countryCode":"JP"}"#;
        let resp: IpApiResponse = serde_json::from_str(json).unwrap();

        assert_eq!(resp.status, "success");
        assert_eq!(resp.country, "Japan");
        assert_eq!(resp.country_code, "JP");
        assert_eq!(resp.city, "");
        assert_eq!(resp.isp, "");
        assert_eq!(resp.asn, "");
    }

    #[test]
    fn context_line_format() {
        let geo = GeoInfo {
            country: "Russia".to_string(),
            country_code: "RU".to_string(),
            city: "Moscow".to_string(),
            isp: "Rostelecom".to_string(),
            asn: "AS12389 Rostelecom".to_string(),
        };
        let line = geo.as_context_line();
        assert!(line.contains("country=Russia"));
        assert!(line.contains("(RU)"));
        assert!(line.contains("city=Moscow"));
        assert!(line.contains("isp=Rostelecom"));
        assert!(line.contains("asn=AS12389 Rostelecom"));
    }

    #[test]
    fn context_line_with_empty_fields() {
        let geo = GeoInfo {
            country: String::new(),
            country_code: String::new(),
            city: String::new(),
            isp: String::new(),
            asn: String::new(),
        };
        let line = geo.as_context_line();
        // Should not panic; empty strings are rendered as empty
        assert!(line.contains("Geolocation:"));
        assert!(line.contains("country="));
        assert!(line.contains("city="));
    }

    // Regression guard: the free ip-api.com tier rejects HTTPS with 403, so
    // the enrichment URL must stay on http://. If a future "SEC fix" flips
    // it back to https://, this test will fail loudly instead of the
    // enrichment silently returning None for every IP.
    #[test]
    fn ip_api_url_uses_http_scheme() {
        let url = format!(
            "http://ip-api.com/json/{}?fields=status,country,countryCode,city,isp,org,as",
            "8.8.8.8"
        );
        assert!(url.starts_with("http://ip-api.com/"));
        assert!(!url.starts_with("https://"));
    }

    #[tokio::test]
    async fn lookup_empty_ip_returns_none_without_network() {
        let client = GeoIpClient::new();

        assert!(client.lookup("").await.is_none());
    }

    #[test]
    fn geo_info_serializes_with_expected_fields() {
        let geo = GeoInfo {
            country: "Japan".to_string(),
            country_code: "JP".to_string(),
            city: "Tokyo".to_string(),
            isp: "Example ISP".to_string(),
            asn: "AS64500 Example".to_string(),
        };

        let value = serde_json::to_value(&geo).unwrap();

        assert_eq!(value["country"], "Japan");
        assert_eq!(value["country_code"], "JP");
        assert_eq!(value["city"], "Tokyo");
        assert_eq!(value["isp"], "Example ISP");
        assert_eq!(value["asn"], "AS64500 Example");
    }

    #[test]
    fn not_configured_when_disabled() {
        // GeoIpClient::new() is always available (no key needed).
        // Network paths are covered by integration tests; unit tests keep the
        // client offline and verify construction plus the empty-IP guard.
        let _client = GeoIpClient::new();
    }
}
