// ---------------------------------------------------------------------------
// DShield (SANS Internet Storm Center) IP reputation enrichment — read-only
// ---------------------------------------------------------------------------
//
// DShield is the community threat-intel feed run by the SANS Internet Storm
// Center: thousands of sensors worldwide submit attack logs, and the ISC
// aggregates per-IP attack history. We use it READ-ONLY as an enrichment
// source alongside AbuseIPDB / CrowdSec — a different, respected community
// dataset, not a competitor and not a control plane.
//
// API (keyless): GET https://isc.sans.edu/api/ip/<IP>?json
// Docs: https://isc.sans.edu/api/
//
// Politeness: the ISC requests a descriptive User-Agent and reasonable rate.
// We send a UA identifying InnerWarden and cache results in the enrichment
// layer (same pattern as `abuseipdb_cache`) so a hot attacker IP is looked up
// at most once per cache window.
//
// Configuration in agent.toml:
//   [dshield]
//   enabled = false   # external call; opt-in like every other enrichment

use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

const DSHIELD_API: &str = "https://isc.sans.edu/api/ip";
const USER_AGENT: &str = concat!(
    "InnerWarden/",
    env!("CARGO_PKG_VERSION"),
    " (+https://innerwarden.com; security enrichment)"
);

// ---------------------------------------------------------------------------
// API response types
// ---------------------------------------------------------------------------

/// Top-level DShield response: `{ "ip": { ... } }`. Unknown IPs still return
/// the object with null fields, so every field is optional.
#[derive(Debug, Clone, Deserialize)]
pub struct DshieldResponse {
    pub ip: DshieldIp,
}

/// DShield per-IP record. DShield encodes "unknown" as JSON `null`, and some
/// numeric fields arrive as either a number or a string depending on the
/// endpoint version — hence the lenient typing.
#[derive(Debug, Clone, Deserialize)]
pub struct DshieldIp {
    /// Total reports across all ISC sensors.
    #[serde(default, deserialize_with = "lenient_i64")]
    pub count: Option<i64>,
    /// Distinct targets attacked (a "spread" signal).
    #[serde(default, deserialize_with = "lenient_i64")]
    pub attacks: Option<i64>,
    /// Most recent date the IP was reported attacking (YYYY-MM-DD).
    #[serde(default)]
    pub maxdate: Option<String>,
    /// Autonomous System number. DShield returns this as a bare integer
    /// (`"as":48090`) for many IPs but as a quoted string (`"as":"4134"`) for
    /// others; parse leniently so a type-flip does not fail the whole record.
    #[serde(rename = "as", default, deserialize_with = "lenient_string")]
    pub as_number: Option<String>,
    /// AS owner name.
    #[serde(default, deserialize_with = "lenient_string")]
    pub asname: Option<String>,
    /// Two-letter country of the AS.
    #[serde(default, deserialize_with = "lenient_string")]
    pub ascountry: Option<String>,
    /// CIDR the IP belongs to.
    #[serde(default, deserialize_with = "lenient_string")]
    pub network: Option<String>,
    /// Named threat feeds this IP is currently a member of. DShield returns
    /// this as an object keyed by feed name (or null/absent).
    #[serde(default)]
    pub threatfeeds: Option<serde_json::Value>,
}

/// Accept a number, a numeric string, or null for an integer field.
fn lenient_i64<'de, D>(de: D) -> Result<Option<i64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let v = serde_json::Value::deserialize(de)?;
    Ok(match v {
        serde_json::Value::Number(n) => n.as_i64(),
        serde_json::Value::String(s) => s.trim().parse::<i64>().ok(),
        _ => None,
    })
}

/// Accept a string, a bare number (stringified), or null for a string field.
///
/// Why this exists: DShield flipped `as` from a quoted string (`"as":"4134"`)
/// to a bare integer (`"as":48090`). With a plain `Option<String>` field, serde
/// fails the WHOLE record with "invalid type: integer, expected a string", so
/// DShield enrichment silently died for every IP — 239 `failed to parse DShield
/// response` warnings in 2 days on prod (2026-06-11). Tolerating either shape on
/// the AS string fields keeps a single upstream type-flip from killing the feed.
fn lenient_string<'de, D>(de: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let v = serde_json::Value::deserialize(de)?;
    Ok(match v {
        serde_json::Value::String(s) => Some(s),
        serde_json::Value::Number(n) => Some(n.to_string()),
        _ => None,
    })
}

/// Normalized DShield reputation attached to enrichment / attacker profiles.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DshieldReputation {
    /// Total attack reports across ISC sensors (0 if unknown).
    pub reports: i64,
    /// Distinct targets attacked (0 if unknown).
    pub targets: i64,
    /// Most recent attack date seen by ISC, if any.
    pub last_seen: Option<String>,
    pub as_number: Option<String>,
    pub as_name: Option<String>,
    pub as_country: Option<String>,
    pub network: Option<String>,
    /// Names of the ISC threat feeds the IP is currently on.
    pub threatfeeds: Vec<String>,
}

impl DshieldReputation {
    /// True when ISC has any attack history or active feed membership for the
    /// IP — i.e. the community has seen it being malicious.
    pub fn is_known_attacker(&self) -> bool {
        self.reports > 0 || !self.threatfeeds.is_empty()
    }

    /// Human-readable summary for the AI prompt / dashboard, mirroring
    /// `IpReputation::as_context_line`.
    pub fn as_context_line(&self) -> String {
        let country = self.as_country.as_deref().unwrap_or("??");
        let asn = match (self.as_number.as_deref(), self.as_name.as_deref()) {
            (Some(n), Some(name)) => format!("AS{n} {name}"),
            (Some(n), None) => format!("AS{n}"),
            (None, Some(name)) => name.to_string(),
            (None, None) => "unknown AS".to_string(),
        };
        let feeds = if self.threatfeeds.is_empty() {
            String::new()
        } else {
            format!(", feeds=[{}]", self.threatfeeds.join(","))
        };
        let last = self
            .last_seen
            .as_deref()
            .map(|d| format!(", last_seen={d}"))
            .unwrap_or_default();
        format!(
            "DShield(ISC): reports={}, targets={}, as={}, country={}{last}{feeds}",
            self.reports, self.targets, asn, country,
        )
    }

    /// Build from a parsed API record.
    fn from_ip(ip: DshieldIp) -> Self {
        let threatfeeds = match ip.threatfeeds {
            Some(serde_json::Value::Object(m)) => m.keys().cloned().collect(),
            _ => Vec::new(),
        };
        DshieldReputation {
            reports: ip.count.unwrap_or(0).max(0),
            targets: ip.attacks.unwrap_or(0).max(0),
            last_seen: ip.maxdate,
            as_number: ip.as_number,
            as_name: ip.asname,
            as_country: ip.ascountry,
            network: ip.network,
            threatfeeds,
        }
    }
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

pub struct DshieldClient {
    http: reqwest::Client,
}

impl Default for DshieldClient {
    fn default() -> Self {
        Self::new()
    }
}

impl DshieldClient {
    pub fn new() -> Self {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .user_agent(USER_AGENT)
            .build()
            .expect("failed to build DShield HTTP client");
        Self { http }
    }

    /// Look up an IP's DShield reputation. Returns `None` on any non-fatal
    /// error (API down, rate limit, parse failure) so callers proceed without
    /// enrichment — read-only, never blocks a decision.
    pub async fn lookup(&self, ip: &str) -> Option<DshieldReputation> {
        debug!(ip, "querying DShield (ISC)");
        let url = format!("{DSHIELD_API}/{ip}?json");

        let resp = match self.http.get(&url).send().await {
            Ok(r) => r,
            Err(e) => {
                warn!(ip, error = %e, "DShield request failed");
                return None;
            }
        };

        if resp.status().as_u16() == 429 {
            warn!("DShield rate limit hit - skipping enrichment");
            return None;
        }
        if !resp.status().is_success() {
            warn!(ip, status = %resp.status(), "DShield returned non-200");
            return None;
        }

        match resp.json::<DshieldResponse>().await {
            Ok(d) => Some(DshieldReputation::from_ip(d.ip)),
            Err(e) => {
                warn!(ip, error = %e, "failed to parse DShield response");
                None
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_known_attacker_with_feeds() {
        // Canonical shape for an IP the ISC community has seen attacking.
        let json = r#"{"ip":{"number":"1.2.3.4","count":4213,"attacks":311,
            "maxdate":"2026-05-30","as":"4134","asname":"CHINANET-BACKBONE",
            "ascountry":"CN","network":"1.2.0.0/16",
            "threatfeeds":{"sansoc":{"lastseen":"2026-05-30"},"blocklistde":{}}}}"#;
        let r: DshieldResponse = serde_json::from_str(json).unwrap();
        let rep = DshieldReputation::from_ip(r.ip);
        assert_eq!(rep.reports, 4213);
        assert_eq!(rep.targets, 311);
        assert_eq!(rep.as_country.as_deref(), Some("CN"));
        assert!(rep.is_known_attacker());
        let mut feeds = rep.threatfeeds.clone();
        feeds.sort();
        assert_eq!(feeds, vec!["blocklistde", "sansoc"]);
        assert!(rep.as_context_line().contains("DShield(ISC)"));
        assert!(rep.as_context_line().contains("feeds="));
    }

    #[test]
    fn parses_unknown_ip_with_nulls() {
        // DShield returns the object with null fields for a clean IP.
        let json = r#"{"ip":{"number":"8.8.8.8","count":null,"attacks":null,
            "maxdate":null,"as":"15169","asname":"GOOGLE","ascountry":"US",
            "network":"8.8.8.0/24","threatfeeds":null}}"#;
        let r: DshieldResponse = serde_json::from_str(json).unwrap();
        let rep = DshieldReputation::from_ip(r.ip);
        assert_eq!(rep.reports, 0);
        assert_eq!(rep.targets, 0);
        assert!(rep.threatfeeds.is_empty());
        assert!(!rep.is_known_attacker(), "clean IP is not a known attacker");
    }

    #[test]
    fn lenient_i64_accepts_string_or_number() {
        // Some ISC endpoint versions stringify the counters.
        let json = r#"{"ip":{"count":"57","attacks":3}}"#;
        let r: DshieldResponse = serde_json::from_str(json).unwrap();
        let rep = DshieldReputation::from_ip(r.ip);
        assert_eq!(rep.reports, 57);
        assert_eq!(rep.targets, 3);
    }

    #[test]
    fn negative_counts_clamp_to_zero() {
        let json = r#"{"ip":{"count":-1,"attacks":-5,"threatfeeds":null}}"#;
        let r: DshieldResponse = serde_json::from_str(json).unwrap();
        let rep = DshieldReputation::from_ip(r.ip);
        assert_eq!(rep.reports, 0);
        assert_eq!(rep.targets, 0);
    }

    #[test]
    fn parses_as_field_as_bare_integer() {
        // Regression (prod 2026-06-11): DShield returns `"as":48090` as a BARE
        // INTEGER for many IPs. The field was typed `Option<String>`, so serde
        // failed the whole record ("invalid type: integer, expected a string")
        // and DShield enrichment died for every IP (239 parse failures / 2 days).
        // This is the real on-wire shape (extra fields like weblogs/number/
        // maxrisk are present and must be tolerated; `as` is the integer).
        let json = r#"{"ip":{"number":"45.148.10.121","count":null,"attacks":null,
            "maxdate":null,"mindate":null,"updated":null,"comment":null,
            "maxrisk":null,"asabusecontact":"abuse@vegatele.com","as":48090,
            "asname":"PPTECHNOLOGY","ascountry":"GB","assize":256,
            "network":"45.148.10.0/24","weblogs":{"count":1},"threatfeeds":null}}"#;
        let r: DshieldResponse = serde_json::from_str(json).expect("must parse with integer `as`");
        let rep = DshieldReputation::from_ip(r.ip);
        assert_eq!(rep.as_number.as_deref(), Some("48090"));
        assert_eq!(rep.as_name.as_deref(), Some("PPTECHNOLOGY"));
        assert_eq!(rep.as_country.as_deref(), Some("GB"));
        assert_eq!(rep.reports, 0);
        assert_eq!(rep.targets, 0);
    }
}
