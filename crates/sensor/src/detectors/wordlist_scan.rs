//! Wordlist-style HTTP path enumeration (spec 050-PR1).
//!
//! Fires when a single source IP requests N distinct paths matching
//! known attack/admin wordlist patterns within a short window. The
//! signal: an attacker enumerating `/admin`, `/phpmyadmin`, `/.env`,
//! `/.git/config`, `/wp-login.php`, `/api/v1/users`, … in tight
//! succession.
//!
//! This complements `web_scan` (which keys off `http.error` rate) by
//! firing **before** the server actually returns 4xx. Wordlist clients
//! frequently get 200/302/401 responses for paths that exist, so
//! error-rate alone misses them.
//!
//! Anti-FP gates:
//!   - Built-in allowlist for health-check / legit endpoints
//!     (`/health`, `/healthz`, `/metrics`, `/favicon.ico`,
//!     `/robots.txt`, `/api/agent/*`, `/static/*`).
//!   - Internal source IPs skipped via `super::is_internal_ip`.
//!   - Cloudflare/AWS-ALB edges respected through the standard
//!     allowlist gates (`cloud_safelist` lives in the agent; the
//!     sensor sees the original IP).
//!
//! Severity escalation: medium at threshold, high at 2× threshold,
//! critical at 3× threshold or when sensitive paths (`/.env`, `/.git/`,
//! `/admin`, `/wp-login.php`) appear.
//!
//! MITRE: T1595.003 (Active Scanning: Wordlist Scanning).

use std::collections::{HashMap, HashSet, VecDeque};

use chrono::{DateTime, Duration, Utc};
use innerwarden_core::{entities::EntityRef, event::Event, event::Severity, incident::Incident};

/// Path patterns that almost always indicate wordlist enumeration when
/// requested without an established session. `starts_with` semantics
/// — matches `/.env`, `/.env.production`, `/.env.local`, etc.
const WORDLIST_PATH_PATTERNS: &[&str] = &[
    "/.env",
    "/.git/",
    "/.git",
    "/.svn/",
    "/.aws/",
    "/.ssh/",
    "/.htaccess",
    "/.htpasswd",
    "/admin",
    "/administrator",
    "/wp-admin",
    "/wp-login",
    "/wp-config",
    "/phpmyadmin",
    "/pma",
    "/mysql",
    "/cgi-bin/",
    "/console",
    "/jenkins",
    "/manager/html",
    "/manager/status",
    "/server-status",
    "/server-info",
    "/.well-known/security.txt",
    "/sftp-config.json",
    "/api/v1/users",
    "/api/v1/admin",
    "/owa/",
    "/ecp/",
    "/autodiscover/",
    "/_ignition",
    "/actuator/",
    "/api/jsonws/",
    "/druid/",
    "/solr/",
    "/.DS_Store",
    "/composer.json",
    "/composer.lock",
    "/wp-content/",
    "/vendor/phpunit/",
    "/cgi-sys/",
    "/error_log",
    "/.npmrc",
    "/.dockerenv",
];

/// "Sensitive" subset — single hit on any of these elevates severity.
const SENSITIVE_PATHS: &[&str] = &[
    "/.env",
    "/.git/",
    "/.aws/",
    "/.ssh/",
    "/.htpasswd",
    "/wp-config",
    "/phpmyadmin",
    "/admin",
    "/manager/html",
];

/// Paths that get a free pass — legit health/metrics traffic.
const PATH_ALLOWLIST_PREFIXES: &[&str] = &[
    "/health",
    "/healthz",
    "/ready",
    "/metrics",
    "/favicon.ico",
    "/robots.txt",
    "/sitemap.xml",
    "/api/agent/",
    "/static/",
    "/assets/",
    "/_next/",
];

pub struct WordlistScanDetector {
    host: String,
    /// Wordlist hits per source IP (timestamp + path).
    windows: HashMap<String, VecDeque<(DateTime<Utc>, String)>>,
    /// Last alert per source IP — keeps a long scan from re-firing.
    alerted: HashMap<String, DateTime<Utc>>,
    threshold: usize,
    window: Duration,
    cooldown: Duration,
}

impl WordlistScanDetector {
    pub fn new(host: impl Into<String>, threshold: usize, window_seconds: u64) -> Self {
        Self {
            host: host.into(),
            windows: HashMap::new(),
            alerted: HashMap::new(),
            threshold,
            window: Duration::seconds(window_seconds as i64),
            cooldown: Duration::seconds(window_seconds as i64 * 5),
        }
    }

    pub fn process(&mut self, event: &Event) -> Option<Incident> {
        if event.kind != "http.request" {
            return None;
        }

        let path = event
            .details
            .get("path")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if path.is_empty() {
            return None;
        }
        if is_allowlisted_path(path) {
            return None;
        }
        if !matches_wordlist(path) {
            return None;
        }

        let ip = event
            .details
            .get("ip")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if ip.is_empty() || super::is_internal_ip(&ip) {
            return None;
        }

        let now = event.ts;
        let cutoff = now - self.window;

        let entries = self.windows.entry(ip.clone()).or_default();
        while entries.front().is_some_and(|(t, _)| *t < cutoff) {
            entries.pop_front();
        }
        entries.push_back((now, path.to_string()));

        let distinct_paths: HashSet<&str> = entries.iter().map(|(_, p)| p.as_str()).collect();
        let distinct = distinct_paths.len();
        if distinct < self.threshold {
            return None;
        }

        if let Some(&last) = self.alerted.get(&ip) {
            if now - last < self.cooldown {
                return None;
            }
        }
        self.alerted.insert(ip.clone(), now);
        if self.alerted.len() > 1000 {
            let cd_cutoff = now - self.cooldown;
            self.alerted.retain(|_, t| *t > cd_cutoff);
        }

        let sample_paths: Vec<&str> = distinct_paths.iter().take(15).copied().collect();
        let touched_sensitive = sample_paths.iter().any(|p| is_sensitive_path(p));

        let severity = if touched_sensitive || distinct >= self.threshold * 3 {
            Severity::Critical
        } else if distinct >= self.threshold * 2 {
            Severity::High
        } else {
            Severity::Medium
        };

        let user_agent = event
            .details
            .get("user_agent")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        Some(Incident {
            ts: now,
            host: self.host.clone(),
            incident_id: format!(
                "wordlist_scan:{}:{}",
                ip,
                now.format("%Y-%m-%dT%H:%MZ")
            ),
            severity,
            title: format!(
                "Wordlist HTTP enumeration from {ip} ({distinct} distinct paths in {}s)",
                self.window.num_seconds()
            ),
            summary: format!(
                "Source IP {ip} requested {distinct} distinct wordlist-pattern paths within \
                 {}s. {} Sample paths: {}",
                self.window.num_seconds(),
                if touched_sensitive {
                    "**Sensitive paths touched** — likely targeted exfil attempt."
                } else {
                    "Likely automated vulnerability/path scanner."
                },
                sample_paths.join(", ")
            ),
            evidence: serde_json::json!([{
                "kind": "wordlist_scan",
                "ip": ip,
                "distinct_paths": distinct,
                "window_seconds": self.window.num_seconds(),
                "sample_paths": sample_paths,
                "sensitive_hit": touched_sensitive,
                "user_agent": user_agent,
                "mitre": ["T1595.003"],
            }]),
            recommended_checks: vec![
                format!("Block IP {ip} at edge (Cloudflare / nftables) if not authorized"),
                format!("Search nginx access log: `grep ' {ip} ' /var/log/nginx/access.log | tail -100`"),
                "If this is a legitimate scanner (e.g. internal pen-test), allowlist via `[ips]`".to_string(),
            ],
            tags: vec!["reconnaissance".to_string(), "web_scan".to_string()],
            entities: vec![EntityRef::ip(ip)],
        })
    }
}

fn matches_wordlist(path: &str) -> bool {
    WORDLIST_PATH_PATTERNS
        .iter()
        .any(|pat| path.starts_with(pat))
}

fn is_sensitive_path(path: &str) -> bool {
    SENSITIVE_PATHS.iter().any(|p| path.starts_with(p))
}

fn is_allowlisted_path(path: &str) -> bool {
    PATH_ALLOWLIST_PREFIXES.iter().any(|p| path.starts_with(p))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn http_event(ip: &str, path: &str) -> Event {
        Event {
            ts: Utc::now(),
            host: "test".into(),
            source: "http_capture".into(),
            kind: "http.request".into(),
            severity: Severity::Info,
            summary: format!("HTTP request from {ip}: {path}"),
            details: serde_json::json!({
                "ip": ip,
                "method": "GET",
                "path": path,
                "user_agent": "curl/7.88",
            }),
            tags: vec![],
            entities: vec![],
        }
    }

    fn external_ip() -> &'static str {
        // Real public IP. RFC 5737 documentation ranges (192.0.2.0/24,
        // 198.51.100.0/24, 203.0.113.0/24) are flagged internal by
        // `Ipv4Addr::is_documentation` and would short-circuit the
        // detector — using a routable address keeps the gate exercised.
        "8.8.8.8"
    }

    #[test]
    fn fires_when_threshold_distinct_paths_within_window() {
        let mut det = WordlistScanDetector::new("test", 5, 60);
        let ip = external_ip();
        // Pre-fill 4 distinct paths — below threshold, none fire.
        for path in ["/admin", "/wp-login.php", "/phpmyadmin", "/.env"] {
            assert!(det.process(&http_event(ip, path)).is_none());
        }
        // 5th distinct path reaches threshold and fires.
        let result = det.process(&http_event(ip, "/.git/config"));
        assert!(result.is_some());
        let inc = result.unwrap();
        // sensitive paths touched → critical
        assert_eq!(inc.severity, Severity::Critical);
    }

    #[test]
    fn does_not_fire_below_threshold() {
        let mut det = WordlistScanDetector::new("test", 5, 60);
        let ip = external_ip();
        let result = det
            .process(&http_event(ip, "/admin"))
            .or_else(|| det.process(&http_event(ip, "/wp-login.php")));
        assert!(result.is_none());
    }

    #[test]
    fn skips_healthcheck_paths() {
        let mut det = WordlistScanDetector::new("test", 3, 60);
        let ip = external_ip();
        for path in [
            "/health",
            "/metrics",
            "/favicon.ico",
            "/api/agent/security-context",
        ] {
            assert!(det.process(&http_event(ip, path)).is_none());
        }
    }

    #[test]
    fn skips_internal_source_ips() {
        let mut det = WordlistScanDetector::new("test", 3, 60);
        for ip in ["10.0.0.5", "192.168.1.10", "172.16.0.1", "127.0.0.1"] {
            for path in ["/admin", "/wp-login.php", "/.env"] {
                assert!(det.process(&http_event(ip, path)).is_none());
            }
        }
    }

    #[test]
    fn dedupes_repeat_paths_in_same_window() {
        let mut det = WordlistScanDetector::new("test", 3, 60);
        let ip = external_ip();
        // Same path 5 times = 1 distinct path — should NOT fire
        for _ in 0..5 {
            assert!(det.process(&http_event(ip, "/admin")).is_none());
        }
    }

    #[test]
    fn medium_severity_below_2x_threshold() {
        // Use only non-sensitive paths to ensure severity is not elevated
        // by a sensitive hit. Pre-fill 4 distinct (under threshold), the
        // 5th call hits threshold and should be medium severity.
        let mut det = WordlistScanDetector::new("test", 5, 60);
        let ip = external_ip();
        for path in ["/console", "/jenkins", "/druid/", "/solr/"] {
            assert!(det.process(&http_event(ip, path)).is_none());
        }
        let result = det.process(&http_event(ip, "/error_log"));
        assert!(result.is_some());
        let inc = result.unwrap();
        assert!(matches!(inc.severity, Severity::Medium | Severity::High));
        assert!(!matches!(inc.severity, Severity::Critical));
    }

    #[test]
    fn ignores_non_wordlist_paths() {
        let mut det = WordlistScanDetector::new("test", 3, 60);
        let ip = external_ip();
        for path in ["/products", "/about", "/contact", "/blog/post/1"] {
            assert!(det.process(&http_event(ip, path)).is_none());
        }
    }

    #[test]
    fn ignores_non_http_events() {
        let mut det = WordlistScanDetector::new("test", 3, 60);
        let mut ev = http_event(external_ip(), "/admin");
        ev.kind = "shell.command_exec".into();
        assert!(det.process(&ev).is_none());
    }
}
