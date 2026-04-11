//! Threat intelligence matching detector.
//!
//! Checks every event against loaded datasets (IPs, domains, JA3, hashes, URLs)
//! in O(1) per lookup. Generates high-severity incidents when matches are found.
//!
//! MITRE ATT&CK: multiple (depends on the IOC type and context).

use chrono::{DateTime, Utc};
use innerwarden_core::{
    entities::EntityRef,
    event::{Event, Severity},
    incident::Incident,
};
use std::collections::HashMap;

use super::datasets::{DatasetMatch, Datasets};

pub struct ThreatIntelDetector {
    host: String,
    /// Cooldown per matched value to prevent alert storms.
    alerted: HashMap<String, DateTime<Utc>>,
    cooldown_secs: i64,
}

impl ThreatIntelDetector {
    pub fn new(host: impl Into<String>, cooldown_secs: i64) -> Self {
        Self {
            host: host.into(),
            alerted: HashMap::new(),
            cooldown_secs,
        }
    }

    /// Check an event against all datasets. Returns an incident if a match is found.
    pub fn process(&mut self, event: &Event, datasets: &Datasets) -> Option<Incident> {
        if !datasets.is_loaded() {
            return None;
        }

        let now = event.ts;

        // Check IPs in event details
        for key in &["src_ip", "dst_ip", "ip", "target_ip", "remote_ip"] {
            if let Some(ip) = event.details.get(*key).and_then(|v| v.as_str()) {
                if let Some(m) = datasets.check_ip(ip) {
                    return self.emit(ip, &m, key, event, now);
                }
            }
        }

        // Check domains (DNS queries, HTTP Host header)
        for key in &["domain", "host", "query_name", "hostname"] {
            if let Some(domain) = event.details.get(*key).and_then(|v| v.as_str()) {
                if let Some(m) = datasets.check_domain(domain) {
                    return self.emit(domain, &m, key, event, now);
                }
            }
        }

        // Check JA3 fingerprints (TLS events)
        if let Some(ja3) = event.details.get("ja3").and_then(|v| v.as_str()) {
            if let Some(m) = datasets.check_ja3(ja3) {
                return self.emit(ja3, &m, "ja3", event, now);
            }
        }

        // Check file hashes
        for key in &["sha256", "hash", "file_hash"] {
            if let Some(hash) = event.details.get(*key).and_then(|v| v.as_str()) {
                if let Some(m) = datasets.check_hash(hash) {
                    return self.emit(hash, &m, key, event, now);
                }
            }
        }

        // Check URLs
        if let Some(url) = event.details.get("url").and_then(|v| v.as_str()) {
            if let Some(m) = datasets.check_url(url) {
                return self.emit(url, &m, "url", event, now);
            }
        }

        None
    }

    fn emit(
        &mut self,
        value: &str,
        m: &DatasetMatch,
        field: &str,
        event: &Event,
        now: DateTime<Utc>,
    ) -> Option<Incident> {
        let key = format!("{}:{}", m.dataset, value);

        // Cooldown
        if let Some(&last) = self.alerted.get(&key) {
            if (now - last).num_seconds() < self.cooldown_secs {
                return None;
            }
        }
        self.alerted.insert(key, now);

        // Prune old cooldowns
        if self.alerted.len() > 1000 {
            let cutoff = now - chrono::Duration::seconds(self.cooldown_secs);
            self.alerted.retain(|_, t| *t > cutoff);
        }

        let severity = match m.dataset {
            "tor_exit" => Severity::Medium,
            _ => Severity::High,
        };

        let title = match m.dataset {
            "threat_ip" => format!("Threat intel match: IP {value} in malicious feed"),
            "tor_exit" => format!("Tor exit node detected: {value}"),
            "threat_domain" => format!("Threat intel match: domain {value} in malicious feed"),
            "threat_hash" => format!("Threat intel match: file hash {value} in malicious feed"),
            "threat_ja3" => {
                format!("Threat intel match: TLS fingerprint {value} matches known malware")
            }
            "threat_url" => format!("Threat intel match: URL {value} in malicious feed"),
            _ => format!("Threat intel match: {value}"),
        };

        let entity = match m.dataset {
            "threat_ip" | "tor_exit" => EntityRef::ip(value.to_string()),
            "threat_domain" => EntityRef::service(value.to_string()),
            _ => EntityRef::path(value.to_string()),
        };

        Some(Incident {
            ts: now,
            host: self.host.clone(),
            incident_id: format!(
                "threat_intel:{}:{}:{}",
                m.dataset,
                &value[..value.len().min(30)],
                now.format("%Y-%m-%dT%H:%MZ")
            ),
            severity,
            title,
            summary: format!(
                "Event field '{field}' value '{value}' matched threat intelligence dataset '{}'. \
                 Event kind: {}. This indicator is associated with known malicious activity.",
                m.dataset, event.kind
            ),
            evidence: serde_json::json!({
                "dataset": m.dataset,
                "matched_field": field,
                "matched_value": value,
                "event_kind": event.kind,
                "event_source": event.source,
            }),
            recommended_checks: vec![
                format!("Investigate connections to/from {value}"),
                "Check if this is a known false positive (VPN, CDN, shared hosting)".into(),
                "Correlate with other incidents from the same source".into(),
                format!("Block if confirmed malicious: innerwarden action block-ip {value}"),
            ],
            tags: vec!["threat_intel".into(), m.dataset.to_string()],
            entities: vec![entity],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_event(kind: &str, details: serde_json::Value) -> Event {
        Event {
            ts: Utc::now(),
            host: "test".into(),
            source: "test".into(),
            kind: kind.into(),
            severity: Severity::Info,
            summary: String::new(),
            details,
            tags: Vec::new(),
            entities: Vec::new(),
        }
    }

    #[test]
    fn test_matches_ip() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("ips.txt"), "1.2.3.4\n").unwrap();
        let ds = Datasets::load(dir.path(), 3600);
        let mut det = ThreatIntelDetector::new("host1", 300);

        let ev = make_event(
            "network.outbound_connect",
            serde_json::json!({"dst_ip": "1.2.3.4", "dst_port": 443}),
        );
        let result = det.process(&ev, &ds);
        assert!(result.is_some());
        let inc = result.unwrap();
        assert!(inc.title.contains("1.2.3.4"));
        assert_eq!(inc.severity, Severity::High);
    }

    #[test]
    fn test_matches_domain() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("domains.txt"), "evil.com\n").unwrap();
        let ds = Datasets::load(dir.path(), 3600);
        let mut det = ThreatIntelDetector::new("host1", 300);

        let ev = make_event("dns.query", serde_json::json!({"domain": "c2.evil.com"}));
        let result = det.process(&ev, &ds);
        assert!(result.is_some()); // parent domain match
    }

    #[test]
    fn test_tor_exit_medium_severity() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("tor-exits.txt"), "9.9.9.9\n").unwrap();
        let ds = Datasets::load(dir.path(), 3600);
        let mut det = ThreatIntelDetector::new("host1", 300);

        let ev = make_event(
            "network.inbound_connect",
            serde_json::json!({"src_ip": "9.9.9.9"}),
        );
        let result = det.process(&ev, &ds);
        assert!(result.is_some());
        assert_eq!(result.unwrap().severity, Severity::Medium);
    }

    #[test]
    fn test_cooldown() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("ips.txt"), "1.1.1.1\n").unwrap();
        let ds = Datasets::load(dir.path(), 3600);
        let mut det = ThreatIntelDetector::new("host1", 300);

        let ev = make_event("test", serde_json::json!({"src_ip": "1.1.1.1"}));
        assert!(det.process(&ev, &ds).is_some()); // first: alert
        assert!(det.process(&ev, &ds).is_none()); // second: cooldown
    }

    #[test]
    fn test_no_match() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("ips.txt"), "1.2.3.4\n").unwrap();
        let ds = Datasets::load(dir.path(), 3600);
        let mut det = ThreatIntelDetector::new("host1", 300);

        let ev = make_event("test", serde_json::json!({"src_ip": "8.8.8.8"}));
        assert!(det.process(&ev, &ds).is_none());
    }
}
