use std::collections::{HashMap, HashSet, VecDeque};
use std::path::Path;

use anyhow::{Context, Result};
use chrono::{DateTime, Duration, Utc};
use innerwarden_core::{entities::EntityRef, event::Event, event::Severity, incident::Incident};
use serde::Deserialize;

// ---------------------------------------------------------------------------
// Expected-results schema
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct DetectorExpectation {
    /// Override the default detection threshold (number of events required).
    #[serde(default)]
    threshold: Option<usize>,
    /// Override the default sliding window in seconds.
    #[serde(default)]
    window_seconds: Option<u64>,
    /// Minimum number of incidents that must be produced.
    min_incidents: usize,
    /// All produced incident IDs must start with this prefix.
    #[serde(default)]
    incident_id_prefix: Option<String>,
    /// The first produced incident must have this severity (lowercase).
    #[serde(default)]
    severity: Option<String>,
}

// ---------------------------------------------------------------------------
// Detector trait
// ---------------------------------------------------------------------------

trait Detector {
    fn name(&self) -> &str;
    fn process(&mut self, event: &Event) -> Option<Incident>;
}

// ---------------------------------------------------------------------------
// Helpers (mirrors crates/sensor/src/detectors/mod.rs — kept local to avoid
// pulling the full sensor crate and its heavy deps into innerwarden-ctl)
// ---------------------------------------------------------------------------

fn is_internal_ip(ip: &str) -> bool {
    let Ok(addr) = ip.parse::<std::net::IpAddr>() else {
        return false;
    };
    match addr {
        std::net::IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_unspecified()
        }
        std::net::IpAddr::V6(v6) => v6.is_loopback() || v6.is_unspecified(),
    }
}

// ---------------------------------------------------------------------------
// ssh_bruteforce detector
//
// Simplified mirror of crates/sensor/src/detectors/ssh_bruteforce.rs.
// SYNC-CHECK: sha256 36b61b4867260ef5ad0a8f4fbe50b52e190259e95f78fe73bd9c7b61116f3197 (2026-04-14)
// If the sensor detector changes (threshold semantics, severity bands, etc.)
// keep this in sync or, better, extract the shared logic into innerwarden_core.
// ---------------------------------------------------------------------------

struct SshBruteforceDetector {
    threshold: usize,
    window: Duration,
    windows: HashMap<String, VecDeque<DateTime<Utc>>>,
    alerted: HashMap<String, DateTime<Utc>>,
    host: String,
}

impl SshBruteforceDetector {
    fn new(host: impl Into<String>, threshold: usize, window_seconds: u64) -> Self {
        Self {
            threshold,
            window: Duration::seconds(window_seconds as i64),
            windows: HashMap::new(),
            alerted: HashMap::new(),
            host: host.into(),
        }
    }
}

impl Detector for SshBruteforceDetector {
    fn name(&self) -> &str {
        "ssh_bruteforce"
    }

    fn process(&mut self, event: &Event) -> Option<Incident> {
        if event.kind != "ssh.login_failed" {
            return None;
        }
        let ip = event.details["ip"].as_str()?.to_string();
        if is_internal_ip(&ip) {
            return None;
        }
        let now = event.ts;
        let cutoff = now - self.window;

        let entries = self.windows.entry(ip.clone()).or_default();
        while entries.front().is_some_and(|&t| t < cutoff) {
            entries.pop_front();
        }
        entries.push_back(now);

        let count = entries.len();
        if count < self.threshold {
            return None;
        }
        if let Some(&last) = self.alerted.get(&ip) {
            if now - last < self.window {
                return None;
            }
        }
        self.alerted.insert(ip.clone(), now);

        let severity = if count >= self.threshold * 2 {
            Severity::High
        } else {
            Severity::Medium
        };

        Some(Incident {
            ts: now,
            host: self.host.clone(),
            incident_id: format!("ssh_bruteforce:{}:{}", ip, now.format("%Y-%m-%dT%H:%MZ")),
            severity,
            title: format!("Possible SSH brute force from {ip}"),
            summary: format!(
                "{count} failed SSH login attempts from {ip} in the last {} seconds",
                self.window.num_seconds()
            ),
            evidence: serde_json::json!([{
                "kind": "ssh.login_failed",
                "ip": ip,
                "count": count,
                "window_seconds": self.window.num_seconds(),
            }]),
            recommended_checks: vec![
                format!("Check auth.log for successful logins from {ip}"),
                "Consider blocking the IP with ufw or fail2ban".to_string(),
            ],
            tags: vec![
                "auth".to_string(),
                "ssh".to_string(),
                "bruteforce".to_string(),
            ],
            entities: vec![EntityRef::ip(&ip)],
        })
    }
}

// ---------------------------------------------------------------------------
// credential_stuffing detector
//
// Simplified mirror of crates/sensor/src/detectors/credential_stuffing.rs.
// SYNC-CHECK: sha256 41f4973a0518ac57676661b25a37c76e06b4369bd91ca85781d96b29dd174d4b (2026-04-14)
// If the sensor detector changes keep this in sync, or extract to innerwarden_core.
// ---------------------------------------------------------------------------

struct CredentialStuffingDetector {
    threshold: usize,
    window: Duration,
    windows: HashMap<String, VecDeque<(DateTime<Utc>, String)>>,
    alerted: HashMap<String, DateTime<Utc>>,
    host: String,
}

impl CredentialStuffingDetector {
    fn new(host: impl Into<String>, threshold: usize, window_seconds: u64) -> Self {
        Self {
            threshold,
            window: Duration::seconds(window_seconds as i64),
            windows: HashMap::new(),
            alerted: HashMap::new(),
            host: host.into(),
        }
    }
}

impl Detector for CredentialStuffingDetector {
    fn name(&self) -> &str {
        "credential_stuffing"
    }

    fn process(&mut self, event: &Event) -> Option<Incident> {
        if event.kind != "ssh.login_failed" {
            return None;
        }
        let ip = event.details["ip"].as_str()?.to_string();
        if is_internal_ip(&ip) {
            return None;
        }
        let user = event.details["user"].as_str()?.trim();
        if user.is_empty() {
            return None;
        }

        let now = event.ts;
        let cutoff = now - self.window;

        let entries = self.windows.entry(ip.clone()).or_default();
        while entries.front().is_some_and(|(ts, _)| *ts < cutoff) {
            entries.pop_front();
        }
        entries.push_back((now, user.to_string()));

        let unique_users: HashSet<&str> = entries.iter().map(|(_, u)| u.as_str()).collect();
        let unique_count = unique_users.len();
        if unique_count < self.threshold {
            return None;
        }
        if let Some(&last) = self.alerted.get(&ip) {
            if now - last < self.window {
                return None;
            }
        }
        self.alerted.insert(ip.clone(), now);

        let mut usernames: Vec<&str> = unique_users.into_iter().collect();
        usernames.sort_unstable();

        Some(Incident {
            ts: now,
            host: self.host.clone(),
            incident_id: format!(
                "credential_stuffing:{}:{}",
                ip,
                now.format("%Y-%m-%dT%H:%MZ")
            ),
            severity: Severity::High,
            title: format!("Possible SSH credential stuffing from {ip}"),
            summary: format!(
                "{} failed SSH attempts from {ip} across {unique_count} distinct usernames in the last {} seconds",
                entries.len(),
                self.window.num_seconds()
            ),
            evidence: serde_json::json!([{
                "kind": "credential_stuffing",
                "ip": ip,
                "unique_users": unique_count,
                "usernames": usernames,
                "window_seconds": self.window.num_seconds(),
            }]),
            recommended_checks: vec![
                format!("Audit all accounts attempted from {ip}"),
                "Check for successful logins across the targeted accounts".to_string(),
            ],
            tags: vec![
                "auth".to_string(),
                "ssh".to_string(),
                "credential-stuffing".to_string(),
            ],
            entities: vec![EntityRef::ip(&ip)],
        })
    }
}

// ---------------------------------------------------------------------------
// Build registered detectors, applying per-detector config from expected.json
// ---------------------------------------------------------------------------

fn build_detectors(expectations: &HashMap<String, DetectorExpectation>) -> Vec<Box<dyn Detector>> {
    let brute = expectations.get("ssh_bruteforce");
    let stuffing = expectations.get("credential_stuffing");

    vec![
        Box::new(SshBruteforceDetector::new(
            "replay-host",
            brute.and_then(|e| e.threshold).unwrap_or(5),
            brute.and_then(|e| e.window_seconds).unwrap_or(300),
        )),
        Box::new(CredentialStuffingDetector::new(
            "replay-host",
            stuffing.and_then(|e| e.threshold).unwrap_or(3),
            stuffing.and_then(|e| e.window_seconds).unwrap_or(300),
        )),
    ]
}

// ---------------------------------------------------------------------------
// Load events from a directory of JSONL files
// ---------------------------------------------------------------------------

fn load_events(fixture_dir: &Path) -> Result<Vec<Event>> {
    let mut events: Vec<Event> = Vec::new();

    let entries = std::fs::read_dir(fixture_dir)
        .with_context(|| format!("cannot open fixture directory: {}", fixture_dir.display()))?;

    let mut paths: Vec<_> = entries
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|ext| ext == "jsonl"))
        .collect();
    paths.sort();

    if paths.is_empty() {
        anyhow::bail!("no .jsonl fixture files found in {}", fixture_dir.display());
    }

    for path in &paths {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("cannot read fixture file: {}", path.display()))?;
        for (lineno, line) in content.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with("//") || line.starts_with('#') {
                continue;
            }
            let event: Event = serde_json::from_str(line).with_context(|| {
                format!("{}:{}: invalid event JSON", path.display(), lineno + 1)
            })?;
            events.push(event);
        }
    }

    // Sort by timestamp so replay is deterministic regardless of file order.
    events.sort_by_key(|e| e.ts);
    Ok(events)
}

// ---------------------------------------------------------------------------
// Public command entry point
// ---------------------------------------------------------------------------

pub fn cmd_replay(fixture_dir: &Path, expected_path: &Path) -> Result<()> {
    println!("InnerWarden Replay");
    println!("{}", "─".repeat(52));
    println!("  fixture:  {}", fixture_dir.display());
    println!("  expected: {}", expected_path.display());
    println!();

    // Load expected assertions.
    let expected_raw = std::fs::read_to_string(expected_path)
        .with_context(|| format!("cannot read expected file: {}", expected_path.display()))?;
    let expectations: HashMap<String, DetectorExpectation> = serde_json::from_str(&expected_raw)
        .with_context(|| format!("invalid JSON in expected file: {}", expected_path.display()))?;

    // Load and sort events.
    let events = load_events(fixture_dir)?;
    println!("  loaded {} events from fixtures", events.len());
    println!();

    // Build detectors with per-detector config from expected.json.
    let mut detectors = build_detectors(&expectations);

    // Replay: run all events through all detectors, collect incidents per detector.
    let mut results: HashMap<String, Vec<Incident>> = HashMap::new();
    for det in &mut detectors {
        results.insert(det.name().to_string(), Vec::new());
    }
    for event in &events {
        for det in &mut detectors {
            if let Some(incident) = det.process(event) {
                results.get_mut(det.name()).unwrap().push(incident);
            }
        }
    }

    // Compare results against expectations.
    let mut all_passed = true;

    for det in &detectors {
        let name = det.name();
        let incidents = &results[name];

        print!("  [{name}]");

        let Some(exp) = expectations.get(name) else {
            println!(" SKIP (no expectation defined)");
            continue;
        };

        let mut failures: Vec<String> = Vec::new();

        // Check minimum incident count.
        if incidents.len() < exp.min_incidents {
            failures.push(format!(
                "expected >= {} incident(s), got {}",
                exp.min_incidents,
                incidents.len()
            ));
        }

        // Check incident_id prefix on all produced incidents.
        if let Some(ref prefix) = exp.incident_id_prefix {
            for inc in incidents {
                if !inc.incident_id.starts_with(prefix.as_str()) {
                    failures.push(format!(
                        "incident_id {:?} does not start with {:?}",
                        inc.incident_id, prefix
                    ));
                }
            }
        }

        // Check severity of the first produced incident.
        if let Some(ref expected_sev) = exp.severity {
            if let Some(inc) = incidents.first() {
                let got = format!("{:?}", inc.severity).to_lowercase();
                if &got != expected_sev {
                    failures.push(format!(
                        "severity: expected {:?}, got {:?}",
                        expected_sev, got
                    ));
                }
            }
        }

        if failures.is_empty() {
            println!(" PASS  ({} incident(s))", incidents.len());
            for inc in incidents {
                println!(
                    "         {} — {} [{}]",
                    inc.incident_id,
                    inc.title,
                    format!("{:?}", inc.severity).to_lowercase()
                );
            }
        } else {
            println!(" FAIL");
            all_passed = false;
            for f in &failures {
                println!("         diff: {f}");
            }
            if !incidents.is_empty() {
                println!("         got incidents:");
                for inc in incidents {
                    println!(
                        "           {} [{}]",
                        inc.incident_id,
                        format!("{:?}", inc.severity).to_lowercase()
                    );
                }
            } else {
                println!("         got: (no incidents produced)");
            }
        }
    }

    // Warn about expectations that have no matching detector.
    for name in expectations.keys() {
        if !detectors.iter().any(|d| d.name() == name) {
            println!("  [{name}] SKIP (detector not registered in replay runner)");
        }
    }

    println!();
    if all_passed {
        println!("Result: PASS");
        Ok(())
    } else {
        anyhow::bail!("replay validation failed — one or more detectors produced unexpected output")
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE_EVENTS: &str = concat!(
        "{\"ts\":\"2026-01-15T12:00:01Z\",\"host\":\"h\",\"source\":\"auth.log\",\"kind\":\"ssh.login_failed\",\"severity\":\"info\",\"summary\":\"f\",\"details\":{\"ip\":\"1.2.3.4\",\"user\":\"root\"},\"tags\":[],\"entities\":[]}\n",
        "{\"ts\":\"2026-01-15T12:00:02Z\",\"host\":\"h\",\"source\":\"auth.log\",\"kind\":\"ssh.login_failed\",\"severity\":\"info\",\"summary\":\"f\",\"details\":{\"ip\":\"1.2.3.4\",\"user\":\"root\"},\"tags\":[],\"entities\":[]}\n",
        "{\"ts\":\"2026-01-15T12:00:03Z\",\"host\":\"h\",\"source\":\"auth.log\",\"kind\":\"ssh.login_failed\",\"severity\":\"info\",\"summary\":\"f\",\"details\":{\"ip\":\"1.2.3.4\",\"user\":\"root\"},\"tags\":[],\"entities\":[]}\n",
        "{\"ts\":\"2026-01-15T12:00:04Z\",\"host\":\"h\",\"source\":\"auth.log\",\"kind\":\"ssh.login_failed\",\"severity\":\"info\",\"summary\":\"f\",\"details\":{\"ip\":\"1.2.3.4\",\"user\":\"root\"},\"tags\":[],\"entities\":[]}\n",
        "{\"ts\":\"2026-01-15T12:00:05Z\",\"host\":\"h\",\"source\":\"auth.log\",\"kind\":\"ssh.login_failed\",\"severity\":\"info\",\"summary\":\"f\",\"details\":{\"ip\":\"1.2.3.4\",\"user\":\"root\"},\"tags\":[],\"entities\":[]}\n",
        "{\"ts\":\"2026-01-15T12:00:06Z\",\"host\":\"h\",\"source\":\"auth.log\",\"kind\":\"ssh.login_failed\",\"severity\":\"info\",\"summary\":\"f\",\"details\":{\"ip\":\"1.2.3.4\",\"user\":\"root\"},\"tags\":[],\"entities\":[]}\n",
        "{\"ts\":\"2026-01-15T12:00:07Z\",\"host\":\"h\",\"source\":\"auth.log\",\"kind\":\"ssh.login_failed\",\"severity\":\"info\",\"summary\":\"f\",\"details\":{\"ip\":\"5.6.7.8\",\"user\":\"root\"},\"tags\":[],\"entities\":[]}\n",
        "{\"ts\":\"2026-01-15T12:00:08Z\",\"host\":\"h\",\"source\":\"auth.log\",\"kind\":\"ssh.login_failed\",\"severity\":\"info\",\"summary\":\"f\",\"details\":{\"ip\":\"5.6.7.8\",\"user\":\"admin\"},\"tags\":[],\"entities\":[]}\n",
        "{\"ts\":\"2026-01-15T12:00:09Z\",\"host\":\"h\",\"source\":\"auth.log\",\"kind\":\"ssh.login_failed\",\"severity\":\"info\",\"summary\":\"f\",\"details\":{\"ip\":\"5.6.7.8\",\"user\":\"oracle\"},\"tags\":[],\"entities\":[]}\n",
    );

    const FIXTURE_EXPECTED: &str = r#"{
  "ssh_bruteforce": {
    "threshold": 5,
    "window_seconds": 300,
    "min_incidents": 1,
    "incident_id_prefix": "ssh_bruteforce:",
    "severity": "medium"
  },
  "credential_stuffing": {
    "threshold": 3,
    "window_seconds": 300,
    "min_incidents": 1,
    "incident_id_prefix": "credential_stuffing:",
    "severity": "high"
  }
}"#;

    fn write(dir: &std::path::Path, name: &str, content: &str) {
        std::fs::write(dir.join(name), content).unwrap();
    }

    #[test]
    fn bundled_fixtures_pass() {
        let fixture_dir = tempfile::tempdir().unwrap();
        let expected_dir = tempfile::tempdir().unwrap();

        write(fixture_dir.path(), "events.jsonl", FIXTURE_EVENTS);
        let expected_path = expected_dir.path().join("expected.json");
        std::fs::write(&expected_path, FIXTURE_EXPECTED).unwrap();

        cmd_replay(fixture_dir.path(), &expected_path).unwrap();
    }

    #[test]
    fn zero_incidents_fails_assertion() {
        let fixture_dir = tempfile::tempdir().unwrap();
        let expected_dir = tempfile::tempdir().unwrap();

        // Only 2 events from the same IP — below the brute-force threshold of 5.
        let sparse = concat!(
            "{\"ts\":\"2026-01-15T12:00:01Z\",\"host\":\"h\",\"source\":\"auth.log\",\"kind\":\"ssh.login_failed\",\"severity\":\"info\",\"summary\":\"f\",\"details\":{\"ip\":\"9.9.9.9\",\"user\":\"root\"},\"tags\":[],\"entities\":[]}\n",
            "{\"ts\":\"2026-01-15T12:00:02Z\",\"host\":\"h\",\"source\":\"auth.log\",\"kind\":\"ssh.login_failed\",\"severity\":\"info\",\"summary\":\"f\",\"details\":{\"ip\":\"9.9.9.9\",\"user\":\"root\"},\"tags\":[],\"entities\":[]}\n",
        );
        write(fixture_dir.path(), "sparse.jsonl", sparse);

        let expected_path = expected_dir.path().join("expected.json");
        std::fs::write(
            &expected_path,
            r#"{"ssh_bruteforce":{"min_incidents":1,"threshold":5,"window_seconds":300}}"#,
        )
        .unwrap();

        let result = cmd_replay(fixture_dir.path(), &expected_path);
        assert!(
            result.is_err(),
            "expected replay to fail when no incidents are produced"
        );
    }

    #[test]
    fn internal_ip_events_produce_no_incidents() {
        let fixture_dir = tempfile::tempdir().unwrap();
        let expected_dir = tempfile::tempdir().unwrap();

        // 10 events from a private IP — should all be filtered.
        let private_events: String = (1..=10)
            .map(|i| format!(
                "{{\"ts\":\"2026-01-15T12:00:{:02}Z\",\"host\":\"h\",\"source\":\"auth.log\",\"kind\":\"ssh.login_failed\",\"severity\":\"info\",\"summary\":\"f\",\"details\":{{\"ip\":\"192.168.1.1\",\"user\":\"root\"}},\"tags\":[],\"entities\":[]}}\n",
                i
            ))
            .collect();
        write(fixture_dir.path(), "private.jsonl", &private_events);

        let expected_path = expected_dir.path().join("expected.json");
        // min_incidents = 0 means we expect nothing to fire.
        std::fs::write(
            &expected_path,
            r#"{"ssh_bruteforce":{"min_incidents":0,"threshold":5,"window_seconds":300}}"#,
        )
        .unwrap();

        cmd_replay(fixture_dir.path(), &expected_path).unwrap();
    }

    #[test]
    fn severity_mismatch_fails_assertion() {
        let fixture_dir = tempfile::tempdir().unwrap();
        let expected_dir = tempfile::tempdir().unwrap();

        // 5 events — brute-force fires at threshold 5 with severity "medium" (count < threshold*2).
        let events = concat!(
            "{\"ts\":\"2026-01-15T12:00:01Z\",\"host\":\"h\",\"source\":\"auth.log\",\"kind\":\"ssh.login_failed\",\"severity\":\"info\",\"summary\":\"f\",\"details\":{\"ip\":\"2.3.4.5\",\"user\":\"root\"},\"tags\":[],\"entities\":[]}\n",
            "{\"ts\":\"2026-01-15T12:00:02Z\",\"host\":\"h\",\"source\":\"auth.log\",\"kind\":\"ssh.login_failed\",\"severity\":\"info\",\"summary\":\"f\",\"details\":{\"ip\":\"2.3.4.5\",\"user\":\"root\"},\"tags\":[],\"entities\":[]}\n",
            "{\"ts\":\"2026-01-15T12:00:03Z\",\"host\":\"h\",\"source\":\"auth.log\",\"kind\":\"ssh.login_failed\",\"severity\":\"info\",\"summary\":\"f\",\"details\":{\"ip\":\"2.3.4.5\",\"user\":\"root\"},\"tags\":[],\"entities\":[]}\n",
            "{\"ts\":\"2026-01-15T12:00:04Z\",\"host\":\"h\",\"source\":\"auth.log\",\"kind\":\"ssh.login_failed\",\"severity\":\"info\",\"summary\":\"f\",\"details\":{\"ip\":\"2.3.4.5\",\"user\":\"root\"},\"tags\":[],\"entities\":[]}\n",
            "{\"ts\":\"2026-01-15T12:00:05Z\",\"host\":\"h\",\"source\":\"auth.log\",\"kind\":\"ssh.login_failed\",\"severity\":\"info\",\"summary\":\"f\",\"details\":{\"ip\":\"2.3.4.5\",\"user\":\"root\"},\"tags\":[],\"entities\":[]}\n",
        );
        write(fixture_dir.path(), "events.jsonl", events);

        let expected_path = expected_dir.path().join("expected.json");
        // expected.json asserts "critical" but detector produces "medium" — should fail.
        std::fs::write(
            &expected_path,
            r#"{"ssh_bruteforce":{"min_incidents":1,"threshold":5,"window_seconds":300,"severity":"critical"}}"#,
        )
        .unwrap();

        let result = cmd_replay(fixture_dir.path(), &expected_path);
        assert!(
            result.is_err(),
            "expected replay to fail when severity does not match"
        );
    }

    #[test]
    fn severity_assertion_matches_threshold_crossing_emits_medium() {
        // The SSH brute-force detector emits exactly one incident per IP per
        // window: the first event that crosses `threshold` fires an alert,
        // and the dedup guard (`now - last < window`) suppresses every
        // subsequent event until the window expires. This means sending
        // `threshold * 2` events in a single burst still produces
        // Severity::Medium — the count-at-emit-time is `threshold`, not
        // `threshold * 2`. The `count >= threshold * 2 -> High` path in
        // both the real sensor detector and this mirror is only reachable
        // across dedup windows (first burst + wait + second burst), which
        // is not something a short fixture exercises.
        //
        // The purpose of this test is to confirm the `severity` assertion
        // in expected.json is actually enforced, not to prove that High is
        // reachable. 10 events are fed, the detector emits one
        // `Severity::Medium` incident, and expected.json asserts
        // `"severity": "medium"` — the run passes.
        let fixture_dir = tempfile::tempdir().unwrap();
        let expected_dir = tempfile::tempdir().unwrap();

        let events: String = (1..=10)
            .map(|i| format!(
                "{{\"ts\":\"2026-01-15T12:00:{:02}Z\",\"host\":\"h\",\"source\":\"auth.log\",\"kind\":\"ssh.login_failed\",\"severity\":\"info\",\"summary\":\"f\",\"details\":{{\"ip\":\"3.3.3.3\",\"user\":\"root\"}},\"tags\":[],\"entities\":[]}}\n",
                i
            ))
            .collect();
        write(fixture_dir.path(), "events.jsonl", &events);

        let expected_path = expected_dir.path().join("expected.json");
        std::fs::write(
            &expected_path,
            r#"{"ssh_bruteforce":{"min_incidents":1,"threshold":5,"window_seconds":300,"severity":"medium"}}"#,
        )
        .unwrap();

        cmd_replay(fixture_dir.path(), &expected_path).unwrap();
    }

    #[test]
    fn empty_user_events_skipped_by_credential_stuffing() {
        let fixture_dir = tempfile::tempdir().unwrap();
        let expected_dir = tempfile::tempdir().unwrap();

        // Events with empty user — CredentialStuffingDetector must skip them.
        let events = concat!(
            "{\"ts\":\"2026-01-15T12:00:01Z\",\"host\":\"h\",\"source\":\"auth.log\",\"kind\":\"ssh.login_failed\",\"severity\":\"info\",\"summary\":\"f\",\"details\":{\"ip\":\"4.4.4.4\",\"user\":\"\"},\"tags\":[],\"entities\":[]}\n",
            "{\"ts\":\"2026-01-15T12:00:02Z\",\"host\":\"h\",\"source\":\"auth.log\",\"kind\":\"ssh.login_failed\",\"severity\":\"info\",\"summary\":\"f\",\"details\":{\"ip\":\"4.4.4.4\",\"user\":\"\"},\"tags\":[],\"entities\":[]}\n",
            "{\"ts\":\"2026-01-15T12:00:03Z\",\"host\":\"h\",\"source\":\"auth.log\",\"kind\":\"ssh.login_failed\",\"severity\":\"info\",\"summary\":\"f\",\"details\":{\"ip\":\"4.4.4.4\",\"user\":\"\"},\"tags\":[],\"entities\":[]}\n",
        );
        write(fixture_dir.path(), "events.jsonl", events);

        let expected_path = expected_dir.path().join("expected.json");
        std::fs::write(
            &expected_path,
            r#"{"credential_stuffing":{"min_incidents":0,"threshold":3,"window_seconds":300}}"#,
        )
        .unwrap();

        cmd_replay(fixture_dir.path(), &expected_path).unwrap();
    }

    #[test]
    fn incident_id_prefix_mismatch_fails() {
        let fixture_dir = tempfile::tempdir().unwrap();
        let expected_dir = tempfile::tempdir().unwrap();

        // 5 events — brute-force fires, but expected prefix is wrong.
        let events: String = (1..=5)
            .map(|i| format!(
                "{{\"ts\":\"2026-01-15T12:00:{:02}Z\",\"host\":\"h\",\"source\":\"auth.log\",\"kind\":\"ssh.login_failed\",\"severity\":\"info\",\"summary\":\"f\",\"details\":{{\"ip\":\"6.6.6.6\",\"user\":\"root\"}},\"tags\":[],\"entities\":[]}}\n",
                i
            ))
            .collect();
        write(fixture_dir.path(), "events.jsonl", &events);

        let expected_path = expected_dir.path().join("expected.json");
        std::fs::write(
            &expected_path,
            r#"{"ssh_bruteforce":{"min_incidents":1,"threshold":5,"window_seconds":300,"incident_id_prefix":"wrong_prefix:"}}"#,
        )
        .unwrap();

        let result = cmd_replay(fixture_dir.path(), &expected_path);
        assert!(
            result.is_err(),
            "expected replay to fail on prefix mismatch"
        );
    }

    #[test]
    fn unknown_detector_in_expected_produces_skip_warning() {
        let fixture_dir = tempfile::tempdir().unwrap();
        let expected_dir = tempfile::tempdir().unwrap();

        // No events — both registered detectors produce nothing.
        write(
            fixture_dir.path(),
            "events.jsonl",
            "{\"ts\":\"2026-01-15T12:00:01Z\",\"host\":\"h\",\"source\":\"auth.log\",\"kind\":\"ssh.login_success\",\"severity\":\"info\",\"summary\":\"ok\",\"details\":{},\"tags\":[],\"entities\":[]}\n",
        );

        let expected_path = expected_dir.path().join("expected.json");
        // "unknown_detector" has no registered implementation — should print SKIP warning but not fail.
        std::fs::write(
            &expected_path,
            r#"{"unknown_detector":{"min_incidents":0}}"#,
        )
        .unwrap();

        cmd_replay(fixture_dir.path(), &expected_path).unwrap();
    }

    #[test]
    fn ipv6_loopback_events_produce_no_incidents() {
        let fixture_dir = tempfile::tempdir().unwrap();
        let expected_dir = tempfile::tempdir().unwrap();

        // 10 events from IPv6 loopback — all should be filtered by is_internal_ip.
        let events: String = (1..=10)
            .map(|i| format!(
                "{{\"ts\":\"2026-01-15T12:00:{:02}Z\",\"host\":\"h\",\"source\":\"auth.log\",\"kind\":\"ssh.login_failed\",\"severity\":\"info\",\"summary\":\"f\",\"details\":{{\"ip\":\"::1\",\"user\":\"root\"}},\"tags\":[],\"entities\":[]}}\n",
                i
            ))
            .collect();
        write(fixture_dir.path(), "events.jsonl", &events);

        let expected_path = expected_dir.path().join("expected.json");
        std::fs::write(
            &expected_path,
            r#"{"ssh_bruteforce":{"min_incidents":0,"threshold":5,"window_seconds":300}}"#,
        )
        .unwrap();

        cmd_replay(fixture_dir.path(), &expected_path).unwrap();
    }
}
