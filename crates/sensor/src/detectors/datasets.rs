//! Threat intelligence datasets with O(1) lookup.
//!
//! Loads external threat feeds (IPs, domains, hashes, JA3 fingerprints) into
//! HashSets for instant matching against live events. Hot-reloads from disk
//! periodically without restart.
//!
//! Data sources (all free, public):
//! - abuse.ch: URLhaus, Feodo Tracker, ThreatFox, SSL Blacklist
//! - Emerging Threats: compromised IPs
//! - Blocklist.de: attacker IPs
//! - Spamhaus DROP: hijacked IP blocks
//! - Tor exit nodes
//! - FireHOL aggregated lists
//! - JA3er.com: malware TLS fingerprints
//!
//! File format: one entry per line (comments start with # or //).
//! Stored in /var/lib/innerwarden/datasets/

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::Instant;

use tracing::{debug, info, warn};

/// All loaded datasets for O(1) matching.
pub struct Datasets {
    /// Malicious IP addresses (IPv4 strings).
    pub ips: HashSet<String>,
    /// Malicious domains (lowercase).
    pub domains: HashSet<String>,
    /// Malicious file hashes (SHA-256, lowercase hex).
    pub sha256: HashSet<String>,
    /// Malicious TLS fingerprints (JA3 MD5 hashes, lowercase hex).
    pub ja3: HashSet<String>,
    /// Malicious URLs (lowercase).
    pub urls: HashSet<String>,
    /// Tor exit node IPs.
    pub tor_exits: HashSet<String>,
    /// Dataset directory.
    dir: PathBuf,
    /// Last reload timestamp.
    last_reload: Instant,
    /// Reload interval (seconds).
    reload_interval_secs: u64,
}

/// Result of checking an event against datasets.
#[derive(Debug)]
pub struct DatasetMatch {
    pub dataset: &'static str,
    #[allow(dead_code)]
    // returned to callers for future enrichment; currently only `dataset` is consumed
    pub value: String,
}

impl Datasets {
    /// Load all datasets from a directory. Files are plain text, one entry per line.
    pub fn load(dir: &Path, reload_interval_secs: u64) -> Self {
        let mut ds = Self {
            ips: HashSet::new(),
            domains: HashSet::new(),
            sha256: HashSet::new(),
            ja3: HashSet::new(),
            urls: HashSet::new(),
            tor_exits: HashSet::new(),
            dir: dir.to_path_buf(),
            last_reload: Instant::now(),
            reload_interval_secs,
        };
        ds.reload();
        ds
    }

    /// Reload datasets from disk if the interval has elapsed.
    pub fn maybe_reload(&mut self) {
        if self.last_reload.elapsed().as_secs() >= self.reload_interval_secs {
            self.reload();
        }
    }

    /// Force reload all datasets from disk.
    pub fn reload(&mut self) {
        if !self.dir.exists() {
            debug!(dir = %self.dir.display(), "datasets dir not found, skipping");
            return;
        }

        self.ips = load_set(&self.dir.join("ips.txt"));
        self.domains = load_set_lowercase(&self.dir.join("domains.txt"));
        self.sha256 = load_set_lowercase(&self.dir.join("sha256.txt"));
        self.ja3 = load_set_lowercase(&self.dir.join("ja3.txt"));
        self.urls = load_set_lowercase(&self.dir.join("urls.txt"));
        self.tor_exits = load_set(&self.dir.join("tor-exits.txt"));

        // Also load any additional files matching pattern *-ips.txt, *-domains.txt etc
        if let Ok(entries) = std::fs::read_dir(&self.dir) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if name.ends_with("-ips.txt") || name.ends_with("_ips.txt") {
                    self.ips.extend(load_set(&entry.path()));
                } else if name.ends_with("-domains.txt") || name.ends_with("_domains.txt") {
                    self.domains.extend(load_set_lowercase(&entry.path()));
                } else if name.ends_with("-sha256.txt") || name.ends_with("_sha256.txt") {
                    self.sha256.extend(load_set_lowercase(&entry.path()));
                } else if name.ends_with("-ja3.txt") || name.ends_with("_ja3.txt") {
                    self.ja3.extend(load_set_lowercase(&entry.path()));
                }
            }
        }

        let total = self.ips.len()
            + self.domains.len()
            + self.sha256.len()
            + self.ja3.len()
            + self.urls.len()
            + self.tor_exits.len();

        if total > 0 {
            info!(
                ips = self.ips.len(),
                domains = self.domains.len(),
                sha256 = self.sha256.len(),
                ja3 = self.ja3.len(),
                urls = self.urls.len(),
                tor_exits = self.tor_exits.len(),
                total,
                "threat datasets loaded"
            );
        }

        self.last_reload = Instant::now();
    }

    /// Check an IP against all IP datasets.
    pub fn check_ip(&self, ip: &str) -> Option<DatasetMatch> {
        if self.ips.contains(ip) {
            return Some(DatasetMatch {
                dataset: "threat_ip",
                value: ip.to_string(),
            });
        }
        if self.tor_exits.contains(ip) {
            return Some(DatasetMatch {
                dataset: "tor_exit",
                value: ip.to_string(),
            });
        }
        None
    }

    /// Check a domain against the domain dataset.
    pub fn check_domain(&self, domain: &str) -> Option<DatasetMatch> {
        let lower = domain.to_lowercase();
        // Exact match
        if self.domains.contains(&lower) {
            return Some(DatasetMatch {
                dataset: "threat_domain",
                value: lower,
            });
        }
        // Parent domain match (e.g., evil.com matches sub.evil.com)
        let parts: Vec<&str> = lower.split('.').collect();
        for i in 1..parts.len().saturating_sub(1) {
            let parent = parts[i..].join(".");
            if self.domains.contains(&parent) {
                return Some(DatasetMatch {
                    dataset: "threat_domain",
                    value: format!("{lower} (parent: {parent})"),
                });
            }
        }
        None
    }

    /// Check a file hash against the SHA-256 dataset.
    pub fn check_hash(&self, hash: &str) -> Option<DatasetMatch> {
        let lower = hash.to_lowercase();
        if self.sha256.contains(&lower) {
            Some(DatasetMatch {
                dataset: "threat_hash",
                value: lower,
            })
        } else {
            None
        }
    }

    /// Check a JA3 fingerprint against the dataset.
    pub fn check_ja3(&self, ja3: &str) -> Option<DatasetMatch> {
        let lower = ja3.to_lowercase();
        if self.ja3.contains(&lower) {
            Some(DatasetMatch {
                dataset: "threat_ja3",
                value: lower,
            })
        } else {
            None
        }
    }

    /// Check a URL against the dataset.
    pub fn check_url(&self, url: &str) -> Option<DatasetMatch> {
        let lower = url.to_lowercase();
        if self.urls.contains(&lower) {
            return Some(DatasetMatch {
                dataset: "threat_url",
                value: lower,
            });
        }
        // Also check if domain part matches
        if let Some(domain) = extract_domain_from_url(&lower) {
            if let Some(m) = self.check_domain(&domain) {
                return Some(m);
            }
        }
        None
    }

    /// Total entries across all datasets.
    pub fn total_entries(&self) -> usize {
        self.ips.len()
            + self.domains.len()
            + self.sha256.len()
            + self.ja3.len()
            + self.urls.len()
            + self.tor_exits.len()
    }

    /// Is any dataset loaded?
    pub fn is_loaded(&self) -> bool {
        self.total_entries() > 0
    }
}

/// Load a text file into a HashSet. One entry per line.
/// Skips comments (#, //) and empty lines. Strips whitespace.
fn load_set(path: &Path) -> HashSet<String> {
    let Ok(content) = std::fs::read_to_string(path) else {
        return HashSet::new();
    };
    content
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#') && !l.starts_with("//"))
        .map(|l| {
            // Handle CSV: take first column only
            l.split(',').next().unwrap_or(l).trim().to_string()
        })
        .filter(|l| !l.is_empty())
        .collect()
}

/// Load a text file into a HashSet, lowercasing all entries.
fn load_set_lowercase(path: &Path) -> HashSet<String> {
    let Ok(content) = std::fs::read_to_string(path) else {
        return HashSet::new();
    };
    content
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#') && !l.starts_with("//"))
        .map(|l| l.split(',').next().unwrap_or(l).trim().to_lowercase())
        .filter(|l| !l.is_empty())
        .collect()
}

/// Extract domain from a URL string.
fn extract_domain_from_url(url: &str) -> Option<String> {
    let without_scheme = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);
    let domain = without_scheme.split('/').next()?;
    let domain = domain.split(':').next()?; // Remove port
    if domain.is_empty() {
        None
    } else {
        Some(domain.to_string())
    }
}

/// Download a dataset from a URL and save to the datasets directory.
/// Used by the feed updater.
pub fn download_feed(url: &str, dest: &Path) -> Result<usize, String> {
    let resp = ureq::get(url)
        .call()
        .map_err(|e| format!("download {url}: {e}"))?;

    let body = resp
        .into_body()
        .read_to_string()
        .map_err(|e| format!("read body: {e}"))?;

    let lines: Vec<&str> = body
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#') && !l.starts_with("//"))
        .collect();

    let count = lines.len();

    std::fs::write(dest, lines.join("\n")).map_err(|e| format!("write {}: {e}", dest.display()))?;

    Ok(count)
}

/// Feed definitions: URL + destination filename.
pub const FEEDS: &[(&str, &str, &str)] = &[
    // (name, url, filename)
    (
        "abuse.ch Feodo Tracker",
        "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt",
        "feodo-ips.txt",
    ),
    (
        "Blocklist.de (all)",
        "https://lists.blocklist.de/lists/all.txt",
        "blocklist-de-ips.txt",
    ),
    (
        "Spamhaus DROP",
        "https://www.spamhaus.org/drop/drop.txt",
        "spamhaus-drop-ips.txt",
    ),
    (
        "Tor Exit Nodes",
        "https://check.torproject.org/torbulkexitlist",
        "tor-exits.txt",
    ),
    (
        "abuse.ch SSL Blacklist",
        "https://sslbl.abuse.ch/blacklist/sslipblacklist.txt",
        "sslbl-ips.txt",
    ),
    (
        "DShield Top 20",
        "https://www.dshield.org/block.txt",
        "dshield-ips.txt",
    ),
    (
        "abuse.ch URLhaus",
        "https://urlhaus.abuse.ch/downloads/text_online/",
        "urlhaus-urls.txt",
    ),
    (
        "abuse.ch ThreatFox IOCs (IPs)",
        "https://threatfox.abuse.ch/downloads/hostfile/",
        "threatfox-domains.txt",
    ),
];

/// Update all feeds. Returns (success_count, total_entries).
pub fn update_all_feeds(datasets_dir: &Path) -> (usize, usize) {
    std::fs::create_dir_all(datasets_dir).ok();

    let mut success = 0;
    let mut total = 0;

    for (name, url, filename) in FEEDS {
        let dest = datasets_dir.join(filename);
        match download_feed(url, &dest) {
            Ok(count) => {
                info!(feed = name, entries = count, file = %dest.display(), "feed updated");
                success += 1;
                total += count;
            }
            Err(e) => {
                warn!(feed = name, error = %e, "feed update failed");
            }
        }
    }

    (success, total)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_set_skips_comments() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.txt");
        std::fs::write(&path, "# Comment\n1.2.3.4\n// Another comment\n5.6.7.8\n\n").unwrap();
        let set = load_set(&path);
        assert_eq!(set.len(), 2);
        assert!(set.contains("1.2.3.4"));
        assert!(set.contains("5.6.7.8"));
    }

    #[test]
    fn test_load_csv_first_column() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.txt");
        std::fs::write(&path, "1.2.3.4,some,extra,data\n5.6.7.8,more\n").unwrap();
        let set = load_set(&path);
        assert!(set.contains("1.2.3.4"));
        assert!(set.contains("5.6.7.8"));
        assert!(!set.contains("some"));
    }

    #[test]
    fn test_check_ip() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("ips.txt"), "1.2.3.4\n10.0.0.1\n").unwrap();
        std::fs::write(dir.path().join("tor-exits.txt"), "9.9.9.9\n").unwrap();
        let ds = Datasets::load(dir.path(), 3600);
        assert!(ds.check_ip("1.2.3.4").is_some());
        assert!(ds.check_ip("9.9.9.9").is_some());
        assert!(ds.check_ip("8.8.8.8").is_none());
    }

    #[test]
    fn test_check_domain_parent() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("domains.txt"), "evil.com\nmalware.org\n").unwrap();
        let ds = Datasets::load(dir.path(), 3600);
        assert!(ds.check_domain("evil.com").is_some());
        assert!(ds.check_domain("sub.evil.com").is_some());
        assert!(ds.check_domain("safe.org").is_none());
    }

    #[test]
    fn test_check_ja3() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("ja3.txt"), "abc123def456\n").unwrap();
        let ds = Datasets::load(dir.path(), 3600);
        assert!(ds.check_ja3("ABC123DEF456").is_some()); // case insensitive
        assert!(ds.check_ja3("unknown").is_none());
    }

    #[test]
    fn test_extract_domain() {
        assert_eq!(
            extract_domain_from_url("https://evil.com/malware.exe"),
            Some("evil.com".into())
        );
        assert_eq!(
            extract_domain_from_url("http://1.2.3.4:8080/cmd"),
            Some("1.2.3.4".into())
        );
    }

    #[test]
    fn test_empty_dir() {
        let dir = tempfile::tempdir().unwrap();
        let ds = Datasets::load(dir.path(), 3600);
        assert_eq!(ds.total_entries(), 0);
        assert!(!ds.is_loaded());
    }

    #[test]
    fn test_wildcard_files() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("feodo-ips.txt"), "1.1.1.1\n").unwrap();
        std::fs::write(dir.path().join("blocklist-ips.txt"), "2.2.2.2\n").unwrap();
        let ds = Datasets::load(dir.path(), 3600);
        assert!(ds.check_ip("1.1.1.1").is_some());
        assert!(ds.check_ip("2.2.2.2").is_some());
    }
}
