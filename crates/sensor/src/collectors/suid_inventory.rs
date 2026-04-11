//! SUID binary inventory collector.
//!
//! Periodically scans the filesystem for setuid/setgid binaries and
//! maintains a baseline. Alerts when new SUID binaries appear,
//! especially in suspicious paths (/tmp, /dev/shm).

use std::collections::HashMap;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use chrono::Utc;
use innerwarden_core::entities::EntityRef;
use innerwarden_core::event::{Event, Severity};
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;
use tracing::info;

/// Paths to scan for SUID binaries.
const SCAN_PATHS: &[&str] = &[
    "/usr/bin",
    "/usr/sbin",
    "/usr/local/bin",
    "/usr/local/sbin",
    "/usr/libexec",
    "/bin",
    "/sbin",
    "/opt",
    "/tmp",
    "/var/tmp",
    "/dev/shm",
];

/// Dangerous paths where SUID binaries should never exist.
const DANGER_PATHS: &[&str] = &["/tmp", "/var/tmp", "/dev/shm", "/home", "/root"];

#[derive(Debug, Clone)]
struct SuidBinary {
    path: String,
    mode: u32,
    uid: u32,
    size: u64,
    sha256: String,
}

pub async fn run(tx: mpsc::Sender<Event>, host_id: String, interval_secs: u64) {
    info!("suid_inventory: starting (interval: {interval_secs}s)");

    // Build initial baseline
    let mut baseline: HashMap<String, SuidBinary> = HashMap::new();
    let initial = scan_suid_binaries();
    for bin in &initial {
        baseline.insert(bin.path.clone(), bin.clone());
    }
    info!("suid_inventory: baseline {} SUID binaries", baseline.len());

    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(interval_secs)).await;

        let current = scan_suid_binaries();
        let now = Utc::now();

        for bin in &current {
            let is_new = !baseline.contains_key(&bin.path);
            let hash_changed = baseline
                .get(&bin.path)
                .map(|b| b.sha256 != bin.sha256)
                .unwrap_or(false);

            if !is_new && !hash_changed {
                continue;
            }

            let in_danger_path = DANGER_PATHS.iter().any(|p| bin.path.starts_with(p));

            let severity = if in_danger_path {
                Severity::Critical
            } else if is_new {
                Severity::High
            } else {
                Severity::Medium // hash changed
            };

            let action = if is_new { "new_suid" } else { "suid_modified" };

            let event = Event {
                ts: now,
                host: host_id.clone(),
                source: "suid_inventory".into(),
                kind: format!("file.{action}"),
                severity,
                summary: format!(
                    "SUID binary {}: {} (mode: {:o}, sha256: {})",
                    action,
                    bin.path,
                    bin.mode,
                    &bin.sha256[..16]
                ),
                details: serde_json::json!({
                    "action": action,
                    "path": bin.path,
                    "mode": format!("{:o}", bin.mode),
                    "uid": bin.uid,
                    "size": bin.size,
                    "sha256": bin.sha256,
                    "in_danger_path": in_danger_path,
                }),
                tags: vec!["suid".into(), "inventory".into()],
                entities: vec![EntityRef::path(bin.path.clone())],
            };

            let _ = tx.send(event).await;
            baseline.insert(bin.path.clone(), bin.clone());
        }
    }
}

fn scan_suid_binaries() -> Vec<SuidBinary> {
    let mut results = Vec::new();

    for scan_path in SCAN_PATHS {
        let path = Path::new(scan_path);
        if !path.exists() {
            continue;
        }
        scan_dir_recursive(path, &mut results, 3); // max depth 3
    }

    results
}

fn scan_dir_recursive(dir: &Path, results: &mut Vec<SuidBinary>, depth: u32) {
    if depth == 0 {
        return;
    }

    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };

    for entry in entries.flatten() {
        let path = entry.path();

        if path.is_dir() {
            scan_dir_recursive(&path, results, depth - 1);
            continue;
        }

        if !path.is_file() {
            continue;
        }

        let Ok(meta) = path.metadata() else {
            continue;
        };

        let mode = meta.permissions().mode();

        // Check for SUID (0o4000) or SGID (0o2000)
        if mode & 0o6000 == 0 {
            continue;
        }

        let sha256 = match compute_sha256(&path) {
            Some(h) => h,
            None => continue,
        };

        results.push(SuidBinary {
            path: path.to_string_lossy().to_string(),
            mode,
            uid: meta_uid(&meta),
            size: meta.len(),
            sha256,
        });
    }
}

fn compute_sha256(path: &Path) -> Option<String> {
    let data = std::fs::read(path).ok()?;
    if data.len() > 100_000_000 {
        return None; // Skip files >100MB
    }
    let mut hasher = Sha256::new();
    hasher.update(&data);
    Some(format!("{:x}", hasher.finalize()))
}

#[cfg(unix)]
fn meta_uid(meta: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::MetadataExt;
    meta.uid()
}

#[cfg(not(unix))]
fn meta_uid(_meta: &std::fs::Metadata) -> u32 {
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_danger_paths() {
        assert!(DANGER_PATHS.iter().any(|p| "/tmp/evil".starts_with(p)));
        assert!(DANGER_PATHS
            .iter()
            .any(|p| "/dev/shm/backdoor".starts_with(p)));
        assert!(!DANGER_PATHS.iter().any(|p| "/usr/bin/sudo".starts_with(p)));
    }
}
