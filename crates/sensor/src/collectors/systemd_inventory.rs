//! Systemd unit inventory collector.
//!
//! Baselines all enabled/running systemd units at startup and polls
//! for new units. Detects persistence mechanisms that existed before
//! InnerWarden was installed, or units loaded from suspicious paths.

use std::collections::HashSet;

use chrono::Utc;
use innerwarden_core::entities::EntityRef;
use innerwarden_core::event::{Event, Severity};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

/// Suspicious paths for systemd unit files.
const SUSPICIOUS_UNIT_PATHS: &[&str] = &[
    "/tmp/",
    "/var/tmp/",
    "/dev/shm/",
    "/home/",
    "/root/",
];

#[derive(Debug, Clone)]
struct SystemdUnit {
    name: String,
    load_state: String,
    active_state: String,
    sub_state: String,
    fragment_path: String,
}

pub async fn run(tx: mpsc::Sender<Event>, host_id: String, interval_secs: u64) {
    info!("systemd_inventory: starting (interval: {interval_secs}s)");

    // Build baseline
    let mut baseline: HashSet<String> = HashSet::new();
    let initial = list_systemd_units();
    for unit in &initial {
        baseline.insert(unit.name.clone());
    }
    info!("systemd_inventory: baseline {} units", baseline.len());

    // Check existing units for suspicious paths on first run
    for unit in &initial {
        if is_suspicious_path(&unit.fragment_path) {
            let event = build_event(
                &unit,
                "suspicious_existing_unit",
                Severity::High,
                &host_id,
                &format!(
                    "Existing systemd unit '{}' loaded from suspicious path: {}",
                    unit.name, unit.fragment_path
                ),
            );
            let _ = tx.send(event).await;
        }
    }

    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(interval_secs)).await;

        let current = list_systemd_units();

        for unit in &current {
            if baseline.contains(&unit.name) {
                continue;
            }

            baseline.insert(unit.name.clone());

            let in_suspicious = is_suspicious_path(&unit.fragment_path);

            let severity = if in_suspicious {
                Severity::Critical
            } else {
                Severity::High
            };

            let event = build_event(
                &unit,
                "new_systemd_unit",
                severity,
                &host_id,
                &format!(
                    "New systemd unit detected: {} (state: {}/{}, path: {})",
                    unit.name, unit.active_state, unit.sub_state, unit.fragment_path
                ),
            );

            let _ = tx.send(event).await;
        }
    }
}

fn build_event(
    unit: &SystemdUnit,
    action: &str,
    severity: Severity,
    host_id: &str,
    summary: &str,
) -> Event {
    Event {
        ts: Utc::now(),
        host: host_id.to_string(),
        source: "systemd_inventory".into(),
        kind: format!("system.{action}"),
        severity,
        summary: summary.to_string(),
        details: serde_json::json!({
            "action": action,
            "unit_name": unit.name,
            "load_state": unit.load_state,
            "active_state": unit.active_state,
            "sub_state": unit.sub_state,
            "fragment_path": unit.fragment_path,
            "suspicious_path": is_suspicious_path(&unit.fragment_path),
        }),
        tags: vec!["systemd".into(), "inventory".into(), "persistence".into()],
        entities: vec![EntityRef::service(unit.name.clone())],
    }
}

fn is_suspicious_path(path: &str) -> bool {
    SUSPICIOUS_UNIT_PATHS.iter().any(|p| path.starts_with(p))
}

fn list_systemd_units() -> Vec<SystemdUnit> {
    let output = match std::process::Command::new("systemctl")
        .args(["list-units", "--type=service", "--all", "--no-pager", "--plain", "--no-legend"])
        .output()
    {
        Ok(o) if o.status.success() => o,
        _ => return Vec::new(),
    };

    let text = String::from_utf8_lossy(&output.stdout);
    let mut units = Vec::new();

    for line in text.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 4 {
            continue;
        }

        let name = fields[0].to_string();
        let load_state = fields[1].to_string();
        let active_state = fields[2].to_string();
        let sub_state = fields[3].to_string();

        // Get the fragment path
        let fragment_path = get_unit_path(&name);

        units.push(SystemdUnit {
            name,
            load_state,
            active_state,
            sub_state,
            fragment_path,
        });
    }

    units
}

fn get_unit_path(unit_name: &str) -> String {
    let output = std::process::Command::new("systemctl")
        .args(["show", "-p", "FragmentPath", "--value", unit_name])
        .output();

    match output {
        Ok(o) if o.status.success() => {
            String::from_utf8_lossy(&o.stdout).trim().to_string()
        }
        _ => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_suspicious_paths() {
        assert!(is_suspicious_path("/tmp/evil.service"));
        assert!(is_suspicious_path("/dev/shm/backdoor.service"));
        assert!(is_suspicious_path("/home/user/.config/systemd/user/mal.service"));
        assert!(!is_suspicious_path("/etc/systemd/system/nginx.service"));
        assert!(!is_suspicious_path("/usr/lib/systemd/system/sshd.service"));
    }
}
