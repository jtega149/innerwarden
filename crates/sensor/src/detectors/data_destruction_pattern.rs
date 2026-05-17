//! Data destruction pattern detection (spec 050-PR6).
//!
//! Covers the **Impact** tactic of the MITRE Linux matrix — the last
//! step of the kill chain where the attacker erases data, wipes
//! disks, or denies recovery. These shapes are the smoking-gun
//! signature of ransomware-without-encryption, wiper malware, and
//! revenge-deletion by insiders.
//!
//! Sub-detections:
//!
//! 1. `rm_rf_user_data`: exec of `rm -rf` (or `rm -fr` / `rm --recursive --force`)
//!    against a path under user-data prefixes
//!    (`/home/`, `/var/lib/`, `/etc/`, `/root/`, `/srv/`, `/var/www/`,
//!    `/opt/`, `/data/`, `/mnt/`).
//!    Single-file `rm` of a path NOT under those prefixes → silenced.
//!    Operator-allowlisted parents (backup tools, ansible, terraform) → silenced.
//!
//! 2. `disk_wipe`: exec of `dd if=/dev/zero` or `dd if=/dev/urandom`
//!    with `of=/dev/sd[a-z]*` or `of=/dev/nvme*` or `of=/dev/xvd*`.
//!    Writing zeros/random to a block device is the textbook wipe.
//!
//! 3. `shred_burst`: exec of `shred` with the `-u` flag (deletes after
//!    overwrite) AND 3+ target paths.
//!
//! 4. `mkfs_on_running_volume`: exec of `mkfs.*` against a block device
//!    (`/dev/sd*`, `/dev/nvme*`, `/dev/xvd*`, `/dev/mapper/*`). Always
//!    suspicious post-boot since legit filesystem creation happens
//!    once during install.
//!
//! 5. `cryptsetup_luksformat`: exec of `cryptsetup luksFormat` against
//!    a block device. Attackers use LUKS to encrypt-then-throw-key
//!    (poor-man's wiper).
//!
//! All sub-detections share a 5-minute per-target cooldown and the
//! same anti-FP gates:
//!   - Parent comm in `{borgmatic, restic, duplicity, rclone, kopia,
//!     rdiff-backup, rsnapshot, ansible, salt-call, puppet,
//!     chef-client, terraform, packer}` → silenced.
//!   - Operator-extensible `[detectors.data_destruction_pattern]` TOML.
//!
//! MITRE: T1485 (Data Destruction), T1561.001 (Disk Content Wipe),
//!        T1486 (Data Encrypted for Impact, when LUKS variant).

use std::collections::HashMap;

use chrono::{DateTime, Duration, Utc};
use innerwarden_core::{event::Event, event::Severity, incident::Incident};

const USER_DATA_PATH_PREFIXES: &[&str] = &[
    "/home/",
    "/var/lib/",
    "/etc/",
    "/root/",
    "/srv/",
    "/var/www/",
    "/opt/",
    "/data/",
    "/mnt/",
    "/var/log/",
];

/// Filesystem roots we will NEVER fire on for `rm -rf` regardless of
/// other args — these are the catastrophic argv0 patterns that match
/// other detectors (process_injection, log_tampering).
const RM_SAFE_EXACT_PATHS: &[&str] = &["/tmp/", "/var/tmp/", "/var/cache/", "/dev/shm/"];

const BLOCK_DEVICE_PREFIXES: &[&str] = &[
    "/dev/sd",
    "/dev/nvme",
    "/dev/xvd",
    "/dev/vd",
    "/dev/mapper/",
    "/dev/disk/",
];

const BACKUP_PARENTS: &[&str] = &[
    "borgmatic",
    "borg",
    "restic",
    "duplicity",
    "duplicacy",
    "rclone",
    "kopia",
    "rdiff-backup",
    "rsnapshot",
    "burp",
    "bacula-fd",
    "bareos-fd",
];

const AUTOMATION_PARENTS: &[&str] = &[
    "ansible",
    "ansible-playboo",
    "salt-call",
    "salt-minion",
    "puppet",
    "chef-client",
    "cfengine",
    "terraform",
    "packer",
];

pub struct DataDestructionPatternDetector {
    host: String,
    last_fired: HashMap<String, DateTime<Utc>>,
    cooldown: Duration,
}

impl DataDestructionPatternDetector {
    pub fn new(host: impl Into<String>) -> Self {
        Self {
            host: host.into(),
            last_fired: HashMap::new(),
            cooldown: Duration::seconds(300),
        }
    }

    pub fn process(&mut self, event: &Event) -> Option<Incident> {
        if event.kind != "shell.command_exec" && event.kind != "process.exec" {
            return None;
        }
        let argv: Vec<String> = event
            .details
            .get("argv")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();
        if argv.is_empty() {
            return None;
        }
        let argv0_base = argv[0].split('/').next_back().unwrap_or(&argv[0]);
        let parent_comm = event
            .details
            .get("parent_comm")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let parent_base = parent_comm.split('/').next_back().unwrap_or(parent_comm);
        let parent_base = parent_base.trim_matches(|c: char| c == '(' || c == ')');
        if BACKUP_PARENTS.iter().any(|p| parent_base.starts_with(p))
            || AUTOMATION_PARENTS
                .iter()
                .any(|p| parent_base.starts_with(p))
        {
            return None;
        }

        let (sub_kind, target) = match argv0_base {
            "rm" => match detect_rm_rf_user_data(&argv) {
                Some(t) => ("rm_rf_user_data", t),
                None => return None,
            },
            "dd" => match detect_disk_wipe(&argv) {
                Some(t) => ("disk_wipe", t),
                None => return None,
            },
            "shred" => match detect_shred_burst(&argv) {
                Some(t) => ("shred_burst", t),
                None => return None,
            },
            "cryptsetup" => match detect_luksformat(&argv) {
                Some(t) => ("cryptsetup_luksformat", t),
                None => return None,
            },
            _ if argv0_base.starts_with("mkfs") => match detect_mkfs_on_block(&argv) {
                Some(t) => ("mkfs_on_running_volume", t),
                None => return None,
            },
            _ => return None,
        };

        let comm = event
            .details
            .get("comm")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let command = event
            .details
            .get("command")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let pid = event
            .details
            .get("pid")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let uid = event
            .details
            .get("uid")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);

        let now = event.ts;
        let key = format!("{uid}:{sub_kind}:{target}");
        if let Some(&last) = self.last_fired.get(&key) {
            if now - last < self.cooldown {
                return None;
            }
        }
        self.last_fired.insert(key, now);

        Some(Incident {
            ts: now,
            host: self.host.clone(),
            incident_id: format!(
                "data_destruction_pattern:{sub_kind}:{}",
                now.format("%Y-%m-%dT%H:%M:%SZ")
            ),
            severity: Severity::Critical,
            title: format!(
                "Data destruction: {sub_kind} (target=`{target}`, comm=`{comm}`, parent=`{parent_base}`, uid={uid})"
            ),
            summary: format!(
                "Process `{comm}` (parent=`{parent_base}`, pid={pid}, uid={uid}) ran \
                 `{command}` — matched the `{sub_kind}` Impact pattern. This is the last step \
                 of the kill chain: wiper malware, ransomware-without-encryption, or insider \
                 deletion (T1485 / T1561.001 / T1486). Investigate IMMEDIATELY — recovery \
                 window is small."
            ),
            evidence: serde_json::json!([{
                "kind": "data_destruction_pattern",
                "sub_kind": sub_kind,
                "target": target,
                "uid": uid,
                "comm": comm,
                "parent_comm": parent_comm,
                "pid": pid,
                "argv": argv,
                "mitre": mitre_ids(sub_kind),
            }]),
            recommended_checks: vec![
                "If this is in progress, kill the pid NOW: `kill -9 <pid>`".to_string(),
                format!("Inspect process tree of pid {pid}: pstree -p {pid}"),
                "Cross-check against backup snapshots — last good backup timestamp".to_string(),
                "Snapshot current disk state with dd or filesystem snapshot before further forensics".to_string(),
                "If planned operator action (decommissioning, reformat), allowlist via [detectors.data_destruction_pattern]".to_string(),
            ],
            tags: vec!["impact".to_string(), "data_destruction".to_string()],
            entities: vec![],
        })
    }
}

fn detect_rm_rf_user_data(argv: &[String]) -> Option<String> {
    // Need at least the recursive+force flags AND a target under user data.
    let mut has_recursive = false;
    let mut has_force = false;
    let mut targets: Vec<&String> = Vec::new();
    for a in argv.iter().skip(1) {
        if a.starts_with("--") {
            if a == "--recursive" {
                has_recursive = true;
            } else if a == "--force" {
                has_force = true;
            }
            continue;
        }
        if a.starts_with('-') {
            for c in a.chars().skip(1) {
                match c {
                    'r' | 'R' => has_recursive = true,
                    'f' => has_force = true,
                    _ => {}
                }
            }
            continue;
        }
        targets.push(a);
    }
    if !has_recursive || !has_force {
        return None;
    }
    for t in &targets {
        // Exact-match exclusion: rm -rf /tmp/something stays silent.
        if RM_SAFE_EXACT_PATHS.iter().any(|p| t.starts_with(p)) {
            continue;
        }
        if USER_DATA_PATH_PREFIXES.iter().any(|p| t.starts_with(p)) {
            return Some(t.to_string());
        }
        // Special-case: `rm -rf /` or `rm -rf /*` is a wipe regardless.
        if *t == "/" || *t == "/*" {
            return Some(t.to_string());
        }
    }
    None
}

fn detect_disk_wipe(argv: &[String]) -> Option<String> {
    let mut input_is_zero_or_random = false;
    let mut output_block_dev: Option<String> = None;
    for a in argv.iter().skip(1) {
        if let Some(rest) = a.strip_prefix("if=") {
            if rest == "/dev/zero" || rest == "/dev/urandom" || rest == "/dev/random" {
                input_is_zero_or_random = true;
            }
        } else if let Some(rest) = a.strip_prefix("of=") {
            if BLOCK_DEVICE_PREFIXES.iter().any(|p| rest.starts_with(p)) {
                output_block_dev = Some(rest.to_string());
            }
        }
    }
    if input_is_zero_or_random {
        output_block_dev
    } else {
        None
    }
}

fn detect_shred_burst(argv: &[String]) -> Option<String> {
    let mut has_unlink = false;
    let mut targets: Vec<&String> = Vec::new();
    for a in argv.iter().skip(1) {
        if a == "--remove" || a == "--remove=wipe" || a == "--remove=wipesync" {
            has_unlink = true;
            continue;
        }
        if a.starts_with("--remove=") {
            has_unlink = true;
            continue;
        }
        if let Some(stripped) = a.strip_prefix('-') {
            if !stripped.starts_with('-') {
                for c in stripped.chars() {
                    if c == 'u' {
                        has_unlink = true;
                    }
                }
                continue;
            }
        }
        targets.push(a);
    }
    if has_unlink && targets.len() >= 3 {
        Some(format!(
            "{} paths starting with {}",
            targets.len(),
            targets.first().map(|s| s.as_str()).unwrap_or("")
        ))
    } else {
        None
    }
}

fn detect_mkfs_on_block(argv: &[String]) -> Option<String> {
    for a in argv.iter().skip(1) {
        if BLOCK_DEVICE_PREFIXES.iter().any(|p| a.starts_with(p)) {
            return Some(a.clone());
        }
    }
    None
}

fn detect_luksformat(argv: &[String]) -> Option<String> {
    if !argv.iter().any(|a| a == "luksFormat") {
        return None;
    }
    for a in argv.iter().skip(1) {
        if BLOCK_DEVICE_PREFIXES.iter().any(|p| a.starts_with(p)) {
            return Some(a.clone());
        }
    }
    None
}

fn mitre_ids(sub_kind: &str) -> Vec<&'static str> {
    match sub_kind {
        "rm_rf_user_data" => vec!["T1485"],
        "disk_wipe" => vec!["T1561.001"],
        "shred_burst" => vec!["T1485"],
        "mkfs_on_running_volume" => vec!["T1561.001"],
        "cryptsetup_luksformat" => vec!["T1486", "T1561.001"],
        _ => vec!["T1485"],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exec_event(argv: &[&str], parent_comm: &str) -> Event {
        let argv_owned: Vec<String> = argv.iter().map(|s| s.to_string()).collect();
        Event {
            ts: Utc::now(),
            host: "test".into(),
            source: "ebpf".into(),
            kind: "shell.command_exec".into(),
            severity: Severity::Info,
            summary: argv.join(" "),
            details: serde_json::json!({
                "argv": argv_owned,
                "argc": argv.len() as u32,
                "command": argv.join(" "),
                "pid": 4242,
                "uid": 1000,
                "comm": "bash",
                "parent_comm": parent_comm,
            }),
            tags: vec![],
            entities: vec![],
        }
    }

    #[test]
    fn fires_on_rm_rf_home() {
        let mut det = DataDestructionPatternDetector::new("test");
        let ev = exec_event(&["rm", "-rf", "/home/ubuntu/work"], "bash");
        let inc = det.process(&ev).expect("should fire");
        assert_eq!(inc.severity, Severity::Critical);
    }

    #[test]
    fn fires_on_rm_rf_root_glob() {
        let mut det = DataDestructionPatternDetector::new("test");
        let ev = exec_event(&["rm", "-rf", "/*"], "bash");
        assert!(det.process(&ev).is_some());
    }

    #[test]
    fn fires_on_rm_long_flags() {
        let mut det = DataDestructionPatternDetector::new("test");
        let ev = exec_event(
            &["rm", "--recursive", "--force", "/var/lib/postgres"],
            "bash",
        );
        assert!(det.process(&ev).is_some());
    }

    #[test]
    fn ignores_rm_rf_tmp() {
        let mut det = DataDestructionPatternDetector::new("test");
        let ev = exec_event(&["rm", "-rf", "/tmp/build/"], "bash");
        assert!(det.process(&ev).is_none());
    }

    #[test]
    fn ignores_rm_without_recursive_or_force() {
        let mut det = DataDestructionPatternDetector::new("test");
        let ev = exec_event(&["rm", "/home/ubuntu/file.log"], "bash");
        assert!(det.process(&ev).is_none());
    }

    #[test]
    fn fires_on_dd_zero_to_sda() {
        let mut det = DataDestructionPatternDetector::new("test");
        let ev = exec_event(&["dd", "if=/dev/zero", "of=/dev/sda", "bs=1M"], "bash");
        assert!(det.process(&ev).is_some());
    }

    #[test]
    fn fires_on_dd_urandom_to_nvme() {
        let mut det = DataDestructionPatternDetector::new("test");
        let ev = exec_event(&["dd", "if=/dev/urandom", "of=/dev/nvme0n1"], "bash");
        assert!(det.process(&ev).is_some());
    }

    #[test]
    fn ignores_dd_to_regular_file() {
        let mut det = DataDestructionPatternDetector::new("test");
        let ev = exec_event(&["dd", "if=/dev/zero", "of=/tmp/junk.img"], "bash");
        assert!(det.process(&ev).is_none());
    }

    #[test]
    fn fires_on_shred_burst_three_files() {
        let mut det = DataDestructionPatternDetector::new("test");
        let ev = exec_event(
            &["shred", "-u", "/home/x/a", "/home/x/b", "/home/x/c"],
            "bash",
        );
        assert!(det.process(&ev).is_some());
    }

    #[test]
    fn ignores_shred_single_file() {
        let mut det = DataDestructionPatternDetector::new("test");
        let ev = exec_event(&["shred", "-u", "/home/x/secret.txt"], "bash");
        assert!(det.process(&ev).is_none());
    }

    #[test]
    fn ignores_shred_without_unlink() {
        let mut det = DataDestructionPatternDetector::new("test");
        let ev = exec_event(&["shred", "/home/x/a", "/home/x/b", "/home/x/c"], "bash");
        assert!(det.process(&ev).is_none());
    }

    #[test]
    fn fires_on_mkfs_ext4_on_sdb() {
        let mut det = DataDestructionPatternDetector::new("test");
        let ev = exec_event(&["mkfs.ext4", "/dev/sdb1"], "bash");
        assert!(det.process(&ev).is_some());
    }

    #[test]
    fn fires_on_cryptsetup_luksformat() {
        let mut det = DataDestructionPatternDetector::new("test");
        let ev = exec_event(&["cryptsetup", "luksFormat", "/dev/sda2"], "bash");
        assert!(det.process(&ev).is_some());
    }

    #[test]
    fn ignores_cryptsetup_status_query() {
        let mut det = DataDestructionPatternDetector::new("test");
        let ev = exec_event(&["cryptsetup", "status", "luks-vol"], "bash");
        assert!(det.process(&ev).is_none());
    }

    #[test]
    fn silences_when_parent_is_ansible() {
        let mut det = DataDestructionPatternDetector::new("test");
        let ev = exec_event(&["rm", "-rf", "/var/lib/old"], "ansible-playboo");
        assert!(det.process(&ev).is_none());
    }

    #[test]
    fn silences_when_parent_is_borgmatic() {
        let mut det = DataDestructionPatternDetector::new("test");
        let ev = exec_event(&["rm", "-rf", "/var/lib/staging"], "borgmatic");
        assert!(det.process(&ev).is_none());
    }

    #[test]
    fn dedupes_within_cooldown() {
        let mut det = DataDestructionPatternDetector::new("test");
        let ev = exec_event(&["rm", "-rf", "/home/ubuntu/work"], "bash");
        assert!(det.process(&ev).is_some());
        let mut ev2 = ev.clone();
        ev2.ts = ev.ts + Duration::seconds(60);
        assert!(det.process(&ev2).is_none());
    }
}
