//! `innerwarden uninstall` — clean, complete removal.
//!
//! Mirrors the `curl | sudo bash` installer's footprint and tears it down in
//! the safe order: stop the supervisor/watchdog FIRST (so it cannot respawn the
//! agent mid-uninstall — the watchdog is anti-tamper, but a stop+disable of its
//! own unit by root is the authorized teardown), then the agent + sensor (a
//! `systemctl stop` kills the whole cgroup, so the PID-namespaced / comm-masked
//! agent goes down too), then remove units, binaries, eBPF pins, sudoers, and
//! firewall rules.
//!
//! Config (`/etc/innerwarden`) and data (`/var/lib/innerwarden`) are KEPT by
//! default so a reinstall keeps history + license; `--purge` removes them and
//! the `innerwarden` system user.
//!
//! Design: the teardown is computed as a pure [`Step`] plan ([`build_plan`])
//! from injected host state ([`Env`]) and executed through an injected applier
//! ([`Sys`]). That keeps the ordering / what-gets-removed / purge-gating logic
//! unit-tested; only the raw `systemctl`/`ufw`/`userdel` shell-outs in
//! [`RealSys`] are non-covered glue.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::Result;

use crate::helpers::require_sudo;
use crate::Cli;

const IW_USER: &str = "innerwarden";
const SUDOERS_DIR: &str = "/etc/sudoers.d";
const SYSTEMD_DIR: &str = "/etc/systemd/system";

const BINARIES: &[&str] = &[
    "/usr/local/bin/innerwarden",
    "/usr/local/bin/innerwarden-ctl",
    "/usr/local/bin/innerwarden-agent",
    "/usr/local/bin/innerwarden-sensor",
    "/usr/local/bin/innerwarden-watchdog",
    "/usr/local/bin/innerwarden-supervisor",
];

/// Removed even without `--purge` (software, not user data).
const SOFTWARE_DIRS: &[&str] = &[
    "/usr/local/lib/innerwarden", // embedded eBPF object + helpers
    "/sys/fs/bpf/innerwarden",    // pinned BPF maps
    "/run/innerwarden",           // runtime (discovery socket etc.)
];

/// Removed only with `--purge` (config + state the operator may want to keep).
const DATA_DIRS: &[&str] = &[
    "/etc/innerwarden",
    "/var/lib/innerwarden",
    "/var/log/innerwarden",
];

/// Stopped first (in this order) so nothing respawns the agent.
const SUPERVISOR_UNITS: &[&str] = &["innerwarden-watchdog", "innerwarden-supervisor"];

// ── plan ────────────────────────────────────────────────────────────────────

/// One unit of teardown work. The plan is pure data so it can be asserted on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    Stop(String),
    Disable(String),
    RemoveFile(String),
    RemoveTree(String),
    DaemonReload,
    ResetFailed,
    DeleteUfwRule(u32),
    Userdel(String),
}

impl Step {
    /// Human-readable line for the dry-run preview.
    pub fn describe(&self) -> String {
        match self {
            Step::Stop(u) => format!("systemctl stop {u}"),
            Step::Disable(u) => format!("systemctl disable {u}"),
            Step::RemoveFile(p) => format!("rm -f {p}"),
            Step::RemoveTree(p) => format!("rm -rf {p}"),
            Step::DaemonReload => "systemctl daemon-reload".to_string(),
            Step::ResetFailed => "systemctl reset-failed".to_string(),
            Step::DeleteUfwRule(n) => format!("ufw --force delete {n}  (innerwarden rule)"),
            Step::Userdel(u) => format!("userdel {u}"),
        }
    }

    /// External command `(program, args)` for this step, or `None` for the
    /// in-process filesystem steps (`RemoveFile`/`RemoveTree`). Pure: the
    /// applier just runs whatever this returns, so the mapping is unit-tested
    /// and only the bare `.status()` exec stays as glue.
    pub fn command(&self) -> Option<(&'static str, Vec<String>)> {
        match self {
            Step::Stop(u) => Some(("systemctl", vec!["stop".into(), u.clone()])),
            Step::Disable(u) => Some(("systemctl", vec!["disable".into(), u.clone()])),
            Step::DaemonReload => Some(("systemctl", vec!["daemon-reload".into()])),
            Step::ResetFailed => Some(("systemctl", vec!["reset-failed".into()])),
            Step::DeleteUfwRule(n) => Some((
                "ufw",
                vec!["--force".into(), "delete".into(), n.to_string()],
            )),
            Step::Userdel(u) => Some(("userdel", vec![u.clone()])),
            Step::RemoveFile(_) | Step::RemoveTree(_) => None,
        }
    }
}

/// Pure: the full teardown plan from discovered host state. Order is the safety
/// contract (supervisors stop first; remove only after stop+disable; data + the
/// user touched only on `purge`).
pub fn build_plan(
    units: &[String],
    sudoers: &[String],
    ufw_rules: &[u32],
    purge: bool,
) -> Vec<Step> {
    let mut steps = Vec::new();

    // 1) Stop supervisors first even if their unit file is already gone — a live
    //    watchdog with no on-disk unit must still be stopped before the agent,
    //    or it respawns it mid-teardown.
    for sup in SUPERVISOR_UNITS {
        let svc = format!("{sup}.service");
        if !units.iter().any(|u| u == &svc) {
            steps.push(Step::Stop(svc));
        }
    }
    // 2) Stop every discovered unit (pre-sorted supervisors-first by order_key).
    for u in units {
        steps.push(Step::Stop(u.clone()));
    }
    // 3) Disable + remove unit files + drop-in dirs (e.g. jeprof.conf).
    for u in units {
        steps.push(Step::Disable(u.clone()));
    }
    for u in units {
        steps.push(Step::RemoveFile(format!("{SYSTEMD_DIR}/{u}")));
        steps.push(Step::RemoveTree(format!("{SYSTEMD_DIR}/{u}.d")));
    }
    steps.push(Step::DaemonReload);
    steps.push(Step::ResetFailed);

    // 4) eBPF pins + software dirs + binaries.
    for d in SOFTWARE_DIRS {
        steps.push(Step::RemoveTree((*d).to_string()));
    }
    for b in BINARIES {
        steps.push(Step::RemoveFile((*b).to_string()));
    }

    // 5) sudoers drop-ins.
    for s in sudoers {
        steps.push(Step::RemoveFile(format!("{SUDOERS_DIR}/{s}")));
    }

    // 6) firewall rules we added (caller passes them DESCENDING so deleting by
    //    number doesn't shift the rest).
    for n in ufw_rules {
        steps.push(Step::DeleteUfwRule(*n));
    }

    // 7) purge config/data/logs + the system user.
    if purge {
        for d in DATA_DIRS {
            steps.push(Step::RemoveTree((*d).to_string()));
        }
        steps.push(Step::Userdel(IW_USER.to_string()));
    }

    steps
}

// ── injection seams ──────────────────────────────────────────────────────────

/// Host-state discovery, injected so the orchestrator is testable.
pub trait Env {
    fn units(&self) -> Vec<String>;
    fn sudoers(&self) -> Vec<String>;
    fn ufw_rules(&self) -> Vec<u32>;
}

/// Side-effecting step applier, injected so the orchestrator is testable.
pub trait Sys {
    fn apply(&mut self, step: &Step, dry: bool);
}

/// Discover + plan + (optionally) execute. Returns the plan that was run (empty
/// if the operator declined). Pure orchestration over the two seams, so a fake
/// `Env` + recording `Sys` cover it fully.
fn run_uninstall(
    env: &dyn Env,
    sys: &mut dyn Sys,
    purge: bool,
    yes: bool,
    dry: bool,
    confirm: impl Fn() -> bool,
) -> Vec<Step> {
    let units = env.units();
    let sudoers = env.sudoers();
    let ufw = env.ufw_rules();
    let plan = build_plan(&units, &sudoers, &ufw, purge);

    println!("InnerWarden uninstall — this will remove:");
    println!(
        "  · services:  {}",
        if units.is_empty() {
            "(none found)".to_string()
        } else {
            units.join(", ")
        }
    );
    println!("  · binaries:  {}", BINARIES.join(", "));
    println!("  · eBPF maps, embedded object, sudoers + firewall rules");
    if purge {
        println!("  · PURGE: config + data + logs + the `{IW_USER}` user:");
        println!("           {}", DATA_DIRS.join(", "));
    } else {
        println!(
            "  · keeping config + data ({}). Use --purge to remove them too.",
            DATA_DIRS.join(", ")
        );
    }
    println!();

    if !yes && !dry && !confirm() {
        println!("Aborted.");
        return Vec::new();
    }

    for step in &plan {
        sys.apply(step, dry);
    }

    println!();
    if dry {
        println!("Dry run complete — nothing changed.");
    } else if purge {
        println!("✅ InnerWarden fully uninstalled (config + data removed).");
    } else {
        println!("✅ InnerWarden uninstalled. Config + data kept under /etc/innerwarden + /var/lib/innerwarden (re-run with --purge to remove).");
    }
    plan
}

pub fn cmd_uninstall(cli: &Cli, purge: bool, yes: bool) -> Result<()> {
    let dry = cli.dry_run;
    // A dry-run preview is safe without root; the real teardown needs it.
    if !dry {
        require_sudo(cli);
    }
    let env = RealEnv::new();
    let mut sys = RealSys;
    run_uninstall(&env, &mut sys, purge, yes, dry, || {
        confirm("Proceed with uninstall?")
    });
    Ok(())
}

// ── real Env (filesystem + ufw) ───────────────────────────────────────────────

struct RealEnv {
    systemd_dir: PathBuf,
    sudoers_dir: PathBuf,
}

impl RealEnv {
    fn new() -> Self {
        Self {
            systemd_dir: PathBuf::from(SYSTEMD_DIR),
            sudoers_dir: PathBuf::from(SUDOERS_DIR),
        }
    }

    /// All `innerwarden-*` unit files (services + timers), supervisors first.
    fn read_units(systemd_dir: &Path) -> Vec<String> {
        let mut found: Vec<String> = std::fs::read_dir(systemd_dir)
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|e| e.file_name().into_string().ok())
            .filter(|n| {
                n.starts_with("innerwarden-") && (n.ends_with(".service") || n.ends_with(".timer"))
            })
            .collect();
        found.sort_by_key(|u| order_key(u));
        found
    }

    fn read_sudoers(sudoers_dir: &Path) -> Vec<String> {
        std::fs::read_dir(sudoers_dir)
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|e| e.file_name().into_string().ok())
            .filter(|n| n.starts_with("innerwarden"))
            .collect()
    }
}

impl Env for RealEnv {
    fn units(&self) -> Vec<String> {
        Self::read_units(&self.systemd_dir)
    }
    fn sudoers(&self) -> Vec<String> {
        Self::read_sudoers(&self.sudoers_dir)
    }
    fn ufw_rules(&self) -> Vec<u32> {
        match Command::new("ufw").arg("status").arg("numbered").output() {
            Ok(o) => parse_ufw_innerwarden_rules(&String::from_utf8_lossy(&o.stdout)),
            Err(_) => Vec::new(), // no ufw
        }
    }
}

// ── pure helpers (unit-tested) ────────────────────────────────────────────────

/// Stop/teardown order key: watchdog (0) and supervisor (1) before the rest (2),
/// so the supervisor can't respawn the agent during teardown.
pub fn order_key(unit: &str) -> u8 {
    if unit.starts_with("innerwarden-watchdog") {
        0
    } else if unit.starts_with("innerwarden-supervisor") {
        1
    } else {
        2
    }
}

/// Parse `ufw status numbered` and return the rule numbers tagged
/// `innerwarden`, DESCENDING (so deleting by number doesn't shift the rest).
pub fn parse_ufw_innerwarden_rules(ufw_numbered: &str) -> Vec<u32> {
    let mut nums: Vec<u32> = ufw_numbered
        .lines()
        .filter(|l| l.to_lowercase().contains("innerwarden"))
        .filter_map(|l| {
            let start = l.find('[')?;
            let end = l[start..].find(']')? + start;
            l[start + 1..end].trim().parse::<u32>().ok()
        })
        .collect();
    nums.sort_unstable_by(|a, b| b.cmp(a)); // descending
    nums
}

// ── real Sys (the only non-covered glue: raw systemctl/ufw/userdel) ───────────

struct RealSys;

impl Sys for RealSys {
    fn apply(&mut self, step: &Step, dry: bool) {
        if dry {
            println!("[dry-run] {}", step.describe());
            return;
        }
        match step {
            Step::RemoveFile(p) | Step::RemoveTree(p) => remove_path(p),
            other => {
                if let Some((prog, args)) = other.command() {
                    let _ = Command::new(prog).args(&args).status();
                }
            }
        }
    }
}

/// Remove a file or directory tree; missing path is a no-op. Testable.
fn remove_path(path: &str) {
    let p = Path::new(path);
    if !p.exists() {
        return;
    }
    let res = if p.is_dir() {
        std::fs::remove_dir_all(p)
    } else {
        std::fs::remove_file(p)
    };
    match res {
        Ok(()) => println!("[ok] removed {path}"),
        Err(e) => println!("⚠ could not remove {path}: {e}"),
    }
}

fn confirm(prompt: &str) -> bool {
    dialoguer::Confirm::with_theme(&dialoguer::theme::ColorfulTheme::default())
        .with_prompt(prompt)
        .default(false)
        .interact()
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn units_full() -> Vec<String> {
        // As discovery would return them: supervisors first.
        vec![
            "innerwarden-watchdog.service".to_string(),
            "innerwarden-supervisor.service".to_string(),
            "innerwarden-agent.service".to_string(),
            "innerwarden-sensor.service".to_string(),
            "innerwarden-smm.timer".to_string(),
        ]
    }

    // ── order_key ───────────────────────────────────────────────────────────
    #[test]
    fn supervisors_stop_before_everything_else() {
        let mut units = [
            "innerwarden-sensor.service".to_string(),
            "innerwarden-agent.service".to_string(),
            "innerwarden-watchdog.service".to_string(),
            "innerwarden-supervisor.service".to_string(),
            "innerwarden-smm.timer".to_string(),
        ];
        units.sort_by_key(|u| order_key(u));
        assert_eq!(units[0], "innerwarden-watchdog.service");
        assert_eq!(units[1], "innerwarden-supervisor.service");
        assert!(units[2..].iter().all(|u| order_key(u) == 2));
    }

    // ── ufw parser ───────────────────────────────────────────────────────────
    #[test]
    fn ufw_parser_finds_tagged_rules_descending_and_ignores_others() {
        let status = "\
Status: active

     To                         Action      From
     --                         ------      ----
[ 1] 22/tcp                     ALLOW IN    Anywhere
[ 2] Anywhere                   DENY IN     203.0.113.7    # innerwarden
[ 3] 8787                       ALLOW IN    10.0.0.5       # innerwarden-dashboard
[ 4] 443/tcp                    ALLOW IN    Anywhere
[ 5] Anywhere                   DENY IN     45.1.2.3       # innerwarden
";
        let nums = parse_ufw_innerwarden_rules(status);
        assert_eq!(
            nums,
            vec![5, 3, 2],
            "tagged rules, descending; non-iw rules ignored"
        );
    }

    #[test]
    fn ufw_parser_empty_when_no_iw_rules() {
        let status = "[ 1] 22/tcp ALLOW IN Anywhere\n[ 2] 443/tcp ALLOW IN Anywhere";
        assert!(parse_ufw_innerwarden_rules(status).is_empty());
    }

    // ── build_plan ───────────────────────────────────────────────────────────
    #[test]
    fn plan_stops_all_units_supervisors_first_then_removes() {
        let units = units_full();
        let plan = build_plan(&units, &[], &[], false);

        // First steps are stops, in unit order (no extra explicit supervisor
        // stops because both already have unit files).
        let stops: Vec<&str> = plan
            .iter()
            .filter_map(|s| match s {
                Step::Stop(u) => Some(u.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(stops, units.iter().map(|u| u.as_str()).collect::<Vec<_>>());

        // Every unit gets disabled + its file + drop-in removed.
        for u in &units {
            assert!(plan.contains(&Step::Disable(u.clone())));
            assert!(plan.contains(&Step::RemoveFile(format!("{SYSTEMD_DIR}/{u}"))));
            assert!(plan.contains(&Step::RemoveTree(format!("{SYSTEMD_DIR}/{u}.d"))));
        }
        assert!(plan.contains(&Step::DaemonReload));
        assert!(plan.contains(&Step::ResetFailed));

        // All disables come after all stops (stop+disable before remove).
        let last_stop = plan
            .iter()
            .rposition(|s| matches!(s, Step::Stop(_)))
            .unwrap();
        let first_disable = plan
            .iter()
            .position(|s| matches!(s, Step::Disable(_)))
            .unwrap();
        assert!(last_stop < first_disable);
    }

    #[test]
    fn plan_always_removes_software_and_binaries() {
        let plan = build_plan(&[], &[], &[], false);
        for d in SOFTWARE_DIRS {
            assert!(plan.contains(&Step::RemoveTree((*d).to_string())));
        }
        for b in BINARIES {
            assert!(plan.contains(&Step::RemoveFile((*b).to_string())));
        }
    }

    #[test]
    fn plan_keeps_config_and_user_without_purge() {
        let plan = build_plan(&units_full(), &[], &[], false);
        for d in DATA_DIRS {
            assert!(
                !plan.contains(&Step::RemoveTree((*d).to_string())),
                "data dir {d} must NOT be removed without --purge"
            );
        }
        assert!(!plan.iter().any(|s| matches!(s, Step::Userdel(_))));
    }

    #[test]
    fn plan_purge_removes_data_and_user_last() {
        let plan = build_plan(&units_full(), &[], &[], true);
        for d in DATA_DIRS {
            assert!(plan.contains(&Step::RemoveTree((*d).to_string())));
        }
        assert_eq!(
            plan.last(),
            Some(&Step::Userdel(IW_USER.to_string())),
            "userdel is the very last step"
        );
    }

    #[test]
    fn plan_supervisors_stopped_even_without_unit_files() {
        // No discovered units at all (e.g. unit files already deleted), but a
        // live watchdog must still be stopped before anything else.
        let plan = build_plan(&[], &[], &[], false);
        assert_eq!(
            plan[0],
            Step::Stop("innerwarden-watchdog.service".to_string())
        );
        assert_eq!(
            plan[1],
            Step::Stop("innerwarden-supervisor.service".to_string())
        );
    }

    #[test]
    fn plan_sudoers_and_ufw_in_given_order() {
        let sudoers = vec![
            "innerwarden-block".to_string(),
            "innerwarden-shell".to_string(),
        ];
        let plan = build_plan(&[], &sudoers, &[9, 4, 1], false);
        assert!(plan.contains(&Step::RemoveFile(format!(
            "{SUDOERS_DIR}/innerwarden-block"
        ))));
        assert!(plan.contains(&Step::RemoveFile(format!(
            "{SUDOERS_DIR}/innerwarden-shell"
        ))));
        let ufw: Vec<u32> = plan
            .iter()
            .filter_map(|s| match s {
                Step::DeleteUfwRule(n) => Some(*n),
                _ => None,
            })
            .collect();
        assert_eq!(
            ufw,
            vec![9, 4, 1],
            "ufw rules deleted in caller order (descending)"
        );
    }

    // ── Step::describe ───────────────────────────────────────────────────────
    #[test]
    fn step_describe_covers_every_variant() {
        assert_eq!(Step::Stop("u".into()).describe(), "systemctl stop u");
        assert_eq!(Step::Disable("u".into()).describe(), "systemctl disable u");
        assert_eq!(Step::RemoveFile("/a".into()).describe(), "rm -f /a");
        assert_eq!(Step::RemoveTree("/a".into()).describe(), "rm -rf /a");
        assert_eq!(Step::DaemonReload.describe(), "systemctl daemon-reload");
        assert_eq!(Step::ResetFailed.describe(), "systemctl reset-failed");
        assert_eq!(
            Step::DeleteUfwRule(7).describe(),
            "ufw --force delete 7  (innerwarden rule)"
        );
        assert_eq!(
            Step::Userdel("innerwarden".into()).describe(),
            "userdel innerwarden"
        );
    }

    #[test]
    fn step_command_maps_every_variant() {
        assert_eq!(
            Step::Stop("u".into()).command(),
            Some(("systemctl", vec!["stop".to_string(), "u".to_string()]))
        );
        assert_eq!(
            Step::Disable("u".into()).command(),
            Some(("systemctl", vec!["disable".to_string(), "u".to_string()]))
        );
        assert_eq!(
            Step::DaemonReload.command(),
            Some(("systemctl", vec!["daemon-reload".to_string()]))
        );
        assert_eq!(
            Step::ResetFailed.command(),
            Some(("systemctl", vec!["reset-failed".to_string()]))
        );
        assert_eq!(
            Step::DeleteUfwRule(7).command(),
            Some((
                "ufw",
                vec!["--force".to_string(), "delete".to_string(), "7".to_string()]
            ))
        );
        assert_eq!(
            Step::Userdel("innerwarden".into()).command(),
            Some(("userdel", vec!["innerwarden".to_string()]))
        );
        // filesystem steps are in-process, not external commands
        assert_eq!(Step::RemoveFile("/a".into()).command(), None);
        assert_eq!(Step::RemoveTree("/a".into()).command(), None);
    }

    // ── RealEnv discovery (tempdir) ──────────────────────────────────────────
    #[test]
    fn real_env_discovers_units_filtered_and_sorted() {
        let dir = tempfile::tempdir().unwrap();
        for f in [
            "innerwarden-agent.service",
            "innerwarden-sensor.service",
            "innerwarden-watchdog.service",
            "innerwarden-smm.timer",
            "sshd.service",          // not innerwarden, ignored
            "innerwarden-notes.txt", // wrong extension, ignored
        ] {
            std::fs::write(dir.path().join(f), "x").unwrap();
        }
        // a drop-in dir alongside the units: not a unit file, must be ignored
        std::fs::create_dir(dir.path().join("innerwarden-agent.service.d")).unwrap();

        let units = RealEnv::read_units(dir.path());
        assert_eq!(
            units[0], "innerwarden-watchdog.service",
            "watchdog sorts first"
        );
        assert!(
            units.contains(&"innerwarden-smm.timer".to_string()),
            "timers included"
        );
        assert!(!units.iter().any(|u| u == "sshd.service"));
        assert!(!units.iter().any(|u| u.ends_with(".txt")));
        assert!(!units.iter().any(|u| u.ends_with(".service.d")));
        assert_eq!(units.len(), 4);
    }

    #[test]
    fn real_env_discovers_innerwarden_sudoers_only() {
        let dir = tempfile::tempdir().unwrap();
        for f in [
            "innerwarden-block-ip",
            "innerwarden-sudo",
            "90-cloud-init",
            "README",
        ] {
            std::fs::write(dir.path().join(f), "x").unwrap();
        }
        let mut got = RealEnv::read_sudoers(dir.path());
        got.sort();
        assert_eq!(got, vec!["innerwarden-block-ip", "innerwarden-sudo"]);
    }

    #[test]
    fn real_env_units_missing_dir_is_empty() {
        let missing = PathBuf::from("/nonexistent/innerwarden/systemd/xyz");
        assert!(RealEnv::read_units(&missing).is_empty());
        assert!(RealEnv::read_sudoers(&missing).is_empty());
    }

    // ── RealSys filesystem application (tempdir) ─────────────────────────────
    #[test]
    fn real_sys_removes_file_and_tree_but_dry_is_noop() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("bin");
        let tree = dir.path().join("lib");
        std::fs::write(&file, "x").unwrap();
        std::fs::create_dir_all(tree.join("nested")).unwrap();
        std::fs::write(tree.join("nested/o"), "x").unwrap();

        let mut sys = RealSys;
        // dry run touches nothing
        sys.apply(&Step::RemoveFile(file.to_string_lossy().into()), true);
        sys.apply(&Step::RemoveTree(tree.to_string_lossy().into()), true);
        assert!(file.exists() && tree.exists(), "dry run must not delete");

        // real run removes both
        sys.apply(&Step::RemoveFile(file.to_string_lossy().into()), false);
        sys.apply(&Step::RemoveTree(tree.to_string_lossy().into()), false);
        assert!(!file.exists() && !tree.exists());

        // removing an already-gone path is a no-op (no panic)
        sys.apply(&Step::RemoveFile(file.to_string_lossy().into()), false);
    }

    // ── run_uninstall orchestration (fake Env + recording Sys) ───────────────
    struct FakeEnv {
        units: Vec<String>,
        sudoers: Vec<String>,
        ufw: Vec<u32>,
    }
    impl Env for FakeEnv {
        fn units(&self) -> Vec<String> {
            self.units.clone()
        }
        fn sudoers(&self) -> Vec<String> {
            self.sudoers.clone()
        }
        fn ufw_rules(&self) -> Vec<u32> {
            self.ufw.clone()
        }
    }

    #[derive(Default)]
    struct RecordingSys {
        applied: Vec<(Step, bool)>,
    }
    impl Sys for RecordingSys {
        fn apply(&mut self, step: &Step, dry: bool) {
            self.applied.push((step.clone(), dry));
        }
    }

    fn fake() -> FakeEnv {
        FakeEnv {
            units: units_full(),
            sudoers: vec!["innerwarden-block".to_string()],
            ufw: vec![5, 2],
        }
    }

    #[test]
    fn run_executes_full_plan_when_confirmed() {
        let env = fake();
        let mut sys = RecordingSys::default();
        let plan = run_uninstall(&env, &mut sys, true, false, false, || true);
        assert!(!plan.is_empty());
        let recorded: Vec<Step> = sys.applied.iter().map(|(s, _)| s.clone()).collect();
        assert_eq!(recorded, plan, "every plan step applied, in order");
        assert!(sys.applied.iter().all(|(_, dry)| !dry), "real run, not dry");
        assert_eq!(plan.last(), Some(&Step::Userdel(IW_USER.to_string())));
    }

    #[test]
    fn run_aborts_and_applies_nothing_when_declined() {
        let env = fake();
        let mut sys = RecordingSys::default();
        let plan = run_uninstall(&env, &mut sys, false, false, false, || false);
        assert!(plan.is_empty(), "declined => empty plan returned");
        assert!(sys.applied.is_empty(), "nothing executed on decline");
    }

    #[test]
    fn run_dry_executes_plan_in_dry_mode_without_confirm() {
        let env = fake();
        let mut sys = RecordingSys::default();
        // confirm returns false, but dry=true must skip the prompt and still run.
        let plan = run_uninstall(&env, &mut sys, false, false, true, || false);
        assert!(!plan.is_empty());
        let recorded: Vec<Step> = sys.applied.iter().map(|(s, _)| s.clone()).collect();
        assert_eq!(recorded, plan);
        assert!(
            sys.applied.iter().all(|(_, dry)| *dry),
            "all steps applied in dry mode"
        );
    }

    #[test]
    fn run_yes_skips_confirm() {
        let env = fake();
        let mut sys = RecordingSys::default();
        // yes=true, confirm would return false; must run anyway.
        let plan = run_uninstall(&env, &mut sys, false, true, false, || false);
        assert!(!plan.is_empty());
        assert_eq!(sys.applied.len(), plan.len());
    }

    // ── cmd_uninstall end-to-end (real Env + real Sys, dry) ──────────────────
    #[test]
    fn cmd_uninstall_dry_run_is_side_effect_free_end_to_end() {
        use clap::Parser;
        let mut cli = Cli::parse_from(["innerwarden", "uninstall"]);
        cli.dry_run = true;
        // Drives the real RealEnv discovery (read_dir on /etc/systemd/system,
        // /etc/sudoers.d, `ufw status`) and RealSys in DRY mode. On a host with
        // no InnerWarden installed this plans only the supervisor-safety stops
        // and changes nothing — it must never panic or touch the system.
        cmd_uninstall(&cli, false, true).expect("dry-run uninstall ok");
        cmd_uninstall(&cli, true, true).expect("dry-run purge uninstall ok");
    }
}
