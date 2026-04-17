//! Containment helpers extracted from session.rs: jail / namespace command
//! construction. These are pure functions — they build a `Command` value
//! without spawning anything — which is exactly what we need in unit
//! tests so we can assert argument shape without running real bwrap /
//! firejail / systemd-run.

use std::path::Path;
use tokio::process::Command;

/// Build the sandboxing command for a namespace-based containment runner
/// (typically `systemd-run --scope` with a private user namespace, or
/// `unshare`). The runner is invoked as an argument to the namespace tool
/// and is marked with `--honeypot-sandbox-runner` so the binary can
/// dispatch to the sandbox code path.
pub(super) fn build_namespace_command(
    namespace_runner: &str,
    namespace_args: &[String],
    runner: &Path,
) -> Command {
    let mut namespace_cmd = Command::new(namespace_runner);
    namespace_cmd
        .args(namespace_args)
        .arg(runner)
        .arg("--honeypot-sandbox-runner");
    namespace_cmd
}

/// Build the sandboxing command for a jail-based runner (`bwrap`,
/// `firejail`). If the user-provided args don't contain the `--`
/// separator, we insert it so the jail doesn't interpret the runner
/// path as one of its own flags.
pub(super) fn build_jail_command(
    jail_runner: &str,
    jail_args: &[String],
    runner: &Path,
) -> Command {
    let mut jail_cmd = Command::new(jail_runner);
    jail_cmd.args(jail_args);
    if !jail_args.iter().any(|arg| arg == "--") {
        jail_cmd.arg("--");
    }
    jail_cmd.arg(runner).arg("--honeypot-sandbox-runner");
    jail_cmd
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn args_of(cmd: &Command) -> Vec<String> {
        cmd.as_std()
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect()
    }

    fn program_of(cmd: &Command) -> String {
        cmd.as_std().get_program().to_string_lossy().into_owned()
    }

    #[test]
    fn namespace_command_appends_runner_and_sandbox_flag() {
        let runner = PathBuf::from("/usr/local/bin/innerwarden-agent");
        let cmd = build_namespace_command(
            "systemd-run",
            &vec!["--scope".into(), "--property=PrivateNetwork=yes".into()],
            &runner,
        );
        assert_eq!(program_of(&cmd), "systemd-run");
        let args = args_of(&cmd);
        assert_eq!(
            args,
            vec![
                "--scope".to_string(),
                "--property=PrivateNetwork=yes".to_string(),
                runner.display().to_string(),
                "--honeypot-sandbox-runner".to_string(),
            ]
        );
    }

    #[test]
    fn namespace_command_with_empty_args_still_works() {
        let runner = PathBuf::from("/bin/true");
        let cmd = build_namespace_command("unshare", &[], &runner);
        assert_eq!(program_of(&cmd), "unshare");
        let args = args_of(&cmd);
        assert_eq!(args.len(), 2);
        assert_eq!(args[0], "/bin/true");
        assert_eq!(args[1], "--honeypot-sandbox-runner");
    }

    #[test]
    fn jail_command_inserts_double_dash_when_missing() {
        let runner = PathBuf::from("/bin/sh");
        let cmd = build_jail_command(
            "bwrap",
            &vec!["--die-with-parent".into(), "--new-session".into()],
            &runner,
        );
        let args = args_of(&cmd);
        assert_eq!(
            args,
            vec![
                "--die-with-parent".to_string(),
                "--new-session".to_string(),
                "--".to_string(),
                "/bin/sh".to_string(),
                "--honeypot-sandbox-runner".to_string(),
            ]
        );
    }

    #[test]
    fn jail_command_preserves_existing_double_dash() {
        let runner = PathBuf::from("/bin/sh");
        let cmd = build_jail_command(
            "firejail",
            &vec!["--private".into(), "--".into(), "extra".into()],
            &runner,
        );
        let args = args_of(&cmd);
        // Should not add a second `--`. The runner and flag append after
        // the caller's existing args verbatim.
        assert_eq!(
            args,
            vec![
                "--private".to_string(),
                "--".to_string(),
                "extra".to_string(),
                "/bin/sh".to_string(),
                "--honeypot-sandbox-runner".to_string(),
            ]
        );
    }

    #[test]
    fn jail_command_with_no_args_inserts_double_dash() {
        let runner = PathBuf::from("/bin/true");
        let cmd = build_jail_command("bwrap", &[], &runner);
        let args = args_of(&cmd);
        assert_eq!(
            args,
            vec![
                "--".to_string(),
                "/bin/true".to_string(),
                "--honeypot-sandbox-runner".to_string(),
            ]
        );
    }
}
