use std::future::Future;
use std::path::Path;
use std::pin::Pin;

use anyhow::{Context, Result};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use tokio::process::Command;
use tracing::{info, warn};

use crate::skills::{ResponseSkill, SkillContext, SkillResult, SkillTier};

const DEFAULT_TTL_SECS: u64 = 1800;
const MIN_TTL_SECS: u64 = 60;
const MAX_TTL_SECS: u64 = 86_400;
const DENY_FILE_PREFIX: &str = "/etc/sudoers.d/zz-innerwarden-deny-";

pub struct SuspendUserSudo;

#[derive(Debug, Serialize, Deserialize)]
struct SuspensionMetadata {
    user: String,
    deny_file: String,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    reason: String,
}

impl ResponseSkill for SuspendUserSudo {
    fn id(&self) -> &'static str {
        "suspend-user-sudo"
    }

    fn name(&self) -> &'static str {
        "Suspend User Sudo"
    }

    fn description(&self) -> &'static str {
        "Temporarily denies all sudo commands for a user by writing a sudoers drop-in rule with TTL metadata."
    }

    fn tier(&self) -> SkillTier {
        SkillTier::Open
    }

    fn applicable_to(&self) -> &'static [&'static str] {
        &["sudo_abuse"]
    }

    fn execute<'a>(
        &'a self,
        ctx: &'a SkillContext,
        dry_run: bool,
    ) -> Pin<Box<dyn Future<Output = SkillResult> + Send + 'a>> {
        Box::pin(async move {
            let Some(user) = ctx.target_user.clone() else {
                return SkillResult {
                    success: false,
                    message: "suspend-user-sudo: no target user in context".to_string(),
                };
            };

            if !is_valid_username(&user) {
                return SkillResult {
                    success: false,
                    message: format!("suspend-user-sudo: invalid username '{user}'"),
                };
            }

            let ttl_secs = ctx
                .duration_secs
                .unwrap_or(DEFAULT_TTL_SECS)
                .clamp(MIN_TTL_SECS, MAX_TTL_SECS);
            let created_at = Utc::now();
            let expires_at = created_at + Duration::seconds(ttl_secs as i64);
            // Wave 2 (AUDIT-WAVE2-SUDOERS-DOT): sudo's `includedir` for
            // `/etc/sudoers.d/` SILENTLY ignores any file whose name
            // contains `.` (period) or ends in `~` (tilde) - per
            // sudoers(5) "files that contain a `.` (period) or end with
            // `~` (tilde) are silently ignored". Real Linux usernames
            // CAN contain `.` (e.g. `john.doe`), and `is_valid_username`
            // intentionally allows it. The deny file's filename is built
            // from the username verbatim, so `john.doe` produces
            // `/etc/sudoers.d/zz-innerwarden-deny-john.doe` which sudo
            // reads, sees the `.`, and skips - the rule never loads, the
            // suspension is silently a no-op, and the operator believes
            // the user was suspended. Sanitize the FILENAME portion only
            // (the rule body still uses the real username so sudo
            // matches the right account).
            let deny_file = format!(
                "{DENY_FILE_PREFIX}{}",
                sanitize_sudoers_filename_segment(&user)
            );

            if dry_run {
                info!(
                    user,
                    ttl_secs, deny_file, "DRY RUN: would suspend sudo for user"
                );
                return SkillResult {
                    success: true,
                    message: format!(
                        "DRY RUN: would suspend sudo for user {user} for {ttl_secs}s via {deny_file}"
                    ),
                };
            }

            let rule = render_sudo_deny_rule(&user, expires_at);
            let tmp_path = std::env::temp_dir().join(format!(
                "innerwarden-sudo-deny-{}-{}.tmp",
                user,
                Utc::now().timestamp_nanos_opt().unwrap_or_default()
            ));

            if let Err(e) = std::fs::write(&tmp_path, rule) {
                return SkillResult {
                    success: false,
                    message: format!("failed to write temp sudoers rule: {e}"),
                };
            }

            let tmp_path_str = tmp_path.to_string_lossy().to_string();
            let install_output = Command::new("sudo")
                .args([
                    "install",
                    "-o",
                    "root",
                    "-g",
                    "root",
                    "-m",
                    "440",
                    &tmp_path_str,
                    &deny_file,
                ])
                .output()
                .await;

            let _ = std::fs::remove_file(&tmp_path);

            match install_output {
                Ok(out) if out.status.success() => {}
                Ok(out) => {
                    let stderr = String::from_utf8_lossy(&out.stderr);
                    warn!(user, stderr = %stderr, "failed to install sudo suspend rule");
                    return SkillResult {
                        success: false,
                        message: format!("failed to install sudo suspend rule: {stderr}"),
                    };
                }
                Err(e) => {
                    warn!(user, error = %e, "failed to spawn install command");
                    return SkillResult {
                        success: false,
                        message: format!("failed to install sudo suspend rule: {e}"),
                    };
                }
            }

            let visudo_output = Command::new("sudo")
                .args(["visudo", "-cf", &deny_file])
                .output()
                .await;

            match visudo_output {
                Ok(out) if out.status.success() => {}
                Ok(out) => {
                    let stderr = String::from_utf8_lossy(&out.stderr);
                    let _ = Command::new("sudo")
                        .args(["rm", "-f", &deny_file])
                        .output()
                        .await;
                    warn!(user, stderr = %stderr, "invalid generated sudoers rule");
                    return SkillResult {
                        success: false,
                        message: format!("generated invalid sudoers rule for {user}: {stderr}"),
                    };
                }
                Err(e) => {
                    let _ = Command::new("sudo")
                        .args(["rm", "-f", &deny_file])
                        .output()
                        .await;
                    return SkillResult {
                        success: false,
                        message: format!("failed to validate sudoers rule: {e}"),
                    };
                }
            }

            let meta = SuspensionMetadata {
                user: user.clone(),
                deny_file: deny_file.clone(),
                created_at,
                expires_at,
                reason: ctx.incident.summary.clone(),
            };

            if let Err(e) = write_metadata(&ctx.data_dir, &meta) {
                warn!(user, error = %e, "failed to write suspension metadata");
            }

            info!(
                user,
                ttl_secs,
                deny_file,
                expires_at = %expires_at,
                "suspended sudo access for user"
            );

            SkillResult {
                success: true,
                message: format!(
                    "Suspended sudo for user {user} for {ttl_secs}s (until {expires_at})"
                ),
            }
        })
    }
}

pub async fn cleanup_expired_sudo_suspensions(data_dir: &Path, dry_run: bool) -> Result<usize> {
    let dir = metadata_dir(data_dir);
    if !dir.exists() {
        return Ok(0);
    }

    let mut removed = 0usize;
    let now = Utc::now();

    for entry in std::fs::read_dir(&dir).with_context(|| format!("read_dir {}", dir.display()))? {
        let entry = match entry {
            Ok(v) => v,
            Err(e) => {
                warn!(error = %e, "failed to read suspension metadata entry");
                continue;
            }
        };
        let path = entry.path();
        if path.extension().and_then(|v| v.to_str()) != Some("json") {
            continue;
        }

        let meta = match std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| serde_json::from_str::<SuspensionMetadata>(&s).ok())
        {
            Some(v) => v,
            None => {
                warn!(path = %path.display(), "invalid suspension metadata; removing file");
                let _ = std::fs::remove_file(&path);
                continue;
            }
        };

        if meta.expires_at > now {
            continue;
        }

        if dry_run {
            info!(
                user = %meta.user,
                deny_file = %meta.deny_file,
                "DRY RUN: would remove expired sudo suspension"
            );
            let _ = std::fs::remove_file(&path);
            removed += 1;
            continue;
        }

        let output = Command::new("sudo")
            .args(["rm", "-f", &meta.deny_file])
            .output()
            .await;

        match output {
            Ok(out) if out.status.success() => {
                let _ = std::fs::remove_file(&path);
                removed += 1;
                info!(user = %meta.user, "expired sudo suspension removed");
            }
            Ok(out) => {
                let stderr = String::from_utf8_lossy(&out.stderr);
                warn!(
                    user = %meta.user,
                    deny_file = %meta.deny_file,
                    stderr = %stderr,
                    "failed to remove expired sudo suspension"
                );
            }
            Err(e) => {
                warn!(
                    user = %meta.user,
                    deny_file = %meta.deny_file,
                    error = %e,
                    "failed to spawn remove command for expired suspension"
                );
            }
        }
    }

    Ok(removed)
}

fn write_metadata(data_dir: &Path, meta: &SuspensionMetadata) -> Result<()> {
    let dir = metadata_dir(data_dir);
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("failed to create metadata dir {}", dir.display()))?;

    let path = dir.join(format!("{}.json", meta.user));
    let content = serde_json::to_string_pretty(meta)?;
    std::fs::write(&path, content)
        .with_context(|| format!("failed to write suspension metadata {}", path.display()))?;
    Ok(())
}

fn metadata_dir(data_dir: &Path) -> std::path::PathBuf {
    data_dir.join("sudo-suspensions")
}

fn render_sudo_deny_rule(user: &str, expires_at: DateTime<Utc>) -> String {
    format!(
        "# Managed by Inner Warden\n# user={user}\n# expires_at={expires_at}\n{user} ALL=(ALL:ALL) !ALL\n"
    )
}

/// Wave 2 (AUDIT-WAVE2-SUDOERS-DOT) helper: replace characters that
/// sudo's `includedir` silently skips (`.` and `~`) with `_` so the
/// resulting `/etc/sudoers.d/` filename is actually loaded. The rule
/// body inside the file still uses the real username so sudo matches
/// the right account; only the on-disk filename is mangled.
///
/// Pinned by `sanitize_sudoers_filename_segment_*` anchor tests.
fn sanitize_sudoers_filename_segment(s: &str) -> String {
    s.chars()
        .map(|c| if c == '.' || c == '~' { '_' } else { c })
        .collect()
}

fn is_valid_username(user: &str) -> bool {
    if user.is_empty() || user.len() > 64 {
        return false;
    }

    let mut chars = user.chars();
    let Some(first) = chars.next() else {
        return false;
    };

    if !(first.is_ascii_alphanumeric() || first == '_' || first == '-') {
        return false;
    }

    chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.' || c == '$')
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Wave 2 anchors (AUDIT-WAVE2-SUDOERS-DOT) ──────────────────────
    //
    // sudo's `includedir /etc/sudoers.d` silently skips files containing
    // `.` or ending in `~` (sudoers(5)). Real Linux usernames may
    // legitimately contain `.` (e.g. `john.doe`), and `is_valid_username`
    // accepts them; without filename sanitisation the deny rule never
    // loads and the suspension is a silent no-op. These tests pin the
    // fix so the bug cannot recur quietly.

    #[test]
    fn sanitize_sudoers_filename_segment_replaces_dots() {
        // The exact prod failure shape: `john.doe` → filename
        // `zz-innerwarden-deny-john_doe`, NOT `..-deny-john.doe`
        // (which sudo would silently ignore).
        assert_eq!(sanitize_sudoers_filename_segment("john.doe"), "john_doe");
        assert_eq!(
            sanitize_sudoers_filename_segment("a.b.c.d"),
            "a_b_c_d",
            "every dot must be replaced, not just the first"
        );
    }

    #[test]
    fn sanitize_sudoers_filename_segment_replaces_tildes() {
        // sudo also skips files ending in `~`. Replace anywhere.
        assert_eq!(sanitize_sudoers_filename_segment("user~"), "user_");
        assert_eq!(sanitize_sudoers_filename_segment("u~ser"), "u_ser");
    }

    #[test]
    fn sanitize_sudoers_filename_segment_passes_safe_chars_through() {
        // ASCII alphanumeric + `_` + `-` + `$` (SAMBA machine accounts)
        // are all safe in sudoers.d filenames - must not be touched.
        for safe in &["alice", "bob_42", "ci-runner-3", "machine$", "x"] {
            assert_eq!(
                sanitize_sudoers_filename_segment(safe),
                *safe,
                "safe input {safe:?} must pass through unchanged"
            );
        }
    }

    #[test]
    fn sanitize_sudoers_filename_segment_handles_combined_skip_chars() {
        // Defense-in-depth: `john.doe~backup` would be doubly skipped
        // by sudo. Both classes of skip-char get replaced.
        assert_eq!(
            sanitize_sudoers_filename_segment("john.doe~backup"),
            "john_doe_backup"
        );
    }

    #[tokio::test]
    async fn dry_run_succeeds() {
        let ctx = SkillContext {
            incident: innerwarden_core::incident::Incident {
                ts: Utc::now(),
                host: "host".to_string(),
                incident_id: "sudo_abuse:deploy:test".to_string(),
                severity: innerwarden_core::event::Severity::Critical,
                title: "t".to_string(),
                summary: "s".to_string(),
                evidence: serde_json::json!({}),
                recommended_checks: vec![],
                tags: vec![],
                entities: vec![],
            },
            target_ip: None,
            target_user: Some("deploy".to_string()),
            target_container: None,
            duration_secs: Some(600),
            host: "host".to_string(),
            data_dir: std::env::temp_dir(),
            honeypot: crate::skills::HoneypotRuntimeConfig::default(),
            ai_provider: None,
        };

        let res = SuspendUserSudo.execute(&ctx, true).await;
        assert!(res.success);
        assert!(res.message.contains("DRY RUN"));
    }

    #[test]
    fn username_validation_is_strict() {
        assert!(is_valid_username("deploy"));
        assert!(is_valid_username("svc_user-1"));
        assert!(!is_valid_username(""));
        assert!(!is_valid_username("../etc/passwd"));
        assert!(!is_valid_username("bad user"));
    }
}
