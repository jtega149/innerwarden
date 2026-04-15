use std::future::Future;
use std::pin::Pin;

use tracing::{info, warn};

use crate::skills::{ResponseSkill, SkillContext, SkillResult, SkillTier};

pub struct BlockIpUfw;

impl ResponseSkill for BlockIpUfw {
    fn id(&self) -> &'static str {
        "block-ip-ufw"
    }
    fn name(&self) -> &'static str {
        "Block IP via ufw"
    }
    fn description(&self) -> &'static str {
        "Permanently blocks the attacking IP using ufw (Uncomplicated Firewall). \
         Adds a DENY rule with the 'innerwarden' comment for traceability. \
         Requires: sudo ufw deny from <IP> (configured in /etc/sudoers.d/innerwarden)."
    }
    fn tier(&self) -> SkillTier {
        SkillTier::Open
    }
    fn applicable_to(&self) -> &'static [&'static str] {
        &["ssh_bruteforce", "port_scan", "credential_stuffing"]
    }

    fn execute<'a>(
        &'a self,
        ctx: &'a SkillContext,
        dry_run: bool,
    ) -> Pin<Box<dyn Future<Output = SkillResult> + Send + 'a>> {
        Box::pin(async move {
            let ip = match &ctx.target_ip {
                Some(ip) => ip.clone(),
                None => {
                    return SkillResult {
                        success: false,
                        message: "block-ip-ufw: no target IP in context".to_string(),
                    }
                }
            };

            if dry_run {
                info!(
                    ip,
                    "DRY RUN: would execute: sudo ufw deny from {ip} comment 'innerwarden'"
                );
                return SkillResult {
                    success: true,
                    message: format!("DRY RUN: would block {ip} via ufw"),
                };
            }

            let output = tokio::process::Command::new("sudo")
                .args(["ufw", "deny", "from", &ip, "comment", "innerwarden"])
                .output()
                .await;

            match output {
                Ok(out) if out.status.success() => {
                    info!(ip, "blocked via ufw");
                    SkillResult {
                        success: true,
                        message: format!("Blocked {ip} via ufw"),
                    }
                }
                Ok(out) => {
                    let stderr = String::from_utf8_lossy(&out.stderr);
                    warn!(ip, stderr = %stderr, "ufw block command failed");
                    SkillResult {
                        success: false,
                        message: format!("ufw block failed for {ip}: {stderr}"),
                    }
                }
                Err(e) => {
                    warn!(ip, error = %e, "failed to spawn ufw command");
                    SkillResult {
                        success: false,
                        message: format!("failed to run ufw: {e}"),
                    }
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::skills::{HoneypotRuntimeConfig, SkillContext};

    fn make_ctx(ip: Option<&str>) -> SkillContext {
        SkillContext {
            incident: innerwarden_core::incident::Incident {
                ts: chrono::Utc::now(),
                host: "h".into(),
                incident_id: "id".into(),
                severity: innerwarden_core::event::Severity::High,
                title: "t".into(),
                summary: "s".into(),
                evidence: serde_json::json!({}),
                recommended_checks: vec![],
                tags: vec![],
                entities: vec![],
            },
            target_ip: ip.map(str::to_string),
            target_user: None,
            target_container: None,
            duration_secs: None,
            host: "h".into(),
            data_dir: std::env::temp_dir(),
            honeypot: HoneypotRuntimeConfig::default(),
            ai_provider: None,
        }
    }

    #[tokio::test]
    async fn dry_run_ufw() {
        let ctx = make_ctx(Some("192.168.1.1"));
        let result = BlockIpUfw.execute(&ctx, true).await;
        assert!(result.success);
        assert!(result.message.contains("DRY RUN"));
        assert!(result.message.contains("192.168.1.1"));
    }

    #[tokio::test]
    async fn no_target_ip_ufw() {
        let ctx = make_ctx(None);
        let result = BlockIpUfw.execute(&ctx, true).await;
        assert!(!result.success);
        assert!(result.message.contains("no target IP"));
    }

    #[test]
    fn skill_metadata_ufw() {
        assert_eq!(BlockIpUfw.id(), "block-ip-ufw");
        assert!(BlockIpUfw.name().contains("ufw"));
        assert_eq!(BlockIpUfw.tier(), SkillTier::Open);
        assert!(BlockIpUfw.applicable_to().contains(&"credential_stuffing"));
    }
}
