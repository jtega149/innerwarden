//! Architectural gate for block-ip `ResponseSkill` invocations from
//! non-canonical paths (honeypot auto-block, Telegram bot, dashboard
//! manual action, post-session block).
//!
//! ## Why this module exists
//!
//! Graphify path analysis on 2026-05-10 surfaced that 5 production
//! block-ip emitters had **no real edge** to the canonical safeguard
//! chain at `decision_block_ip::execute_block_ip_decision`. The shortest
//! path from `handle_always_on_connection` (honeypot auto-block) to
//! `apply_post_decision_safeguards` (cooldown + audit-chained log) went
//! through `now()` — an INFERRED bridge that just reflects shared use of
//! `Instant::now()`. There was no architectural link.
//!
//! Concrete symptom (operator-reported on 2026-05-10 SESSION_LOG): the
//! honeypot's `handle_always_on_connection` called `BlockIpUfw.execute()`
//! directly, bypassing the operator allowlist that the normal decision
//! flow honours. Loopback and the Oracle internal IP — both in
//! `cfg.allowlist.trusted_ips` — got firewall-blocked during smoke
//! testing.
//!
//! Same class of bypass exists in `bot_actions.rs` (Telegram operator
//! quick-block), `honeypot_post_session.rs`, and `dashboard/actions.rs`.
//!
//! ## What this module does
//!
//! [`gate_block_ip`] is a stateless check covering the three guards every
//! block-ip path must respect:
//!
//! 1. **IP shape** — reject empty strings and malformed targets so the
//!    firewall backend never sees garbage that would leak into the
//!    response lifecycle as a zombie "active" entry.
//! 2. **Operator allowlist** — reject IPs/CIDRs in
//!    `cfg.allowlist.trusted_ips`. This is the explicit operator
//!    contract: "never auto-respond to these endpoints."
//! 3. **Cloud-provider safelist** — reject IPs in the static
//!    Cloudflare / AWS / GCP / Azure / Oracle CDN ranges
//!    (see `cloud_safelist::safelist_label`). Closes the
//!    repeat-offender cascade that took Cloudflare ranges offline in
//!    prod on 2026-04-18.
//!
//! On success, [`gate_block_ip`] returns a [`GatedBlockIp`] proof token.
//! [`execute_block_skill_gated`] is the only function that accepts this
//! token — so a non-canonical caller cannot invoke a `block-ip-*`
//! `ResponseSkill::execute` without first running the gate. The type
//! system is the architectural anchor.
//!
//! ## Scope vs canonical path
//!
//! `decision_block_ip::execute_block_ip_decision` keeps its richer
//! state-based gates (per-minute rate limit, operator-session IPs,
//! circuit breaker per UTC hour) because they require `&mut AgentState`,
//! which the non-canonical callers do not all have access to. The
//! stateless subset here is the safety floor every block-ip path must
//! clear — a strict subset of the canonical gates, never weaker than
//! them on the overlap.

use crate::{allowlist, cloud_safelist, decision_block_ip, skills};

/// Opaque proof token returned by [`gate_block_ip`]. Holding one means
/// the IP cleared the stateless block-ip safety gates (shape + operator
/// allowlist + cloud safelist). [`execute_block_skill_gated`] is the
/// only consumer.
///
/// The lifetime ties the token to the IP string it was minted for, so a
/// caller cannot mint a gate for one IP and execute against another.
#[derive(Debug)]
pub(crate) struct GatedBlockIp<'a> {
    pub(crate) ip: &'a str,
}

/// Reason the gate refused a block-ip request. `Display` keeps the
/// `"skipped: ..."` prefix the canonical path uses so audit-trail
/// consumers see consistent strings regardless of which path refused
/// the block.
#[derive(Debug)]
pub(crate) enum BlockGateRefusal {
    EmptyIp,
    InvalidTarget(String),
    TrustedIp(String),
    CloudSafelist { ip: String, provider: &'static str },
}

impl std::fmt::Display for BlockGateRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyIp => write!(f, "skipped: block decision has empty IP"),
            Self::InvalidTarget(ip) => {
                write!(f, "skipped: {ip} is not a valid IP address or CIDR")
            }
            Self::TrustedIp(ip) => {
                write!(f, "skipped: {ip} is in operator trusted_ips allowlist")
            }
            Self::CloudSafelist { ip, provider } => {
                write!(
                    f,
                    "skipped: {ip} is in cloud provider safelist ({provider})"
                )
            }
        }
    }
}

/// Run the stateless block-ip gate. Returns a proof token on success;
/// non-canonical callers can then call [`execute_block_skill_gated`].
pub(crate) fn gate_block_ip<'a>(
    ip: &'a str,
    trusted_ips: &[String],
) -> Result<GatedBlockIp<'a>, BlockGateRefusal> {
    if ip.is_empty() {
        return Err(BlockGateRefusal::EmptyIp);
    }
    if !decision_block_ip::is_valid_block_target(ip) {
        return Err(BlockGateRefusal::InvalidTarget(ip.to_string()));
    }
    if allowlist::is_ip_allowlisted(ip, trusted_ips) {
        return Err(BlockGateRefusal::TrustedIp(ip.to_string()));
    }
    if let Some(provider) = cloud_safelist::safelist_label(ip) {
        return Err(BlockGateRefusal::CloudSafelist {
            ip: ip.to_string(),
            provider,
        });
    }
    Ok(GatedBlockIp { ip })
}

/// Execute a `block-ip-*` `ResponseSkill` with a gate proof token. The
/// `&GatedBlockIp` argument is required by the type system, so a caller
/// cannot bypass [`gate_block_ip`].
///
/// Runtime invariant: `ctx.target_ip` must match the IP the gate was
/// minted for. Catches the bug-class where a caller mints a gate for
/// IP A but constructs a `SkillContext` targeting IP B — the firewall
/// rule would then apply to B without B ever clearing the gate.
pub(crate) async fn execute_block_skill_gated(
    skill: &dyn skills::ResponseSkill,
    ctx: &skills::SkillContext,
    dry_run: bool,
    gate: &GatedBlockIp<'_>,
) -> skills::SkillResult {
    if ctx.target_ip.as_deref() != Some(gate.ip) {
        return skills::SkillResult {
            success: false,
            message: format!(
                "skipped: gate-token IP {} does not match ctx.target_ip {:?}",
                gate.ip, ctx.target_ip
            ),
        };
    }
    skill.execute(ctx, dry_run).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Once;

    static INIT: Once = Once::new();
    fn init_cloud_safelist() {
        INIT.call_once(cloud_safelist::init);
    }

    #[test]
    fn empty_ip_refused() {
        let r = gate_block_ip("", &[]);
        assert!(matches!(r, Err(BlockGateRefusal::EmptyIp)));
        assert_eq!(
            format!("{}", r.unwrap_err()),
            "skipped: block decision has empty IP"
        );
    }

    #[test]
    fn invalid_target_refused() {
        let r = gate_block_ip("not-an-ip", &[]);
        match r {
            Err(BlockGateRefusal::InvalidTarget(ip)) => assert_eq!(ip, "not-an-ip"),
            other => panic!("expected InvalidTarget, got {other:?}"),
        }
    }

    #[test]
    fn trusted_exact_ip_refused() {
        let trusted = vec!["10.0.0.1".to_string()];
        let r = gate_block_ip("10.0.0.1", &trusted);
        match r {
            Err(BlockGateRefusal::TrustedIp(ip)) => assert_eq!(ip, "10.0.0.1"),
            other => panic!("expected TrustedIp, got {other:?}"),
        }
    }

    #[test]
    fn trusted_cidr_range_refused() {
        let trusted = vec!["10.0.0.0/8".to_string()];
        let r = gate_block_ip("10.42.5.7", &trusted);
        assert!(matches!(r, Err(BlockGateRefusal::TrustedIp(_))));
    }

    #[test]
    fn loopback_with_trusted_ips_refused() {
        // Reproduces the 2026-05-10 honeypot smoke incident: 127.0.0.1
        // was in trusted_ips but the honeypot's direct skill.execute
        // call bypassed the allowlist. With the gate in place,
        // loopback never reaches the firewall backend.
        let trusted = vec!["127.0.0.1".to_string()];
        let r = gate_block_ip("127.0.0.1", &trusted);
        assert!(matches!(r, Err(BlockGateRefusal::TrustedIp(_))));
    }

    #[test]
    fn cloud_safelist_cloudflare_refused() {
        // 104.16.0.1 is inside the Cloudflare 104.16.0.0/13 range
        // declared in cloud_safelist::CLOUDFLARE_RANGES. Closes the
        // 2026-04-18 repeat-offender cascade that auto-blocked
        // Cloudflare edges in production. cloud_safelist::init() lazy-
        // populates the CLOUD_RANGES OnceLock; without it `safelist_label`
        // returns None and the gate would let the block through.
        init_cloud_safelist();
        let r = gate_block_ip("104.16.0.1", &[]);
        match r {
            Err(BlockGateRefusal::CloudSafelist { ip, provider }) => {
                assert_eq!(ip, "104.16.0.1");
                assert!(
                    provider.to_lowercase().contains("cloudflare"),
                    "expected Cloudflare label, got {provider}"
                );
            }
            other => panic!("expected CloudSafelist refusal, got {other:?}"),
        }
    }

    #[test]
    fn clean_external_ip_passes() {
        let r = gate_block_ip("198.51.100.42", &[]);
        let gate = r.expect("clean external IP should pass");
        assert_eq!(gate.ip, "198.51.100.42");
    }

    #[test]
    fn refusal_messages_keep_canonical_skipped_prefix() {
        init_cloud_safelist();
        // Audit-trail consumers (notification gate, dashboard live
        // feed) parse the "skipped:" prefix to classify refusals
        // differently from successful blocks. The gate's Display must
        // preserve that prefix so non-canonical refusals look the same
        // as canonical ones in the operator's view.
        for r in [
            gate_block_ip("", &[]).unwrap_err(),
            gate_block_ip("garbage", &[]).unwrap_err(),
            gate_block_ip("10.0.0.1", &["10.0.0.1".to_string()]).unwrap_err(),
            gate_block_ip("104.16.0.1", &[]).unwrap_err(),
        ] {
            let msg = format!("{r}");
            assert!(
                msg.starts_with("skipped:"),
                "refusal display missing 'skipped:' prefix: {msg}"
            );
        }
    }

    #[test]
    fn valid_cidr_passes() {
        // Operator CLI accepts CIDRs (`innerwarden block 10.0.0.0/24`).
        // The gate must permit a syntactically valid CIDR through —
        // the automated-path callers run `is_single_ip_block_target`
        // separately when they need to reject CIDRs.
        let r = gate_block_ip("203.0.113.0/24", &[]);
        assert!(r.is_ok(), "valid CIDR should pass gate: {r:?}");
    }

    // ─────────────────────────────────────────────────────────────────
    // execute_block_skill_gated runtime invariant: gate IP must match
    // ctx.target_ip. The proof token alone is not enough — a caller
    // could mint a gate for IP A and execute against a SkillContext
    // targeting IP B. The runtime check catches that bug-class.
    // ─────────────────────────────────────────────────────────────────

    struct StubSkill {
        result: skills::SkillResult,
    }

    impl skills::ResponseSkill for StubSkill {
        fn id(&self) -> &'static str {
            "stub-skill"
        }
        fn name(&self) -> &'static str {
            "Stub Skill"
        }
        fn description(&self) -> &'static str {
            "test-only skill returning a canned SkillResult"
        }
        fn tier(&self) -> skills::SkillTier {
            skills::SkillTier::Open
        }
        fn applicable_to(&self) -> &'static [&'static str] {
            &[]
        }
        fn execute<'a>(
            &'a self,
            _ctx: &'a skills::SkillContext,
            _dry_run: bool,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = skills::SkillResult> + Send + 'a>>
        {
            Box::pin(async move {
                skills::SkillResult {
                    success: self.result.success,
                    message: self.result.message.clone(),
                }
            })
        }
    }

    fn ctx_for(ip: Option<&str>) -> skills::SkillContext {
        skills::SkillContext {
            incident: crate::tests::test_incident(ip.unwrap_or("198.51.100.1")),
            target_ip: ip.map(str::to_string),
            target_user: None,
            target_container: None,
            duration_secs: None,
            host: "test-host".to_string(),
            data_dir: std::path::PathBuf::from("/tmp"),
            honeypot: skills::HoneypotRuntimeConfig::default(),
            ai_provider: None,
        }
    }

    #[tokio::test]
    async fn execute_block_skill_gated_proxies_to_skill_when_ctx_matches() {
        let gate = gate_block_ip("198.51.100.42", &[]).expect("clean IP");
        let skill = StubSkill {
            result: skills::SkillResult {
                success: true,
                message: "applied".to_string(),
            },
        };
        let ctx = ctx_for(Some("198.51.100.42"));
        let r = execute_block_skill_gated(&skill, &ctx, true, &gate).await;
        assert!(r.success);
        assert_eq!(r.message, "applied");
    }

    #[tokio::test]
    async fn execute_block_skill_gated_rejects_mismatched_ctx_target_ip() {
        // The gate was minted for `.42` but the context targets `.99`.
        // The skill must NOT run — without this check, a buggy caller
        // could pass any ctx to an arbitrary gate token.
        let gate = gate_block_ip("198.51.100.42", &[]).expect("clean IP");
        let skill = StubSkill {
            result: skills::SkillResult {
                success: true,
                message: "should not see this".to_string(),
            },
        };
        let ctx = ctx_for(Some("198.51.100.99"));
        let r = execute_block_skill_gated(&skill, &ctx, true, &gate).await;
        assert!(!r.success, "mismatched ctx must short-circuit");
        assert!(
            r.message.contains("does not match ctx.target_ip"),
            "diagnostic must point at the mismatch: {}",
            r.message
        );
    }

    #[tokio::test]
    async fn execute_block_skill_gated_rejects_missing_ctx_target_ip() {
        let gate = gate_block_ip("198.51.100.42", &[]).expect("clean IP");
        let skill = StubSkill {
            result: skills::SkillResult {
                success: true,
                message: "should not see this".to_string(),
            },
        };
        let ctx = ctx_for(None);
        let r = execute_block_skill_gated(&skill, &ctx, true, &gate).await;
        assert!(!r.success);
        assert!(r.message.contains("does not match ctx.target_ip"));
    }
}
