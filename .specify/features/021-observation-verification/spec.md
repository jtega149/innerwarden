# Spec 021: Observation Verification — Active FP Clearing

**Created**: 2026-04-15
**Status**: DRAFT
**Priority**: P0 (blocks autonomous MDR — FPs in OBSERVING destroy operator trust)
**Depends on**: Spec 018 Phases A-D (done)

## Problem

The agent detects and correlates, but the OBSERVING queue fills with false positives that nobody clears. Every legitimate process that reads files and makes outbound connections (OpenClaw, CrowdSec, apt, composer, any Rust tokio app) matches CL-008 (Data Exfiltration) or similar patterns.

Hardcoded process allowlists don't scale — every new software installed needs a new entry. PID tree walking is fragile — threads report as `tokio-rt-worker` regardless of parent binary. The operator ends up ignoring the dashboard because it's full of noise.

The real problem: **the system detects but never verifies.** A human looking at the dashboard immediately knows "that's OpenClaw talking to Telegram" — but nothing in the pipeline does that verification automatically.

## Solution

Every item in OBSERVING gets actively verified before it stays there. Verification has two layers:

1. **Behavioral checks** (scripted, free, <10ms) — score 0-100 based on process identity, parent chain, network behaviour, binary integrity, temporal context
2. **AI verification** (batch, for ambiguous scores) — AI looks at the observation context and says "normal" or "suspicious", exactly like an operator would

Items that score high are auto-dismissed. Items that score low escalate immediately. The ambiguous middle gets AI-verified. The OBSERVING queue stays clean.

## Architecture

```
Incident/Event → Fase 1 (auto-rules) → Fase 2 (correlation)
                                              │
                                     not matched
                                              │
                                              ▼
                                    ┌─────────────────┐
                                    │   OBSERVING      │
                                    │   (new state)    │
                                    └────────┬────────┘
                                             │
                              ┌──────────────┴──────────────┐
                              │    FASE 3: VERIFICATION      │
                              │    (every 30s tick)          │
                              │                              │
                              │  ┌────────────────────────┐  │
                              │  │ Layer A: Behaviour Score│  │
                              │  │ 5 checks, 0-100 points │  │
                              │  │ <10ms, zero cost        │  │
                              │  └───────────┬────────────┘  │
                              │              │               │
                              │    ≥70       │40-69     <40  │
                              │     │        │          │    │
                              │     ▼        ▼          ▼    │
                              │  DISMISS   AI VERIFY  ESCALATE│
                              │            (batch)           │
                              │              │               │
                              │        ┌─────┴─────┐        │
                              │     normal     suspicious    │
                              │        │           │         │
                              │     DISMISS     ESCALATE     │
                              └──────────────────────────────┘
                                             │
                                   ESCALATE goes to
                                             │
                                             ▼
                                    ┌─────────────────┐
                                    │  FASE 4: DECISION │
                                    │  AI triage full   │
                                    │  block/alert/etc  │
                                    └─────────────────┘
```

## Fase 3 Detail: Behavioural Checks

### Check 1 — Installation Legitimacy (+0 to +30 points)

**What**: Is the binary installed by a package manager or in a known path?

**How**:
```
binary path in /usr/bin, /usr/sbin, /usr/local/bin, /opt, /snap → +10
dpkg -S <binary_path> succeeds (Debian/Ubuntu) → +20
rpm -qf <binary_path> succeeds (RHEL/Rocky) → +20
snap list shows package → +20
binary path in /tmp, /dev/shm, /var/tmp, /home/*/Downloads → -20
```

**Why it works**: legitimate software is installed through package managers. Attackers drop binaries in /tmp. This check doesn't need to know WHAT the software is — just HOW it got there.

**Edge case**: user compiles from source (cargo build, go build) → binary in /home or /opt, no package manager → score +10 only. Falls to AI verification.

### Check 2 — Process Chain (+0 to +20 points)

**What**: Does the process tree trace back to a trusted root?

**How**:
```
Walk /proc/PID/status PPid up to init/systemd:

parent chain ends at systemd (PID 1) → +10
parent chain includes: cron, systemd, sshd, docker → +10
NO parent in /tmp, /dev/shm, /var/tmp → +10 (else -20)
process has controlling TTY → neutral (could be operator OR attacker)
parent is a shell spawned from sshd with operator IP → +10
```

**Why it works**: legitimate daemons are spawned by systemd. Legitimate user commands come from sshd→bash. Attackers spawn from exploited services (nginx→sh) or from /tmp binaries.

### Check 3 — Network Behaviour (+0 to +20 points)

**What**: Are the outbound connections going to legitimate destinations?

**How**:
```
destination IP has forward DNS resolution → +5
destination IP has reverse DNS matching forward → +5
destination port is standard service (80, 443, 53, 22, 5432, 3306, 6379, 8080, 8443) → +5
destination TLS certificate is valid (optional, expensive) → +5
destination IP in known CDN/cloud ranges (Cloudflare, AWS, GCP, Azure) → +5
destination port is high/unusual (4444, 1337, 31337, >50000) → -15
destination has no DNS at all (raw IP, no PTR) → -10
```

**Why it works**: legitimate services connect to well-known APIs over HTTPS. Attackers connect to raw IPs on unusual ports. This doesn't need to know "is this Telegram?" — it checks "is this how legitimate software behaves?".

### Check 4 — Binary Identity (+0 to +20 points)

**What**: Is the binary known-good and unmodified?

**How**:
```
SHA-256 of binary matches package manager database → +20
binary file age > 7 days → +10 (stable, not just dropped)
binary file age > 24h → +5
binary has valid ELF header, not packed/obfuscated → +5
binary file age < 1 hour AND not from package manager → -10
```

**Why it works**: legitimate binaries are installed days/weeks ago and match their package signatures. Freshly dropped binaries with no package provenance are suspicious.

### Check 5 — Temporal Context (+0 to +10 points)

**What**: Does the timing explain the behaviour?

**How**:
```
operator SSH session active in last 30 min → +10
apt/dnf/snap ran in last 10 min → +10 (deployment context)
systemctl restart ran in last 5 min → +5
event happened during configured maintenance window → +10
event happened at 3 AM with no operator session → -5
```

**Why it works**: operator installing Magento at 21:00 explains hundreds of new connections. The same connections at 3 AM with nobody logged in are suspicious.

### Score Interpretation

| Score | Meaning | Action | AI cost |
|---|---|---|---|
| 70-100 | Almost certainly legitimate | AUTO-DISMISS | Free |
| 40-69 | Ambiguous — could be either | AI VERIFY (batch) | 1 API call per batch |
| 0-39 | Almost certainly suspicious | ESCALATE to Fase 4 | Paid by Fase 4 |

**Expected distribution** (based on production data):
- ~80% of OBSERVING items score ≥70 → auto-dismissed, zero AI cost
- ~15% score 40-69 → AI verifies in batch (1 call per ~5 items)
- ~5% score <40 → escalated (real threats + edge cases)

## Fase 3 Detail: AI Verification (for score 40-69)

### When it runs

Every 30s tick, after behavioural checks. Collects all OBSERVING items with score 40-69 into a single batch.

### Prompt structure

```
You are a security analyst reviewing items in the observation queue of a Linux server.

Host profile:
- OS: Ubuntu 24.04 on Oracle Cloud
- Services: nginx, postgres, innerwarden (security agent), openclaw (AI bot), crowdsec
- Normal hours: this server runs 24/7, operator usually active 09:00-22:00 UK time

For each item below, answer: NORMAL or SUSPICIOUS + one-line reason.

Items in observation:

1. Process: openclaw-gatewa (PID 1536)
   Event: outbound connection to 149.154.166.110:443
   Parent chain: systemd → openclaw-gatewa
   Binary: /home/ubuntu/openclaw/bin/openclaw-gateway (age: 8 days)
   Behaviour score: 60/100 (no package manager, but systemd parent, DNS resolves to api.telegram.org)

2. Process: php (PID 8821)
   Event: outbound connection to 54.230.67.12:443
   Parent chain: bash → composer → php
   Binary: /usr/bin/php8.3 (dpkg verified)
   Behaviour score: 65/100 (package managed, operator SSH active, but destination is CDN IP)

3. Process: node (PID 9102)
   Event: outbound connection to 45.33.12.88:8443
   Parent chain: bash → npm → node
   Binary: /usr/bin/node (dpkg verified)
   Behaviour score: 45/100 (package managed, but unusual port 8443, destination has no reverse DNS)
```

### AI response format

```json
[
  {"item": 1, "verdict": "NORMAL", "reason": "OpenClaw bot connecting to Telegram Bot API (149.154.160.0/20 is Telegram's IP range)"},
  {"item": 2, "verdict": "NORMAL", "reason": "Composer downloading packages from Packagist CDN via CloudFront"},
  {"item": 3, "verdict": "SUSPICIOUS", "reason": "npm postinstall connecting to non-standard port on IP with no reverse DNS — possible supply chain attack"}
]
```

### Cost

- **Ollama local** (qwen2.5:3b): free, 1-3s per batch
- **OpenAI/Anthropic**: ~$0.001 per batch of 5 items (gpt-4o-mini / haiku)
- **Max batches per day**: ~2880 (every 30s) × ~15% ambiguous = ~430 AI calls/day
- **Realistic**: most ticks have 0 ambiguous items → ~10-50 AI calls/day

### What AI knows that scripts don't

| Script check says | AI knows |
|---|---|
| "IP 149.154.166.110 resolves in DNS" | "That's Telegram's API server range" |
| "Port 443 is standard" | "But port 8443 on an unknown IP is C2 pattern" |
| "Binary is in /usr/bin" | "But curl|sh followed by /usr/bin/curl is different from normal curl usage" |
| "Parent is bash" | "bash from sshd at 3 AM from Brazil for a UK user is unusual" |
| "File age >7 days" | "But the file was modified 1 hour ago (supply chain)" |

## Implementation

### New module: `crates/agent/src/observation_verify.rs` (~500 lines)

```rust
/// Score an OBSERVING item using behavioural checks.
pub(crate) fn behaviour_score(
    event: &Event,
    incident: &Incident,
    state: &AgentState,
) -> VerificationResult {
    let mut score: i32 = 50; // start neutral
    
    score += check_installation(&event.details);
    score += check_process_chain(&event.details);
    score += check_network_behaviour(&event.details);
    score += check_binary_identity(&event.details);
    score += check_temporal_context(&event.details, state);
    
    let score = score.clamp(0, 100) as u8;
    
    match score {
        70..=100 => VerificationResult::Dismiss { score, reason: "legitimate behaviour" },
        40..=69  => VerificationResult::NeedsAiVerification { score },
        _        => VerificationResult::Escalate { score, reason: "suspicious behaviour" },
    }
}

/// Batch-verify ambiguous items with AI.
pub(crate) async fn ai_verify_batch(
    items: &[ObservingItem],
    provider: &dyn AiProvider,
    host_profile: &str,
) -> Vec<AiVerdict> { ... }

/// Individual check functions (pure, testable).
pub(crate) fn check_installation(details: &serde_json::Value) -> i32 { ... }
pub(crate) fn check_process_chain(details: &serde_json::Value) -> i32 { ... }
pub(crate) fn check_network_behaviour(details: &serde_json::Value) -> i32 { ... }
pub(crate) fn check_binary_identity(details: &serde_json::Value) -> i32 { ... }
pub(crate) fn check_temporal_context(details: &serde_json::Value, state: &AgentState) -> i32 { ... }
```

### Integration in agent loop

```rust
// In slow loop (30s tick), after correlation:
let observing_items = state.get_observing_items();
for item in &observing_items {
    let result = observation_verify::behaviour_score(item, state);
    match result {
        Dismiss { score, reason } => {
            state.auto_dismiss_observation(item, score, reason);
            // Log to brain for training
            log_deterministic_decision_to_brain(item, "Dismiss", ...);
        }
        NeedsAiVerification { score } => {
            ai_verify_batch.push(item);
        }
        Escalate { score, reason } => {
            state.escalate_to_phase4(item, score, reason);
        }
    }
}
// Batch AI verification for ambiguous items
if !ai_verify_batch.is_empty() && ai_enabled {
    let verdicts = observation_verify::ai_verify_batch(&ai_verify_batch, provider, host_profile).await;
    for (item, verdict) in ai_verify_batch.iter().zip(verdicts) {
        match verdict {
            Normal { reason } => state.auto_dismiss_observation(item, reason),
            Suspicious { reason } => state.escalate_to_phase4(item, reason),
        }
    }
}
```

### Config

```toml
[observation]
enabled = true
# How often to run verification (seconds). Default: every slow-loop tick (30s).
verify_interval_secs = 30
# Minimum score to auto-dismiss without AI.
auto_dismiss_threshold = 70
# Maximum score to auto-escalate without AI.
auto_escalate_threshold = 40
# Use AI for ambiguous items (score between thresholds).
ai_verification = true
# Maximum items per AI batch call.
ai_batch_size = 10
# Maintenance windows (items during these hours get +10 context points).
maintenance_windows = ["02:00-04:00", "14:00-15:00"]
```

### Dashboard changes

OBSERVING items now show their verification score:

```
149.154.166.110
OBSERVING → DISMISSED (score: 80/100 — legitimate behaviour)
  ✅ Package managed binary
  ✅ systemd parent chain
  ✅ DNS resolves to api.telegram.org
  ✅ Standard HTTPS port
```

Or for suspicious items:

```
45.33.12.88
OBSERVING → ESCALATED (score: 25/100 — suspicious behaviour)
  ✅ Package managed binary
  ❌ Non-standard port 8443
  ❌ No reverse DNS
  ❌ First time connecting to this destination
  🤖 AI: "Possible supply chain attack via npm postinstall hook"
```

## Phases

| Phase | What | Lines | Sessions |
|---|---|---|---|
| A | Behavioural score engine (5 checks, pure functions) | ~300 | 1 |
| B | Integration in agent loop + OBSERVING state management | ~150 | 1 |
| C | AI batch verification prompt + response parsing | ~150 | 1 |
| D | Dashboard: score display + dismiss/escalate indicators | ~100 | 1 |
| **Total** | | **~700** | **4** |

## What this replaces

This spec replaces the `trusted_processes` approach (hardcoded process lists) and the PID-tree walking hack. Those can be removed once spec 021 lands. The behavioural checks are strictly more general:

| Approach | OpenClaw FP | apt FP | Magento install FP | Unknown Rust app FP |
|---|---|---|---|---|
| trusted_processes list | ✅ (hardcoded) | ✅ (hardcoded) | ❌ (need to add) | ❌ (need to add) |
| PID tree walk | ❌ (not our child) | ❌ (not our child) | ❌ | ❌ |
| **Behaviour score** | ✅ (systemd parent, DNS resolves) | ✅ (package managed) | ✅ (operator active, dpkg binary) | ✅ (AI verifies context) |

## Product tier

**Spec 021 is 100% FREE (innerwarden repo, Apache-2.0).**

The behavioural checks and AI batch verification are observation — they determine if something is normal or suspicious. They don't enforce or block. Enforcement (blocking unknown binaries, freezing processes) is paid (spec 020 Phase A/B/E in active-defence repo).

Spec 021 is the foundation that spec 020 builds on:
- Free: score 0-100 → auto-dismiss or escalate to AI triage
- Paid: score feeds into enforcement decisions (low score + enforce mode → block at LSM)

## Interaction with other specs

- **Spec 018 (Autonomous Response)**: Phases A-D done. Spec 021 adds Fase 3 between Fase 2 and Fase 4.
- **Spec 020 (Zero Trust MDR)**: Spec 021 behavioural checks feed into Phase C (trust scoring). Phase A (execution gate, paid) reuses the binary identity checks from spec 021. The score engine is free; enforcement is paid.
- **Spec 015 (Signal Quality)**: spec 021 reduces noise in the graph by dismissing FPs before they become incident nodes.

## Success criteria

1. OBSERVING queue has ≤5 items at any time on a stable server (currently: 50+)
2. Zero legitimate processes blocked after Fase 3 verification
3. Time from "new software installed" to "auto-dismissed" < 60 seconds
4. AI verification costs < $0.10/day on OpenAI, $0 on Ollama
5. All 5 behavioural checks are pure functions with unit tests
6. Score breakdown visible in dashboard for each OBSERVING item
7. Brain receives dismiss/escalate decisions as training signals

## Scenarios validated by this spec

| Scenario | Score | Outcome |
|---|---|---|
| apt update (cron, 3 AM) | 90 | Auto-dismiss |
| composer install (operator active) | 100 | Auto-dismiss |
| OpenClaw → Telegram API | 80 | Auto-dismiss |
| CrowdSec → api.crowdsec.net | 70 | Auto-dismiss |
| New Magento cron job | 80 | Auto-dismiss |
| SSH brute force | — | Blocked in Fase 1 (never reaches Fase 3) |
| Credential compromise + wget | 20 | Escalate → AI block |
| Fileless injection (nginx RWX) | 30 | Escalate → AI contain |
| Supply chain (npm postinstall) | 25 | Escalate → AI block |
| Hacker reverse shell | — | Kill chain in Fase 2 (never reaches Fase 3) |
| Unknown compiled binary in /opt | 55 | AI verify → depends on context |
| Docker container outbound | 60 | AI verify → depends on destination |
