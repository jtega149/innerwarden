# Spec 020: Zero Trust Autonomous MDR

**Created**: 2026-04-15
**Updated**: 2026-04-16
**Status**: DRAFT
**Priority**: P0 (product differentiator)
**Depends on**: Spec 018 (Phases A-D done), Spec 021

## Vision

InnerWarden evolves from reactive (detect → respond) to proactive (deny by default → permit with proof). Split across two products:

- **innerwarden** (free, Apache-2.0): detects, observes, auto-blocks obvious threats, AI triages ambiguous ones, brain learns
- **innerwarden-active-defence** (paid, proprietary): prevents execution of unknown binaries, contains processes, remediates damage, enforces Zero Trust policies

**The line**: free detects and responds. Paid prevents and contains.

## Product split

```
FREE (innerwarden, Apache-2.0):
  detect → observe → verify (spec 021) → auto-block → AI triage → brain learns
  
  "We saw SSH brute-force and blocked the IP"
  "AI says this looks like data exfil, blocked"
  "Observation verified: composer install is normal, auto-dismissed"

PAID (active-defence, proprietary):
  prevent → contain → remediate → recover
  
  "Unknown binary tried to execute — BLOCKED before it ran"
  "nginx tried to connect to port 4444 — BLOCKED"
  "Suspicious process FROZEN, evidence preserved"
  "Malicious crontab entry removed automatically"
```

## Phase breakdown by product

### FREE — innerwarden repo

| Phase | What | New code | Repo | Sessions |
|---|---|---|---|---|
| **C** | Continuous Trust Scoring Engine | ~300 lines | innerwarden | 1 |
| **D** | AI SOC Daily Checks + Threat Hunting | ~400 lines | innerwarden | 2 |
| **F-partial** | Graduated enforcement: learning + notify modes | ~100 lines | innerwarden | 1 |

**Phase C — Continuous Trust Score** (free)

Every entity in the knowledge graph gets a trust score 0-100 that decays with anomalies. This is observation — it informs but doesn't enforce.

```rust
struct TrustScore {
    score: f32,          // 0.0 - 100.0
    factors: Vec<TrustFactor>,
    last_updated: DateTime<Utc>,
}

enum TrustFactor {
    KnownBinary { hash_verified: bool },       // +30
    BaselineConformity { deviation: f32 },      // +20 to -20
    LoginHours { within_normal: bool },          // +10 or -10
    NewDestination { count: u32 },               // -5 per new dest
    UnknownLineage { parent: String },           // -20
    ReputationScore { abuseipdb: f32 },          // -0 to -40
    OperatorVerified { when: DateTime<Utc> },    // +30
    IncidentHistory { count_7d: u32 },           // -5 per incident
}
```

Dashboard shows scores. AI receives scores as context. Operator sees why a score is low. No enforcement — that's paid.

**Phase D — AI SOC Daily Checks** (free)

AI runs 15 system checks at 06:00 UTC, compares with yesterday, reports anomalies. Uses agent-guard for safe execution. Results go to dashboard + Telegram.

Checks: open ports, recent logins, system errors, disk usage, user accounts, executables in /tmp, failed services, firewall rules, crontab changes, SSH authorized_keys, kernel modules, SUID binaries, package integrity.

The commands run and AI analyses results — that's observation. The user's own AI provider (Ollama free, or their OpenAI key).

**Phase F-partial — Graduated enforcement: learning + notify** (free)

The state machine exists in the free product but only supports `learning` and `notify` modes. The `enforce` mode (blocking unknown binaries/connections) requires the paid product.

```toml
[zero_trust]
execution_mode = "notify"    # free: learning | notify. Paid: enforce
network_mode = "learning"    # free: learning | notify. Paid: enforce
```

### PAID — active-defence repo

| Phase | What | New code | Repo | Sessions |
|---|---|---|---|---|
| **A** | Execution Identity Registry + Script Signing | ~400 lines | active-defence | 2 |
| **B** | Network Micro-Segmentation | ~350 lines + eBPF | active-defence | 2 |
| **E** | File Quarantine + Process Containment + Remediation | ~500 lines | active-defence | 2 |
| **F-full** | Graduated enforcement: enforce mode | ~100 lines | active-defence | 1 |

**Phase A — Execution Gate** (paid, active-defence)

No unknown binary executes without verification. Uses LSM `bprm_check_security` to hold execve and check against allowlist BPF map.

Design already documented in `innerwarden-active-defence/crates/common/src/execution_gate.rs`. Ed25519 signing infra already in `config-sign/` crate. Key components:

- Binary Identity Registry: SHA-256 hash + lineage for every known binary
- Script Signing Cache: AI evaluates script content, signs with SHA-256, cached for instant re-execution
- Pre-scan: startup scan of /usr/bin, /usr/local/bin, package manager DBs
- BPF map: `EXEC_ALLOWLIST: HashMap<[u8; 32], u32>` pinned at `/sys/fs/bpf/innerwarden/exec_allowlist`
- Learning mode (free): records binaries, no blocking
- Notify mode (free): alerts on unknown, no blocking
- **Enforce mode (paid)**: blocks unknown binaries at LSM

**Phase B — Network Micro-Segmentation** (paid, active-defence)

Per-process outbound network policy enforced via eBPF at `connect` tracepoint.

```toml
[[zero_trust.network.policies]]
comm = "nginx"
allowed_ports = [80, 443, 8080]

[[zero_trust.network.policies]]
comm = "postgres"
allowed_ports = [5432]
deny_external = true
```

- Learning mode (free): baseline records all connections per process
- Notify mode (free): alerts when process connects to new destination
- **Enforce mode (paid)**: blocks unauthorized connections at eBPF level

**Phase E — Response & Recovery** (paid, active-defence)

- **File Quarantine**: move malicious file to `/var/lib/innerwarden/quarantine/`, preserve metadata, restore capability. New skill: `quarantine_file`
- **Process Containment**: cgroup freeze instead of kill. Process halted, memory preserved for investigation. New skill: `contain_process`
- **Automated Remediation**: per-detector cleanup actions (remove crontab entry, remove SSH key, disable systemd unit). New skill: `remediate`
- **Break-glass Recovery**: pre-generated recovery key for emergency access when operator is locked out

**Phase F-full — Enforce mode** (paid, active-defence)

Unlocks the `enforce` setting in graduated enforcement config. Without the paid product, `enforce` is not available — the system observes and alerts but never blocks unknown binaries or unauthorized connections.

```toml
# With active-defence license:
[zero_trust]
execution_mode = "enforce"    # blocks unknown binaries
network_mode = "enforce"      # blocks unauthorized connections
```

## Existing active-defence code to reuse

| Active-defence file | Lines | Reuse for |
|---|---|---|
| `execution_gate.rs` | 78 (design doc) | Phase A — complete design, needs implementation |
| `config-sign/sign.rs` | ~50 | Phase A — Ed25519 script signing |
| `config-sign/verify.rs` | 86 | Phase A — signature verification |
| `config-sign/keystore.rs` | ~60 | Phase A — key management |
| `lsm_policy.rs` | 150 | Phase F — BPF map read/write for LSM policy |
| `watchdog/monitor.rs` | 161 | Phase E — process monitoring infra |
| `watchdog/integrity.rs` | 92 | Phase A — binary SHA-256 verification |
| `watchdog/stealth.rs` | 141 | Anti-tamper — complementary |
| `decoy/orchestrator.rs` | 234 | Per-session honeypot namespaces |
| `license.rs` | 197 | License validation for paid features |

## Pricing

| Tier | Price | What |
|---|---|---|
| **Free** (innerwarden) | $0 forever | Detection, auto-response, AI triage, observation verification, trust scoring, daily checks |
| **Active Defence** | $10-15/host/month | Execution gate, network micro-seg, file quarantine, process containment, remediation, enforce mode |
| **Lifetime single-host** | $199 | Launch campaign — one-time payment, one host, forever |

## Competitive positioning

| | CrowdStrike | SentinelOne | Falco | Wazuh | **IW Free** | **IW + Active Defence** |
|---|---|---|---|---|---|---|
| Detection | Yes | Yes | Yes | Yes | **Yes** | **Yes** |
| Auto-response | Yes | Yes | No | No | **Yes** | **Yes** |
| Prevention (exec gate) | Yes | Yes | No | No | No (notify only) | **Yes** |
| Process containment | Yes | Yes | No | No | No | **Yes** |
| File quarantine | Yes | Yes | No | No | No | **Yes** |
| Remediation | Partial | Partial | No | No | No | **Yes** |
| Self-hosted | No | No | Yes | Yes | **Yes** | **Yes** |
| Price/host/year | $300-600 | $240-480 | $0 | $0 | **$0** | **$120-180** |

The free tier is already better than Falco + Wazuh combined. The paid tier competes with CrowdStrike at 1/3 the price, self-hosted.

## Implementation order

```
NOW (free, innerwarden repo):
  1. Spec 021 — Observation Verification (cleans FPs, no enforcement)
  2. Phase C — Trust Scoring (informs, no enforcement)
  3. Phase D — Daily AI Checks (observes, no enforcement)
  4. Phase F-partial — learning + notify modes

THEN (paid, active-defence repo):
  5. Phase A — Execution Gate (uses existing design + signing infra)
  6. Phase B — Network Micro-Segmentation
  7. Phase E — Quarantine + Containment + Remediation
  8. Phase F-full — Enforce mode
```

## Success criteria

### Free product
1. Trust score updates within 30s of relevant event
2. Daily check runs in <2min, report by 06:15 UTC
3. Observation verification auto-dismisses 80%+ of FPs
4. Zero additional API cost beyond user's own AI provider

### Paid product
1. Unknown binary blocked within 1ms at LSM (enforce mode)
2. Process frozen via cgroup freeze, not killed
3. File quarantine preserves path, perms, hash, timestamps
4. Graduated enforcement: each subsystem transitions independently
5. Zero false-positive blocks during learning period
6. Works offline (no cloud dependency for enforcement)

## Out of scope

- **Multi-host central console** — separate spec
- **Cloud telemetry** (AWS/GCP/Azure) — future XDR spec
- **IdP integration** (LDAP/OIDC) — future identity spec
- **GNN model** — requires 100+ labeled scenarios
- **Network deep parsing** (TCP reassembly, HTTP/2, SMB) — separate spec
