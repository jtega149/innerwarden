# Changelog

All notable changes to Inner Warden are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

## [0.15.18] - 2026-06-18

### Changed
- **Daily Security Briefing rewritten to be accurate and boss-readable.** The daily Telegram/Slack/Discord briefing was misleading a non-technical operator on four counts; all four are fixed. (1) **"Needs review" now equals the LIVE dashboard number.** It used to render `grouping_engine.drain_digest_stats().needs_review_groups`, a transient per-window group counter drained on every send, which diverged from the dashboard "Needs review" tile the operator actually clicks into. A Low/Medium `needs_review` incident auto-dismissed by the spec-062 24h timeout was still counted by the grouped counter even though it had already dropped out of the live count, so the briefing told the operator to "review N items" the dashboard showed as zero. The briefing now reads the SAME canonical source the dashboard reads (`dashboard::live_needs_review_count` → `data_api::compute_overview_counts_from_sqlite`'s per-attacker `KpiBucket::Attention`), renders it as actionable copy (`N security event(s) still need your decision. Open InnerWarden → Cases → "Needs review" and Block, Dismiss, or Monitor each.`), and reconciles to the live source so it can never point the operator at an already-closed item; 0 → `Nothing needs you right now`. (2) **No raw detector names.** Every per-category line now routes through `detector_catalog::digest_gloss(detector)` (spec-075 catalog) for a plain-language label plus a one-clause "why it matters", and the `_ => detector` raw fallback in `friendly_detector_name` is gone, a new `humanize_detector` Title-Cases any uncurated/dotted name so no `kernel_devnode_exposed` / `telemetry.stream_silence` snake_case ever leaks. The catalog gained curated entries for the previously-uncovered briefing detectors (`threat_intel`, `proto_anomaly`, `kernel_devnode_exposed`, `network_sniffing`, `kernel`, `telemetry.stream_silence`, `logging_config_change`, `automated_file_collection`, `suspicious_login`, plus a `honeypot` response gloss); the long tail collapses into `… and N more (see dashboard)`. (3) **Headline numbers explained.** `Made N automatic decisions across M security events (one event can need several decisions)` kills the "more decisions than events?" confusion, the cryptic `(post-posture)` token became `after accounting for this server's hardening`, and the briefing leads with a plain bottom-line verdict (`Quiet day` / `Busy day, all contained` / `N items need your decision`). (4) **Leads with blocked sources.** A real daily report now opens with `Blocked N attacking IP(s) (K still contained)` and the top sources by block frequency (with country flag on a cheap geo-cache hit, never an HTTP call from the digest path; cross-referenced against `response_lifecycle.active_block_ip_targets` for live containment). All three profiles (simple/technical/enriched) are boss-readable; `technical` only appends a raw-counter footer. An optional one-line `💡 Proactive:` suggestion fires on an unambiguous pattern (e.g. heavy SSH password-guessing → recommend key-only SSH). The old `format_daily_digest_enriched`/`PipelineDigestStats` are superseded (kept `#[allow(dead_code)]` for their copy-regression anchors).
- **Burst summary now names the server and explains the attack.** The "heavy attack" Telegram/Slack/Discord notification that fires when 50+ threats are auto-blocked in an hour used to say only `50 threats auto-blocked this hour. All contained.`, useless to a multi-server operator: it never said WHICH server, never said WHAT kind of attack, and always read "50" (it fires the instant the count crosses the threshold). It now (a) names the server via a `[agent] tags` → knowledge-graph hostname → `/etc/hostname` ladder (resolved once, cheap), (b) breaks down the top categories blocked so far into ~7 plain-language buckets (DDoS / flood, Password-guessing, Scans & probes, Exploit / C2, Data-exfiltration, Privilege-escalation / escape, Other) with counts, (c) reports how many distinct attacker IPs, and (d) says honestly `Blocked 50+` (it fires at the threshold, not the final total) plus a "should you worry?" reassurance that this is normal internet background noise. `BurstTracker::record_contained` now accumulates per-category counts + distinct source IPs over the window and returns a `BurstSummary` snapshot; a new `burst_category(detector)` classifier maps detector/kill-chain/shield kinds to the coarse buckets. The single shield "DDoS Shield" SendNow alert also gains the `[host]` prefix. Wired into all four burst-emit paths (incident pipeline, killchain inline, shield inline, mesh). Host strings are HTML-escaped.

### Security
- **Bumped the `tract-*` family 0.22.1 → 0.22.2 (CVE-2026-55093 / GHSA-x5mv-8wgw-29hg).** `tract-nnef`'s NNEF `.dat` tensor parser had an unchecked `product(shape) * size_of` that wraps in release builds, yielding a `Tensor` whose reported `len` (e.g. 2^61) far exceeds its tiny backing allocation → an out-of-bounds read on model load (CWE-190 → CWE-125, medium). `tract-onnx` is the on-device Local Warden classifier backend (`local-classifier` feature); InnerWarden only loads its own pinned, SHA-256-verified ONNX model (not attacker-supplied NNEF archives), so exposure is low, but the dependency is patched anyway. Dependabot could not apply the bump alone because the interdependent `tract-*` crates must move together; updated as a family to 0.22.2.

### Fixed
- **Managed-agent verifier now resolves a real `agent connect`-registered agent (spec 081 follow-up).** Deploying 0.15.16 to the Azure box surfaced that `innerwarden agent connect <pid>` records the process **COMM** (`MainThread` for a node-launched agent) as the registry `name`, while the verifier's live `identify_cmdline` resolves the **signature** name (`OpenClaw`). The verifier required `live_sig_name == reg.name`, so a CORRECTLY-registered OpenClaw was rejected → it would still have been auto-blocked/kernel-blocked under enforce. (The spec-081 tests used `connect_with_facts("OpenClaw", …)` and masked it; production `connect` stores the comm.) The name-equality was **redundant** with the exact `cmdline_fingerprint` match (the real identity pin — it already defeats pid-reuse / a different agent at the same pid), so it is dropped: the verifier now requires only that the live cmdline re-IDs *a* known agent signature AND the live `interpreter|script` fingerprint EQUALS the one captured at `connect()`. No relaxation — a regression test proves a comm-named entry whose live fingerprint differs still BLOCKS. The audit line now surfaces the resolved signature name (`OpenClaw`) rather than the stored comm. Without this, `[responder] dry_run=false` (enforce) on a host running a registered agent would still sever it.

## [0.15.16] - 2026-06-18

### Added
- **Spec 081 — Managed-Agent Coexistence: stop severing a co-located, IW-managed AI agent.** When a legit AI agent IW is meant to GUARD (e.g. OpenClaw running as `node .../node_modules/openclaw/dist/index.js`, comm `MainThread`) reads its OWN `.env` and connects to its OWN Slack/Azure endpoint, that NORMAL startup matched the generic `sensitive_read → outbound_connect` exfil/C2 signature and IW auto-BLOCKED the (shared) destination IP **and** KERNEL-PID-BLOCKED the agent (denying its next execve) — severing the very agent IW guards. New `crates/agent/src/managed_agent_guard.rs` verifier withholds ONLY the auto-block/kernel-deny RESPONSE for a positively-verified managed agent on its own services; DETECTION is untouched (the incident still fires + the operator is still notified — downgrade, never silence). The relaxation is **source-based** (the agent identity — registry hit AND live `/proc/<pid>/cmdline` re-ID AND non-attacker-writable exe root AND own-config-path-owned-by-agent-uid, all re-verified live, fail-closed), **never destination-based** (keeps working when the Slack/Azure IP rotates; a known-bad destination still forces the block), and **agent-agnostic** (any agent-guard signature, not hardcoded to OpenClaw). Wired at the kernel PID-block (`killchain_inline::register_kernel_blocks`, gated to the `data_exfil`/`exploit_c2` FP shape) and at the userspace destination-IP block convergence point (`decision_block_ip::execute_block_ip_decision`, covering both the AI-router and killchain paths). Registry hardened to capture `exe_path`/`owner_uid`/`cmdline_fingerprint` live at `connect()` (backward-compatible serde defaults) so a self-registered or pid-recycled process cannot inherit the exemption. 7 required anti-evasion tests lock the no-hole property; the response-side wiring (`SystemProc` real-`/proc` resolver, `registry::capture_proc_facts`/`connect()` live capture, the userspace-IP-block and kernel-block decision helpers) was extracted into pure-of-`AgentState` functions and covered by unit tests plus a cross/integration test proving the SAME OpenClaw incident is spared on BOTH response paths (IP-block downgrade + kernel-block withhold) while an unregistered pid blocks on both.

### Fixed
- **macOS release job no longer flakes the whole release red on the runner thread-cap.** The `Build and publish (macOS)` job re-ran the full `cargo test --workspace` on the macOS runner, where a low per-process thread cap + leaked r2d2/scheduled-thread-pool reaper threads make `pthread_create` fail with EAGAIN near the end of the agent crate's large test binary — so `0.15.12`, `0.15.14` and `0.15.15` all published Linux assets but failed to publish the light-tier ("Phantom") macOS binaries even though the code was fine. The macOS job `needs: build-release`, and that Linux job already runs the IDENTICAL `cargo test --workspace` as a hard gate before macOS starts (and the PR `validate` workflow runs it on every change), so the macOS re-run was redundant for correctness — its only unique surface is the tiny macOS-specific code path (there is no eBPF on macOS). The macOS test step is now `continue-on-error: true` (still runs, failures stay visible in its log) with `--test-threads=1`, so a runner thread-cap flake can never block the macOS binary publish while a real logic regression is still caught by the Linux gate.

## [0.15.15] - 2026-06-18

### Fixed
- **DNS Guard export now cleans hosts-file feed entries.** A field deploy on a real box surfaced that the agent's consolidated threat-feed stores many malicious domains in hosts-file form (`127.0.0.1\tevil.com`, `0.0.0.0 evil.com`) — public domain blocklists ship that way and the feed ingestion kept the raw lines. The exporter was writing those raw lines to the DNS Guard denylist, producing tens of thousands of `127.0.0.1\t…` junk entries that never match a real query. It now extracts the actual domain (last whitespace token), lowercases + strips a trailing dot, and rejects bare IPs / no-dot / non-hostname junk. The default `denylist_path` also moved from `/etc/innerwarden` (root config dir) to `/var/lib/innerwarden` (the agent's data dir): the agent runs as the unprivileged `innerwarden` user and the `/etc` default failed with permission denied. Found by deploying the guard in observe on a lab box whose feed had 65k "domains", all hosts-format; with the fixes the agent exported 64,252 clean domains and the guard would-blocked them.

### Added
- **DNS Guard block events become incidents — the block loop is now visible in IW.** Closes the bridge: the agent tails the DNS Guard's events JSONL (`[dns_guard] events_path`, byte-offset cursor so each line is seen once) and turns every `dns_guard.blocked` into a **High incident** — a host/agent tried to resolve a known-bad domain and was stopped, a strong compromise indicator. `would_block` (observe-mode telemetry) is intentionally NOT an incident (observe is for measuring the blast radius, not alerting). The incident id is stable per domain so repeats group; same-domain hits dedup within a batch. Gated by `ingest_enabled` (default off). With the exporter (which feeds IW's intel into the guard's denylist) this completes the round trip: IW detects → guard blocks the lookup → IW records the block.
- **DNS Guard intel bridge — free detection feeds the paid domain-prevention layer.** The paid Active Defence ships a second pre-authorization moat alongside the Execution Gate: `innerwarden-dns-guard`, a forwarding resolver that refuses to *resolve* a malicious domain (C2 / exfil / DGA / tunneling) before the connection is made — the AI-agent guardrail (point a sandbox's `resolv.conf` at it and the agent literally cannot look up an exfil/C2 domain). This OSS change is the free half of the wire: a new `[dns_guard]` config section + a slow-loop exporter that, when `export_enabled = true`, writes the agent's known-malicious domains (the consolidated threat-feed intel: IOC feeds + dns_c2 / dns_tunneling) to `denylist_path` (default `/var/lib/innerwarden/dns-deny.txt`). The write is atomic (temp + rename, so the guard never reads a half-written file), throttled (5 min), and skipped when unchanged (no reload churn); the running DNS Guard hot-reloads the file and blocks the listed domains. Off by default — an OSS-only install does nothing. Same free-detect / paid-prevent line as the Execution Gate (the detection is free and auditable; arming the prevention is the paid layer).

## [0.15.14] - 2026-06-17

### Added
- **Execution Gate divergence monitor — the free honesty net so the paid gate can never silently go inert (spec 080 G4).** The Execution Gate (paid Active Defence) is armed from a signed allowlist file that a watcher reconciles into kernel BPF maps. A 2026-06-17 fleet audit found a silent failure mode: a prod box with a signed `observe` allowlist of 1685 entries while the live kernel map was **inert with 0 entries** — staged but never applied, so the gate was doing nothing and nobody knew. Now the agent slow loop reads the LIVE pinned `EXEC_ALLOWLIST` + `LSM_POLICY` maps every 10 min and compares them to the signed file; on divergence it raises a self-incident: **High** for apply-drift (signed config not in the kernel) and **Critical** for the brick case (gate armed in enforce mode but the live allowlist is empty → every exec would be denied). It verifies the LIVE kernel state, never an internal record (same principle as spec 076 block live-verify), and an unreadable map never cries wolf. `innerwarden doctor` gains an **Execution Gate** section showing signed-vs-live counts + mode. This honesty net is **free/OSS** by design (spec 080 §10) — keeping the paid feature accountable is a safety net, not a paid add-on. The arming/reconcile tooling itself remains the paid layer.
- **`innerwarden uninstall` — one-command, complete removal (closes #1047).** There was no documented way to remove InnerWarden; users had to reverse-engineer the install footprint by hand. New `innerwarden uninstall` tears it down in the safe order: stops the watchdog/supervisor FIRST (so nothing respawns the agent mid-uninstall), then stops the agent + sensor (a `systemctl stop` kills the whole cgroup, so the PID-namespaced / comm-masked agent goes down with it), then removes the systemd units + drop-ins, binaries, embedded eBPF object, pinned BPF maps, sudoers drop-ins, and the firewall rules InnerWarden added (matched by `innerwarden` tag, deleted high-number-first so the indices don't shift). Config (`/etc/innerwarden`) and data (`/var/lib/innerwarden`) are KEPT by default so a reinstall keeps history + license; `--purge` removes them plus `/var/log/innerwarden` and the `innerwarden` user. `--dry-run` prints the exact plan and needs no root; the real teardown requires sudo and confirms first (`--yes` to skip). The installer mirrors this for broken-binary cases: `curl … | sudo bash -s -- --uninstall [--purge]` prefers `innerwarden uninstall` and falls back to an inline teardown if the binary is unusable. README gains an Uninstall section.
- **`innerwarden dashboard` — easy + secure dashboard access (no more systemd surgery).** The dashboard binds to localhost by default (secure). Opening it used to mean hand-editing the systemd unit (or the watchdog `--agent-arg`), `daemon-reload`, restart, and a manual firewall rule. Now it is config-driven (`[dashboard] bind` in agent.toml, which takes precedence over the `--dashboard-bind` flag) and managed by one command: `innerwarden dashboard` (status: bind, URL, login, ready-to-paste SSH-tunnel command), `dashboard open` (exposes it **securely** — generates a login if none exists, sets the bind, and **firewall-locks to your current SSH client IP** by default; `--public`/`--allow <ip>` to widen/narrow), `dashboard close` (back to localhost), `dashboard tunnel` (print the exact SSH-forward command). Exposing is always password-protected: the agent refuses to serve a non-loopback bind without credentials (SEC-005), so `open` sets a login first.
- **Surface-aware agent-guard benchmark (spec 079 P2, deep-MCP inspection) — catch rate to 100% on the corpus.** The MCP guard inspects several surfaces with different rules (a command via `analyze_command`, a poisoned tool *result* via `inspect_response`, a poisoned tool *description*/manifest via `inspect_tool_description`), but the benchmark previously ran every case through the command path, so an indirect-injection-via-tool-result was scored against the wrong rules and missed. Corpus cases now carry a `surface` and the evaluator routes each to the matching inspector. This closed the last two misses — an indirect-injection tool result and a hex-escaped command — taking the corpus to **35/35 caught (100%)** at the same 5.6% false-positive rate. Supporting detection: a more flexible exfil-directive rule (`exfiltrate/POST <sensitive> to <url|email>`, tolerant of words between the verb and the data noun) and `\xNN` hex-escape obfuscation detection.

### Fixed
- **Agent-Guard false-positive rate cut from 27.8% to 5.6% while raising catch rate to 94.3%** (spec 079 P3, gated by the agent-attack benchmark). Root cause was an engine category error: `rules.rs::parse_field` mapped any unknown condition field — including `tool_name` — to the `UserInput` catch-all, so tool-NAME word lists (`chmod|sudo|bash|rm -rf`) matched raw command substrings (`~/.bashrc` matched `bash`, `sudo apt install` matched `sudo`, `rm -rf ./build` matched `rm -rf`), flagging normal dev commands as CRITICAL. Fixes: (1) a dedicated `AtrField::ToolName` evaluated only against an actual tool name via `check_tool_name`, never against user input/commands; (2) ATR-2026-064 no longer treats `chmod +x` as privesc (only setuid `+s`) and only flags privilege-escalating `sudo` (a root shell), not `sudo apt-get install`; (3) ATR-2026-061 generic `any`-token matching (bare `curl`/`wget`/`rm -rf`/`$VAR`) tightened to malicious-specific shapes. No detection blind spot: the catches those over-broad rules were incidentally making are restored via proper specific signals — `curl … | python3 -` (versioned-interpreter download-exec), `dd` disk-wipe + fork bomb (new destructive signals), and a hidden-exfil-to-URL tool-poisoning condition — so catch rate went UP (91.4% → 94.3%), not down. A `p3_fp_reduction_regression_gate` test locks the result so future changes can't silently regress it.

### Added
- **Agent-Guard proof benchmark (`cargo run -p innerwarden-agent-guard --example agent_attack_benchmark`).** A curated 53-case corpus (35 agent-native attacks across reverse-shell / download-exec / obfuscation / destructive / persistence / credential-access / privesc / prompt-injection / indirect-injection / tool-poisoning / multi-step + 18 benign controls) plus a reproducible scoring harness that runs each case through the real `check-command` engine and writes an honest `SCOREBOARD.md` (catch rate, hard-deny rate, false-positive rate, per-category breakdown, and the explicit list of misses). Measured baseline of the current engine: **91.4% caught (85.7% hard-denied) on 35 attacks**; the **27.8% benign false-positive rate** and 2 destructive-technique gaps (`dd`-to-block-device, fork bomb) are now measured, not assumed — they are the backlog for the guardrail-hardening work (spec 079 P2/P3).

### Fixed
- **No more CRITICAL "keylogger persistence" false positive when a toolchain installer writes `~/.profile`.** `rustup-init` (and `pip`/`npm`/`nvm`/`conda`/…) appending a `PATH`/env line to the invoking user's own shell startup file fired the `shell_startup_write` detector as a CRITICAL keylogger alert (T1546.004). The detector now recognizes language/runtime installers and, when they write **within their own user scope**, downgrades to Low (still recorded for provenance) instead of paging. This is a downgrade, never a suppression: a comm-spoofing attacker still leaves a triage-able incident, and any installer-claimed write **outside** its scope (a non-root process touching `/root` or `/etc`) stays CRITICAL — no detection blind spot. Anti-evasion tests included.
- **`innerwarden doctor` no longer false-warns that the dashboard is down when it serves HTTPS.** doctor probed the dashboard over plain HTTP; on an HTTPS-only deployment that connection is refused, so doctor reported "Dashboard port 8787 is not responding" even while the dashboard returned HTTPS 200. doctor now falls back to a scheme-agnostic TCP connect, so a listening dashboard is reported up regardless of HTTP vs HTTPS.
- **Integrity collector stops re-warning every minute about an unhashable file.** A single unreadable integrity target (e.g. permission denied) logged `cannot hash file` every poll interval forever — ~10k lines in 7 days on one host. It now warns ONCE per path and clears the latch when the path becomes hashable again, so a real new blind spot still surfaces immediately without the per-minute spam.
- **Anomaly recalibration no longer spams WARN before the autoencoder has trained.** On a fresh or frequently redeployed host the nightly autoencoder has no model yet, and post-graph recalibration logged `no model loaded: train_nightly first` at WARN every 30s tick (~2.7k lines in 7 days). That expected pre-training condition is now a debug line; genuine recalibration errors still WARN.
- **Flaky `run_agent` orchestration test de-flaked.** The slow-loop side-effect test used a fixed 8s `timeout(run_agent)` that always burned the full window and failed on slower hardware (2 of 3 isolated runs on a slow box) when the grouping-engine tick had not landed in time. It now polls for the snapshot and finishes the instant it appears (30s ceiling), so it is deterministic on loaded CI and faster on success.
- **XDP TTL cleanup no longer hammers `sudo bpftool` every tick when the agent lacks privilege.** When the agent runs unprivileged (e.g. `User=innerwarden`) with a non-XDP block backend (`ufw`), the boot-loop XDP TTL sweep's `sudo bpftool map delete` fails with a permission/sudo error every slow-loop tick. The old code treated that as a *transient* drift and retried + logged every 30s forever: one stuck entry produced **44,415 failed sudo-auths + 44,260 WARN lines in 7 days** on a production box. A new classifier (`is_xdp_privilege_failure`) routes permanent privilege failures into exponential backoff (60s → 1h cap) and logs only on the first failure and once at the cap; transient kernel/map drift keeps the retry-next-tick behaviour. Backoff is runtime-only, so a restart (or a newly added sudoers rule) retries immediately. Surfaces the entry for drift visibility instead of flooding.
- **AI briefing "Ignored" count now matches the dashboard "Filtered out" tile.** The briefing said "Ignored 21" while the Home tile said "Filtered out 11" — the briefing counted `dismissed.incidents + allowlisted.incidents` while the tile is `dismissed.unique_attackers` (one attacker fires many incidents). The briefing's `ignored` is now `dismissed.unique_attackers` and drops the separate allowlisted/operator-trust bucket. The incident-count lines ("operator-relevant incidents today", "observing") stay incident-based so they keep agreeing with the Sensors HUD and Report totals.
- **Operator suggestions are operator-actionable again.** The dashboard "Suggestions" surfaced trial/rollout/dev-tuning notes ("improve detector payload completeness", "before widening rollout", "proceed to next phase", "signal quality") that a steady-state operator can't act on. Rewrote them to plain operator guidance and dropped the internal detector-payload diagnostic from the operator surface.

### Fixed
- **Daily briefing/digest now names the host.** The digest body led with no host, so on a shared Telegram chat / Slack channel you couldn't tell which server's briefing it was. It now leads with `🖥 <host>` (the incident host label / sensor `host_id`, same as real alerts), falling back to the system hostname.

### Fixed
- **Daily digest ("Daily Security Briefing") now reaches Slack + Discord, not just Telegram.** The once-a-day report was sent only through `telegram_client`, so Slack-only hosts (and shared channels) never got it. It now fans out through the spec 078 chat-channel registry: Telegram keeps its uncapped `send_text_message` path (a busy day can't drop it), and Slack/Discord receive it too. One dedup marker still guarantees one send per day.

### Changed
- **`innerwarden notify test` now names the host.** The test alert (Telegram + Slack) includes the host label (sensor `[agent] host_id`, same as real incidents) so operators sharing one chat/channel across several boxes can tell which server it came from.

### Added
- **Discord notifications.** A new `[discord]` channel (Incoming Webhook) gets
  incident alerts, action reports, and burst summaries as colour-coded Discord
  embeds — full parity with Telegram and Slack. Enable with `[discord] enabled =
  true` + `webhook_url = "https://discord.com/api/webhooks/…"` (or env
  `DISCORD_WEBHOOK_URL`); optional `min_severity` / `dashboard_url` /
  `channel_notifications` mirror Slack. Off by default; an empty webhook
  disables it at boot with a warning (never panics). Built on the spec 078
  chat-channel registry — it touched only a new `discord` module, the config,
  one boot block, and one registry line, with no dispatch-site edits. (Spec 078
  Phase 3.)
- **`innerwarden notify discord` setup command** + a **Discord integration card**
  on the dashboard's Alerts & Notifications panel. The command (and its
  `innerwarden config discord` alias) prompts for / accepts a webhook URL, saves
  it, flips `[discord]`, sends a test message, and restarts the agent — same UX
  as `notify slack`. (Spec 078 Phase 3b.)
- **`innerwarden setup` wizard now offers Discord** as a notification channel
  in the `[3/4] Notification channels` multi-select, with detection of an
  existing `[discord]` config and a guided configurator at apply-time. (Spec 078
  Phase 3c.)

### Changed
- **Unified chat-channel registry for notifications (internal).** Telegram and
  Slack incident alerts now fan out through one `ChatChannel` trait + registry
  (`notification_channels`) instead of two hand-wired dispatch blocks. Each
  channel applies the same severity-rank + filter-level gate, and one channel
  failing never blocks the others. Behaviour is identical for existing
  channels; the point is that a new operator-facing channel (e.g. Discord) now
  plugs in by implementing one trait + one registry line, with no edits to any
  dispatch site. Webhook and Web Push remain non-chat sinks. (Spec 078 Phase 1.)
- **Action reports and burst summaries reach Slack too.** Post-execution action
  reports ("🛡️ Threat neutralized — Blocked …") and burst rollups were
  Telegram-only; they now fan out through the chat-channel registry so Slack
  (and future Discord) render the same disposition. `SlackClient` gained
  `send_action_report` (Block Kit) + `send_summary`. The `Dismiss`/`Ignore`
  suppression stays — only real actions report, on every channel. Action reports
  now follow the Telegram notification master switch (`[telegram] enabled`)
  instead of the conversational-bot switch. (Spec 078 Phase 2.)

### Fixed
- **No more "Threat neutralized — Dismissed" notification spam.** The
  post-execution action report fired for every decided action, including
  `Dismiss` and `Ignore` — which are *non-actions* (the agent judged the
  incident benign). Operators were flooded with "Threat neutralized —
  Dismissed" messages for false positives that needed no response. Dismissed
  and ignored incidents now skip the action report entirely; the first-alert
  and daily digest still record them.
- **False-positive "data exfiltration" on source/package files.** The exfil
  detector's sensitive-path list matched generic substrings (`/secret`,
  `/token`, `/credentials`) anywhere in a path, so an AI agent loading its own
  `node_modules/.../secret-contract-api.js` or `.../token/const.mjs` and then
  calling an API was flagged CRITICAL. Source files (`.js/.mjs/.ts/...`) and
  anything under `node_modules/` are no longer treated as credential reads
  (`.json` stays sensitive — gcloud's credentials file is genuine).

## [0.15.13] - 2026-06-15

### Added
- **`innerwarden setup` is now cloud-aware.** It detects the host's cloud
  platform (offline, via DMI) and adds that platform's fixed infrastructure
  addresses (e.g. Azure's wireserver, used for DNS/DHCP/health) to the host
  allowlist automatically, so the responder treats the cloud's own platform
  traffic as infrastructure rather than a third party. A per-host server-side
  rule the operator can see/edit in `agent.toml [allowlist]` — not a hardcoded
  entry in the product's block path. Idempotent.
- **`innerwarden mesh connect <peer>` — one-command collaborative defense.**
  Enables mesh, registers the peer, and opens the local host firewall
  (ufw/firewalld, source-scoped to the peer IP) for the mesh port in a single
  step, instead of `mesh enable` + `mesh add-peer` + a manual firewall edit.
  Accepts `host`, `host:port`, or a URL; normalizes to the mesh's HTTP scheme.
- **`innerwarden harden` — two new check categories.**
  - **Kernel Hardening**: 15 CIS-aligned sysctls the advisor did not check
    before (`kptr_restrict`, `dmesg_restrict`, Yama `ptrace_scope`,
    `unprivileged_bpf_disabled`, `bpf_jit_harden`, `protected_{hardlinks,
    symlinks,fifos,regular}`, `suid_dumpable`, `rp_filter`, `log_martians`,
    `icmp_echo_ignore_broadcasts`, `send_redirects`, `kexec_load_disabled`).
    Deliberately does **not** check `perf_event_paranoid` — raising it would
    break InnerWarden's own eBPF sensor.
  - **Access Control**: flags a host with neither AppArmor nor SELinux
    enforcing (a root compromise would otherwise be unconfined); warns when
    SELinux is merely permissive.

### Changed
- **`innerwarden harden` — cloud-aware false-positive reduction.** A clean
  public-cloud host no longer raises noise that buries real findings:
  - `cifs-utils`' SUID-root `/usr/sbin/mount.cifs` (and `ecryptfs-utils`) are
    recognised as packaged mount helpers, not anomalous SUID binaries. The
    trusted-owner dpkg lookup now also handles **usrmerge path aliasing** —
    `find` reports the canonical `/usr/sbin/...` while some packages record the
    pre-merge `/sbin/...` path, so the query retries the alias before flagging.
  - Stock cloud/virt/AMD/NIC kernel modules (Azure Hyper-V + MANA, RDMA/IB,
    AMD `ccp`, `irqbypass`, AWS `ena`, GCP `gve`, `dm_multipath`, common NIC
    drivers, ...) are added to the known-good set, clearing the "unusual kernel
    module(s)" low finding on Azure/AWS/GCP images.

### Fixed
- **Mesh could be silently disabled by a corrupt state file.** A zero-byte
  `mesh-state.json` (left by the previous non-atomic save when the agent was
  killed mid-write) made `load_state` return an error, which aborted mesh
  init — no listener, no peering — with only a swallowed warning. Mesh
  persistence now (a) writes atomically (temp + rename) and (b) fails soft on an
  empty/corrupt file (warn + start fresh). `innerwarden mesh status` no longer
  errors on such a file either. (innerwarden-mesh bumped to `12890c08`.)
- **`innerwarden agent scan` missed interpreter-launched AI agents.** Detection
  matched `/proc/<pid>/comm` only, so a node/python-launched agent (OpenClaw,
  aider, goose, cline, ...) whose `comm` is `node`/`python`/`MainThread` was
  reported as "No known agents detected". Detection now also scans
  `/proc/<pid>/cmdline` when the executable is a known interpreter, matching a
  signature name as an exact path component or a `python -m <module>` argument.
  Stays precise — bare args and `<name>.md` do not match.
- **`configure ai azure_openai` wrote a config that silently 404'd.** Azure's
  chat endpoint needs an `api-version` query param the agent reads from
  `[ai].api_version`; `configure ai` never wrote it. Now a known-good default is
  written for Azure, `azure` is accepted as an alias for `azure_openai`, and
  configuring Azure without `--base-url` fails loudly at configure-time.
- **`innerwarden doctor` reported a false `OPENAI_API_KEY not set` for Azure.**
  `doctor` now resolves and validates `AZURE_OPENAI_API_KEY` for
  `azure_openai`/`azure` instead of falling through to the OpenAI check.
- **`innerwarden enable` could not repair a half-enabled capability.** A
  capability marked enabled in config but missing its sudoers drop-in (so
  block-ip silently could not run firewall commands) was a dead end: `enable`
  replied "already enabled, nothing to do" and never re-applied. `enable` now
  takes `--force` to re-run apply and repair drift (idempotent), and `doctor`
  points at `sudo innerwarden enable <cap> --force`.
- **Integration Advisor no longer flags Telegram + Slack as a problem.** Running
  both notification channels (Telegram for real-time, Slack for team visibility)
  is an intentional setup; it is now a neutral "MULTI-CHANNEL ACTIVE" note rather
  than a red "OVERLAP DETECTED" warning.
- **Flaky MCP-proxy pipe tests eliminated.** Tests that pipe through a real
  spawned child occasionally saw a partial/empty read under CI load; they now
  run on a multi-worker runtime and re-run the exchange until the expected
  output is present. Test-only; no behavior change.

## [0.15.12] - 2026-06-14

### Fixed
- **Installer (`install.sh`) failed on a clean `curl | sudo bash`.** Three bugs,
  all on the product's front-door install path, now fixed + guarded by CI:
  1. `SUPERVISED: unbound variable` — the var was referenced under `set -u` but
     never declared. Now defaulted (`SUPERVISED="${SUPERVISED:-false}"`, opt-in)
     with a `--supervised` flag.
  2. `[responder]: command not found` — a backtick in a comment **inside an
     unquoted `<<EOF` heredoc** ran as a command substitution. Backticks removed.
  3. `/dev/tty: No such device or address` — the headless guard tested the device
     node's permission bits (`-r`) but the actual open still fails with no
     controlling terminal (piped/cloud-init/CI), aborting the install. Now probes
     by actually opening `/dev/tty`, and the interactive wizard is non-fatal.
  Removed dead `prompt_yes_no` (zero callers).
- **New `Installer` CI workflow** (`.github/workflows/installer.yml`) so this
  class never ships again: shellcheck (static, catches the heredoc/quoting class)
  **plus** a runtime smoke test that runs the installer exactly as users do
  (piped, no TTY) and asserts `innerwarden-sensor` + `innerwarden-agent` come up
  active — the only way to catch the `set -u` / heredoc / tty runtime failures
  shellcheck can't see.
- **Truthful containment for already-blocked `needs_review` cases.** A
  High/Critical case decided `needs_review` *before* its IP was blocked stayed in
  the dashboard's "Needs your attention" forever once the firewall started
  dropping it — pestering the operator about an already-contained threat (#987
  only verified at first-decision; the in-memory block record can also diverge
  from an orphaned ufw rule). A new slow-loop pass
  (`orphan_recovery::reverify_already_blocked_needs_review`) re-checks every
  current `needs_review` case against the **live firewall** (ufw + iptables probe,
  never the internal record — per spec-076) and records a truthful Contained
  decision for any IP it is actually dropping. Hole-free: it only contains
  recon-class detectors a firewall block fully mitigates (active-harm —
  reverse_shell/c2/data_exfil/ransomware/kill_chain — always stays surfaced even
  when blocked), a failed probe contains nothing, and a returning attacker raises
  a new incident handled by the live-verified re-block path (no free pass).
- **De-flake `mcp_proxy::transport::advisory_is_a_transparent_pipe`.** The test
  awaited the proxy task before reading its output, a duplex race that could
  observe an empty/partial buffer under CI load. It now drains concurrently
  (`tokio::join!`).

### Added
- **Execution Gate operator "Trust Exec" + allow_exec rules (spec 077 P3/P4).**
  The approve side of the gate, open-core: the OSS agent owns the approval UX, the
  paid `exec-gate watch` daemon owns enforcement, and they meet at the shared
  `/etc/innerwarden/rules/exec-gate` rules directory.
  - New `operator_exec_trust` module writes `allow_exec` rules (the same artifact
    an advanced user can hand-write) the paid daemon hot-reloads into the kernel
    allowlist.
  - Dashboard `POST /api/action/trust-exec` (+ `untrust-exec`, `GET trusted-execs`)
    authorise/revoke a binary path. Authorising an exec is a **sensitive action**,
    so it is **2FA-gated** (`verify_dashboard_totp`, when `[security].method = totp`)
    and recorded in the hash-chained admin-actions audit. Globs are rejected (the
    kernel enforces an exact path).
  - `innerwarden rule list` now shows Execution Gate `allow_exec` rules, and
    `rule disable/enable <id>` toggles them (revoke takes effect within one watch
    cycle). Without the paid daemon these rules are inert.
- **Execution Gate observe mode (spec 077 P2).** `LSM_POLICY` key 3 gains mode
  `2 = observe`: the eBPF gate computes the path-hash and, on an allowlist miss,
  emits a `lsm.exec_gate_would_block` event (Info) **but allows the exec** —
  instead of `-EPERM` (mode 1 = enforce). This is the safe-onboarding primitive:
  a host runs the gate in observe to *learn* its allowlist without bricking, then
  flips to enforce after a clean window. The would-block carries the real
  attempted path (marker `EXEC_OBSV`, distinct from the enforce `EXEC_GATE`).
  Ships inert (mode 0 default); arming/observe is the paid Active Defence step.
- **Operator "Trust IP" — a monitor-only allowlist managed from the dashboard.**
  New endpoints `POST /api/action/trust-ip`, `POST /api/action/untrust-ip`, and
  `GET /api/action/trusted-ips` (all under the existing dashboard auth + CSRF
  gate) let an operator mark an IP or CIDR as trusted so the agent stops
  AUTO-blocking it. Trust is deliberately the *safe* half of allowlisting: a
  trusted IP is **still detected, still logged, and still notified** (Telegram /
  Slack / webhook) — only the automated response is suppressed. There is no
  "drop / suppress detection" mode on this surface, so a dashboard-authenticated
  session cannot self-allowlist into silence. Internal/private ranges are allowed
  (trusting your own office/VPN/LB range is the point); ranges broader than
  `/8` (v4) or `/16` (v6) are rejected — this blocks `0.0.0.0/0` and the
  `0.0.0.0/1` + `128.0.0.0/1` two-halves end-run that would otherwise trust the
  whole internet from a hijacked session. Entries can be **time-boxed**
  (`ttl_hours`) and expire on their own within one slow-loop tick — no manual
  cleanup. Every add/remove is recorded in the hash-chained admin-actions audit
  trail. **Integrated with the user-facing rule system:** entries are written as
  ordinary `suppress_response`/`scope: ip` rules into the event_pipeline rules
  dir (`70-operator-trust.yml`) — the same format a user can hand-write — so they
  show up in `innerwarden rule list`, can be disabled with
  `innerwarden rule disable <id>`, appear in `innerwarden trust list` (now reads
  the dynamic rules too), and are hot-reloaded into `dynamic_trusted_ips` with
  TTL honoured. The sensor's `suppress_response` schema was relaxed
  (`SuppressConfig { detector?, scope? }`) so these shared-dir rules parse
  cleanly instead of warn-and-skipping — a fix that also benefits any
  hand-written `suppress_response` rule. **Dashboard:** a "✓ Trust IP" button on
  the case/journey view (next to Block/Unblock) opens a confirm modal and calls
  `trust-ip`; available on any IP case. Manage/time-box trusted entries via the
  CLI (`innerwarden trust`).

### Fixed
- **macOS release signing.** The release workflow's "Sign macOS release
  binaries" step failed on every run from 0.15.9 through 0.15.11
  (`pkeyutl: Option unknown option -rawin`, exit 1) because macOS runners
  expose LibreSSL as the system `openssl`, and LibreSSL's `pkeyutl` cannot
  raw-sign Ed25519. It now uses Homebrew's `openssl@3` explicitly, keeping the
  signature scheme byte-for-byte identical to the Linux job. Linux releases were
  never affected. (Note: macOS binaries ship without eBPF — eBPF is Linux-only;
  the macOS sensor uses log-based collectors. See README "Platform Support".)

### Changed
- **Install/upgrade telemetry is now opt-OUT (was opt-in), transparent, and
  covers upgrades.** The anonymous install ping flips to on-by-default; disable
  it with `INNERWARDEN_NO_TELEMETRY=1`. The installer and `innerwarden upgrade`
  each print a one-line notice (what is sent + how to opt out + link to
  `/privacy`) before sending, so the default-on collection is informed. The ping
  now also fires on `innerwarden upgrade` (previously only fresh `install.sh`, so
  upgrades were invisible) and carries an `event=install|upgrade` field. The data
  is unchanged — anonymous and minimal: release version + OS + CPU arch + event,
  no IP (the server hashes ip+day into a one-way dedup id and discards the raw
  IP), no host/agent/config data. See https://www.innerwarden.com/privacy.

## [0.15.11] - 2026-06-12

Headline: the **Execution Gate eBPF primitive** ships — a free, auditable,
kernel-level allowlist primitive that is **inert by default** and changes
nothing for existing users. Plus a Zero-Trust input-robustness sweep across the
enrichment clients and a batch of false-positive + operator-experience fixes.
Also reactivates the install-ping for the client deployment.

### Fixed
- **`systemd_persistence` false positives on benign systemctl ops.** Two FP classes
  reported from a live Telegram alert (2026-06-11): (1) `systemctl is-enabled <unit>`
  — a read-only query — fired because `contains("enable")` matched the "enable" inside
  "is-enabled"; (2) a bare `systemctl daemon-reload` (ubiquitous: every package install,
  deploy, and the agent's own restart dance) fired as High. Now persistence verbs are
  matched as TOKENS (`enable`/`reenable`/`link`), read-only verbs (`is-enabled`,
  `is-active`, `status`, …) stay silent, and a bare `daemon-reload` only alerts when the
  command references a suspicious path. Real persistence (unit-file writes + `enable`) is
  still caught aggressively. Regression tests added.
- **MCP proxy: capped the line reader (OOM/DoS).** The agent-guard MCP proxy
  (`innerwarden agent proxy -- <server>`) sits in front of UNTRUSTED MCP servers
  (and an untrusted client); its `tokio` `Lines` reader grew a single
  newline-less line without limit, so a hostile server/client could OOM the
  proxy with a multi-GB line. A new `CappedLines` reader (4 MB ceiling) fails the
  session closed instead of buffering unbounded. Regression tests cover normal
  lines, oversized-without-newline, and oversized-with-newline-past-cap.
- **Input-robustness hardening across the enrichment clients (same class as the
  DShield bug).** A Zero-Trust audit found the DShield failure mode lurking in
  siblings and a few unbounded reads:
  - **geoip** (`ip-api.com`): `isp`/`asn` were strict `String`s, so a bare-integer
    `as` or a `null` field failed the whole record and silently killed geo
    enrichment for every IP — exactly the DShield incident. Now a `lenient_string`
    deserializer (string/number/null) + a body cap.
  - **AbuseIPDB**: required scalars (`abuseConfidenceScore`, `totalReports`,
    `numDistinctUsers`, `isPublic`) get `#[serde(default)]` so a schema flip can't
    fail the record.
  - **Body-size caps** on the threat-feed IOC reader (operator-configured, often
    plain-`http://`, MITM-able), DShield, and the fleet poller — an unbounded
    `text()`/`json()` could OOM the agent. Mirrors the CrowdSec 8 MB cap.
  - **Honesty fix**: the orphan-recovery contained-decision text said "verified
    live" when it only consults the in-memory response lifecycle (no live firewall
    re-check); the text now states the real source.
- **DShield enrichment was silently dead.** DShield's per-IP API returns the AS
  number as a bare integer (`"as":48090`) for many IPs, but the `as_number`
  field was typed `Option<String>` (tests only covered the quoted-string form).
  serde failed the whole record — `invalid type: integer, expected a string` —
  so the ISC reputation signal was dropped for every IP (239 `failed to parse
  DShield response` warnings in 2 days on prod). A `lenient_string` deserializer
  now accepts string-or-number-or-null on the AS string fields.
- **Already-blocked threats no longer show up under "Needs your attention".**
  When a High/Critical incident became an orphan (no AI decision recorded — a
  deploy orphan or provider skip) the orphan-recovery sweep routed it to
  `needs_review` unconditionally, even when its IP was already blocked at the
  firewall. On prod this surfaced threat-intel IPs that `ufw`/`nft` were already
  dropping as cases that "need your attention". The sweep now verifies LIVE
  (`response_lifecycle::is_ip_actively_blocked`, mirroring the fast-loop churn
  guard: a block-mitigated detector AND a TTL-valid live block) and records a
  truthful `block_ip`/contained decision instead — so a neutralised threat reads
  as contained, not as pending operator action. Genuinely-unhandled High/Critical
  orphans still route to `needs_review` (Spec 062 invariant preserved).
- **Operator decision overrides now actually drive the case outcome.** The
  dashboard's override/reopen rows (`operator_override:<action>`,
  `operator_reopen`) were classified as unknown strings, so a "Dismiss" left the
  case stuck in "Needs your attention". `threat_contract::classify_decision` now
  understands the operator-action vocabulary, so Dismiss clears a case, Monitor
  moves it to Observing, Reopen returns it to attention, and an operator unblock
  resolves it.

### Added
- **Execution Gate primitive (eBPF, ships INERT).** A new dedicated minimal LSM
  program `innerwarden_lsm_exec_gate` on `bprm_check_security`: when armed
  (`LSM_POLICY` key 3 = 1), an exec whose path-hash (FNV-1a of `bprm->filename`,
  ≤256 bytes) is absent from the new `EXEC_ALLOWLIST` map is denied with `-EPERM`
  and an `EXEC_GATE_BLOCKED` event is emitted; allowlisted paths run untouched.
  Default is key 3 = 0 — the gate is **inert** out of the box and arming is
  operator-driven tooling, so OSS behaviour is unchanged. It lives in its own
  program (not `innerwarden_lsm_exec`) because the full hook fails the verifier
  on kernel ≥ 6.4. The `bprm->filename` byte offset is read from kernel BTF at
  load time (`BPRM_OFFSETS` map, CO-RE — it is 96 on 6.8, not the 72 older code
  assumed, which is `cred`), with 96 as fallback. `EXEC_ALLOWLIST` is pinned at
  `/sys/fs/bpf/innerwarden/exec_allowlist` so userspace tooling can populate it.
  Path read uses a per-CPU scratch buffer (zero BPF stack cost) and the gate
  fails OPEN (allow) on any read error. Proven end-to-end on kernel 6.8 x86_64:
  unknown binary blocked at exec, allowlisted binaries run, clean disarm, no
  brick. `scripts/verify-lsm-hooks.sh` now also pins the per-program FUNC
  symbol surface (bpf-linker folds same-hook programs into one ELF section, so
  the section check alone cannot see a dropped program). The gate's block is
  surfaced as a dedicated **`lsm.exec_gate_blocked`** event carrying the real
  attempted path inline (`details.filename` + `blocked_by: exec_gate`) — read
  straight from `bprm->filename`, since a denied exec leaves `/proc/<pid>`
  pointing at the old image and the path is unrecoverable afterwards.
- **More case actions than just "Block IP".** The case detail offered only a
  Block button (which hid once a case was blocked, leaving zero actions). New
  operator actions, all behind the same auth + CSRF gate as block-ip and
  honouring watch/guard mode:
  - **Unblock IP** (`POST /api/action/unblock-ip`) — the inverse of Block. It
    QUEUES the revert (writes an `operator_unblock_request`); the agent slow
    loop drains it and performs the real revert through `response_lifecycle`,
    clearing the persisted block records only on a confirmed revert. Going
    through the agent loop is deliberate: a dashboard-side rule removal would be
    re-applied by the spec-076 block-enforcement reconciler within minutes.
  - **Dismiss / Monitor / Reopen a case** (`POST /api/action/triage-case`) —
    writes one operator-action decision per incident in the case; the read
    path's latest-decision-per-incident selection makes the operator's verb win.

## [0.15.10] - 2026-06-10

### Fixed
- **Block enforcement now verifies the LIVE firewall rule before skipping a
  re-block (spec 076) — closes a free-pass hole.** The redundant-re-block guard
  in `execute_block_ip_decision` skipped re-blocking based on the agent's
  internal TTL record (`response_lifecycle::is_ip_actively_blocked`), not the
  actual firewall. When that record diverged from reality (a TTL removal that
  did not clear the record, an agent restart reloading a stale set, or an
  externally-flushed rule) it false-positived "already blocked" and skipped, so
  a still-attacking repeat offender got a free pass. Found in prod on a
  known-malicious IP whose every block decision logged "already blocked: live
  firewall rule already active" while it was absent from ufw/nft/iptables/XDP.
  The guard now confirms the rule against the live backend (`backend_status_cmd`
  + `rule_present_in` + `is_ip_live_blocked`); if it cannot be confirmed live it
  re-applies (idempotent, never opens a gap). Can only add blocks, never remove
  or widen them.

### Added
- **Explained Alerts (spec 075) — every notification teaches and reassures.** A
  new `detector_catalog` maps each detector to a plain-language "what + why",
  fused with the live MITRE mapping from `mitre.rs`. The plain-language Telegram
  alert (`format_simple_message`) now carries a "Why this matters" line with the
  attacker goal and MITRE attribution, so an alert reads as "InnerWarden saw
  this, knows what it is, and is handling it" instead of a raw detector name.
  Communication-only — no detection or severity change. Also maps three
  previously-unmapped detectors (`keylogger_bash_trap` -> T1056.004,
  `auditd_disable` / `selinux_apparmor_disable` -> T1562.001) so their alerts
  carry MITRE too.

## [0.15.9] - 2026-06-10

### Added
- **Audit-state monitor (spec 074) — catch an audit disable by ANY method.** A
  new `audit_state` collector polls the kernel audit `enabled` flag
  (`auditctl -s`) every 60s and emits `audit.disabled` when it is found off —
  either already disabled when the sensor starts or transitioning
  enabled->disabled at runtime. The `auditd_disable` detector turns it into a
  Critical incident (T1562.001). This closes a real gap found in prod on
  2026-06-09: a host ran with kernel audit disabled (`enabled 0`) for ~22h with
  NO alert, because the existing detector only watches for the disabling
  *command* in execve and that disable left no observed command. A state poll
  catches it regardless of how audit was disabled (`auditctl -e 0`, a netlink
  `AUDIT_SET`, etc.). Default-on like the other always-on collectors; fail-open
  when auditctl is absent. Brings the sensor to 30 collectors.

## [0.15.8] - 2026-06-09

### Added
- **Warden Context Gate — deterministic guardrail around the on-device decider (spec 071).**
  A pre/post gate around the Local Warden ONNX classifier: it surfaces under-rated
  High/Critical threats (escalates when the model's confidence is below the floor)
  and NEVER dismisses a High/Critical incident on a forgeable signal (`comm` /
  argv0 / prctl). Red-teamed: an attacker renaming a payload to a trusted process
  name can no longer talk the gate into a silent dismiss. Closes the false-positive
  source where the decider acted on a context-starved input, without weakening
  real detection.
- **MCP inspecting proxy (`innerwarden agent proxy`).** A stdio
  man-in-the-middle that wraps a real MCP server and inspects the JSON-RPC
  traffic in both directions: `tools/call` arguments (prompt injection,
  credential leaks, dangerous commands, ATR rules), `tools/list` descriptions
  (tool poisoning), and tool results (injection in responses). Four modes:
  `advisory` (default — a transparent, alerting pipe, no behavior change),
  `warn` (same forward-and-alert behavior as advisory, never blocks, but
  tagged for louder operator surfacing), `guard` (a disallowed `tools/call`
  is not forwarded; the client gets an `isError` denial keyed to the request
  id), and `kill` (block + terminate the server). Usage: `innerwarden agent
  proxy --mode guard -- npx -y <server>`.
  The decision logic is pure and unit-tested; the transport is a single-task
  `select!` loop (one client writer, no shared lock). Pass-through preserves
  original bytes; stdout carries only MCP traffic. New `crates/agent-guard/src/
  mcp_proxy/` (jsonrpc, router, enforce, transport) + CTL subcommand. Operator
  snitch (Telegram/Slack) + per-agent policy belong to the registry-aware
  in-agent mode (a later epic); this ships the standalone CLI.
- **`innerwarden_agent_guard_atr_rules_loaded` Prometheus gauge.** The
  `/metrics` endpoint now exports the number of ATR rules loaded in the
  agent-guard engine. `0` means the engine is degraded (rules failed to load
  or were never deployed) and `check-command` is running on built-in heuristics
  only — a state a scrape/alert can now catch. Always emitted, so absence vs
  zero is unambiguous. (Boot already logs the count; this makes it observable
  in monitoring.)

### Changed
- **agent-guard capability descriptions made honest (C1 audit follow-up).** The
  crate docs and Cargo description claimed "MCP protocol inspection", "process
  monitoring via eBPF", and "wrap MCP servers / enforce security policies" —
  none of which exist: tool-call screening is pattern/regex scanning over the
  serialized call (no MCP-protocol parsing, no inline proxy), discovery is a
  `/proc` walk (no eBPF), and detection is advisory ("snitch" alerts), not
  enforcement. Descriptions now state what the code actually does. Added
  count-anchor tests pinning the advertised numbers to the code (prompt-injection
  patterns = 24 — the previously marketed "29" was false; dangerous commands = 14;
  API-key patterns = 7; AI agent/tool/runtime signatures = 20, not "25+"), so a
  doc/code drift fails CI.
- **Orphan-recovery retries the decider for High/Critical orphans before queueing (spec 071 Part C).**
  A High/Critical incident left without an AI decision (e.g. a provider skip during
  an agent restart) is now re-run through the decider before being routed to the
  `needs_review` queue, instead of leaking straight there. Fewer ambiguous incidents
  reach the human queue; the queue stays the rung of last resort.
- **The decider gate refuses to dismiss `provenance:illegitimate` incidents (spec 072 Phase 2).**
  An incident whose evidence carries a non-forgeable illegitimate-provenance tag is
  never auto-dismissed — it is always surfaced, regardless of the model's verdict.

### Fixed
- **False-positive suppression via non-forgeable exe-path provenance (specs 071/072).**
  Several FP-prone detectors now gate their benign-self / toolchain skips on the
  non-forgeable `/proc/<pid>/exe` path instead of the forgeable `comm`:
  `data_exfiltration` excludes the zig / build-script toolchain and only skips a
  build tool when its exe path is itself trusted (not a renamed binary in `/tmp`);
  `host_drift`'s comm allowlist is gated on the exe path; `rootkit` timing no longer
  flags `tcp_stream.{http,ssh,smb}`; `suspicious_archive` suppresses InnerWarden's
  own self-unpack into `/var/lib/innerwarden`. These clear the operator- and
  self-traffic false positives that were piling in `needs_review`, without weakening
  real detection.
- **`innerwarden get` reads the unified SQLite store, not legacy JSONL (#969).** The
  CLI under-reported decisions/incidents by reading the old jsonl files instead of
  `innerwarden.db`; it now reads the unified store (with a jsonl fallback).
- **De-flaked the `privesc` provenance tests (#976).** The tests read real `/proc`,
  so a live PID matching a hardcoded test pid made provenance resolve to a real
  trusted process intermittently in CI; they now use guaranteed-dead pids (above
  `pid_max`) so provenance resolves deterministically to Unknown.
- **ATR community rules now actually load in production (agent-guard).** The
  `check-command` snitch path advertised "71 ATR community rules", but the agent
  loaded them from `/etc/innerwarden/rules` while `deploy-prod.sh` only ever
  copied `rules/sigma` there — so the ATR engine booted with **zero** rules in
  prod and `check-command` ran on built-in heuristics alone. The 62 pattern-tier
  ATR rules are now embedded into the agent binary at compile time via
  `include_dir!` (`RuleEngine::load_embedded`), so they are always present with
  no deploy step and cannot drift from the vendored `rules/atr` tree. Operators
  can still drop override/extra rules in the on-disk rules dir
  (`RuleEngine::load_with_overlay`, override-by-id). Boot now logs the loaded
  ATR rule count so a degraded engine is observable. A new crate-level test
  anchors the embedded corpus at 62 pattern-tier rules so a malformed community
  rule or a regex-compile regression fails CI here instead of silently in prod.

## [0.15.7] - 2026-06-04

### Fixed
- **setns events from `call_usermodehelper` kernel helpers are no longer dropped.**
  `dispatch_setns` shared the comm/cgroup suppression gate with the other syscall
  handlers. For a kernel-helper process spawned via `call_usermodehelper` (e.g.
  `cifs.upcall`) that gate bailed before `EVENTS.reserve` even with empty
  allowlist maps — the kprobe fired but no `namespace.setns` event reached the
  ring, so the spec-070 `setns_owner` detector never saw a root task joining a
  non-root-owned user namespace. `dispatch_setns` now emits unconditionally and
  the userspace `setns_owner` detector does the container-runtime filtering by
  non-forgeable exe path + owner-uid. Closes the blind spot for any
  `call_usermodehelper` abuse (CIFS/NFS/quota upcalls), incl. CVE-2026-46243;
  validated live against the real PoC on kernel 6.8.

## [0.15.6] - 2026-06-04

### Added
- **Privilege-provenance / technique-independent LPE detection (spec 070).**
  The escalation *mechanism* of a local privilege escalation varies per bug, but
  the end-state is observable: a process acquires or uses root through a path its
  non-forgeable provenance (executable, parent, target-namespace owner) does not
  justify. New shared `provenance` module (`/proc/<pid>/exe` readlink, exe
  owner/mode, cgroup container hint → Trusted/Unknown/Illegitimate). New
  detectors: `setns_owner` (root joining a non-root-owned user namespace outside
  any container runtime — backed by a new `setns(2)` eBPF kprobe emitting
  `namespace.setns`) and `untrusted_root_exec` (uid-0 execve of a binary from an
  unprivileged-writable path). `privesc` now decides legitimacy by the parent/self
  exe **path** rather than the forgeable comm (defeats a payload renamed `sudo` in
  `/tmp`); `sensitive_write` adds an exe-path gate for its Critical categories.
  New correlation rule **CL-072**: any illegitimate-provenance signal followed by
  any high-value root action (sudoers/shadow/cron/persistence/kmod) on the same
  host within 120s collapses into one Critical incident (68 → 69 built-in rules).
  Container runtimes are filtered by non-forgeable exe-prefix/cgroup; the
  provenance verdict is attached as evidence, not suppressed at detect.
- Detector count 79 → 82.

### Changed
- **Namespace-pivot events routed to the priority event lane.** `namespace.*`
  events carried severity `Debug` and were classified as shed-able bulk
  telemetry; they are now priority so a rare privilege-escalation pivot is not
  dropped under the burst an exploit generates.
- **Autonomy gap (spec 062):** orphan-recovery now routes High/Critical orphan
  incidents to `needs_review` (awaiting human) instead of auto-dismissing them.

### Fixed
- `kernel_promote` `container_mount_escape` skips kernel threads.
- Calibrated three detector false positives from routine system activity
  (kernel-update kmod tooling, package-manager state `rm -rf`, shell history
  append).

## [0.15.5] - 2026-06-03

### Added
- **Defense-evasion detection: killing a security tool.** A process that sends
  a killing/freezing signal (SIGKILL/SIGTERM/SIGSTOP, plus SIGHUP/INT/QUIT/ABRT/
  USR1/USR2 and real-time signals) to a security/monitoring daemon (auditd,
  falco, tetragon, osquery, OSSEC/Wazuh, CrowdStrike/SentinelOne/Carbon Black,
  InnerWarden's own components, …) now raises a Critical incident
  (T1562.001 Impair Defenses). Layered false-positive containment: a default
  allowlist of service/process managers (systemd-shutdown, logrotate, dpkg/rpm/
  apt, container runtimes, supervisord/monit, the watchdog), a **PID-1
  anti-spoof** check for `systemd`/`init` (a `prctl(PR_SET_NAME)` rename does not
  buy a pass), plus the per-server allowlist and AI triage downstream.

### Fixed
- **DATA_EXFIL false-positive flood from world-readable reads.** The
  data-exfiltration kill chain treated `/etc/passwd` (read by virtually every
  process via glibc nss) and the whole `.ssh/` directory as sensitive reads, so
  any download tool (apt, curl, rustup) that read one and connected to a CDN /
  mirror produced a Critical false positive. The sensitive-read set is now tight
  — shadow/gshadow/sudoers, private keys (`.ssh/id_*`, `authorized_keys`),
  dotenv secrets, and explicit cloud/cluster credentials (`.aws/credentials`,
  `.docker/config.json`, gcloud/azure, `.kube/config`, k8s service-account
  token, `.netrc`) — in **both** the userspace kill-chain tracker and the
  in-kernel eBPF chain. Real exfil detection (shadow / keys / cloud-creds +
  outbound) is unchanged.
- **block_ip responses lost across the UTC midnight boundary.** A block_ip
  decision recorded shortly before midnight (still within its 1h TTL, but under
  yesterday's date partition) was silently dropped from the active-response set
  on any agent restart in the first hour after UTC midnight — the kernel block
  stayed up while the dashboard believed it was gone. Hydration now queries
  yesterday + today.
- **Spurious macOS release-CI failure.** A one-shot HTTP test server closed the
  socket before the client finished sending the request, intermittently failing
  the macOS build job.

### Changed
- **Removed ~1,250 lines of dead eBPF.** 20 legacy `sys_enter` tracepoint
  handlers superseded by the spec-069 kprobes were compiled into the object but
  never attached by the loader; removed. The loaded program set is unchanged.
- **Quieter logs.** The per-event diagnostic log (one INFO line per event,
  millions per day on a busy host) was demoted to `trace`.
- Dependency bumps: tokio 1.52.3, tikv-jemallocator 0.7, aes-gcm 0.11.0-rc.4,
  rpassword 7.5.4, toml_edit 0.25.12, plus 5 GitHub Actions.

## [0.15.4] - 2026-06-03

### Fixed
- **aarch64 release binaries had broken syscall-arg capture (spec 069,
  critical).** The eBPF object bakes in arch-specific `pt_regs` syscall-argument
  offsets, selected by `sensor-ebpf/build.rs` from the build-host arch. The
  release builds **both** architectures on a single x86_64 runner from **one**
  shared object, so the aarch64 sensor embedded x86_64 offsets and read syscall
  args at the wrong registers — silently dropping every arg-filtering handler
  (`kill`/`openat`/`connect`/`setuid`/`ptrace`/`execve`) on aarch64 in
  0.15.1–0.15.3. (Non-arg handlers — exit/accept/mount/memfd — were unaffected,
  which is why it went unnoticed; #6's BTF self-check can't catch it because
  aarch64's `regs[]` is nested.) `build.rs` now honours an `IW_EBPF_DEPLOY_ARCH`
  override, and `release.yml` rebuilds the object per deploy arch (x86_64 then
  aarch64) so each binary embeds matching offsets. From-source builds
  (`deploy-prod.sh`, where build-host == deploy-host) were always correct.

## [0.15.3] - 2026-06-03

### Fixed
- **pt_regs offset self-check false positive on aarch64 (spec 069 #6).** The
  startup self-check logged a scary `offset MISMATCH — syscall args may read
  GARBAGE` on aarch64 kernels. It is a false alarm: aarch64's `pt_regs.regs[31]`
  lives inside an anonymous union, so a flat top-level BTF scan never finds a
  member literally named `regs`, even though the layout (regs at offset 0) is
  correct and syscall capture works. The check now distinguishes a **wrong
  offset** (a member present at a different offset → real, warns) from an
  **absent field** (not a direct member → inconclusive, info, no alarm). x86_64
  (direct `di`/`si`/… members) still validates true.

## [0.15.2] - 2026-06-02

Headline: **spec 069 — full kernel-7.0 eBPF syscall capture + 6 hardening
follow-ups** (no silent event drops under load, kernel-exploit detection,
reliable object embedding, dead-code removal, and a BTF offset self-check).
Sensor pipeline hardening; no new detectors/collectors.

### Fixed
- **Kernel 7.0 syscall argument capture (spec 069 Phase 2).** On kernel 7.0 /
  Ubuntu 26.04 with `perf_event_paranoid=4`, the non-root sensor's syscall
  probes could not capture arguments: the prior `sys_enter` raw_tracepoint
  approach fired on every syscall and flooded the event ring buffer, dropping
  events before userspace saw them. Each per-syscall handler is now a **kprobe on
  the architecture syscall entry wrapper** (`__x64_sys_<name>` / `__arm64_sys_<name>`),
  which fires only on its target syscall and reads arguments from the wrapper's
  `pt_regs` via fully-inline reads. Validated live on kernel 7.0 x86_64
  (`kill(pid,sig)`, `openat` of `/etc/shadow`/`/etc/passwd`/ssh config all read
  exactly). Includes: per-PID memoisation of container-id resolution (was a
  `/proc` read per event on the ring-drain hot path), `openat` always-emitting
  genuine credential-file reads while rate-limiting broad `/etc`,`/home`,`/root`
  telemetry, and per-PID rate limits on the high-frequency `dup`/`prctl`
  handlers. Fail-open: a wrapper symbol that does not resolve is skipped with a
  warning, never aborting sensor startup.
- **No silent event drops under load (spec 069 #1).** The eBPF ring reader was
  coupled to the single synchronous detector consumer through a bounded channel;
  when the consumer lagged, the kernel ring overflowed and dropped the next
  event — blindly, uncounted, attack events included. The reader now emits
  **non-blocking across three lanes** (priority security events / a compact
  emergency-overflow signal / bulk telemetry); the kernel-ring drain never
  blocks; a brownout sheds bulk telemetry to protect the priority lane; and
  every drop is counted and logged. An attacker can no longer bury a
  kill / ptrace / credential read behind a syscall flood.
- **Reliable eBPF object embedding (spec 069 #3).** The embedded eBPF object now
  re-embeds automatically when rebuilt (build-script copy into `OUT_DIR` +
  `rerun-if-changed`), eliminating a stale-object foot-gun.

### Added
- **Kernel-exploit syscall detection (spec 069 #2).** Direct `ptrace` injection,
  RWX `mprotect` (shellcode staging), `memfd_create` (fileless execution), and
  in-container `mount` (namespace escape) now raise incidents — previously they
  were logged but never escalated to the AI triage / response path. Layered
  false-positive containment: a curated cross-server default allowlist, a
  per-server `allowlist.toml`, per-detector suppression, then the agent's
  baseline learning + AI triage.
- **pt_regs offset self-check (spec 069 #6).** At startup the sensor validates
  the eBPF object's hardcoded `pt_regs` syscall-argument offsets against the
  running kernel's BTF and warns loudly on mismatch — turning a future-kernel
  layout change from a silent mis-read into a visible diagnostic.

### Changed
- **eBPF filter audit + dead-code removal (spec 069 #4, #5).** An adversarial
  audit confirmed every high-volume syscall handler already discards in-kernel
  (per-PID rate limit + comm/cgroup allowlist + path/IP narrowing), so no
  over-broad emit remained. Removed the dead spec-053 tail-call dispatcher and a
  dead duplicate `accept` tracepoint, both orphaned by the kprobe migration.

## [0.15.1] - 2026-06-01

**Headline:** Spec 067 — AI context completeness. The two AI surfaces are now fully grounded. The autonomous `decide()` brain reasons over DShield (SANS ISC) telemetry, host posture, and the operator's prior decisions for the same incident shape (so it stops re-surfacing settled noise and stops over-reacting to attacks the host config already refuses). The operator-facing chat answers like the warden that lives on the box: "why did you block 1.2.3.4?" pulls that IP's incident + decision + the real reason; "how's my server?" returns a live pulse (posture + top attackers + what is unusual versus baseline) with an answer-style guide that forbids vague filler. Plus a security fix: the Telegram bot now drops inbound commands from any chat that is not the configured operator.

### Added — Spec 067 decide() context

- **DShield (SANS ISC) into the decide prompt** (#908). The cached attacker-profile DShield line (global attacked-target count + threat-feed membership) reaches the LLM with no extra network call on the hot path.
- **Host posture into the decide prompt** (#909). The LLM sees the same defensive facts the severity-downgrade engine uses (PasswordAuthentication / PermitRootLogin / MaxAuthTries), so its reasoning matches the assigned severity.
- **Prior operator decisions into the decide prompt** (#910). A compact summary of how this exact `(detector | ip)` shape was decided before (genuine dismissals vs weighty actions), reusing the learned-suppression query. The biggest "stop re-surfacing settled noise" lever.

### Added — Spec 067 operator chat

- **`/ask` + free-text decision deep-dive** (#911). Naming an IP ("why did you block 1.2.3.4?") surfaces that IP's incident + decision + the stored `decision_reason`, not just subgraph edges. Free-text questions share the `/ask` handler, so no slash is required.
- **Live server pulse** (#912, #913). The chat context carries the host's real posture, the top attackers tracked right now (by risk), and what is unusual versus this host's baseline (training maturity + recent anomalies).
- **Answer-style guide** (#914). A resident-voice directive prepended to the chat persona: cite the real data by name, justify "quiet" instead of shrugging, never answer with vague filler like "just the usual scanners."

### Fixed — Spec 067 Phase 1

- **Inbound Telegram authorization (security)** (#907). The poll loop now drops commands, `/ask`, `/enable` / `/disable`, and approval callbacks from any chat that is not the configured operator chat. Previously there was no inbound sender check.
- **Richer `needs_review` card** (#907). The Block / Ignore / Dismiss card now carries the detector, what happened (summary), recommended checks, and MITRE tags, so the operator can decide from the alert.
- **Honeypot debrief "Block now" button** (#907). Routed through the gated quick-block path; it previously always hit "that choice expired" because the post-session debrief never registered a pending entry.

## [0.15.0] - 2026-05-31

**Headline:** Operator-in-the-loop, end to end. Spec 056 ships the **SOC playbook engine** (declarative response sequences, virtual skills, shadow mode, dashboard API, `innerwarden playbook test`, bundled Log4Shell playbook). Spec 062 closes the real **Autonomy Gap**: ambiguous incidents now route to an explicit `needs_review` floor with severity-gated honest timeouts, Telegram inline Block/Ignore/Dismiss buttons, learned suppression, an optional LLM second opinion, and a warden retrain label channel + mesh corroboration — every path has a deterministic fallback when no LLM is present. Spec 066 stops already-blocked IPs from churning the decide/re-block/orphan loop. Plus: the OSS `innerwarden-supervisor` now ships in the install path, a `firewalld` block backend for RHEL/Rocky/Fedora, DShield (SANS ISC) read-only IP reputation enrichment, `[agent]` host asset tags (spec 058), Local Warden auto-provisioning on install, and two offline harnesses (`--playbook-replay`, `--backtest-anomaly`).

### Added — Spec 056 SOC playbooks

- **Playbook loader + schema + executor** (#864, #865). Declarative response sequences in `/etc/innerwarden/rules/playbooks/`, run with precedence before the auto-handle gate (#878). Two built-in playbooks ship embedded.
- **Stateless + state-coupled virtual skills** (#866, #867). Playbook steps map to virtual skills resolved against config; outcomes feed back as AI context (#868).
- **Dashboard + CLI surface** (#869, #870, #871). `GET /api/playbooks`, `POST /api/playbook/test` simulate endpoint, and `innerwarden playbook test`.
- **Shadow mode + offline replay** (#874, #875). `[playbooks] shadow` validates on-host without acting; `--playbook-replay` re-runs recorded incidents through the executor offline.
- **Bundled Log4Shell playbook** (#872). `cve-2021-44228` JNDI-in-HTTP response sequence shipped built-in (spec 056 phase 6).

### Added — Spec 062 decision review + human escalation + learning

- **`needs_review` floor for ambiguous incidents** (#890). Incidents the Local Warden is not confident about, that no deterministic gate resolves, route to `needs_review` instead of leaking silently to the orphan-recovery sweep. Closes the still-open Autonomy Gap proven in production on 2026-05-30.
- **Severity-gated honest timeout** (#891). Low/Medium auto-resolve with an honest note after notify; High/Critical re-notify and **never** silently auto-dismiss. Timeout counts only after a notification actually succeeds.
- **Telegram inline action buttons** (#896-class). Operators Block / Ignore / Dismiss a `needs_review` incident directly from the alert, mirroring the honeypot operator-in-the-loop pattern.
- **Learned suppression** (#892). Weight-aware, LLM-optional: trivial repeated noise is suppressed without asking; high-impact actions confirm with a human.
- **LLM second-opinion escalation + `needs_human` veto** (#893). An optional LLM verification step that can escalate to a human, never a dependency.
- **Warden retrain label channel + mesh corroboration** (#897, #898). Human and learned decisions feed a retrain label channel; mesh peers corroborate suppression signals.

### Added — platform

- **OSS `innerwarden-supervisor`** (#883). The crash-recovery supervisor (rate-limited restart, HTTP `/metrics` health probe, Telegram alerts, `RestartHook`) now ships in the OSS install path. The proprietary watchdog wraps it with stealth + integrity gating; OSS users get auto-restart on its own. Health probe defaults to HTTPS since the agent serves TLS (#886-class).
- **`firewalld` block-ip backend** (#884-class). Sixth block backend, for RHEL / Rocky / Fedora hosts.
- **DShield (SANS ISC) read-only IP reputation enrichment** (#899). Keyless, mirrors the AbuseIPDB enrichment path; backfills incident context.
- **`[agent]` host asset tags** (#882-class, spec 058 minimal slice). Operator-supplied host tags flow into incident context.
- **Local Warden auto-provisioning on install** (#873, #882). Fresh installs (including headless) provision the on-device ONNX classifier and activate `[ai.warden]` automatically.
- **Offline anomaly backtest harness** (#904). `--backtest-anomaly` trains a fresh autoencoder before a cutoff and scores held-out events (no leakage) to measure decision separation and guard-dog novelty concentration; optional first-ever-entity novelty features.

### Changed

- **Coverage patch floor raised 70% → 85%** (#863) with a 10pp slack window.
- **Daily briefing reads canonical decision-count surfaces** (#879, #880, and the FP-exclusion fix): agent-dismissed false positives no longer inflate the "real compromises" / "autonomous decisions" counts.
- **eBPF unavailability surfaced in collector health** instead of failing silently (#881-class).
- **SOC playbooks run with precedence** before the auto-handle gate (#878).

### Fixed

- **Spec 066 — already-blocked-IP churn guard** (#905). An IP with a live (TTL-valid) firewall block no longer re-fires the decide/re-block path or leaks fresh incidents to orphan-recovery. Recon/protocol/auth-brute detectors short-circuit on an already-blocked IP (active-harm detectors still surface); the canonical block path skips redundant re-blocks. Field-validated on two production deployments.
- **`imds_ssrf` legitimacy by non-forgeable exe-path** (#900, #901), not a spoofable process name; trusts `systemd-resolved` and root-owned vendor dirs.
- **`dns_tunneling` trusts cloud-internal VCN DNS** with hardened dot-boundary suffix matching (#902).
- **`proto_anomaly` stops flagging external scanners on web ports** as anomalies (#889).
- **`baseline` silence false positive** when an auth_log drop is caused by log rotation, not a real silence (#888-class).

## [0.14.5] - 2026-05-28

**Headline:** Three specs closed in two days. Spec 053 ships the event pipeline DSL (declarative filter / sample / promote in the sensor, hot-reloaded YAML). Spec 054 unifies all rule paths under `/etc/innerwarden/rules/{event_pipeline,sigma,yara,atr,correlation}/` and deprecates `allowlist.toml`. Spec 055 migrates the 68 cross-layer correlation rules from a 1770-line Rust literal to YAML in five small phases, also shipped today. Net: rules are operator-editable and hot-reloadable across the entire detection stack, with `innerwarden rule list/disable/enable` covering all five rule types.

### Added — Spec 053 event pipeline (sensor)

- **Declarative filter / sample / promote engine** (#826). YAML rules in `/etc/innerwarden/rules/event_pipeline/` decide which events the sensor persists. Four built-in rule packs ship embedded in the binary; operator files merge in lexicographic order with override-by-id semantics. Hot-reload every 60s via mtime. Resolves the 3.1 M events/day disk crisis (prod disk usage dropped 83 % → 73 % after the post-deploy soak).
- **Package-manager + backstop incident packs** (#828). Suppresses dpkg / apt / rpm / yum / pip / npm / cargo etc. exec noise; keeps a backstop incident path so safety floor stays intact even with operator overrides.
- **Per-PID forensic scoring** (#832). Each PID accumulates a deterministic score from emit-tier events; `force_emit` on credential paths keeps high-signal events through aggressive sampling.
- **Sigma rule suppression wired into detector** (#840). The pipeline's `suppress_incident` action now affects the sigma detector, not just event_pipeline drops.
- **Named lists in event pipeline DSL** (#842). Operators define lists once (`$service_daemons`, `$package_managers`, etc.) and reference them in any rule predicate. Built-in packs migrated to use them.

### Added — Spec 054 config consolidation

- **Unified rules dir** (#837). All five rule types (event_pipeline, sigma, yara, atr, correlation) now live under `/etc/innerwarden/rules/<type>/`. Sensor + agent both read from this shared tree.
- **Agent reads YAML rules from shared dir** (#841). Removes the old per-crate path divergence.
- **`allowlist.toml` deprecated + `innerwarden rule migrate-allowlist`** (#831, #838). Process and per-detector entries convert to pipeline `drop` and `suppress_incident` rules. Operators run the migration once; `allowlist.toml` becomes dead config.

### Added — Spec 055 correlation rules in YAML (5 phases, same day)

- **Phase 1: YAML loader + byte-equality parallel mode** (#843). New `crates/agent/src/correlation_engine_yaml/` with embedded `00-builtin.yml`. Byte-for-byte equality anchor against the hardcoded Rust literal as the safety floor.
- **Phase 2: hot-reload + operator workflow** (#845). mtime-based 60 s reload, schema validation with `#[serde(deny_unknown_fields)]`, invalid rules skipped with a WARN.
- **Phase 3: CTL integration** (#851). `innerwarden rule list --type correlation` shows 68 CL-rules (id / severity / window / stages / name); `innerwarden rule disable CL-024` auto-routes to the correlation dir. Built-in correlation YAML embedded via `include_str!` across the crate boundary so CTL stays decoupled.
- **Phase 4: named lists in `kind_patterns`** (#857). Four built-in lists (`exfil_kinds`, `recon_kinds`, `persistence_kinds`, `c2_kinds`) usable with `$name` in any correlation rule. Same first-defined-wins semantics as the event pipeline lists from #842.
- **Phase 5: delete hardcoded `builtin_rules()`** (#858). The 1770-line Rust literal is gone; `builtin_rules()` is now a thin wrapper around `correlation_engine_yaml::load_builtin()`. `correlation_engine.rs` 3872 → 2124 lines (-1748 net).

### Fixed

- **eBPF connect/bind handlers had inverted IPv4 byte order** (#836). `.to_be()` was double-flipping octets, so GitHub IPs (140.82.0.0/16) rendered as US DoD (32.140.0.0/16) in attribution. Single-line fix; large impact on every IP-pivoted detector.
- **`silent_stream` alert severity** (#827, #844). Was Medium → bundled into the daily briefing instead of pushed immediately. Now High, fires through the push path within the on-call window.
- **`innerwarden rule disable` YAML indentation** (#834). `ensure_disabled` now inserts `disabled: true` at the correct sibling-field indent so re-parsing stays clean.

### Tests + infra

- **Elite anchors: backstop incident + Caldera replay assertions** (#833). The `suppress_incident` action gets a permanent regression guard; Caldera replay diffs catch correlation-engine drift before it reaches prod.
- **`abuseipdb.rs` pure helpers anchored** (#829, #820). Coverage and behavioural regressions both addressed.

### Operator-visible numbers

- Workspace version: `0.14.4` → `0.14.5`.
- `correlation_engine.rs`: 3872 → 2124 lines (-45 %).
- Prod disk usage on Oracle 130.162.171.105: 83 % → 73 % under spec 053 event filtering.
- `events-*.jsonl` files no longer ship in `/var/lib/innerwarden/` by default (filtered out by the pipeline); raw event taps are now a deliberate operator opt-in via YAML.
- 21 PRs since v0.14.4 (16 on 2026-05-27 + 5 on 2026-05-28).
- All five rule types now operator-editable and hot-reloadable: event_pipeline, sigma, yara, atr, correlation.

### Deploy

Oracle prod (130.162.171.105) cut over piecewise as PRs landed: event pipeline + config consolidation + spec 055 Phases 1-2 deployed 2026-05-28 07:13 UTC; Phase 3 (CTL) at 06:13 UTC; Phase 4 at 07:15 UTC; Phase 5 mid-afternoon same day. Watchdog respawned the agent cleanly each cycle (root child per the documented dual-path; the `innerwarden-agent.service` systemd unit stays disabled). Post-deploy: zero panics in watchdog log, 28+ incidents detected today against the YAML rule set, cloud_safelist gate working against AWS prefixes during the kill_chain DATA_EXFIL bursts that fired post-restart.

### Why this version exists

Three specs were in flight: 053 (event pipeline DSL) had been blocking the 3.1 M events/day disk-pressure story; 054 (config consolidation) was the natural follow-on once events lived in YAML; 055 (correlation rules in YAML) was the third leg, originally scoped to a week of soak between phases. All three landed in 48 hours because the work shared the same YAML/rules-dir machinery — testing one validated the next. The 1-week soak gate on spec 055 Phase 5 was overridden per the founder-pace operator preference after 5h+ of clean prod signal on Phases 1-4.

## [0.14.4] - 2026-05-26

**Headline:** End of the `async fn main` decomposition that started mid-May. Four PRs (#813 → #816) cut sensor::run into a testable `boot_init` + `run_loop` split, config-gated 14 always-on collectors, extracted `DetectorSet` out of `main.rs`, and root-fixed a CL-008 correlation-engine saturation that fired 80 chains in 2 min on every vanilla LAMP/LEMP host the agent ran on (2026-05-26 prod incident).

### Added

- **`sensor::boot_init` + `sensor::run_loop` split** (#813). `pub(crate) async fn run` became `boot_init(cfg) -> Result<SensorContext>` + `run_loop(ctx) -> Result<()>` + a thin wrapper. The split returns a `SensorContext` the test can drop without leaking background work, unblocking integration anchors that the pre-split shape couldn't reach. Three boot-time anchors land in `sensor::tests`: timeout, sqlite-db-created, collector-health-snapshot-written.
- **`AlwaysOnCollectorConfig` + 14 config gates** (#814). 14 collector spawns in `boot/spawn_collectors.rs` had no config gate — they ran unconditionally and held clones of `tx` alive forever, which made `rx.recv()` never return `None` and `run` end-to-end untestable. Every one now sits behind `if cfg.collectors.X.enabled { … }`, with defaults that preserve production behaviour (omission = on). `CollectorsConfig::all_disabled()` constructor + `Config::test_default` update bring the test surface to true zero state. Three end-to-end anchors test the full `run(cfg)` pipeline including the shutdown path.
- **`crates/sensor/src/detector_set.rs`** (#815). Pulled the 35 detector type imports + ~100 LoC of `DetectorSet` struct fields out of `main.rs` into a standalone file. `main.rs` is now 141 lines (was 271), of which most are tests and comments — `async fn main` is back to its 5-line CLI → config → `sensor::run` skeleton.
- **`CL008_SERVICE_DAEMON_COMMS` suppression list** (#816). Apache2, httpd, nginx, caddy, php-fpm (every Debian-tracked version 7.4 → 8.3), mysqld, mysqld_safe, mariadbd, postgres, crowdsec, cscli. CL-008-only carve-out — every other rule still fires on these comms, so a hijacked web stack is still caught by `lateral_movement` / `c2_callback` / etc. Five anchor tests including an anti-leak test that iterates every new comm against five non-CL-008 rules.

### Operator-visible numbers

- Workspace version: `0.14.3` → `0.14.4`.
- `crates/sensor/src/main.rs`: 271 → 141 lines (-48%).
- Sensor anchor tests: +6 (3 `boot_init_*` + 3 `run_*` end-to-end).
- Correlation engine anchor tests: +5 (`cl008_suppressed_when_comm_is_service_daemon_*` × 4 + `service_daemon_suppression_does_not_leak_to_other_rules`).
- Prod CL-008 chains in the 24 h since deploy: 0 (pre-fix: 80 in 2 min).

### Why this version exists

A refactor series and a hot-fix landed in the same hour because they passed through the same code path. The refactor (#813 → #815) had been in flight since mid-May — the goal was for `sensor::run` to be 100 % testable without the inferno of mocking every always-on collector. PR-F3 (#812, in v0.14.3) shipped the textually-extracted run function but punted on `run_loop` anchors, citing 14 unconditional `tokio::spawn` calls as a blocker. #813 split the function, #814 gated the spawns, #815 finished the cleanup by moving DetectorSet out of `main.rs`. The "untestable" docstring is gone; `run(cfg)` now has six anchors covering boot + spawn + loop + shutdown.

The CL-008 fix (#816) was the prod incident that landed the same hour. The agent on 130.162.171.105 had been firing 80 correlation chains in 2 minutes on the host's own web stack — every nginx → php-fpm → mysqld pipeline matched `file.read + outbound connect` because that is literally how a PHP-backed HTTP request works. The fix shipped in the same release because both touched the same boot-init machinery; testing one validated the other.

Deploy: 130.162.171.105 cut over 2026-05-26 03:11 UTC via `scripts/deploy-prod.sh all`. 44 eBPF programs loaded, dashboard `/livez` returning 200, knowledge graph restored across five shards (~250 K edges), anomaly trainer pulling 7.8 M events from the last week. Pipeline alive 30 s after restart (first post-deploy incident at 03:12:01). Zero panics in the watchdog log, zero CL-008 chains, every other detector firing at baseline rate.

## [0.14.3] - 2026-05-23

**Headline:** new `suid_page_cache_integrity` detector closes the entire 2026 Linux kernel page-cache-corruption LPE family — Copy Fail (CVE-2026-31431), Dirty Frag (CVE-2026-43284 + CVE-2026-43500), and Fragnesia (CVE-2026-46300). The detector periodically compares an `O_DIRECT` disk read against a page-cache-served read for a small allowlist of high-value SUID-root binaries; divergence fires a Critical incident. This is the result of v0.14.2's honest lab miss against Copy Fail (see `_innerwarden/innerwarden-cve-lab/cve-2026-31431-copy-fail/RESULTS.md`): we measured what the existing detectors missed, then shipped what would have caught it.

### Added

- **`suid_page_cache_integrity` detector** (#793). Polls `/usr/bin/su`, `sudo`, `passwd`, `chsh`, `chfn`, `mount`, `umount`, `newgrp`, `gpasswd`, `pkexec` every 30 s by default. For each binary it computes SHA-256 via `read()` (page-cache path) and via `O_DIRECT` `read()` (disk path), with `posix_fadvise(POSIX_FADV_DONTNEED)` between the two so the disk read is genuinely from disk. SHA divergence → Critical event `integrity.page_cache_mismatch` + promoted Incident with minute-grained dedup ID, MITRE T1014 + T1068.
  - Trait-based `PageCacheReader` abstraction (mirrors the `BlockedPidsMap` pattern from spec 052) so the inner scan is unit-testable without a real filesystem.
  - 6 anchor tests cover: divergence → fires Critical, match → silent, missing binary → no-op, IO error → fail-open with recovery on next poll, real-reader tempfile smoke, run loop with paused tokio clock + cancellation.
  - Fail-open everywhere: missing files, read errors, fadvise errors all warn and continue. Periodic loop survives task panics.
  - Config: `[detectors.suid_page_cache_integrity]` with `enabled`, `poll_interval_secs`, `allowlist` keys. Defaults enabled.
  - Cross-platform: Linux uses `libc::posix_fadvise` + `O_DIRECT` + page-aligned buffer via `posix_memalign`; non-Linux stub falls back to a normal `std::fs::read` so the detector compiles on macOS/Windows builds without `#[cfg]` scattered through call sites.

### Operator-visible numbers

- Workspace version: `0.14.2` → `0.14.3`.
- Detectors: `76` → `77`.
- Unit tests: `8010` → `8024`.

### Why this version exists

Patch release driven entirely by a measured product gap, not a feature roadmap. The v0.14.2 release shipped a working LSM kernel-block path but the lab run (PID 950484 GC validation aside, the Copy Fail attempt on the Azure VM) proved the agent had zero visibility into in-kernel page-cache corruption — a class of LPE that bypasses every behavioural hook the agent shipped because the exploited binary's bytes on disk never change, only the cached copy that the kernel actually executes. The Codex offensive run produced result.json, RESULTS.md captured the honest verdict ("missed, root achieved, page-cache corruption visible"), and PR #793 ships the detector that would have caught it. The next lab run will be Run 2 of the same CVE on v0.14.3 — if `suid_page_cache_integrity` fires within the 30 s poll window after the PoC corrupts `/usr/bin/su`, the gap is closed.

## [0.14.2] - 2026-05-23

**Headline:** 5 LSM kernel-block hooks live in prod with synchronous `-EPERM` enforcement on kernel ≥ 6.4. The "stops attacks mid-keystroke" copy is no longer half-true for the process-exec subset — it's now true for exec, user-namespace creation, ptrace attach, BPF program load, and mmap of sensitive files.

Spec 052 (minimal LSM hook refactor) and Spec 053 (skip-dispatcher workaround + collateral fixes) shipped end-to-end. Validated against the Oracle prod kernel 6.8.0-1052-oracle with the sched_process_exit GC test (PID 950484, 2026-05-23): register → kill → 13 s later agent emits `lsm_policy: unregistered exited PID from BLOCKED_PIDS`, `bpftool map lookup` returns `Not found`.

### Added

- **5 LSM kernel-block hooks** wired into the kill-chain detector via `BLOCKED_PIDS` LRU map (4096 slots, pinned at `/sys/fs/bpf/innerwarden/blocked_pids`). Kernel decides synchronously, userspace populates the map. (#773 #774 #775 #776 #777 #778 #779 #780 #783 #784 #785 #786 #787 #788 #789)
  - `bprm_check_security` — exec blocking (Spec 052 Phase 1a)
  - `userns_create` — container escape via `unshare(CLONE_NEWUSER)` (PR-A, #779)
  - `ptrace_access_check` — process injection via PTRACE_ATTACH/POKETEXT (PR-B, #780, **not** sleepable — verifier rejects sleepable on this hook)
  - `bpf_prog_load` — VoidLink-style eBPF weaponisation (PR-C, #783)
  - `mmap_file` — real-time RWX block, replacing the 5 s `proc_maps` polling window (PR-D, #784)
- **sched_process_exit GC** for BLOCKED_PIDS (#787 #788 #789). When a registered PID exits, the agent's slow-loop drops it from the map — without this, the LRU filled with dead PIDs until ~8-day eviction. The `process.exit` event was previously dropped by the SQLite sink's high-volume filter; the agent never saw it.
- **`scripts/verify-lsm-hooks.sh` + CI workflow** anchors the 7 LSM hook sections in the built `.o` against an EXPECTED list. Catches accidental hook renames, sleepable changes, and cfg gating regressions. (#785)
- **Shield `cloudflare_failover` + `origin_lockdown` panic mode**, dry-run default (#763). Operator opts in by lowering the threshold; the failover/lockdown action records to the decision log even in dry-run.

### Changed

- **`process.exit` is no longer filtered out of the SQLite sink** (#788). Cost: ~50 K extra rows/day on a busy host. Benefit: the GC path can see the events. Anchored with `test_is_high_volume_event` so a future cleanup can't silently re-add it.
- **Kill-chain `evidence` reader hardened** against shape drift (#778). Six call sites silently parsed `evidence` as Object when the producer had moved to Array, returning `None` and skipping the PID extraction. Helper `evidence_obj` now tolerates both shapes; 6 anchor tests pin the bug, including a `demonstrates_the_silent_bug` anti-pattern test.
- **`SYSCALL_DISPATCHER` tail-call path skipped** (#777). The aya `BPF_MAP_TYPE_PROG_ARRAY` + `tail_call` pattern silently failed on kernel 6.8 (entries persisted in the array, `tail_call` fell through). Workaround: attach each hook as a standalone tracepoint, no dispatcher. The `dispatcher` Cargo feature was removed from the build path in #786.
- **Codecov gate switched from `target: auto` (drift) to fixed floors set 2 pp below 2026-05-23 main** (#790). The auto/drift gate kept tripping on refactor PRs that moved tested code around without changing the underlying signal. New gates cover 13 components.
- **`lsm_policy` split into `lsm_policy/{mod.rs, aya_impl.rs}`** (#789). Testable trait + inner GC logic lives in `mod.rs` with 3 new mock-driven anchor tests; the aya FFI wrapper lives in `aya_impl.rs` and is excluded from the patch coverage gate with the same justification as `main.rs` / `boot.rs`.
- **Dashboard logo: crossed-swords SVG replaced by the steel W mark** (#791). Last surface still showing the old logo.
- **README + wiki Home stats refreshed** to match source on 2026-05-23 (#791): 49 eBPF programs, 76 detectors, 68 cross-layer rules, 90+ MITRE technique IDs, 8000+ unit tests with 665 named anchors. Drops the playbook engine references — playbooks were removed in PR #413 (decisions flow through the AI skill executor inline now).

### Fixed

- **eBPF LSM section** finally loads on kernel ≥ 6.4 — `sleepable` attribute (#768), BTF emission via `shim.c` + `--btf` link flag (#767), minimal hook body refactor (Spec 052). The earlier "func 'bpf_lsm_bprm_check_security' arg0 has btf_id 3620 type STRUCT 'linux_binprm'" rejection was misleading verifier preamble; the real rejection was body-complexity-driven, diagnosed on `lsm/diagnostic-minimal` branch.
- **`russh` bumped 0.60.1 → 0.60.3** to patch GHSA-g9f8-wqj9-fjw5 (#772).
- **Killchain "LSM-blocked" detector wired** and the misleading `lsm=bpf` log message dropped (#764).
- **Sensors panel zero-day fixes** for syslog_firewall + inventories (#761).
- **jemalloc drop-in** is now version-controlled with `prof_active=false` default (#760).
- **Cases-tab leaks** plugged from the 2026-05-21 prod orphan audit (#759).

### Removed

- **All `specs/` and `.specify/` files removed from the repo** (#771). Specs are local-only workspace now (operator's `.specify/` directory is gitignored).

### Operator-visible numbers

- Workspace version: `0.14.1` → `0.14.2`.
- eBPF kernel programs: `44` → `49` (added 4 LSM hooks + raw_tracepoints expanded from 1 dispatcher to 7 standalone).
- LSM kernel-block hooks: `2` (file_open, bpf — legacy) → `7` (5 new + 2 legacy retained in parallel).
- Detectors: `73` → `76`.
- Cross-layer correlation rules: `47–67` (drift across docs) → **68** (authoritative grep of `CL-NNN` in `correlation_engine.rs`).
- MITRE technique IDs: `75+` → `90+` (93 unique T-IDs grep'd from source).
- Unit tests: `7300+` → `8000+` (8010 authoritative via `cargo test --workspace -- --list`).
- Named anchor tests: previously overstated as `1275` → corrected to **665** per `scripts/verify-anchor-tests.sh`.

## [0.14.1] - 2026-05-20

Dashboard observability polish + correlation engine wiring fix. Seven PRs against `main` after v0.14.0 was tagged. Verified end-to-end on Oracle prod (ARM64 aarch64, kernel 6.8.0-1052-oracle) before tagging.

### Added

- **Community feedback banner on the Home page** (PR #752, refined in #753 / #754). Spec 051 PR1. In-dashboard ask routed through `feedback@innerwarden.com`, GitHub Discussions, Issues, and good-first-issues — preserves the zero-telemetry contract while giving operators a friction-free way to surface back to the project. Dismissible with "remind me in 30 days" or "hide forever", persisted in `localStorage`. Graceful degradation when storage is unavailable (private-mode Safari, quota errors).
- **Local Warden Model heuristic decision markers in the reason field** (PR #751). When the local classifier shadows or drives a `block_ip` / `monitor_ip` / `escalate` decision, the operator-visible reason now exposes the heuristic markers that drove the head's vote (e.g. `[scanner-burst]`, `[c2-callback]`, `[exfil-after-recon]`). Closes the "Decide but don't explain" gap operators flagged after the v0.14.0 shadow-mode rollout — the head was already producing the markers internally, this just surfaces them.

### Fixed

- **Cross-layer correlation engine now actually sees firmware ticks** (PR #749). `firmware_tick` events from the SMM crate fired every 5 minutes but never reached the correlation engine, so CL-041 / CL-042 / CL-043 (Blue Pill, VM Escape, Deep Ring Compromise) could not anchor on the firmware leg. The hypervisor tick path had the wire; the firmware path was silently dropped at the `tokio::select!` dispatcher. Now firmware ticks feed the engine, which means firmware-leg correlation rules can fire as designed.
- **`operator_timezone` test race** (PR #750). Three tests in `data_api.rs` mutated the global `TZ` env var in parallel under `cargo test`, producing intermittent CI failures on `main`. Extracted a pure `operator_timezone_from(env_tz, etc_timezone)` helper that takes its inputs as arguments, so the tests no longer touch process-global state. Race is permanently gone.
- **Community banner copy** (PR #753, PR #754). Initial banner (#752) shipped with a pleading tone that framed the privacy stance as a deficit ("I genuinely don't know if anyone is using this") and routed feedback through a personal gmail. Reframed the copy to position zero-telemetry as the load-bearing feature it is, switched the email to `feedback@innerwarden.com`, dropped a Discord/Telegram placeholder that promised a channel before it existed.

### Notes

- `[Unreleased]` is now empty.
- Cargo workspace version bumped to `0.14.1`. No breaking changes; configs from `0.14.0` upgrade with no edits.

## [0.14.0] - 2026-05-18

Major Linux MITRE ATT&CK coverage release. Adds 21 new detectors across six tactics (Reconnaissance, Collection, Command & Control, Privilege Escalation, Lateral Movement, Persistence, Defense Evasion, Impact) and 20 new cross-layer correlation rules covering full kill-chain attack patterns. **Detector count: 53 → 73. Cross-layer correlation rules: 47 → 67. MITRE technique IDs covered: 65 → 75+.** Also lands first-class OpenClaw / peer AI agent integration on the same host, dashboard counters migrated to canonical SQLite source-of-truth, telemetry name-drift cleanup, and a license harmonisation across the four satellite crates.

Verified end-to-end on Oracle prod (ARM64 aarch64, kernel 6.8.0-1052-oracle) and `test001` (Ubuntu 24.04 x86_64, kernel 6.8.0-117-generic). 49 detectors active on prod, 44 eBPF kernel hooks loaded, agent-guard registry persisted across the watchdog binary swap.

### Added

#### Linux MITRE ATT&CK coverage (8 PRs, 21 detectors, 20 correlation rules)

- **Reconnaissance detectors** (PR #657): `discovery_anomaly` — context-aware allowlist promotion (PR #655) + argv-driven anomaly scoring; `discovery_burst` upgrade. Covers T1018, T1033, T1057, T1082, T1083, T1087, T1518.
- **Collection detectors** (PR #664): `clipboard_capture`, `screen_capture`, `archive_collection` (password-protected zip/7z/rar), `data_staged_egress`. Covers T1056.004, T1113, T1560.001, T1074.
- **Command & Control variants** (PR #665): C2 callback over non-standard ports, tunnel detection (ngrok/cloudflared/bore), DNS/ICMP/SSH-forward protocol tunneling, encrypted channel anomaly. Covers T1071.001, T1095, T1572, T1573, T1090.
- **Privilege Escalation + Lateral Movement** (PR #667): `setuid_exploit_pattern`, `capabilities_abuse`, `lateral_egress_ssh`, `lateral_egress_scp_rsync`. 34 anchored tests. Covers T1548.001, T1068, T1021.004, T1570.
- **Persistence + Defense Evasion** (PR #668): `pam_module_change`, `auditd_disable`, `selinux_apparmor_disable`, `startup_script_persistence`. 41 anchored tests. Covers T1556.003, T1562.001, T1037.004.
- **Data destruction (Impact)** (PR #669): `data_destruction_pattern` with 5 sub-shapes — `rm -rf` on user data, disk wipe, mkfs/luksFormat on mounted volumes, journal truncation, backup-target tampering. 17 anchored tests. Covers T1485, T1490, T1561.
- **Symlink hijack + service-account shells** (PR #676): `symlink_hijack` detects `ln -s` of sensitive paths (T1555, T1574.005); `system_user_interactive` flags 47 service accounts (nobody, www-data, nginx, postgres, mysql, …) opening interactive shells (T1059, T1078.003).
- **20 new cross-layer correlation rules CL-051 → CL-070** (PR #670). Includes a full 5-stage kill chain (CL-067: Initial Access → Foothold → Persistence → Defense Evasion → Impact) and 19 multi-stage chains across Discovery → Privesc → Lateral, eBPF-sequence data exfiltration, hypervisor + kernel ring-spanning chains.

#### OpenClaw / peer AI agent integration

- **Agent discovery file** (PRs #683 + #684). The agent now publishes `/run/innerwarden/agent-discovery.json` at startup describing how peer AI agents on the same host should reach Inner Warden — URL, endpoints, auth mode, TLS posture, schema/agent version. World-readable (0644) so unprivileged AI agent processes (OpenClaw runs as `ubuntu`, not root) can read it without auth. FHS-compliant runtime location; survives across deploys because the parent dir is auto-chmod'd to 0755 on every boot. End-to-end validated with OpenClaw reading the file, calling `/api/agent/security-context`, and answering "yes, Inner Warden is active here" inside its own session.
- **Loopback-bypass auth on `/api/agent/*` and `/api/agent-guard/*`** (PR #680). Calls from `127.0.0.1` / `::1` / `localhost` no longer require Basic Auth. The middleware reads the peer IP from `axum::extract::ConnectInfo<SocketAddr>` (not from `X-Forwarded-For`, which a proxy can spoof). Six anchored tests cover the truth table.
- **Agent-guard registry persists across agent restarts** (PR #685). The ag-id binding (`openclaw pid 1109 → ag-0001`) used to vanish on every binary swap. Now snapshotted to `<data_dir>/agent-guard-registry.json` after every connect / disconnect (atomic via `.tmp` + rename), rehydrated on dashboard start. `NEXT_ID` reseeded above the max restored ag-id so future connects can't collide.
- **`innerwarden agent connect` picker shows real connection state** (PR #682). The picker now annotates each candidate with `[official, not connected]` or `[official, already connected as ag-0001]`, pre-checks only unconnected rows so a plain Enter does the obvious thing, and short-circuits with a friendly summary when every detected agent is already connected. Same merge logic also fixes `agent scan` (previously hardcoded "not connected" on every row).
- **`innerwarden agent connect` arrow-key picker** (PR #680). Replaces the typed-index `"1,3,5"` flow with `dialoguer::MultiSelect` when stdin is a TTY. Numeric input retained as the non-TTY fallback so CI / scripted pipelines don't break.

#### Other

- **eBPF bytecode embedded by default on Linux builds** (PR #678). The sensor binary now ships with eBPF programs baked in via `include_bytes!`, removing the runtime requirement for a separate bytecode file at `/var/lib/innerwarden/ebpf/`. No-op on macOS / dev shells. Operator-visible: fresh installs go from `0 eBPF hooks loaded` to `44 hooks loaded` with no extra setup.
- **`innerwarden agent status` over HTTPS** (PR #681). Used to shell out to `curl http://...` and fail with "connection refused" because the dashboard is HTTPS-only since v0.13. Now uses the TLS-aware ureq helper that the `connect` / `disconnect` paths use, and reads the `connected: false` flag from the server response so duplicate-pid connects no longer print "✓ connected as unknown".
- **Smoke harness + testing map for the new detector wave** (PR #672). 75-test smoke harness with SQLite poll + per-test `BEFORE_TS` + `TEST_USER` privilege drop. `scripts/SMOKE_TEST_MAP.md` documents every detector + trigger + expected event signature.

### Changed

#### Dashboard counters migrated to canonical SQLite source

- **`/api/overview` and `/api/sensors` now read events_today via `canonical_counts::compute`** (PRs #659, #660, #661). The process-lifetime KG counter that used to feed these endpoints reset on every restart and double-counted across uptime days — operator saw 130k events on Home but 3.7k on Sensors. Both endpoints now go through the same SQLite per-date query. Cross-endpoint anchor test asserts every dashboard handler calls the canonical function so no future handler can resurrect the divergence pattern.
- **Sensors HUD tile roster: union of canonical SQLite + KG roster** (PR #661). Canonical gives the per-date counts; KG gives the long-lived collector list including ones quiet today. `or_insert(0)` for missing collectors so the active-vs-broken indicator never silently drops a row.
- **Event Timeline chart uses canonical SQLite** (PR #659). Same migration as the tile totals; interned-key shape rebuilt on-the-fly from the canonical map so the rendering pipeline didn't have to change.

#### Telemetry name drift killed (PR #686)

Operator screenshot flagged `fanotify TELEMETRY 0` looking like broken telemetry. Three classes of bug, all fixed:

- **Wire-name drift.** `fanotify_watch.rs` emits `source: "fanotify"` — the manifest entry was `fanotify_watch`. Dashboard category lookup defaulted to TELEMETRY because the wire name wasn't in the manifest. Same drift for `ebpf_syscall.rs` (emits `ebpf`) and `exec_audit.rs` (emits `auditd`). All three drift aliases removed from `COLLECTOR_MANIFEST` and the frontend `COLLECTOR_CATEGORY` map. `fanotify` now correctly renders as ALARM (silence is healthy).
- **Phantoms.** `osquery_log` and `suricata_eve` were in the frontend map even though the collectors were retired in Wave 8b/8c. Added `KNOWN_COLLECTORS` const + roster filter so stale KG entries no longer leak through.
- **Integration card count fix.** "Shell Audit (auditd)" card called `count_source("exec_audit")` and always showed 0. Now `count_source("auditd")`.

A cross-file consistency test asserts the sensor manifest, the agent's KNOWN_COLLECTORS const, and the frontend COLLECTOR_CATEGORY map describe the same set — drift in any of the three surfaces fails CI.

#### License harmonisation (PR #671)

Relicensed four satellite crates from BUSL-1.1 to Apache-2.0:
- `crates/killchain` (kill chain detection engine)
- `crates/dna` (threat DNA behavioural fingerprinting)
- `crates/smm` (Ring -2 firmware audit)
- `crates/hypervisor` (Ring -1 hypervisor audit)

The whole repo is now uniformly Apache-2.0.

### Fixed

- **`-sf` flag bundle no longer misclassified as hardlink** (PR #677). `symlink_hijack` previously matched only `argv == "-s"`, so `ln -sf` slipped through as a hardlink. Now uses a bundle parser. Same PR adds per-target slug to `incident_id` so two symlinks to different sensitive paths in the same second no longer collide on the SQLite UNIQUE constraint.
- **Canonical `file.write_access` schema in fanotify** (PR #674). The earlier schema collided with `ebpf_syscall` field names; canonical schema now ensures the `details.filename` field matches what the PR1-6 file-write detectors read. Also dropped two phantom collectors from `COLLECTOR_MANIFEST` here.
- **fanotify default watch paths unioned with operator config** (PR #675). Pre-fix any operator config was treated as a *replacement* for the default list — hosts with custom paths silently dropped PAM / cron / RC / audit / SELinux / shell-startup from monitoring. Defaults are now the minimum every host observes; operator config extends.
- **Correlation rule OR-patterns cover legacy detector names** (PR #673). CL-053 / 057 / 066 / 069 chain rules now match `data_archive | suspicious_archive | data_exfil_cmd | ...` so historical detector renames don't silently break the chain match.
- **eBPF events prefer kernel-provided ppid over `/proc` fallback** (PR #663). `/proc/<pid>/stat` is racy on short-lived processes; the kernel-provided `ppid` from the tracepoint context is the canonical source.
- **PR1 detectors match argv[0] not comm** (PR #662). `comm` is the first 16 chars of the binary name — too narrow to identify binary identity reliably. The Reconnaissance / Privesc / Lateral detectors now match argv[0] which is the full invocation path.
- **Honeypot recurring-attacker silent drops surfaced on the live feed** (PR #658). The auto-dismiss path used to skip the SSE feed entirely, so operators couldn't tell whether the honeypot was active or silent. Now emits a dim recurring-attacker line.
- **`deploy-prod.sh agent` watchdog dance** (PR #681). When `innerwarden-watchdog` is active, the deploy script now stops it before `cp` and restarts it after, so the agent binary can be swapped cleanly without EBUSY. Always-on `[4/4]` health audit added.
- **`innerwarden setup` non-TTY guidance** (PR #679). Setup now fails fast with an actionable message when stdin is not a TTY (CI, piped input) instead of looping forever on the first interactive prompt.

### CI / build / release infrastructure

- **Sign classifier-v* releases + attach SLSA bundles** (PR #654). Model release artefacts now ship signed alongside binaries.
- **Replace `pip install cryptography` with `openssl pkeyutl -sign -rawin`** (PR #666). Closes OpenSSF Scorecard alert #189 (unpinned dependency in release workflow). Verified that Ed25519 signature bytes are byte-identical between `cryptography` and `openssl` CLI.
- **CI guard renamed to vendor-neutral name** (PR #686). `scripts/verify-no-falco-mentions.sh` → `scripts/verify-retired-integrations.sh`. Workflow display name `No Falco Mentions` → `Retired Integrations Guard`. Header docstrings rewritten in vendor-neutral language so the script doesn't read like evidence-scrubbing — Inner Warden has always been a clean-room Rust implementation that briefly shipped an optional one-way input adapter for a third-party tool, then dropped the adapter when the native eBPF + detector layer covered the same surface.

### Removed

- **Standalone Sensors view + dead "Check sensors →" link on Home** (Wave 2026-05-15 + this release). The per-collector panel folded into Home as `#homeSensorsPanel` in the earlier Wave; the leftover Home button pointed at that same-page anchor and felt like a no-op since the panel is already visible.
- **Phantom collector entries `osquery_log` and `suricata_eve` from the frontend telemetry map** (PR #686). Those collectors never shipped; their map entries kept rendering as TELEMETRY 0 forever.
- **Three drift-alias manifest entries** (`fanotify_watch`, `ebpf_syscall`, `exec_audit`, all PR #686). The collectors emit `fanotify`, `ebpf`, `auditd` respectively; the duplicate manifest slots never matched a real `Event.source`.

## [0.13.6] - 2026-05-16

Patch release: SHA pin for the `minilm-l6` classifier (warden) variant.

### Fixed

- **`innerwarden install-warden` now works end-to-end for the default `warden` variant** (PR #652, completes the work started in #642). v0.13.5 shipped with the compiled-in SHA-256 still set to the literal `TBD-publish-pin-after-release` placeholder because the `classifier-v1` model release was published *after* v0.13.5 was tagged. Operators running `sudo innerwarden install-warden` on a fresh v0.13.5 install would hit the placeholder error even though the model artefact (`minilm-l6.tar.gz`, 80 MB, SHA-256 `7c1745fd…`) was already public at https://github.com/InnerWarden/innerwarden/releases/tag/classifier-v1 — the CLI just didn't know its hash yet. v0.13.6 pins the real SHA so the install path closes end-to-end. The `roberta-v1` (SecureBERT teacher) variant remains pinned to TBD until the next `classifier-v2` cut bundles its artefact.

## [0.13.5] - 2026-05-16

Operator-facing polish release. Eight PRs against `main` after v0.13.4 was tagged, all motivated by the v0.13.4-rc.1 lab install on `test001` and the operator-reported Telegram FPs during an `apt upgrade` on Oracle prod. Verified end-to-end on Oracle prod (ARM64 aarch64, kernel 6.8.0-1052-oracle, post-reboot) and `test001` (Ubuntu 24.04 x86_64, kernel 6.8.0-117-generic) before tagging.

### Added

- **Setup wizard step `[1/4] Local Warden Model`** (PR #644). The wizard now opens with a yes/no pitch for the on-device classifier as an alternative to a cloud LLM for the `Decide` path. The pitch quantifies the trade-off: zero tokens spent on Decide, ~60 ms p50 vs ~500-2000 ms cloud round-trip, Decide traffic stays on the server, ~91 MB disk + ~150 MB RAM cost. The other three wizard steps were renumbered to `[2/4] AI`, `[3/4] Notification channels`, `[4/4] Protection`. The operator's choice is currently non-binding because the `classifier-v1` model release has not been cut (tracked in #642); saying yes prints a reminder to run `innerwarden install-warden` once the artefact lands. Re-prompted on every wizard run until the install path is wired end-to-end; the section-detection helper already covers the `[ok] already configured` branch for re-runs once `[ai.warden]` is written.
- **`innerwarden --version` / `-V`** (PR #641). Operators kept hitting `innerwarden --version` and getting `error: unexpected argument '--version' found` because clap only wires the flag when `version = ...` is set on the parent `#[command(...)]`. Now prints `innerwarden 0.13.4`.

### Fixed

- **`bash: line 50: BASH_SOURCE[0]: unbound variable`** on every `curl | sudo bash` install (PR #641). `set -u` plus `BASH_SOURCE[0]` aborts before the banner when the script is piped, because `BASH_SOURCE` is empty under that execution mode. Fall back to `${BASH_SOURCE[0]:-$0}`, then to `pwd`, so the same line works under `bash install.sh` and `curl | bash`.
- **Setup ends with "Dashboard not reachable (Connection refused)"** even when the dashboard is live (PR #641). Two bugs in `resolve_dashboard_url`: (a) `starts_with("bind")` matched `bind_addr` inside `[honeypot]` and pulled `127.0.0.1` as the dashboard address with no port; (b) the helper defaulted to `http://` even though the agent boots `--dashboard` with a self-signed TLS cert ("dashboard HTTPS started" in the log). Rewrite parses TOML sections properly, defaults to `https://`, rewrites `0.0.0.0` / `[::]` to `127.0.0.1`, and appends `:8787` when the bind has no port.

### Changed

- **Install banner is now an ASCII wordmark** instead of the double-sword art (PR #641, in both `install.sh::print_install_banner` and `crates/ctl/src/welcome.rs::LOGO_WIDE`). ASCII-only (no unicode / box-drawing) so it renders identically in journald, SSH-tunnelled terminals, and curl|bash pipes. Coloured ANSI-green when stdout is a TTY; `print_centered_line` strips ANSI sequences before measuring so the wordmark stays centred.
- **`install-warden` error explains why the SHA is a placeholder** (PR #643). When the compiled-in SHA-256 is the `TBD-publish-pin-after-release` placeholder, the error now points operators at #642, shows the exact workaround invocation (`--url <mirror> --sha256 <hex>`), and tells them what the agent will do meanwhile (fall back to the configured cloud provider for `Decide`). Bail string still contains the literal `"requires --sha256"` so the existing test anchor at `crates/ctl/src/commands/ai.rs:1188` still catches this branch.
- **install.sh telemetry block now self-documents** (PR #643). Same `INNERWARDEN_TELEMETRY=1` opt-in (SEC-019 unchanged). The block now spells out exactly what the ping sends (version, OS family, CPU arch), what it never sends (raw IP, host identifier, agent state), how the server keeps the ping anonymous (one-way hash of `ip + UTC day + server secret` for dedup, raw IP discarded), and links the receiving endpoint in `inner-warden-site`. The curl is now `-fsS -m 5` so a transient DNS or network fault never produces stderr noise during the install.

### Fixed — Detector false positives during apt upgrade

- **Per-detector allowlist now consulted by the four noisiest detectors** (PR #647). Operator-reported on 2026-05-16 while running `apt upgrade` on the Oracle prod box: `kernel_module_load`, `sudo_abuse`, `systemd_persistence`, and `mitre_hunt::destructive_dd` all fired Critical/High on completely legitimate maintenance activity — Ubuntu loading storage-subsystem modules (`bcache`, `dm_raid`, `iscsi_*`, `cxgb*`, `libcrc32c`), the `ubuntu` user exceeding the 3-commands-in-300s sudo threshold during `sudo apt-get install`, `needrestart` calling `systemctl --quiet is-enabled crowdsec` on every package, and the operator using `dd` for legitimate disk imaging. Root cause: the `[detectors.<NAME>]` section in `allowlist.toml` was already supported by the parser, but those four detectors never consulted it. Fix wraps each emit site with `DynamicAllowlist::suppress_incident_for_detector(&incident, name)`, which extracts the relevant field (module + comm, user, comm, comm + kind respectively) and matches against `per_detector[<name>]`. No detector disabled, no threshold raised, no built-in detection removed — a real attacker who loads a fresh module not in the operator's allowlist still fires Critical. The same gate has been extended in a follow-up to twelve more detectors (`integrity_alert`, `log_tampering`, `privesc`, `rootkit`, `crontab_persistence`, `user_creation`, `sensitive_write`, `host_drift`, `container_drift`, `ssh_key_injection`, `fileless`, `discovery_burst`) so the same operator-edit-allowlist.toml workflow now works across sixteen detectors.

### Reference

- Companion endpoint shipped to `inner-warden-site/master`: `/api/ping` is now wired up (issue #640) — install pings have a real receiver instead of returning 404. Per-IP-per-day hashing for dedup; admin view at `/admin/installs` gated by `DB_ADMIN_TOKEN`. The CLI side stays opt-in (`INNERWARDEN_TELEMETRY=1`).
- Companion site label fix: the `/live` page KPI labelled "Decisions made (7d)" was sourcing its value from `apiTotals.total_today` (today-only), so an operator-reported confusion ("31 blocks in 30 days?") on 2026-05-16 traced back to the label mismatch. Re-labelled to "Decisions today" so the period matches the data. Shipped direct to `inner-warden-site/master`. Deeper agent-side bug (the 7-day blocked count returns unique-IPs which is intentionally lower than the raw block_ip event count in SQLite) is documented but not changed — "Attackers stopped" is semantically correct as unique-attackers.

## [0.13.4] - 2026-05-16

Dashboard simplification release. 56 commits since v0.13.3 collapsing the dashboard from ~10 tabs with overlapping content into a 4-tab main nav (Home / Cases / Health / Intel) plus a More menu (Sensors / Briefings / Compliance). The headline is the PR-A → PR-H series (#631–#638) that finished the post-PR-H baseline; the rest is the data-source canonicalisation work (spec 049) so every panel reads from SQLite instead of the stale in-memory knowledge graph.

### Changed — Dashboard simplification PR-A → PR-H (#631 – #638)

- **PR-A (#631) Shared Attacker Dossier modal.** `openProfileModal(ip)` in `intel.js` is the single drill-down surface used by Cases journey "View full profile →", Intel profile-row click, and Campaign modal member-IP chip click. Fixes the operator-reported regression where the deeplink used to land on the generic Intel list because of the PR #628 120 ms setTimeout race. The modal renders `renderProfileDossierHtml(p)` from `/api/attacker-profiles/<ip>` and includes a Honeypot Intel section gated on `honeypot_sessions > 0`.
- **PR-B (#632) Intel slim — Campaigns / Chains / MITRE sub-tabs deleted.** Campaign membership now surfaces as a tag on the Cases journey header (PR-D below); per-incident chains were already on the Cases journey; the MITRE heatmap is already on the Monthly/Briefings month view. Net: one less navigation layer for the same information.
- **PR-C (#633) Baseline moved to Health, Intel collapses to Profiles.** Baseline was Intel's fourth sub-tab; it is now a section on the Health tab where it semantically belongs (it describes how the host normally behaves). Intel becomes a single surface — Profiles list.
- **PR-D (#634) Campaign-membership tag on Cases journey header.** Replaces the deleted Campaigns sub-tab with an in-context affordance: when a case's IP belongs to a detected campaign cluster, the journey header shows a clickable tag that opens the Campaign modal.
- **PR-E (#635) Intel UX slim + AI Explain SQLite fallback.** `build_explain_context_sqlite` in `data_api.rs` falls back to SQLite when the KG window (~24 h) has aged out, so any IP visible on Cases gets a real explanation instead of the generic "No incidents on record" message. Fixes a class of operator-surfaced confusion where the AI Explain looked broken on older IPs.
- **PR-F (#636) Honeypot tab dropped, per-IP intel stays on Dossier modal.** The standalone Honeypot tab duplicated the Honeypot Intel section that already renders inside the shared dossier modal whenever an IP has honeypot sessions. Drop is safe because the per-IP intel is one click away on every IP-bearing surface.
- **PR-G (#637) Unified Briefings tab with Day / Month period switcher.** Briefings (daily) and Monthly were two separate tabs producing structurally similar content. Now one tab with a Day / Month switcher; same API endpoints under the hood.
- **PR-H (#638) Real pagination on Intel + Audit + visible spec leaks dropped.** Intel Profiles got 10/50/100 paginators (default 10), 3 risk chips (All / ≥40 / ≥70), and an IP-search box. Compliance's Decision Audit Records got the same 10/50/100 paginator. "spec 049 PR…" internal references that had leaked into operator-facing strings were rewritten.

### Changed — Pre-series dashboard cleanup

- **Sensors page deleted, content folded into Home (#629, #630).** The Sensors tab moved its collector breakdown + Event Timeline into Home below the AI Intelligence Briefing block, then the standalone Sensors page was deleted. The `Sensors` entry in the More menu now redirects to the Home anchor.
- **Home page slim (#621).** Removed four overlapping sections (the alert-toast stack and three duplicative status blocks) so Home is now: hero strip, activity strip, AI Intelligence Briefing, Sensors panel.
- **Cases sidebar slim (#622).** Single canonical band that mirrors Home's activity strip, replacing the five-band scrollable sidebar.
- **Responses tab removed (#624).** Decision rows scattered into Cases (per-IP) and Health (system-wide enforcement counters); the standalone tab was deleted, and the equivalent listing now lives behind `innerwarden ctl decisions` on the CLI.

### Changed — Spec 049 canonical data sources (SQLite-first)

The dashboard historically blended two data sources: the in-memory knowledge graph (live and rich but ~24 h window) and SQLite (slower but complete). Mixing them produced count divergence (incident totals differed between Home, Cases, Report, Monthly) and stale reads when the agent restarted. Spec 049 routes every panel through SQLite as the canonical source, with the KG used only for the live feed.

- **`canonical_counts` foundation (#558, #557, #556, #553, #551, #550)** — single helper that every count-bearing endpoint calls; eliminates "Cases says 12, Home says 14" mismatches.
- **`/api/overview` + `/api/sensors` routed through `canonical_counts` (#619).**
- **Live feed reads from SQLite (#626).** Pre-fix the live feed read the in-memory KG and missed any incident written after the agent's most recent KG rebuild — operators saw an empty live feed even when new incidents were landing.
- **Cases / Home / Report / Monthly all read SQLite, not the KG (#557, #609, #610, #612, #614, #615, #623).** Includes filter-self-traffic on Top IPs (#612), research-only incidents excluded from Trend counters (#614), Trend events count from SQLite (#615), and regenerate-Monthly-for-current-month fix (#610).
- **Boot-probe collector health wired end-to-end (#618).** Sensor emits a one-shot health probe per collector at boot; agent persists it; dashboard renders `READY / DEGRADED / FAILED` in the Sensors panel.
- **Write-time pin of `decision_layer` at every prod writer (#556).** Closes a class of bugs where the layer attribution drifted between the AI router output and what the dashboard later displayed.
- **Boot replays today's incidents into the KG (#553).** After an agent restart, the KG was empty until new events arrived; today's incidents are now replayed so the live feed and Cases journey are populated immediately.

### Changed — Misc dashboard truth

- **Health truth + public live feed FP filter + community README (#627).** Health tab numbers now match what the rest of the dashboard shows; the public live feed (sentinel.innerwarden.com) filters out known-noise false positives; community README updated.
- **Intel deeplink + honest KPI counts + IP search (#628).** Intel KPI counters now match the underlying profile list (was double-counting in some cases); deeplink-by-IP supported on the URL; IP search box added.
- **Removed-filter read guard in `syncFiltersFromUi` (#623).** Defensive fix for a TypeError that fired when a filter was removed mid-render.

### Tests

- `cargo test --workspace`: full suite green on CI. Pre-existing macOS-local flake (`incident_flow::tests::evaluate_pre_ai_flow_pipeline_test_writes_acknowledgement_decision`, `Os { code: 2, NotFound }`) remains unrelated to this release and is not regressed by any PR in the series.
- Anchor coverage: registered anchors went from 633 → 665 across PR-A through PR-H (8 new anchor sections in `ANCHOR_TESTS.md`).

### Known caveat (carried from v0.13.x line)

- The `cargo zigbuild` cross-compile path used by the release workflow does NOT propagate the `--enable-prof` C flag to `jemalloc-sys`, so the `_rjem_je_opt_prof` symbol is absent from every GHA-released agent binary. **Effect:** operators who manually wire the spec-030 jeprof systemd drop-in will see the agent segfault on every spawn. **Workaround:** build via `scripts/deploy-prod.sh` (native `cargo build --release`). **Not affected:** new users installing via `curl | sudo bash` without `MALLOC_CONF`. The binary feature-parity guard treats this as a WARN until the zigbuild build path is fixed in a follow-up release.

## [0.13.3] - 2026-05-10

Hotfix release for the silent Local Warden Model regression that affected every GHA-released binary in the v0.13.x line. Anyone installing via the `curl | sudo bash` script or `innerwarden upgrade` for v0.13.0–v0.13.2 was getting an agent that logged the on-device classifier as missing and silently fell back to whatever cloud provider was configured. v0.13.3 is the first release where the binary on the GitHub release page actually has the Local Warden classifier linked in.

### Fixed

- **GHA-released agent now ships with Local Warden Model linked in.** Pre-fix the release workflow built the agent with `cargo zigbuild --release -p innerwarden-agent` without `--features local-classifier`, which meant every binary downloaded from the GitHub release page (including via the `curl | sudo bash` install script and `innerwarden upgrade`) had the on-device ONNX classifier missing — at startup the agent logged `local_warden provider requires building innerwarden-agent with --features local-classifier` and silently fell back to whatever cloud provider was configured. Operators using `scripts/deploy-prod.sh` were unaffected because that script always passed the feature explicitly. The condition has existed at least since v0.13.0 and went undetected because the prior asset manifest checked filenames, not binary content. Fix: pass `--features local-classifier` on both x86_64 and aarch64 build steps in `release.yml`. The binary feature-parity guard from PR #520 verifies the `local_classifier` symbol is present and now hard-fails the release if it is not — so the regression cannot recur.

### Release pipeline

- **Binary feature-parity guard** in `release.yml`. After staging the release assets, the workflow now greps each `innerwarden-agent-linux-{x86_64,aarch64}` binary for the symbol/string markers that prove production features were linked in: `opt_prof` / `prof_init` from jemalloc heap profiling (spec 030, the systemd `MALLOC_CONF=prof:true,...` drop-in), and `local_classifier` from the Local Warden Model provider (spec 029, the `--features local-classifier` build). Local Warden absence is now a hard fail (the build above passes the feature explicitly); jemalloc heap-profile absence is a hard fail too (would segfault every operator with the spec-030 jeprof systemd drop-in). Both regressions reached production in v0.13.0–v0.13.2 undetected because the prior asset manifest only checked filenames, never binary content.

### Known caveat (v0.13.0 – v0.13.2 GHA-released binaries)

- The agent binaries on the GitHub release pages for v0.13.0, v0.13.1, and v0.13.2 were all built without `--features local-classifier`, so the **Local Warden Model is inert** on those binaries — the agent silently falls back to whichever cloud provider is configured (or runs without AI if none is). **v0.13.3 is the first release where the GHA-released binary has Local Warden actually linked in.** Operators on the older releases should re-install via `curl | sudo bash` or build locally via `scripts/deploy-prod.sh`.

### Known caveat (jemalloc heap profiling on GHA-released binaries — all v0.13.x)

- The `cargo zigbuild` cross-compile path used by the release workflow does NOT propagate the `--enable-prof` C flag to `jemalloc-sys`, so the `_rjem_je_opt_prof` symbol is absent from every GHA-released agent binary. **Effect:** operators who manually wire the spec-030 jeprof systemd drop-in (`Environment="MALLOC_CONF=prof:true,..."` in `/etc/systemd/system/innerwarden-watchdog.service.d/jeprof.conf`) will see the agent segfault on every spawn. **Workaround:** build via `scripts/deploy-prod.sh` (native `cargo build --release`) which produces the symbol correctly. **Not affected:** new users installing via `curl | sudo bash` who do not set `MALLOC_CONF`. The binary feature-parity guard treats this as a WARN (informational) rather than a hard FAIL until the zigbuild build path is fixed in a follow-up release.

## [0.13.2] - 2026-05-10

Dashboard UX + AI explainer clarity + architecture-diagram honesty bundle. Three small operator-surfaced fixes from the post-v0.13.1 dashboard review, packaged as the next stable release so the v0.13.x line keeps moving.

### Fixed

- **Baseline tab: pagination collapsed the "What I consider normal here" section.** Operator-surfaced 2026-05-10. Repro: Intel → Baseline → expand the learned-baseline `<details>` → click Next on the user-list pagination → section collapses unexpectedly. Root cause: `loadBaseline()` rebuilds `intelContent.innerHTML` from scratch on every pagination click, and the `<details>` element was recreated without the `open` attribute. Fix persists the open state in `localStorage` (mirroring the existing "Show system accounts" toggle pattern) and re-applies the attribute on every render. (`crates/agent/src/dashboard/frontend/js/intel.js`)
- **AI Explainer: "No incidents on record" was confusing on baseline pages.** Operator clicked "Ask AI to explain" for an IP shown on the Baseline tab (50 deviations attributed to the IP) and got "No incidents on record". Technically correct (baseline deviations are not `Node::Incident`), but the operator read this as "the entity is unknown" rather than "the explainer covers a different signal class". Message rewritten to spell out the boundary: the explainer summarises incident-grade events that reached the decision pipeline (block / dismiss / escalate / honeypot), NOT baseline deviations / process-trust drift / threat-intel hits / honeypot probes that did not produce an incident. (`crates/agent/src/dashboard/data_api.rs::build_explain_context`)

### Changed

- **README architecture diagram now shows the Local Warden classifier.** Pre-fix the diagram listed only "AI Triage (opt) — OpenAI / Anthropic / Ollama" as the AI block, which understated reality: Spec 029 (PR #258) made the on-device Local Warden ONNX classifier the canonical Decide path; cloud LLMs are the optional fallback / Explain capability via the AI Capability Router. The diagram now shows Local Warden first (with the model name, on-disk size, and p50 latency) and the cloud LLMs as a second tier behind the router. Reflects what every install with the default `local-classifier` feature actually does at runtime.

### Release pipeline note

- **v0.13.1 macOS binaries are intentionally absent.** Release workflow #113 hit a tag-pointing race (the v0.13.1 tag was force-pushed from the prep-PR commit to the post-merge squash commit while the macOS job was still running, so the macOS runner saw a checkout mismatch and aborted). Linux x86_64 / aarch64 + Docker + GitHub Artifact Attestations all shipped clean for v0.13.1. v0.13.2 is cut from a stable main HEAD so the same race cannot recur; macOS binaries return on the v0.13.2 release.

### Tests

- `cargo test --workspace`: **6632 passed + 5 ignored** across 35 test suites in 94 s.

---

## [0.13.1] - 2026-05-10

Honeypot effectiveness, posture-aware alerting, and infrastructure honesty release. The headline shift is the honeypot turning from a credential mirror with the door always open into a real behavioural trap that captures Mirai-class bots, manual brute-forcers, and human-direct attackers, without giving away what it is. 50 commits since 0.13.0.

### Added — Spec 046 honeypot effectiveness (PRs #508, #509, #510)

- **Tiered SSH authentication** (`crates/agent/src/skills/builtin/honeypot/ssh_interact.rs`). Reject the first `MIN_ATTEMPTS_BEFORE_ACCEPT = 2` password attempts unconditionally, single-shot credential scanners disconnect on the first reject, dropper bots iterate. Then accept ONLY when `(user, password)` matches `KNOWN_WEAK_CREDENTIALS` (38 entries: classic root defaults + Mirai canonical defaults + appliance defaults). Random brute-force NEVER accepted; single-shot scanners NEVER accepted. Credential capture is unconditional and runs BEFORE any branch.
- **Phase A.5 adaptive accept**: after `MIN_UNIQUE_CREDS_FOR_ADAPTIVE_ACCEPT = 3` distinct passwords on a single connection, the next attempt accepts regardless of weakness. Catches human-direct attackers typing org-specific guesses (`Welcome2024!`, `OracleVM!`, `MyHost_admin`) without double-firing on bots (which hit `KNOWN_WEAK` first).
- **OpenSSH banner masquerade**. The russh default `SSH-2.0-russh_*` was a one-token honeypot fingerprint; replaced with `SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6` via `Config::server_id`. 80 ms `tokio::time::sleep` per rejected attempt simulates real OpenSSH timing.
- **Dashboard pagination + engaged-only default**: `GET /api/honeypot/sessions` accepts `?page=N&size=M&engaged_only=true|false`. Default `engaged_only=true` makes the tab open to the wow-surface (sessions with auth attempts or commands), not the wall of port-scan probes. Page size clamped `[1, 100]`. Three distinct empty states.
- **Per-session transcript expand**: engaged sessions get an "Expand transcript" button revealing full attacker activity inline.
- **Auto-dismiss honeypot probe noise**: `proto_anomaly` (`SshVersionAnomaly`) on the honeypot port writes a `dismiss` decision with reason `honeypot-probe-fp` and removes from "needs attention". KG-hardened: keeps the proto_anomaly visible if the same IP has any non-`proto_anomaly` incident in the last 24h.
- **Feynman-style AI explanations** (`crates/agent/src/dashboard/data_api.rs::explain_system_prompt`): "Ask AI to explain" returned generic 2-sentence summaries that did not help non-technical operators understand "should I worry?". Rewrote the prompt around the Feynman technique (story, why, threat verdict, with explicit honeypot-context awareness). New `build_explain_context` helper extracts as a pure function with KG fallback (walks Incident nodes by `decision_target` / title / summary text when the IP has no `Node::Ip`), retiring the legacy "No data found for IP X" message.

### Added — Spec 044 posture-aware alerting (PRs #502, #503, #504)

- **`HostPosture` snapshot module** (`crates/agent/src/posture/`): every 10 min, the slow loop reads `sshd_config`, `sudoers`, `services`, `firewall`, persists to `data_dir/posture.json`. New CLI subcommand `innerwarden get posture`.
- **Severity downgrade engine** (`effective_severity`): incidents whose severity is dictated by an attack vector the host's posture has already neutralised get demoted (e.g., `ssh_bruteforce method=password` on a host with `PasswordAuthentication=no` becomes Low instead of High). Hard invariant: NEVER demote when `session_established | process_executed | file_written` (you only suppress severity for things the posture provably bounds).
- **Telegram `/posture` command + dashboard panel**: operator can read the live posture from either surface.
- **Daily briefing rewrite**: the dishonest "0/100 server health score" was retired (formula was `100 − critical*20 − high*5` clamped 0..100, dropped to zero on routine activity). Replaced with posture-aware narrative.

### Added — Spec 043 KG justification follow-ups (PRs #472–#481)

- **Decide path reads KG** (`kg_decide_features`): 6 features extracted at decision time (risk_score, prior_incidents_24h, first_seen_age_days, etc.), 4 modifier bands, Critical floor preserved, JSONL shadow log.
- **`/ask` deep context**: Telegram and dashboard `/ask` surfaces now reference KG features and threat-feed datasets directly when the question mentions an IP. 8000-char prompt budget, subgraph triggered by IP regex.
- **KG modifier on direct-block paths**: `apply_kg_decide_modifier` wired into repeat-offender, multi-technique, completed-chain code paths.
- **Four "zona morta" detectors activated**: `yara_match`, `sysctl_drift`, `packed_binary`, `short_lived_process`. Default ON via `[kg]` config.
- **KG-based FP suppression (shadow-first)**: `kg_fp_suppression` module; `fp_likelihood = 0.7×history + 0.3-cap-bonus`; Critical floor hardcoded; `suppress_threshold=0.80`.
- **Akamai/Fastly/CloudFront-specific CIDRs** added to cloud safelist.
- **KG audit hook on AbuseIPDB-gate**: captures the IP's KG snapshot at block time for forensics.

### Added — Kill chain fast-path (PR #507)

- Deterministic strong patterns (`reverse_shell`, `bind_shell`, `code_inject`, `inject_shell` and their sensor-detector aliases `ebpf_reverse_shell`, `ebpf_bind_shell`) bypass the AI router and trigger `decision_block_ip::execute_block_ip_decision` directly. AI verdict was 100% deterministic for these patterns, so the AI call latency (~100 ms local / 1-3 s cloud LLM) was pure overhead. `data_exfil` and `exploit_c2` deliberately stay in the AI path so the codex/openclaw dismiss helpers continue to fire. 10 anchor tests pin every fast-path boundary.

### Fixed

- **Honeypot: russh strips `Password` from method list after reject** (PR #509). Caught during prod smoke. `Auth::Reject { proceed_with_methods: None }` triggers `auth_request.methods.remove(MethodKind::Password)` inside russh-0.60.1. After the first reject, the OpenSSH client saw only `publickey,hostbased,keyboard-interactive` and disconnected, the dropper bot never reached attempt #2 on the same connection. Fix: send `Some(MethodSet::all())` on every reject branch.
- **Honeypot off-by-one in threshold guard** (PR #508 review). First push used `attempt_n < MIN_ATTEMPTS_BEFORE_ACCEPT`, leaking attempt #2 with `admin/admin` through to accept on the second try. Fixed to `<=`. New anchor `weak_credential_on_second_attempt_still_rejects`.
- **Honeypot `max_auth_attempts` floor** (PR #508 review). Caller passing `1` or `2` made the shell unreachable even for perfect Mirai matches (russh closes session before our accept branch runs). New `floor_max_auth_attempts` clamps below-floor values up to `MIN_ATTEMPTS_BEFORE_ACCEPT + 1`.
- **CIDR auto-block** (PRs #496, #497, #498). Three paths (automated decision flow, repeat-offender, safelist gate, AI router execute boundary) still allowed CIDR targets in automated decisions. Closed in layered fashion. ip_reputations zombie cleanup.
- **Decision-cooldown retention** (PR #499). Window was 2h; the longest consumer needed 24h. Raised retention so cooldowns survive the slow path window.
- **AI router suppression when inline path already decided** (PR #500). Avoids double-decisions when kill_chain fast-path or other inline routes already wrote a decision before AI router runs.
- **AbuseIPDB autoblock honesty** (PR #495). Multiple bypass paths fixed; AWS CIDR gap closed; kill_chain `wget` FP eliminated.
- **XDP infrastructure honesty** (PR #494). Three cascading bugs from prod 2026-05-08 audit: cleanup state drift between local set and kernel map, parse failures dropping local entries, adaptive TTL expiry signalling.
- **Profiles dashboard geo** (PRs #492, #493). Cloud-provider IPs now badged + operator can opt-in to exclude; ASN majority drives geo consolidation when WHOIS and ip-api disagree.
- **Threat-DNA hour_distribution drift** (PR #491). Same-actor cross-day clusters were splitting because the hour-of-day distribution changed across midnight. Dropped from the DNA hash.
- **Operator-FP attack chain suppression** (PR #501). Suppress at persistence boundary so the chain UI does not show transient operator-self traffic as "active attack chain".
- **Chains tab honesty bundle** (PR #500). Five lies on the Intelligence > Chains panel fixed: window scope, count cardinality, severity distribution, "active" semantics, attribution.
- **Wave 2-10 audit fixes** (PRs #461-#469): IPv6/IPv4 entity holes, `flock(LOCK_EX)` on hash-chain append, in-batch AbuseIPDB counter prevents burst bypass, agent-guard pipe detector evasion, Cloudflare real-client-behind-edge attribution, blocks counted via non-incident paths.
- **Dashboard label honesty (Wave 8)** (PR #460): every operator-visible counter now declares its window, scope, and cardinality explicitly. Removed implicit "today" / "all" labels that drifted between surfaces.
- **SECURITY.md + THREAT_MODEL.md drift fix (Wave 7)** (PR #461): two of the operator-facing security docs had aged out of sync with the implementation. Synced + added anti-drift anchors that fail CI when prose disagrees with the code.
- **Notification noise + Top-5 leftovers** (PR #470): bundle-fix for the `Top 5 attackers` widget showing duplicate IPs across rows, plus three Telegram digest noise sources (idle-hour kernel-module event spam, stale honeypot session re-emit, briefing redundancy).
- **Briefing "all clear" honesty** (PR #482): suppressed when High+ activity exists.

### Fixed — CTL + harden surface (operator self-audit)

- **Watchdog-aware harden score** (PR #505): `innerwarden harden` was reading `systemctl is-active innerwarden-agent` and reporting "agent not running" because in the new watchdog deploy model the agent is a child process of `innerwarden-watchdog` and `innerwarden-agent.service` is intentionally inactive. New detection logic walks the watchdog process tree. Combined with auditctl rule-syntax fix (the harden-suggested `-w` mixed with `-a -F arch -S` was rejected by auditctl), prod harden score went from 59 → 89 on the operator's box.
- **CTL `nginx error log` discovery + soft-warn** (PR #486, Bug 4 from prod audit): `innerwarden scan` was hard-failing when nginx error.log existed at a non-default path. Now soft-warns + suggests the canonical path; harden continues.
- **CTL `auditd category score` recalibration** (PR #485): auditd rules had a 30-pt bonus that was double-counted across two categories, inflating clean-system scores by ~25 pts.
- **CTL `systemctl bus failure` cascade** (PR #484): a single missing systemd bus connection cascaded the entire harden run into "unknown" status. Split into a tri-state (`active` / `inactive` / `bus-unreachable`) so operator sees the actual problem.

### Performance

- **`Arc<str>` interning** on hot Event-kind/source paths, telemetry counters, baseline HashMap keys (PRs #463, #464, #465). KG telemetry counter keys now share allocations across threads.

### Tests

- **2954 / 2954 pass + 2 ignored**. Net add of ~50 anchor tests across honeypot, posture, KG, CIDR-guard, dismiss helpers.
- **Coverage batches 2 + 3** (PRs #487, #488): 16 files lifted to ≥ 70% with gate-contract anchors. CI fuzz workflow fix.
- **4 new honeypot integration scenarios** (Mirai-class bot, root brute bot, human-direct attacker, retry-loop anti-regression) via real `russh::client` against ephemeral listeners.

### Changed

- Cargo workspace version → `0.13.1`.
- Default honeypot `interaction = "llm_shell"` is now the canonical "trap that captures behaviour" path; `medium` (`RejectAll`) preserved unchanged for credential-only deployments.

### Operator-visible

- Honeypot tab opens to the engaged-only first page by default. Pagination at top + bottom. Engagement banner explains the engaged-vs-unengaged split with Spec 046 context.
- "Ask AI to explain" returns a coherent narrative even when the IP is not yet in the KG node table (operator's 2026-05-10 case for `175.110.112.8`).
- Daily Telegram briefing reflects host posture and dropped the dishonest 0/100 score line.

---

## [0.13.0] - 2026-05-03

Operator-trust release. Closes the recurring "the dashboard says one number, the site says another, JSONL says a third" class of bug. Adds the persistent IP→geo cache that keeps the site map honest at scale (138+ unique attackers/day on the operator's prod host). Removes the half-shipped playbook engine (deferred to Spec 042).

### Added — Wave 6a (PR #434)
- **Persistent GeoIP cache** (`crates/agent/src/geo_cache.rs`) — IP → geo-entry map with 7-day TTL, atomic tmp-rename persistence at `data_dir/geo-cache.json`. Public site `Attack origins` map was making N round-trips to ip-api.com per page load (N = unique attacker IPs); with 138 unique IPs in 24h and ip-api free tier capped at 45 req/min, cold-cache load took ~3 minutes to plot all markers. Cache makes subsequent loads instant.
- **`/api/live-feed` carries pre-attached geo** — new `sources: Vec<{ip, country, lat, lon, incidents}>` field (capped at 200 by activity). Frontend renders the map immediately for cached IPs without per-IP `/geoip` follow-up. Cache misses arrive with `country=""`/`lat=lon=0` so the JS can decide to skip or render at the equator until a backfill round.
- **`/api/live-feed/geoip` is cache-first** — hits return immediately with no network call. Misses fall through to ip-api and write back to the cache so the next call is instant.

### Fixed — Wave 5 / 5b / 5c (PRs #427 #429 #430 #431 #432 #433)

**Number honesty:**
- **Site live-feed and dashboard counts now match prod truth (PR #433)** — public `/api/live-feed` walked ONLY the in-memory KG; KG TTL evicted everything older than ~1 day. Site reported `4 events / 0 IPs blocked / 0 high (24h)` while prod JSONL had 42 incidents and 647 block decisions for the same window. New `merge_incidents_prefer_kg` / `merge_decisions_prefer_kg` helpers concat KG (rich entity context) with JSONL (full daily history), dedup by `incident_id`. Today + yesterday window covers cross-midnight. Anchored by `jsonl_fallback_recovers_count_when_kg_is_empty`.
- **Knowledge graph snapshot no longer carries dangling edges (PR #432)** — `enforce_memory_limit` removed nodes (which tombstones edges via `remove_node`) AFTER the gated `compact_edges` ran in slow_loop. Tombstones leaked into the persisted blob; reload tagged them as dangling and emitted `Knowledge graph has dangling edge references — pruning dangling=30157` every save cycle for days. New `compact_edges_force()` (no 20%-ratio gate) runs LAST in the maintenance order so both passes' tombstones are swept before serialise. Anchored by `snapshot_after_node_eviction_carries_no_dangling_edges`.

**Detection / response correctness:**
- **`graph_discovery_burst` no longer fires HIGH on snap_daemon (PR #432)** — operator's site home rendered `HIGH: Graph Discovery Burst — user uid:584788 (92 actions in 60s)` for routine `snap refresh`. Even with the PR #418 5x Service-class threshold (5×5=25), 92 actions tripped the `>= adjusted * 2 → HIGH` branch. Now caps severity at Medium for Service-class users; signal still recorded (visible in journey + Telegram digest) but no red banner for non-actionable noise. Evidence JSON gains `user_class` field.
- **Baseline learning rejects honeypot + brute-force usernames (PR #429)** — operator's `baseline.json` was full of `Admin`, `AdminGPON`, `Administrator`, `1234`, `123456789`, plus literal special chars. Three filters added: skip events with `source` starting `honeypot` or tag `honeypot`; reject entity values that fail `is_valid_unix_username` (POSIX `[a-z_][a-z0-9_-]{0,31}`); one-shot prune at boot wipes pre-existing pollution. Four anchors pin each layer.
- **Reverse_shell incident summary no longer leaks `uid={uid}` (PR #428, CodeQL #144)** — `uid` already lives in `evidence.uid` as structured data. Removing the redundant interpolation cleared the `rust/cleartext-logging` finding without losing forensic fidelity.

**Runtime resilience:**
- **XDP unavailability stops spamming the journal (PR #430)** — when bpffs is not mounted at `/sys/fs/bpf/innerwarden`, every block decision was emitting two WARN lines (`shield XDP blocklist add failed` + `XDP blocklist map not found`). New `xdp_availability` module gates both call sites: after one observed failure, XDP attempts skip for 5 min and exactly one operator-actionable WARN with the recovery recipe is logged. Auto-recovers when bpffs is mounted. Steady-state log volume drops from ~6 WARN/hour to 1 every 5 min.
- **`events.src_ip` backfill no longer races sensor for SQLite writer lock (PR #431)** — agent and sensor are separate processes sharing the .db file. Agent's 1000-row UPDATE batch held the writer lock long enough that the sensor's INSERTs blocked past `busy_timeout=5000ms`. Three changes: `BACKFILL_BATCH_SIZE` 1000 → 100 (10× shorter lock hold), throttle to 1/min (was every 30s tick), retry-with-backoff up to 3× on `database is locked`. Steady-state log volume drops from ~120 WARN/hour to <5.

**Dashboard UX honesty:**
- **Baseline tab "Who logs in, when" heatmap default-hides daemon PAM sessions (PR #427)** — operator opened the tab and reported many "users logged in" when only `ubuntu` had real SSH sessions. Endpoint enriches the response with `user_classes` map (read from `/etc/passwd` via existing `parse_passwd_for_user_classes` from PR #418). Frontend default-hides Service-class rows behind a "Show system accounts (N)" toggle (state persisted in localStorage). Per-row class badge so the operator sees Human / Root / Service / Unknown. Pagination at 21+ visible rows. Heatmap now uses full card width.

### Changed
- **README + GitHub repo "About" sidebar** (PR #434) — drop "autonomous alternative to MDR / no SOC cost" framing in favour of the site's voice ("The security agent that fights back. ... runs inside your server, decides what's a real threat, and stops it."). Same key points (one binary, one SQLite, no SIEM/IDS/cloud) without renting positioning from a category the project does not occupy.
- **Stale `20 automated playbooks` claim removed from README** — PR #413 (in this release) already removed the playbook engine; the README boast was leftover. Spec 042 active defense will be the future home for declarative orchestration.

### CI / supply chain
- **OpenSSF Scorecard hardening (PR #428)** — `anchor-tests.yml` workflow gained an explicit top-level `permissions: contents: read` block (was implicitly write-all, scoring 0/10 on Token-Permissions) and pinned `actions/checkout@v4` to its commit SHA (Pinned-Dependencies 9 → 10). Recovers ~0.7 of overall Scorecard.

### Anchor-test count
- 8 → 26 (+18 new anchors across Waves 5/5b/5c/6a). Manifest at `ANCHOR_TESTS.md`; CI gate `verify-anchor-tests` runs on every PR.

---

## [0.12.4-pre — entries below were on `Unreleased` from 0.12.4 onward; rolled into 0.13.0]

### Fixed
- **Home tile "X handled today" now matches the Threats tab entry count** — the home tile read `safely_resolved` (incident-count) while the Threats tab grouped by attacker IP. Operators saw "54 handled" then clicked through and counted ~14 entries. New `handled_ips_today` field on `OverviewResponse` is the unique-IP count; `home.js` reads it (with `safely_resolved` fallback for older backends). Validated in prod canary 2026-04-23: home shows 2, threats shows 2 blocked + 12 resolved = 14, site live-feed shows `unique_sources: 14`. (`NUMBER_CONSISTENCY.md` row "handled count")
- **Threats tab now applies the same internal/research filter as the public site** — pre-fix, advisory-only detectors (`neural_anomaly`, `host_drift`, `network_sniffing`, `discovery_burst`) and InnerWarden system processes (`(en-agent)`, `(en-sensor)`, `(systemd)`, etc) showed up in the Threats tab as "attackers" but were filtered out of the site live-feed. Same `is_internal_incident_fields` predicate now applied at both surfaces. Validated in prod: `/api/entities` returns the same 14 unique sources as `/api/live-feed`.
- **Threats tab `?date=`, `?severity_min=`, `?detector=` filters now actually filter** — frontend sent the query string but `api_overview`, `api_entities`, `api_pivots` ignored severity_min/detector. Wired end-to-end through `InvestigationFilters::{severity_min_rank, detector_lower}` helpers; same predicate runs in both the home overview and the threats tab so `/api/overview?severity_min=high` and `/api/entities?severity_min=high` count the same set. Validated: `?severity_min=high` narrows 14→2; `?severity_min=critical` → 0; `?detector=nope` → 0.
- **`sqlite_store` no longer stuck at None after boot-time `database is locked` race** — the boot-only `Store::open` left `state.sqlite_store` as `None` for the entire process lifetime when the file was contended at startup. Discovered during the Finding 5 canary on 2026-04-23: SQLite snapshot saves became silent no-ops for hours after a contended boot. New `try_recover_sqlite_store` runs on every slow_loop tick (60s back-off so a permanent error does not become a tight retry loop) and lazily reopens the store. Underlying long-term lock contention with `innerwarden-sensor` is a separate sensor-coordination bug tracked outside this PR.

### Performance
- **Slow-loop graph-maintenance no longer blocks dashboard for 100-300 ms every 60 s** — the periodic snapshot block held a single write lock across `cleanup_expired + compact_edges + enforce_memory_limit + serialize + gzip + fs::write + SQLite bind + cleanup_old_snapshots`. Restructured into three lock scopes: write (cheap mutations), read (serialize bytes via new `serialize_snapshot_bytes` / `SerializedSnapshot`), no-lock (disk + SQLite I/O). Validated in prod canary: 60/60 dashboard `/api/health` pings completed in 0 ms during a snapshot tick (pre-fix would show 100-300 ms bursts every 60 s).
- **`KnowledgeGraph::metrics()` is now O(N) instead of O(N × E_avg log E_avg)** — `total_degree` was computed by calling `all_edges(id).len()` per node, allocating + sorting a `Vec<&Edge>` per call. Same anti-pattern that PR #261 fixed in `enforce_memory_limit`. Now sums adjacency-list lengths directly: `outgoing.values().map(Vec::len).sum() + incoming.values().map(Vec::len).sum()`. Self-loops contribute +2 here vs +1 in the old `all_edges` (which de-duped); accept the rounding — `avg_degree` is diagnostic only.
- **Dashboard handlers `api_sensors` and `api_honeypot_sessions` no longer block tokio worker threads** — both held `std::sync::RwLock<KG>` and ran sync work inside async scope. Same `tokio::task::spawn_blocking` pattern PR #261 applied to `api_quickwins` / `api_live_feed` / `api_export`. The 30 s cache on `api_sensors` made contention rare but not impossible; now the cache miss path runs on the blocking pool so it cannot stall sibling handlers.

### Performance
- **`/api/quickwins` endpoint always returned empty** — the JSONL reader looked at field `action` but the writer (`decisions.rs`) writes the field as `action_type`, so the blocked-IPs deduplication set was always empty. Severity filter compared against `"High"`/`"Critical"` (PascalCase) but the wire format is lowercase per `Severity` `#[serde(rename_all = "lowercase")]`, so the filter never matched. Both bugs fixed in `dashboard/actions.rs`; 7 fixture-driven regression tests added (`api_quickwins_*`).
- **6h-window report subcounted to zero around midnight** — `compute_recent_window` was string-comparing bucket keys formatted as `"HH:MM"` against `cutoff.format("%H:%M")`. At 02:00 UTC the cutoff was `"20:00"` (yesterday), but today's snapshot only had buckets `"00:00".."02:00"` — all alphabetically less than `"20:00"`, so the loop counted zero events. Fix carries a date dimension on bucket keys (`YYYY-MM-DDTHH:MM`), parses them back to `chrono::DateTime` for comparison, and walks both today's and yesterday's snapshots whenever the cutoff falls into yesterday. Reader is back-compat with legacy bare-`HH:MM` keys via the snapshot's date as fallback.
- **`event_timeline` and `detector_timeline` lost the date dimension under multi-day uptime** — same root cause as the 6h-window bug. Bucket key is now ISO-prefixed; sensors-tab serializer projects keys back to `HH:MM` for chart-display compactness so the UI is unchanged.
- **Dashboard async handlers blocked tokio worker threads** — `api_quickwins`, `api_live_feed`, and `api_export` held the `std::sync::RwLock<KnowledgeGraph>` and ran synchronous JSONL/serde work inside async handler scope. Each now wraps its body in `tokio::task::spawn_blocking`, freeing the runtime for concurrent requests. The full lock migration (71 call sites) is deliberately out of scope; the spawn_blocking pattern addresses the user-impact (worker-starvation under contention) without the migration risk.
- **`KnowledgeGraph::enforce_memory_limit` allocated O(N × E) under memory pressure** — the LRU-eviction path called `all_edges(id)` per node to find each node's last edge timestamp. `all_edges` allocates a `Vec<&Edge>` and sorts it. Worst possible time to allocate is when memory pressure has just triggered the path. New `last_edge_ts: HashMap<NodeId, DateTime<Utc>>` is updated on every `add_edge` and queried in O(1). Index is rebuilt from `edges` on snapshot load (same precedent as `outgoing`/`incoming`), so the wire format is unchanged. 7 invariant tests added (`last_edge_ts_*`).
- **Atomic write for `playbook-log.json` and `attack-chains.json`** — both files used a read-modify-write pattern with `std::fs::write` directly over the target. A crash mid-write would leave dashboard readers with a half-written corrupt JSON array. New shared `crate::capped_log::append_with_cap` helper writes to a sibling temp file (`<path>.<pid>.tmp`) and atomically renames onto the target. POSIX rename is atomic on same-filesystem moves. 6 unit tests including atomic-rename invariants.

### Performance
- **KG snapshot writes shrink ~10× (gzip)** — `save_snapshot` and `save_to_store` now gzip the serialized JSON before write/bind. On the prod baseline (14.5k nodes, 145k edges, ~47 MB JSON) the file/blob shrinks to ~5 MB. Reduces both disk usage AND the per-tick SQLite BLOB-bind transient that pressed RSS. Reader is back-compat: detects gzip via magic bytes (`0x1f 0x8b`), falls through to raw JSON for legacy snapshots.
- **`events_for_training` no longer re-parses each row's full JSON** — schema v2 added an `events.src_ip` column populated at insert time. The training query now reads the column directly. One-time backfill scans existing rows on the first agent boot post-upgrade. (`RECURRING_BUGS.md` "events_for_training reparses full JSON to extract src_ip")

### Schema
- **events table v2** — added `src_ip` column + `idx_events_src_ip` partial index. Migration `apply_v2` ALTERs existing tables and backfills from `details.src_ip` (preferred) or `details.ip` (fallback). `CURRENT_VERSION` bumped to 2.

### Performance
- **Boot heap reduction (~200 MB transient)** — `loops/boot.rs` now constructs the primary AI provider and the spec-029 capability router exactly once and shares the `Arc`-wrapped handles between the dashboard task and the main agent loop. The previous code path built each provider twice (once per consumer), which on production with `[ai.classifier].enabled = true` re-parsed the ONNX classifier model end-to-end (~107 MB allocation pipeline through `tract_onnx::Onnx::parse → into_optimized → codegen`). Validated against jeprof heap dump on 2026-04-22.
- **Knowledge graph snapshot save no longer clones the entire graph** (`knowledge_graph/persistence.rs`) — `save_snapshot` and `save_to_store` now serialise from a borrowing `GraphSnapshotRef<'a>` instead of building an owned `GraphSnapshot` with `nodes.clone() + edges.clone() + …`. Removes ~272 MB of transient allocation per slow-loop tick on the 1354-attacker-profile production baseline. Wire format unchanged; existing roundtrip test (`test_save_and_load_snapshot`) covers the equivalence.
- Removed the unused `ai::router::build_for_dashboard` wrapper (and its three unit tests) — orphaned by the dashboard-router consolidation above.

### Removed
- **AlphaZero defender brain (#258)** — the embedded 19,615-param dual-head MLP (`crates/agent/src/defender_brain.rs`, 1,361 lines, plus `defender-brain.bin`) was a comparison-only second opinion that never influenced production decisions. In production it had 12% AI agreement and collapsed to outputting `capture_forensics` for every incident. The trained SecureBERT V1 classifier (precision 0.975 on 2,481 incidents) is a strict superset and is already wired through the AI router as the `local_classifier` provider. Net diff: -2,841 / +354 lines.
- 🧠 Brain tab from the dashboard intel sub-tabs and the three `/api/defender-brain/*` routes.
- 72-feature builder (`build_brain_features`, `event_kind_layer`, `fill_history_features`, `fill_new_detector_flags`), the rolling-history helper, the AI-agreement helper, the brain-training feeds in `incident_auto_rules` and `correlation_response`, the daily retrain block in `loops/boot.rs`, and the `recent_event_kinds` field on `AgentState`.
- `.specify/features/031-defender-brain-feature-alignment/` spec (made obsolete by this change).

### Added
- **`innerwarden install-classifier` (#258)** — top-level CLI that downloads, SHA-256-verifies and extracts the local SecureBERT classifier into `/var/lib/innerwarden/models/classifier/`. Two variants: `minilm-l6` (87 MB distilled, default, ~60 ms p50 on ARM) and `roberta-v1` (478 MB, validated 0.975 precision on `block_ip`). `--url` and `--sha256` overrides for air-gapped mirrors. The command refuses to install while the artifact SHA is still `TBD-`, forcing the operator to pass an explicit hash until the release is pinned.
- Documented `[ai.classifier]` and `[ai.llm]` slots in `agent-test.toml` so operators see how to wire SecureBERT into the spec 029 capability router after running the installer.

---

## [0.12.4] - 2026-04-19

### Added
- **Circuit breaker for autonomous blocks (#181)** — per-UTC-hour cap (`responder.max_blocks_per_hour`, default 100) that halts the block pipeline when crossed. Three modes via `responder.circuit_breaker_mode`: `pause` refuses further blocks, `log_only` counts but never refuses, `dry_run` audit-writes the decision but skips the skill. Motivated by the CL-008 cascade that queued 1021 blocks in 24h. Auto-rearms on the next UTC hour; operator can reset immediately with the new CLI.
- **`innerwarden system circuit-status` / `circuit-reset` (#182)** — inspect and clear the breaker without editing SQLite by hand. Plaintext and `--json` outputs.
- **`innerwarden system reconcile-blocks` (#188)** — walks ufw DENY rules and releases any target that now falls inside the cloud safelist (Cloudflare, Oracle peers, link-local, agent services, Telegram edge). Dry-run default; `--apply` actually releases via `innerwarden action unblock`. Motivating incident: 60 pre-safelist rules were still blocking Cloudflare after #181 landed.
- **`innerwarden` startup banner (#184)** — running the CLI with no subcommand prints a stylised block-letter banner, version, and a rotating tagline, then falls through to help. Respects `NO_COLOR`.
- **Fuzz harnesses (#190)** — three cargo-fuzz targets for parsers that consume attacker-controlled bytes: `tls_client_hello` (JA3/JA4), `core_event_json`, `core_incident_json`. Excluded from the workspace so stable CI stays on stable; nightly GitHub Actions runs 5 min per target and uploads any crash as an artifact.

### Changed
- **Autonomy gap closed (#183)** — production audit on 2026-04-15 found 1812 incidents produced 0 AI-executed blocks in three days. Two compounding defects:
  - `ai.confidence_threshold` set to `1.01` in prod silently disabled every AI-driven auto-execute. `AiConfig::clamp_confidence_threshold` now warns and resets out-of-range values at load time.
  - The obvious-gate required `ip_seen_before` for every detector. Reasonable for ssh_bruteforce / port_scan, wrong for reverse_shell / web_shell / c2_callback / process_injection / rootkit / crypto_miner. Split the gate into `RepeatOffender` and `FirstHit` policies; those six detectors plus `threat_intel` now auto-block on first observation.
- **`ai.min_severity` default dropped from `"high"` to `"medium"` (#187)** — the Medium layer (port scans, credential stuffing below brute-force threshold, web scans, suspicious_login) was never reaching AI triage; it went straight to the noise-gate. AI now sees Medium/High/Critical. Operators on paid providers with cost sensitivity can set `"high"` explicitly in `agent.toml`.
- **AI voice unified across Telegram, dashboard briefing, threat explain (#185, #186, #188)** — one `cfg.telegram.bot.personality` string is plumbed through `DashboardActionConfig` and injected into every AI-facing prompt. `compose_system_prompt` helper merges persona + runtime snapshot + recent incidents + recent decisions. Persona rewritten from generic "proportional analyst" to a short, confident, dry voice; `briefing_prompt` no longer re-asserts tone that fights the persona. Greeting / small-talk now routes to a friendly one-liner instead of the security catchphrase.
- **Dashboard Home "Handled" KPI single-sourced from `overview.safely_resolved` (#188)** — hero sub, KPI tile, and AI briefing now quote the same number. Prior to this, three code paths reported three different counts for the same time window.
- **Incident decision reasons have a voice (#184)** — the strings written to the decision audit trail and emitted as logs went from stock `Auto-blocked: X from Y` to `Shut the door on {ip}. {detector} caught on first try. Compromise averted.` etc.
- **Telegram daily digest phrasing (#186)** — `Everything is under control.` / `No action needed — everything is under control.` replaced with `All clear. Nothing needs you.`

### Fixed
- **`rand` dependabot alert (#181)** — transitive `rand 0.8.5` via russh's forked ssh-key is unreachable in our build (no `log`-feature custom logger calls `rand::rng()`); dismissed with `tolerable_risk`.
- **Dashboard "Blocked Today" KPI silently swapping data source (#186)** — tile used to fall back from entity-based count to `ai_responded` when the active set was empty. Single source now, label clarified to "Handled".
- **Dashboard `onclick="showContained()"` called a function that never existed (#186)** — replaced with `viewActivity()`.
- **`/api/responses` empty shape missing `state_counts` (#188)** — a clean install returned `{active, active_count, history, totals}` but `responses.js` read `r.state_counts.revert_pending` and threw. `empty_responses_payload` helper now populates every field the renderer consumes; shape-lock test pins the contract.
- **Report tab "events ✗ Absent" (#188)** — spec 016 migrated events to SQLite; the row now reads "SQLite · (in db)".
- **Briefing tone fighting the persona (#188)** — `briefing_prompt` used to demand "Be reassuring" and "Write for a non-technical operator", which overrode the bot personality and produced consultant-speak. Rewritten to carry format structure only.
- **Telegram `/ask` over-applied "bot noise, handled" to greetings (#186)** — persona taught the model a catchphrase without context. Added a "how to read the operator's message first" branch.
- **Threats tab stuck on "Loading..." (#191)** — regression from #188. Removing the hidden `kpi-events` / `kpi-incidents` / `kpi-attackers` spans and the `clusterList` / `topDetectors` divs broke `refreshLeft`, which still wrote to those ids. The first `null.textContent` threw, swallowed by the outer try/catch, and `attackerList.innerHTML` was never reached. Every left-panel write now funnels through `setText` / `setHtml` helpers that no-op on missing nodes.
- **Dashboard "Cannot set properties of null (setting 'textContent')" (#189)** — SSE refresh could reach `threats.js` / `home.js` write paths while the target view was hidden; guarded three sites that wrote without a null check.
- **Dead UI in dashboard (#186, #188)** — removed Recent Activity section from Home (duplicated Threats tab), hidden KPI spans in Threats left panel (never populated), cluster list + top detectors divs (state never assigned).
- **Scenario 04-honeypot-unknown envelope drift (#187)** — with `ai.min_severity = "medium"` the Medium honeypot-from-unknown-IP incident now reaches AI triage and the Monitor action auto-executes a packet capture. `decisions_auto_executed` envelope bumped from `{min:0, max:0}` to `{min:1, max:1}`.

### Tests
- **+93 agent unit tests (#189 #192 #193 #194)** — report.rs 89.1% → 93.4%, playbook engine coverage, defender_brain suggestion engine, monthly threat report pipeline. Total agent tests 1466 → 1559.
- **Circuit breaker CLI commands ~100% patch coverage (#182)** — 19 unit tests covering `read_status`, `reset_hour`, render helpers, and the two end-to-end command entry points.

---

## [0.12.3] - 2026-04-18

### Fixed
- **Autoencoder scores saturated at 1.000 regardless of live event shape** — production emitted `score=1.000 maturity=1.00` on every event even after v0.12.2 repaired the training pipeline. Root cause was in the scoring math: `baseline_std` is tiny by construction when computed on the same windows the autoencoder memorised, so z-score + sigmoid saturates on almost every live window. Replaced the sigmoid path with a 101-anchor percentile table computed over a held-out 20% of training windows. Live MSE is now ranked against that distribution — `p50 → 0.50`, `p95 → 0.95`, `p99 → 0.99` — instead of collapsing to 1.0 anywhere above p95. Falls back to the legacy z-score path when the table is degenerate (v1 model files / tiny datasets), so v0.12.2 installations upgrade without a forced retrain.
- **AbuseIPDB report quota burn-through** — the `/report` endpoint had no daily cap or per-IP dedup (the existing `ABUSEIPDB_DAILY_LIMIT=800` guard lived only on the `/check` path). Production burnt 1,021 reports in 24h during the CL-008 cascade. Added `abuseipdb_report_budget` module with per-IP dedup (24h TTL in sqlite `abuseipdb_reported` KV) + daily hard cap (`abuseipdb.report_daily_cap`, default 800, 0 pauses reporting). Planner + dispatcher are pure helpers so the whole decision matrix is unit-tested without a live HTTP endpoint.

### Added
- **Deterministic train/holdout split** for nightly autoencoder training. `training_holdout_fraction` config (default 0.2, clamped to [0.0, 0.5]) selects every Nth window for baseline computation; the other windows train the network. Setting 0.0 preserves legacy single-set baseline for small datasets.
- **Model file format v2** with embedded percentile anchor table (101 × f32 between the IWAE header and the length-prefixed JSON weights). Loaders auto-detect via the version byte — v1 files still parse and populate a zeroed anchor table.
- **Per-outcome telemetry for AbuseIPDB queue flush**: `SkipCloud`, `Skip(AlreadyReportedToday)`, `Skip(DailyCapReached)`, and `Send` each log their reason + IP, making queue pressure visible in `journalctl` without the `/metrics` endpoint.

### Changed
- **Coverage closeout**: patch tests landed for `shield_inline` rate-limiter + `telemetry_tick` emitter (#150), incident enrichment adapters (#148), and `slow_loop` guard orchestration (#151). Workspace test count grew from 3,712 → 3,763+.

---

## [0.12.2] - 2026-04-18

### Fixed
- **AbuseIPDB daily report quota exhausted** — operator email 2026-04-18: "You've exhausted your daily limit of 1,000 requests for report endpoint." Direct fallout of the CL-008 cascade that v0.12.1 fixed: ~900 false-positive blocks against Cloudflare CIDRs were queued for community reporting, each consuming one `report` call. The block refusal lands at `execute_block_ip_decision`, which prevents NEW reports from being queued, but entries already sitting in `state.abuseipdb_report_queue` before the fix deployed would still fire on the 5-minute grace flush. The slow-loop flush now consults `cloud_safelist::identify_provider` one more time before calling `client.report`, so any pre-fix queue entries targeting cloud ranges are dropped with a log line instead of polluting the community feed and burning our quota.
- **CI `Secrets scan` job flaky on transient 504** — `curl -sSfL` fetching the gitleaks release tarball from github.com sometimes hits a 504 at the CDN edge, failing the whole PR check. Added `--retry 5 --retry-delay 5 --retry-all-errors --retry-connrefused --retry-max-time 180` so the download survives transient upstream hiccups.

---

## [0.12.1] - 2026-04-18

### Fixed
- **Autoencoder trained on zero events since spec 016** — `neural_lifecycle::train_nightly` iterated `events-YYYY-MM-DD.jsonl` files, but spec 016 moved every event into `innerwarden.db`. Every nightly trigger returned `"insufficient data"` and left the stale model in place. `baseline_std` drifted to ~0.0018, saturating sigmoid on every live window (`score=1.000` forever, maturity 1.00 on day 30+). Now reads from SQLite first, falls back to JSONL.
- **Seven high-volume event kinds invisible to the brain** — `http.request` (22K/3d), `tcp_stream.ssh`, `memory.anon_executable`, `network.snapshot`, `memory.deleted_file_mapping`, `file.extracted_from_network`, `kernel.bpf_program_loaded` were not in `kind_index`, so the autoencoder was training on a biased slice. Added at slots 24..30; `NUM_FEATURES` bumped 58 → 65. Models from 0.12.0 auto-invalidate via dimension-mismatch check.
- **Autonomy cascade blocking Cloudflare** — `correlation:CL-008` (file.read_access → network.outbound_connect within 60s) was matching the platform's own outbound traffic and auto-blocking whatever IP the outbound connection targeted. Production 24h snapshot: 1021 auto block_ip decisions, top 9 all Cloudflare CIDRs, 552 triggered by CL-008 alone + 375 `repeat-offender` compounding. New `check_block_eligibility_with_safelist` refuses any block whose target resolves via `cloud_safelist::identify_provider`, and short-circuits `correlation_response::handle_completed_chain` + repeat-offender before they mutate `ip_reputations`.
- **Dashboard decisions table stale since legacy migration** — `DecisionWriter` only wrote JSONL; dashboards, `/metrics`, and scenario-qa all query sqlite `decisions`, which was untouched for a month. `DecisionWriter::with_store` now dual-writes: JSONL remains the audit trail of record, sqlite gets mirrored via `insert_decision`. Failure to persist logs a warning but does not reject the write.
- **`cloud_safelist::identify_provider` mislabelled Cloudflare** — first-octet heuristic classified 104.x as Azure and 172.x as Google Cloud. Now walks `CLOUDFLARE_RANGES` first; heuristic stays as fallback for other providers.

### Added
- **`innerwarden-agent --retrain-anomaly`** one-shot flag (mirrors the spec 015 cleanup pattern). Reads events from `innerwarden.db`, trains `anomaly-model.bin` in place, prints maturity + cycles + model path, exits. Operator no longer has to wait until 03:00 UTC to recalibrate after a feature-layout bump.
- `Store::events_for_training(since_ts, limit)` — streams `(kind, Option<src_ip>)` tuples without deserialising full events. RAM-budget friendly; used by the nightly training path.

### Changed
- Neural feature vector layout encoded in named constants (`KIND_SLOTS`, `BIGRAM_BASE`, `SEQ_BASE`, `GRAPH_BASE`). Future additions bump constants in one place instead of shifting magic slot numbers across the file.

---

## [0.12.0] - 2026-04-18

### Added
- **Regression safety net (spec 024)** — `make scenario-qa` with 7 deterministic canonical scenarios (SSH brute single/coordinated, honeypot known-bad/unknown, port scan, DDoS SYN flood, grouped campaign) gated in CI via envelope assertions; 18 contract tests across the 5 boundary subsystems; `/metrics` now exposes all 10 drift metrics; `docs/prometheus-alerts.yaml` with 10/h warn + 50/h crit thresholds post spec 005 grouping; dashboard "Health → Metrics drift" tab.
- **Intelligent notifications (spec 005)** — incident grouping, channel filter, daily briefing digest, bootstrap environment profile, periodic census, operator feedback loop, AI batch triage (opt-in). Agent now sends ≤ 1 grouped Telegram instead of one-per-incident.
- **Structured subgraph in LLM prompts (spec 025)** — JSON graph context replaces prose narrative (qwen2.5:3b bench: 53% → 73% action accuracy, hallucinated target 47% → 7%).
- **Zero-trust MDR (spec 020)** — continuous trust scoring engine, AI SOC daily checks with 11 system parsers, graduated enforcement state machine (Phase F-partial).
- **Observation verification (spec 021)** — behavioural score engine, AI batch verification for ambiguous observations, dashboard score display.
- **CTL** — new `innerwarden replay` command for E2E validation.
- **Scenario seed mechanism** — `scripts/scenario_seed.py` pre-populates `innerwarden.db` and KV cache so scenarios that require eBPF / root / packet generators still run headless in CI.
- **Auto-response coverage (spec 018 Phases A-D)** — correlation-driven escalation + trusted_processes filter.
- **Graph full connectivity (spec 014)** — 8 → 18 active relations, edges 12K → 33K, Process nodes 411 → 4,470.
- **Graph signal quality audit (spec 015)** — caught 3,954 false-positive `graph_user_creation` incidents from a single presence-scan detector.

### Changed
- **Unified SQLite store (spec 016)** — single `innerwarden.db` replaces 15 storage artifacts; redb removed, JSONL removed, 14 maintenance tasks consolidated.
- **AbuseIPDB per-incident lookup** — now consults SQLite cache before hitting the live API. Removes redundant HTTP on every incident and closes the "no API key → always None" gap.
- **Telegram mock outbox** — new `INNERWARDEN_MOCK_TELEGRAM=1` mode for deterministic scenario testing without touching api.telegram.org.
- **GeoIP** — switched ip-api.com to HTTP (free tier rejects HTTPS).
- **Coverage scaffolding** — 11 coverage batches from spec 023 + 3 decomposition phases from spec 026 (agent crate +10.98pp). 1426 agent tests passing, patch coverage 72% on 7,300 changed lines.

### Fixed
- **Invalid-IP zombie ufw rules** — `response_lifecycle.register()` now rejects invalid targets before hydration; 8 previously-orphaned rules no longer recur.
- **Self-triggered DATA_EXFIL** — killchain now skips the agent's own threads (was producing 40+ self-incidents/day).
- **Kill chain persistence** — incidents now land in sqlite alongside jsonl; honeypot activity accepted as kill chain input.
- **Dashboard threat pivot** — unhidden pivot tabs, detector-pivot drill-down in `/api/journey`, entity population on sigma + crypto_miner incidents, live-feed `/api/live-feed/geoip` returns empty list on missing params instead of 400.
- **Telemetry monotonicity** — `gate_suppressed_total` + `telegram_sent_count` never decrement; `serde(default)` on new counters for backward compat.
- **Replay test expectation** — matches detector dedup reality.
- **Sensor host_drift** — test allowlist synced with detector.
- **Dependency** — `rand` 0.9.2 → 0.9.4 (GHSA unsoundness fix).

---

## [0.11.1] - 2026-04-14

### Added
- **Auto-calibration** — cloud VM detection via DMI (22 signatures), operator UID auto-detection, graph detector CalibrationContext. Eliminates ~1500 FPs/day on fresh installs.
- **Centralized notification gate** — single policy for ALL channels (Telegram, Slack, Webhook, Web Push). Only uncontained active intrusions notify immediately.
- **Burst summary** — 50+ auto-blocked threats/hour sends single "all handled" message instead of 50 alerts.
- **AbuseIPDB cache** — SQLite KV with 24h TTL + 800/day cap. Stops exhausting free tier.
- **GeoIP cache** — SQLite KV with 7-day TTL. Survives restarts.
- **notification_gate.rs** — 27 unit tests for notification policy rules.

### Changed
- **Event retention** — 8 days to 2 days for raw events.
- **Telegram rate limit** — MAX_ALERTS_PER_HOUR 30 → 10.
- **Dashboard toasts** — only uncontained CRITICAL/HIGH. Close button added. Click navigates to Threats tab.
- **Dashboard KPIs** — Home and Threats now use same data source for consistent numbers.

### Fixed
- **SQLite DB growth** — 1.8GB/day → ~80MB/day. High-volume events (tcp_stream.flow, process.exit, etc.) filtered from persistence.
- **AbuseIPDB daily exhaustion** — was using 1440 checks/day on free tier (limit 1000).
- **Honeypot notification spam** — probe-only sessions (0 commands, ≤2s) no longer notify.
- **Kill chain false positives** — allowlist for ruby, node, python, nginx, postgres (legitimate socket+dup).
- **Timing anomaly FPs on cloud** — z-score threshold 20 on VMs (was 4), eliminates I/O jitter noise.
- **Discovery burst FPs for operators** — trusted UIDs get 3x threshold.

---

## [0.11.0] - 2026-04-13

### Added
- **Unified SQLite Store** (Spec 016) — replaces 15 storage artifacts (JSONL files, redb, JSON snapshots) with a single `innerwarden.db` SQLite database. WAL mode for concurrent sensor+agent access.
- **New crate `crates/store/`** — 12 modules, 49 tests. Events, incidents, decisions tables + namespaced KV + graph snapshots + state blobs + cursor tracking.
- **Maintenance scheduler** — automated background tasks: WAL checkpoint (5min), incremental vacuum (hourly), retention cleanup, hash chain verification, integrity check (daily).
- **Legacy migration** — one-shot import on first startup. JSONL/redb/JSON files migrated to SQLite, originals archived to `legacy-archive/`.
- **TOTP QR code in terminal** — `innerwarden config 2fa` renders QR code as ASCII art. Secret never touches disk or logs.
- **SMM + Hypervisor as CTL subcommands** — `innerwarden system smm` and `innerwarden system hypervisor` integrated into the CLI.
- **Centered terminal screens** — install and welcome UX improvements.

### Changed
- **Sensor writes only to SQLite** — JSONL sink removed. No more daily file rotation, 1GB cap, or silent event drops.
- **Agent reads only from SQLite** — JSONL parser and byte-offset cursor removed. Rowid-based cursor tracking.
- **State store migrated from redb to SQLite KV** — 7 redb tables mapped to namespaced KV. Same public API, zero caller changes.
- **Graph snapshots in SQLite** — replaces JSON file rotation with database table. Load/save via `save_to_store()`/`load_from_store()`.
- **6 JSON state files migrated to SQLite blobs** — attacker profiles, campaigns, baseline, playbook log, threat feeds, responses.
- **DB file pre-created with 0664 permissions** — sensor (root) and agent (innerwarden) both write without permission conflicts.

### Removed
- **redb dependency** — replaced entirely by SQLite KV.
- **JsonlWriter** — replaced by SqliteWriter.
- **JSONL reader/parser** — replaced by SQLite rowid-based queries.
- **JSON snapshot rotation** — 3-backup rotation replaced by SQLite table with date-based retention.

### Fixed
- **Silent event drop compliance bug** (ISO 27001 A.12.4) — events at 1GB cap were silently dropped. Now returns explicit backpressure error.
- **6 CodeQL security alerts** resolved — path traversal sanitization, cleartext logging fixes.
- **Firewalld detection** — harden command now detects firewalld alongside UFW.
- **io_uring property test** — bun/deno/node added to allowlist (legitimate io_uring users).

### Security
- **Path traversal prevention** — `Store::open()` canonicalizes data_dir before any file operations.
- **TOTP secret handling** — QR code rendered in terminal only, never written to files or logs.

---

## [0.10.0] - 2026-04-08

### Added
- **Supervised defender brain with agreement tracking** (Feature 006) — brain observes every AI decision and logs agreement/disagreement. Foundation for online learning and AI override.
- **72-dimensional brain-log** — agent records enriched feature vectors to `brain-log.jsonl` for offline model retraining.
- **Autoencoder as decision signal** — converted from standalone detector to integrated decision signal in the agent pipeline.
- **Shield migrated into monorepo** — `innerwarden-shield` now lives as `crates/shield` in the workspace.
- **Dynamic operator IP protection** — active SSH sessions from trusted operators get session-based expiry protection; agent never auto-blocks the operator.
- **CTL restructured** — CLI reorganized from 40 flat commands to 8 intent-based groups (`get`, `stream`, `action`, `trust`, `config`, `system`, `module`, `agent`) for better discoverability. Old commands still work as aliases.

### Changed
- **Autoencoder trains on clean traffic only** — excludes blocked IPs from training data to prevent model poisoning.
- **Live feed uses rolling 24h window** — shows only real external attacks with attacker IP (today + yesterday).
- **Unified XDP blocklist** — shield and agent skill share one source of truth via `XdpManager`. IPv6 support added. XDP now covers 20 detectors (was 5).
- **Defender brain upgraded to V5 50M** — 3.1M training steps, [72→128→64→30] architecture, with daily retrain at 3:30 AM UTC from production decisions.
- **Cross-module correlation** — baseline anomalies, autoencoder scores, and shield escalation now feed the correlation engine. 4 new rules: CL-044 Silence After Compromise, CL-045 Coordinated Volume Attack, CL-046 Neural-Confirmed Attack, CL-047 Attacker IP Rotation.
- **Shield ↔ Attacker Intel bidirectional** — shield blocks enrich attacker profiles (risk score, block count); known high-risk IPs (risk > 60) get 2x tighter rate limits pre-emptively.
- **DNA Cross-IP tracking** — behavioral fingerprint index detects same attacker across different IPs (VPN/Tor rotation). Emits `dna.ip_rotation` correlation event. No other IDS does this.
- **Attacker intel risk scores in decision pipeline** — IPs with risk > 50 get confidence boost in AI triage, reducing latency and API costs for repeat offenders.
- **README fully updated** — all stats aligned (49 detectors, 47 correlation rules, 2361 tests), CLI examples use new command groups, architecture diagram corrected.
- **Website fully updated** — stats, CLI commands, meta tags, and SEO schema version aligned across 25 files.
- **GitHub About & Topics updated** — description includes 46 correlation rules + 65 MITRE techniques; added mitre-attack, behavioral-analysis, kill-chain topics.

### Fixed
- **Notification spam reduced** — 3 critical fixes: gate repeated alerts, suppress non-threat group summaries, rate-limit action reports.
- **Auto-block gates respect operator/trusted IPs** — prevents lockout during active management sessions.
- **Security: XSS in dashboard** — attacker IPs in onclick handlers now escaped via `esc()` function.
- **Security: russh 0.58→0.59** — removes vulnerable `libcrux-sha3` dependency.
- **CI stability** — flaky timing test ignored in CI, dead_code allows for BrainStats, clean deny.toml.

---

## [0.9.4] - 2026-04-06

### Added
- **Consolidated satellite modules into workspace** — killchain, dna, hypervisor, smm migrated from standalone repos to `crates/`. Single build, single CI, unified versioning.
- **Neural model advisory-only mode** — autoencoder observes and scores but never blocks or notifies. Safe ramp-up.
- **Operator IP protection** — never blocks active trusted SSH sessions (publickey detection).
- **AlphaZero defender brain embedded** — IWD1 binary (538KB) integrated as advisory decision signal with dashboard UI + FP audit + API endpoints.

### Changed
- **Dashboard UX overhaul** — defender brain panel, FP audit view, action config improvements.

### Fixed
- **Dashboard JS fixes** — duplicate `esc()` declaration, broken script tag in template literal, HTTP actions with auth.
- **eBPF connect/accept IP byte order** corrected.
- **Security: safe_write_data_file for brain-log** (CodeQL CWE-22 path traversal).
- **Dependencies updated** — fancy-regex 0.17, redb 4.0, redis 1.2, russh yanked version resolved.

---

## [0.9.3] - 2026-04-06

### Added
- **Immediate-threat gate for Telegram** — only real threats (reverse_shell, data_exfil, ransomware, privesc, lateral_movement, container_escape, web_shell, process_injection, fileless, c2_callback, credential_harvest, ssh_key_injection, kernel_module_load, log_tampering, dns_tunneling, persistence detectors) send immediate Telegram notifications. Routine detections (ssh_bruteforce, discovery_burst, port_scan, packet_flood) go to daily digest. Reduces ~70 notifications/day to ~1-3 real threats.
- **Daily notification budget** — configurable `telegram.daily_budget` (default: 10). Critical severity always breaks the budget. Counter resets daily.
- **Daily Security Briefing** — enriched digest with deferred incident breakdown showing what was handled silently overnight. Pre-configured at setup (9 AM, no extra steps).
- **CLI commands** — `innerwarden notify digest <hour|off>` and `innerwarden notify budget <max>` for post-setup tuning.
- **Neural incident pipeline fix** — autoencoder anomaly incidents now route through AgentState buffer instead of writing to sensor's file (was silently failing due to file permissions). 415 detections/day were being lost.
- **Correlated anomaly** (baseline + neural convergence) added to immediate threat list — always pings Telegram.
- **5 new correlation rules** (CL-036 to CL-040) from AlphaZero V4 self-play discoveries.

### Changed
- **Premium Telegram message quality** — all message formats rewritten: structured alerts with severity header + detector label + IP + action status; action reports with shield emoji and confidence line; daily digest as "Security Briefing"; group summaries with human-readable labels.
- **Neural anomaly messaging** — "Neural anomaly: 97% score" → "AI Spider Sense: highly unusual HTTP traffic — 97% anomaly" with training cycle context.
- **Group summaries gated** — non-threat group summaries no longer ping Telegram.
- **All Telegram send paths gated** — action reports (post-AI, obvious gate) and AbuseIPDB autoblock now check immediate-threat before sending.

### Fixed
- **Clippy warnings** — resolved all dead_code, derivable_impl, manual_range_contains, collapsible_if, too_many_arguments warnings.
- **Flaky test** — `execve_event_maps_to_shell_command_exec` used PID 1234 which collided with real CI processes.
- **Correlation rule count** — test assertion updated (35 → 40).

---

## [0.9.2] - 2026-04-03

### Added
- **Main branch catch-up with develop** — synchronized mainline with the latest development baseline (spec-driven artifacts, governance updates, and organization improvements) so stable releases include the full current platform state.

### Changed
- **CI license gate compatibility** — `cargo-deny` policy now explicitly allows `BUSL-1.1` for the `innerwarden-smm` dependency path to keep security checks green while preserving Apache-2.0 licensing for the core project.

### Fixed
- **Telegram triage test stability** — provider assertion updated to match operator identifier semantics, preventing false failures in the release test pipeline.

---

## [0.9.1] - 2026-04-03

### Changed
- **License opened to Apache 2.0** — project moved from BUSL-1.1 to Apache License 2.0 across repository metadata and Cargo package manifests.
- **Documentation and metadata refresh** — updated README license badge/section, governance references, and release collateral to keep licensing and project messaging fully consistent.

---

## [0.9.0] - 2026-04-03

### Changed
- **Large internal modularization (agent + ctl)** — extracted decision flows, narrative pipeline, honeypot runtime, incident processing, and command handlers into focused modules. This keeps behavior stable while making future development and debugging significantly easier.
- **Spec-driven artifacts added to repository workflow** — feature specs/plans/tasks now tracked under `.specify/features/` to keep implementation aligned with product intent.

### Fixed
- **ATR rule compatibility on production hosts** — rule loader now accepts mixed YAML shapes for `tags`/`references` (map, list, string) and supports regex patterns with look-around/backreferences via `fancy-regex` fallback.
- **Doctor accuracy for protected configs** — config checks now distinguish “permission denied” from “file missing” so diagnostics are correct on hardened servers.
- **Doctor sudo-protection check** — corrected expected sudoers drop-in name (`innerwarden-suspend-user`), eliminating false warning when capability is properly enabled.

---

## [0.8.5] - 2026-04-02

### Added
- **`innerwarden daily`** — simplified command group for day-to-day operations (aliases: `quick`, `day`). Subcommands: `status`, `threats`, `actions`, `report`, `doctor`, `test`, `agent`.
- **`innerwarden configure 2fa`** — TOTP wizard (Google Authenticator, Authy, 1Password). Protects allowlist changes, mode switches, and detector disable. Brute force protection: lockout after 3 failures/hour.
- **Telegram triage v2** — allowlist and false positive reporting directly from phone. `/undo` shows last 10 allowlist additions with Remove buttons. Auto-learn: after 3+ same-pattern FP reports, suggests permanent allowlist via Telegram.

### Changed
- **`agent connect` PID is now optional** — auto-detects running agents, connects automatically when one is found, shows guided selection for multiple. New `--name` flag to match by process name.
- **Setup wizard redesigned** — 4 clean steps (Experience, AI, Alerts, Protection) with pre-configured safe defaults and review screen before applying.
- **Dashboard scroll** — page now scrolls instead of cramming content into fixed height.

### Fixed
- **CWE-312 cleartext logging** — Telegram operator first_name (PII) was persisted in cleartext to `decisions-*.jsonl` and `allowlist-history.jsonl`. Replaced with static channel identifier across all 12 occurrences.
- **Security hardening defaults** — dashboard now binds localhost only, insecure HTTP guard added, sensitive URLs redacted from logs.
- **redb 2 → 3** — attacker profile database upgraded to redb 3.1.1.

---

## [0.8.3] - 2026-04-02

### Added
- **Autoencoder anomaly detection** — neural engine learns "what is normal" for each host. 48-feature sliding window, nightly training at 3 AM UTC, maturity-weighted scoring. Replaces V10 classifier.
- **208 Sigma community rules** — imported from SigmaHQ (120 process_creation, 53 auditd, 22 builtin, 8 file_event, 5 network). Field aliasing for eBPF events.
- **ATT&CK Navigator export** — `innerwarden navigator` generates JSON layer for MITRE Navigator visualization. 65 technique IDs mapped.
- **Steganography detection** — 4 LSB steganalysis detectors (Chi-Square, RS, SPA, Primary Sets) with fusion scoring.
- **Cloud provider IP safelist** — prevents auto-blocking Google, AWS, Azure, Oracle, Cloudflare, DigitalOcean, Hetzner IPs (~80 CIDR ranges).
- **Dynamic allowlist** — `/etc/innerwarden/allowlist.toml` for runtime configuration without rebuild. Supports processes, IPs, CIDRs, ports, DNS domains, per-detector suppressions, sigma rule suppression.
- **Telegram alert batching** — groups repeated same-detector alerts into periodic summaries (60s window). First occurrence immediate, repeats batched. Critical always immediate.
- **Deploy script** — `scripts/deploy-prod.sh [sensor|agent|ctl|all]` for one-command production deploys.
- **Canary release channel** — GitHub Actions workflow builds on every develop push, publishes as pre-release.
- **MITRE hunt detector** — 6 new checks: destructive dd (T1485), private key search (T1552.004), suspicious archive (T1560), logging config change (T1562.006), prctl rename (T1036.004), hidden artifacts.

### Changed
- **Setup wizard redesigned** — 3 clean steps (AI, Telegram, Responder) instead of 6. Modules and sensitivity auto-configured.
- **Full argv capture** — eBPF exec events now read full argv from /proc/PID/cmdline instead of just argv[0].
- **Sigma rule engine rewrite** — supports multiple named selections, filters, `|contains|all` modifier, YAML list values.
- **MITRE coverage expanded** — 42 → 65 unique technique IDs via mitre_hunt + multi-technique mapping.

### Fixed
- **15+ false positive sources eliminated** — build tools (cc, ld, cargo), CrowdSec (cscli DNS, http /etc/passwd), Node.js (node→sh), admin deploys (service_stop, discovery_burst uid=0), cloud metadata (254.169.254.169), CDN domains, InnerWarden PAM reads, .git/ paths, profile.d reads.
- **Sigma rules suppression** — noisy rules (Inline Python Execution, Shell Pipe to Shell) suppressed. Dynamic suppression via allowlist.toml.
- **CodeQL CWE-22** — path traversal in threat_report.rs month parameter.

---

## [0.8.1] - 2026-03-31

### Added
- **20 automated response playbooks** — every detector now has a corresponding response path. 14 new playbooks: timestomp, log tampering, privilege escalation (kill + suspend sudo), kernel module load (isolate + escalate), process injection, SSH key injection, crontab persistence, systemd persistence, container escape (block container + isolate), crypto miner (kill + block pool), DNS tunneling, lateral movement (isolate + escalate), web shell (kill + quarantine), discovery burst (forensics + notify).
- **Centralized allowlists** — runtime-security allowlists module (`allowlists.rs`) with ~200 entries across 8 categories: SYSTEM_DAEMONS, PACKAGE_MANAGERS, LOGIN_BINARIES, DISCOVERY_ALLOWED, SENSITIVE_FILE_READERS, TRUNCATE_ALLOWED, PRIVESC_ALLOWED, C2_OUTBOUND_ALLOWED. All detectors reference centralized lists instead of ad-hoc exceptions.

### Fixed
- **Neural V10 scoring disabled** — classifier generates false positives on Cloudflare, WordPress, and Docker production traffic. Disabled until replaced by per-host autoencoder anomaly detection.
- **Privilege escalation FP** — InnerWarden's own tokio runtime threads (uid 998) no longer trigger privesc detector. Kernel truncates thread names to 16 chars producing unpredictable substrings.
- **Sigma rule self-detection** — SIGMA-004 (shadow/passwd access) no longer fires when the sensor reads /etc/shadow for integrity verification. Global exclusion for innerwarden uid + sensitive file reader allowlist.
- **C2 callback FP** — agent's outbound HTTP requests (AbuseIPDB, GeoIP, CrowdSec) no longer trigger C2 beaconing detector. Allowlist covers innerwarden, cloud agents, monitoring tools, web servers.
- **Discovery burst FP** — bpftool (kernel integrity collector), Ubuntu MOTD scripts (00-header, run-parts), and admin tools (cargo, git, journalctl) added to allowlist. Cooldown increased from 5 min to 30 min.
- **Truncate event noise** — expanded allowlist for system daemons (irqbalance, ufw, fail2ban, landscape, tokio-rt-worker).

### Security
- Red team re-validated with allowlists: **41/42 MITRE techniques detected (98%)** — zero blind spots introduced by allowlists.

---

## [0.8.0] - 2026-03-31

### Added
- **eBPF timestomp detection** — kprobe on `vfs_utimes` detects file timestamp manipulation (MITRE T1070.006). Catches `touch -t`, `touch -r`, `utimensat` syscall.
- **eBPF log truncation detection** — kprobe on `do_truncate` detects log file truncation (MITRE T1070.003). Catches `truncate -s 0`, shell redirects (`> /var/log/syslog`).
- **Defense evasion detectors** — userspace patterns for timestomp (`touch -t`, `touch -d`, `touch -r`), log tampering (truncate/clear), LD_PRELOAD injection, history clearing, process injection via ptrace.
- **Discovery burst detector** — alerts on 5+ reconnaissance commands (ps, id, whoami, ss, cat /etc/passwd, etc.) from same user within 60 seconds. Catches MITRE T1087, T1082, T1016, T1049, T1057.

### Changed
- **Detection rate** — 86% → **95%** (42/42 MITRE ATT&CK techniques detected in red team).
- **eBPF hooks** — 38 active → **40 active** (timestomp + truncate kprobes fixed).
- **Tests** — 1,548 → **1,798** passing.
- **Neural scoring** — V10 classifier **disabled** in production. Generates false positives on WordPress/Docker/Cloudflare traffic. Will be replaced by per-host autoencoder anomaly detection in future release. Rules + kill chain + 48 detectors provide 95% detection without ML.
- **Discovery burst cooldown** — 5 min → 30 min. Expanded allowlist: cargo, git, journalctl, systemctl, landscape, apt-check.

### Fixed
- **eBPF verifier rejection** — utimensat/truncate kprobes were rejected by BPF verifier due to `?` operator after `EVENTS.reserve()` leaking ring buffer reference (Aya's `RingBufEntry` has no `Drop` impl). Fixed by using `if let Ok(comm)` pattern, `#[inline(always)]`, and mutable reference instead of raw pointer dereference.
- **Privilege escalation false positives** — innerwarden's own tokio runtime threads (truncated comm: "en-agent", "rden-dna", "illchain", "n-shield") were detected as privilege escalation. Fixed by filtering service uid 998.
- **Truncate event noise** — system daemons (systemd-journal, logrotate, rsyslogd, irqbalance, ufw, fail2ban, sshd, tokio-rt-worker, landscape) filtered from truncate/timestomp events. Non-root truncate always alerts.
- **Stale loader comments** — eBPF syscall collector comments updated to match current kprobe attribute usage.

---

## [0.7.0] - 2026-03-29

### Added
- **Native DNS capture** — AF_PACKET raw socket on UDP:53. Parses domain + query type. Feeds dns_tunneling detector. No external IDS dependency.
- **Native HTTP capture** — AF_PACKET on TCP:80/8080/8443/8787/3000/5000/9090. Parses method/path/Host/User-Agent. Feeds web_scan + user_agent_scanner.
- **TLS fingerprinting** — captures ClientHello, computes JA3 (MD5) and JA4. 10 known malicious fingerprints (Cobalt Strike, Metasploit, Emotet, etc.).
- **Neural scoring model V10** — trained on 2.1M production events, 94.6% F1 cross-validated. 58KB model, microsecond inference.
- **Monthly threat report** — auto-generated on 1st of each month. Top attackers, MITRE heatmap, campaigns, trends.
- **Pcap capture** — selective packet capture on High/Critical incidents. Spawns tcpdump for 60s per attacker IP.

### Changed
- **Correlation rules** — 23 → 30 (4 gym-discovered + 3 red team gaps).
- **Detectors** — 40 → 48 (dns_tunneling, data_exfil_ebpf, discovery_burst, + others).

---

## [0.6.0] - 2026-03-28

### Added
- **Agent Guard** — new `innerwarden-agent-guard` crate for AI agent protection. Auto-detects agents (OpenClaw, ZeroClaw, Claude Code, Aider, Cursor, +15 more), monitors tool calls, blocks credential exposure and data exfiltration. Three-layer defense: warn → shadow → kill.
- **Agent Guard CLI** — `innerwarden agent add/scan/connect/status/list` commands for managing AI agents on the server. Interactive menu, guided install, auto-detection via `/proc` scan.
- **Agent Guard API** — `POST /api/agent-guard/connect`, `GET /api/agent-guard/agents`, `POST /api/agent-guard/disconnect`. Agents self-register with InnerWarden and receive policy + check-command URL.
- **Sensitive path write protection** — LSM hook on `security_file_open` blocks unauthorized writes to `/etc/shadow`, `sudoers`, `authorized_keys`, `crontab`, `systemd units`, `ld.so.preload`, `PAM`. Observe by default, block in guard mode (`LSM_POLICY` key 1).
- **io_uring monitoring** — eBPF tracepoints on `io_uring_submit_sqe`/`io_uring_submit_req` + `io_uring_create`. Closes the biggest blind spot in eBPF security (io_uring bypasses syscall monitoring). Alerts on CONNECT, ACCEPT, OPENAT, URING_CMD. Handles kernel 6.4+ rename.
- **Container drift detection** — eBPF overlayfs upper-layer check at execve (`__upperdentry` at `inode_ptr + sizeof(struct inode)`). Detects binaries dropped after container start. `INODE_SIZE` map populated from kernel BTF at runtime.
- **Host drift detection** — flags execution from non-standard paths (`/tmp`, `/dev/shm`, `/var/www`). Trusted path allowlist, package manager awareness.
- **Capability-based guard mode** — 10 capability bits (`CAP_WRITE_CREDENTIALS`, `CAP_WRITE_SSH`, `CAP_IO_URING`, etc.) in `CGROUP_CAPABILITIES` and `COMM_CAPABILITIES` BPF maps. Per-cgroup and per-process fine-grained permissions replace hardcoded allowlists.
- **ISO 27001 A.13.2** — Information transfer control added. Dashboard now shows 13 controls (was 12).
- **Telegram dev mode** — `dev_mode = true` adds "Check FP" button to every notification. Logs flagged incidents to `fp-review.jsonl` for detector tuning.
- **Property-based tests** — 12 proptest invariants across all 4 new detectors via `proptest` crate.

### Changed
- **Dashboard UX overhaul** — integration cards grouped into 5 collapsible categories (Core, Kernel Hardening, Alerts, Threat Intel, External). Top Action widget surfaces most urgent incidents. Collectors split into active/available. Compliance progress bar with actionable items. Report hero KPIs. Journey TL;DR narrative. Threats panel widened to 380px with search feedback.
- **Default `allowed_skills`** — now includes all block backends (iptables, nftables, pf), not just ufw.
- **Detector count** — 36 → 40 detectors (sensitive_write, io_uring_anomaly, container_drift, host_drift).
- **eBPF hooks** — 22 → 25 hooks (io_uring_submit, io_uring_create, LSM file_open).

### Fixed
- Rate anomaly empty IP — packet_flood detector tracks per-IP connection counts; top offending IP reported instead of empty string.
- Block skill failures — AI parser rejects empty IPs in fallback path. `execute_decision` logs actual failure reason instead of misleading "no block skill available".
- macOS install — `BASH_SOURCE[0]` removed from curl-piped path, `NEXT_GID` scoping on re-install, exact dscl grep matches, quoted install variables.
- 16 pre-existing clippy warnings fixed (exposed by new `lib.rs` target).
- C2 allowlist — web servers and databases no longer trigger false C2 callback alerts.
- Ollama local detection in `innerwarden setup` + macOS config path fix.

---

## [0.5.3] - 2026-03-28

### Fixed
- **macOS install** - `BASH_SOURCE[0]` is unavailable when piping install.sh from curl; macOS now creates the `innerwarden` group via dscl before the user; binaries installed with group `wheel` instead of `root`. Fix NEXT_GID scoping on re-install, exact dscl grep matches, quoted variables. (PR #35 by @aya + follow-up)
- **Rate anomaly empty IP** - packet_flood detector now tracks per-IP connection counts in each minute bucket. Rate anomaly incidents report the top offending IP instead of empty string, eliminating repeat-offender noise with no actionable IP.
- **Block skill failures** - AI parser fallback path (`block-ip-*` skill IDs) now rejects empty IPs instead of passing them through. `execute_decision` early-rejects empty IPs and logs actual failure reason when firewall skill execution fails (was misleading "no block skill available").
- **Default allowed_skills** - all block backends (iptables, nftables, pf) now included in default whitelist, not just ufw. Users overriding `block_backend` no longer silently fall out of the allowed list.
- **C2 allowlist** - web servers (nginx, apache, caddy, traefik, haproxy, envoy) and databases (postgres, mysql, redis, mongodb) added to C2 callback allowlist to prevent false positives on outbound connections.
- **Ollama local detection** - `innerwarden setup` now detects local Ollama instances correctly; macOS config path uses `~/.config/innerwarden/` instead of `/etc/innerwarden/`.
- **Memory badge** - sensor 55MB + agent 26MB confirmed under 100MB badge threshold.

---

## [0.5.2] - 2026-03-27

### Fixed
- **C2 callback: gomon on port 443** - monitoring processes (gomon, prometheus, telegraf) were skipped only for non-C2 ports. Port 443 (HTTPS) is in the C2 port list, so regular HTTPS health checks from monitors triggered beaconing alerts. Now verified infra processes are skipped from all C2 checks (beaconing, exfil, port). Binary path verification via `/proc/PID/exe` prevents evasion.
- **user_creation: NSS cache hooks** - `usermod` invokes `/usr/sbin/nscd` and `/usr/sbin/sss_cache` as NSS cache invalidation hooks after user modifications. These were detected as suspicious user management commands. Now skipped when the command target is a known system utility path.
- **README** - architecture diagram updated: 19 tracepoints (was 18), 1 kprobe (was 2), kill chain 8 patterns shown in LSM box, mesh network box added, 12 skills listed. Skills table includes kill-chain-response.

---

## [0.5.1] - 2026-03-27

### Added
- **Kill chain pipeline E2E** - sensor now creates Critical incidents from `lsm.exec_blocked` events (was only emitting events, agent never saw them). Full pipeline tested: kill chain trigger to sensor incident to AI triage (Feynman 0.95) to Telegram notification.
- **Agent auto-enable LSM** - `should_auto_enable_lsm()` correctly triggers on kill chain incidents. Fixed `Path::exists()` pre-check that failed without root (agent runs as `innerwarden` user). Added sudoers for `innerwarden` user to run bpftool.
- **`AiAction::KillChainResponse`** - new AI action variant for the kill-chain-response skill. AI parser now recognizes `kill-chain-response` and `block-ip-*` skill IDs (was defaulting to Ignore).
- **Mesh broadcast on block** - when the agent blocks an IP (via AI decision), it broadcasts to mesh peers (Layer 2.5 in the layered block). Previously mesh signals only came from test nodes.
- **Mesh peer discovery** - agent now calls `discover_peers()` on startup and `rediscover_if_needed()` on each mesh tick. Nodes that weren't up during initial discovery are found later.
- **Verified infra allowlist** - `is_verified_infra_process()` helper checks `/proc/PID/exe` binary path. Prevents evasion by renaming a malicious binary to "crowdsec" or "nginx". Only allows processes from `/usr/`, `/opt/`, `/snap/`, `/bin/`, `/sbin/`.
- **Mesh tick logging** - agent logs `mesh tick staged=N new_blocks=N` on each mesh tick for observability.

### Fixed
- **Kill chain: 5 handlers chain_flag ordering** - bind, listen, ptrace, mprotect, and openat set chain flags AFTER noise filters, allowing allowlisted processes to evade detection. Fixed: move chain_flag BEFORE `is_comm_allowed`/`is_cgroup_allowed`.
- **Kill chain: `bpf_probe_read_user_str_bytes` on sockaddr_in** - string-read helper stops at null bytes in binary struct (sockaddr_in family 0x0002 has null second byte). Port/addr always read as 0. Fixed: use `bpf_probe_read_user`.
- **Kill chain: dup2/dup3 fallback on aarch64** - dup2 syscall doesn't exist on aarch64, need dup3 fallback. Server code was missing the fallback.
- **Sensor pin management** - `map.pin()` fails with EEXIST when old pin from previous sensor instance exists. Fixed: `remove_file()` before `pin()` for LSM_POLICY, blocklist, and allowlist maps.
- **AbuseIPDB auto-block: ghost blocks** - the auto-block inserted IP into `state.blocklist` BEFORE `execute_decision()`. If the block failed (XDP map missing, ufw error), the IP was still marked as "blocked", causing the AI gate to skip all future detections. Real attacker 144.31.137.41 exploited this. Fixed: insert AFTER execution, verify result.
- **Mesh peer dedup** - config peers with empty `public_key` matched `""==""`, causing only the first peer to be added. Fixed: dedup by endpoint instead of node_id.
- **False positives eliminated:**
  - `fileless:runc` (15+/2h) - Docker container runtimes (runc, crun, containerd-shim) legitimately execute from memfd.
  - `privesc:(en-agent)` (6/2h) - innerwarden agent/sensor added to LEGITIMATE_ESCALATION with starts_with matching.
  - `outbound_anomaly:nginx` - reverse proxies (nginx, haproxy, envoy, caddy, traefik) and monitors excluded.
  - `dns_tunneling:crowdsec` - CrowdSec, gomon, systemd-resolved excluded from eBPF DNS checks.
  - `c2_callback:gomon` - monitoring processes excluded from beaconing/exfil checks.
  - `c2_callback:169.254.169.254` - cloud metadata service (Oracle/AWS/GCP) excluded.
  - `c2_callback:port 0` - DNS resolution artifacts excluded.
  - `privesc:fwupdmgr` - firmware update manager added to legitimate escalation list.

### Changed
- **Mesh crate updated** to `bed8512` (periodic re-discovery, peer dedup by endpoint, rediscover_if_needed in example).
- **innerwarden-mesh** - 3 bug fix releases: discover_peers, peer dedup, example rediscovery.

---

## [0.5.0] - 2026-03-27

### Added
- **Kill chain integration** — kernel-detected attack patterns now flow into the full agent pipeline. AI receives `KILL CHAIN INTELLIGENCE` section in prompts with pattern name, C2 IP, process details, and syscall timeline. Dramatically increases response confidence.
- **Kill chain response skill** — new `kill-chain-response` atomic skill: kills process tree, blocks C2 IP via XDP, captures forensics (`ss`, `/proc` snapshot) in a single action.
- **DATA_EXFIL pattern (8th kill chain pattern)** — new `CHAIN_SENSITIVE_READ` bit flag (bit 8) set when `openat` accesses `/etc/shadow`, `.ssh/`, `.aws/`, credential files. Combined with `CHAIN_SOCKET`, detects data exfiltration without `execve`.
- **IPv6 XDP wire-speed blocking** — new `BLOCKLIST_V6` and `ALLOWLIST_V6` BPF HashMaps with 16-byte keys. XDP program now parses both EtherType `0x0800` (IPv4) and `0x86DD` (IPv6). `block-ip-xdp` skill auto-detects IP version.
- **EFI Runtime Services kprobe (EXPERIMENTAL)** — observational kprobe on `efi_call_rts` to establish firmware behavioral baseline. Monitors UEFI Runtime Services calls (GetVariable, SetVariable, GetTime). Tagged as experimental in all events.
- **Kill chain metrics in dashboard** — `/api/status` includes `kill_chain` counters (total blocked, pre-chain, per-pattern). Dashboard shows Kill Chain integration card with live stats.
- **Kill chain timeline visualization** — incidents with kill chain evidence render as visual timelines showing the syscall sequence with blocked steps highlighted in red.

### Fixed
- **Telegram 4096-char message limit** — all message types now enforced with 4000-char hard limit before POST. Prevents silent message rejection by Telegram API.
- **Telegram rate limiting** — 50ms minimum gap between sends (~20 msg/sec), prevents 429 errors during incident bursts.
- **Telegram bot token in logs** — all log output now sanitizes the bot token from API URLs (`***REDACTED***`).
- **Telegram callback IP validation** — `quick:block:` callbacks validate IP format before processing. Rejects malformed input.
- **Telegram config validation** — startup now validates `bot_token`, `chat_id` are set when enabled, and `daily_summary_hour` is 0-23. Fails fast on misconfiguration.
- **Daily digest truncation** — lowered from 3800 to 3500 chars to account for HTML escaping expansion.

### Changed
- 8 kill chain patterns (was 7): reverse shell, bind shell, code inject, exploit-to-shell, inject-to-shell, exploit-to-C2, full exploit, **data exfiltration**.
- 9 monitored syscall bit flags (was 8): added `CHAIN_SENSITIVE_READ`.
- `block_backend` default recommendation changed to `"xdp"` for wire-speed blocking.
- Skill registry now has 12 skills (was 11): added `kill-chain-response`.

---

## [0.4.5] - 2026-03-26

### Added
- **Dashboard overhaul** - comprehensive update to the embedded SPA dashboard.
- **15 sensor collectors** - added 5 missing collectors to the Sensors HUD: syslog_firewall (iptables/nftables DROP logs), firmware_integrity (UEFI/EFI monitoring), cloudtrail (AWS CloudTrail), macos_log (macOS unified log), and a legacy runtime-security log source.
- **20 integration cards** - added 5 missing cards: Mesh Network (collaborative defense), Web Push (browser notifications), Fail2ban Sync (jail management), Shield DDoS (packet flood + Cloudflare), Threat DNA (attacker fingerprinting). Integration Advisor now recommends Mesh.
- **ISO 27001 control mapping** - Compliance tab maps 12 ISO 27001 Annex A controls to current config state (A.5.1 through A.18.2), showing which controls are met and what to enable.
- **SHA-256 hash chain verification** - Compliance tab verifies the integrity of the decision audit trail hash chain in real time, showing chain length, last hash, and intact/broken status.
- **Data retention policy display** - Compliance tab shows configured retention periods for events (7d), incidents (30d), decisions (90d), telemetry (14d), and reports (30d) with GDPR export/erase commands.
- **Version badge** - dashboard header shows current version from CARGO_PKG_VERSION. Also exposed in `/api/action/config` and `/api/status` responses.
- **`/api/compliance` endpoint** - returns hash chain verification, retention config, and ISO 27001 control checklist in a single call.
- **eBPF description corrected** - collector HUD now shows "22 kernel hooks (19 tracepoints + kprobe + LSM + XDP)" instead of the outdated "6 kernel programs".
- **Expanded `/api/status`** - includes mesh, web_push, shield, dna integration states, data retention config, and version.

### Changed
- **DashboardActionConfig** - added fields for mesh_enabled, web_push_enabled, shield_enabled, dna_enabled, and retention config (events/incidents/decisions/telemetry/reports days).
- **Compliance tab redesign** - replaced Advisory Cache and Audit Trail KPIs with ISO 27001 score and Hash Chain status. Added 3 new sections (hash chain, retention, ISO controls) above the existing admin actions, advisories, and sessions.
- **Compliance data loading** - all compliance data (admin actions, advisories, sessions, compliance API) loaded in parallel via `Promise.all`.
- **Sensor color palette** - added colors for syslog_firewall, firmware_integrity, macos_log, and legacy runtime-security sources in timeline charts.

---

## [0.4.4] - 2026-03-25

### Added
- **Trusted Advisor model** - new `POST /api/advisor/check-command` endpoint tracks advisory recommendations with `advisory_id`. When an AI agent ignores a deny and executes the command, Inner Warden detects it via eBPF/auditd and notifies the server owner via Telegram.
- **Admin action audit log** - hash-chained `admin-actions-YYYY-MM-DD.jsonl` records every CLI and dashboard admin action (enable, disable, configure, block, allowlist, mesh) with operator identity and parameters.
- **Session-based authentication** - `POST /api/auth/login` returns a Bearer token. Configurable timeout (default 8h) and max concurrent sessions (default 5). Login/logout audited.
- **GDPR data subject commands** - `innerwarden gdpr export --entity <ip-or-user>` and `innerwarden gdpr erase --entity <ip-or-user>` with hash chain recomputation after erasure.
- **Privacy documentation** - `docs/privacy.md` with data categories, third-party flows, retention schedule, and data subject rights.
- **GitHub Wiki** - all documentation moved to Wiki as single source of truth. `docs/` folder now redirects to Wiki.

### Changed
- **Documentation consolidation** - replaced 10 docs/ markdown files with a single redirect to the GitHub Wiki. Images preserved.
- **OpenClaw skill rewritten** - uses `INNERWARDEN_DASHBOARD_TOKEN` env var (not interactive passwords), explicit privilege approval rules, passes ClawHub security scan.
- **All em-dashes removed** - replaced with hyphens, commas, or periods across the entire codebase (181 files), Wiki (8 files), and site (6 files).

### Fixed
- **GitHub Actions pinned** - validate-modules.yml and stale.yml actions pinned to SHA (was using tags).
- **sensor-ebpf version** - bumped from 0.3.0 to 0.4.4 (was out of sync with workspace).
- **.gitignore** - added `crates/sensor-ebpf/target/`, removed duplicate `.claude/` entry.

---

## [0.4.3] - 2026-03-25

### Security

- **eBPF parser hardening** - replaced 69 `.try_into().unwrap()` calls in ring buffer parsing with safe macros that continue on malformed events instead of crashing the sensor.
- **Sudoers TOCTOU fix** - replaced predictable `/tmp/innerwarden-sudoers-<PID>` with `tempfile::Builder` (exclusive create, random suffix).
- **Sudoers wildcard constraints** - narrowed `*` wildcards in sudoers rules to `/tmp/innerwarden-*` and `/etc/sudoers.d/innerwarden-*` paths only.
- **Sudoers filename validation** - `SudoersDropIn::path()` now rejects names containing `/`, `..`, or special characters.
- **Dashboard X-Forwarded-For** - proxy headers only trusted when connecting IP is in `dashboard.trusted_proxies` config (default: empty, trust nothing).
- **AI provider HTTPS enforcement** - `http://` base URLs rejected for remote hosts (allowed only for localhost/127.0.0.1/::1).
- **Config file permission warning** - agent warns on startup if `agent.toml` is readable by group/other users.
- **Honeypot handoff injection fix** - replaced `{target_ip}` placeholder expansion in command args with environment variables (`INNERWARDEN_SESSION_ID`, `INNERWARDEN_TARGET_IP`, etc.).
- **Honeypot allowlist path traversal fix** - `is_command_allowed()` now uses `fs::canonicalize()` to resolve symlinks and `../` before matching.
- **Supply chain: pin innerwarden-mesh** - dependency pinned to commit hash instead of branch master.
- **CTL temp file hardening** - all `/tmp/innerwarden-*` paths in CTL replaced with `tempfile::Builder`.
- **Dashboard security headers** - `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: strict-origin-when-cross-origin` on all responses.
- **SSE connection limit** - max 50 concurrent SSE streams, returns 429 on overflow.
- **Event size enforcement** - JSONL sink skips events exceeding 16KB with a warning.

### Fixed

- **Live feed filter typo** - `(imesyncd)` → `(timesyncd)` in system daemon privesc filter.
- **cargo fmt** - trailing whitespace in dashboard.rs that broke CI.

### Changed

- **README overhaul** - full ASCII architecture diagram, eBPF/detector count badges, all em-dashes removed, warning moved to disclaimer section.

---

## [0.4.2] - 2026-03-25

### Added
- **Firmware & boot integrity collector** - monitors ESP binaries, UEFI variables (SecureBoot, DBX, PK, KEK), ACPI tables, DMI/SMBIOS, and kernel tainted flag every 5 minutes. Detects BlackLotus, LoJax, MosaicRegressor, ACPI rootkits. Based on Peacock (arxiv:2601.07402) and UEFI Memory Forensics (arxiv:2501.16962).
- **Firmware & boot hardening checks** - `innerwarden harden` now checks Secure Boot status, kernel tainted flags, TPM presence, boot loader permissions, IOMMU, and kernel lockdown mode.
- **redb persistent state store** - agent state (cooldowns, block counts) stored in embedded database instead of unbounded HashMaps. Heap stays stable regardless of attack volume.
- **eBPF bytecode embedded in sensor binary** - `include_bytes!()` bakes the 54KB bytecode into the sensor. Single binary deploy, `innerwarden upgrade` updates everything.
- **Shield → Telegram notifications** - escalation/de-escalation events sent to Telegram with state, drops/sec, attacker count, Cloudflare proxy status.
- **Shield → JSONL incidents** - escalation events written to incidents file for live feed visibility.
- **Live feed shows all incidents** - removed IP-only filter, now displays Shield escalations, privilege escalation, rootkit indicators, and all detector types.
- **CLI improvements** - `innerwarden list` shows full system coverage (22 hooks, 36 detectors), `innerwarden status <IP>` searches incidents, `innerwarden test` shows injected incident details.

### Fixed
- **Shield warmup** - ignores first 10 seconds of backlog to prevent false escalation on boot.
- **Live feed internal filter** - hides Inner Warden's own privilege escalation (agent/shield/sensor doing setuid for skills).
- **Unused imports** in firmware_integrity collector.

### Changed
- **3 HashMaps migrated to redb** - decision_cooldowns, notification_cooldowns, block_counts now persistent and bounded.

---

## [0.4.1] - 2026-03-25

### eBPF v2

- **22 kernel hooks** (was 7) - added ptrace, setuid, bind, mount, memfd_create, init_module, dup2, listen, mprotect, clone, unlinkat, renameat2, kill, prctl, accept4
- **Kill chain detection** - 7 patterns blocked at kernel level (reverse shell, bind shell, code injection, 4 zero-day patterns)
- **Kernel-level noise filters** - COMM_ALLOWLIST (137 processes from production rulesets), CGROUP_ALLOWLIST, PID_RATE_LIMIT, PID_CHAIN
- **Ring buffer epoll wakeup** - microsecond latency (was 100ms polling)
- **CO-RE/BTF portability** - any kernel 5.8+
- **Tail call dispatcher** via ProgramArray
- **Ring buffer increased** 256KB → 1MB

### Infrastructure

- **Redis Streams integration** - optional event transport replacing JSONL for events
- **DNA engine deployed to production** - behavioral fingerprinting + attack chains + anomaly detection
- **Shield deployed to production** - DDoS protection, XDP blocking active
- **Cloudflare auto-failover** - configured and tested
- **Shield adaptive kernel defense** - tightens PID_RATE_LIMIT and XDP BLOCKLIST on escalation

### Fixes

- **Ransomware false positives** - allowlist for compilers and package managers
- **clippy if_same_then_else** in ransomware severity logic
- **CodeQL CWE-22** - path traversal fixes (canonicalize paths)
- **russh 0.57→0.58** - libcrux-sha3 vulnerability
- **gitleaks CI** pinned to v8.24.0
- **Shield ingestor** - parse IP from details/entities (was expecting source_ip field)

### UX

- **Professional personality messages** on live feed
- **Telegram messages cleaned up** - no aggressive language
- **Site disclaimer updated**
- **Auto-scroll removed** from live feed

---

## [0.4.0] - 2026-03-23

### New detectors
- **Fileless malware** - detects execution via memfd_create, /proc/self/fd, deleted binaries
- **Log tampering** - detects unauthorized access to auth.log, syslog, wtmp, btmp
- **DNS tunneling** - Shannon entropy analysis on subdomains + eBPF fallback for port 53 beaconing (works without external IDS)
- **Lateral movement** - detects internal SSH scanning, port scanning, and sensitive service probing on private networks

### Agent improvements
- **Adaptive blocking** - repeat offenders get escalating TTL (1h → 4h → 24h → 7d)
- **Local IP reputation** - per-IP scoring persisted to disk, exposed in live-feed API
- **Automated forensics** - captures /proc/{pid}/ data (cmdline, exe, fds, network, memory maps) on High/Critical incidents with PID
- **Configurable AI gate** - `ai.min_severity` setting: "high" (default, conservative) or "medium" (aggressive, more API calls)
- **Honeypot always-on mode** - SSH honeypot with AI-powered fake shell, accepts password auth to lure attackers
- **Live feed API** - real daily totals (total_today, total_blocked, total_high), honeypot sessions endpoint, server-side GeoIP proxy

### Hardening advisor
- **TLS/SSL check** - audits nginx, apache, and OpenSSL configs for deprecated protocols, weak ciphers, missing HSTS
- **Crontab audit** - scans for suspicious entries (download+execute, reverse shells, base64)
- **Kernel modules** - detects known rootkits (diamorphine, reptile, etc)
- **Accepted risks** - `/etc/innerwarden/harden-ignore.toml` for environment-specific exceptions
- **Accuracy fixes** - excludes Inner Warden/Docker services from findings, uses `sudo ufw status verbose`

### Security fixes
- Path validation for ip-reputation and sensors API (CodeQL CWE-22 #37, #38)

---

## [0.3.1] - 2026-03-22

### Hardening advisor + live threat feed

- **`innerwarden harden`** - security hardening advisor that scans SSH, firewall, kernel params, file permissions, pending updates, Docker config, and exposed services. Prints actionable fix commands with severity scoring (0-100). Advisory only - never applies changes.
- **Live threat feed API** - public `/api/live-feed` and `/api/live-feed/stream` (SSE) endpoints with CORS for real-time incident display on external sites. Includes `/api/live-feed/geoip` proxy for server-side GeoIP batch lookups.
- **Dashboard bind fix** - `tower-http` CORS layer added to agent for cross-origin live feed access.

---

## [0.3.0] - 2026-03-21

### Deep kernel security + intelligent response

- **XDP wire-speed firewall** - blocks IPs at the network driver level (10M+ pps drop rate). Pinned BPF map at `/sys/fs/bpf/innerwarden/blocklist` managed by agent via bpftool.
- **kprobe privilege escalation** - hooks kernel `commit_creds` function to detect real-time uid transitions from non-root to root through unexpected paths.
- **LSM execution blocking** - BPF LSM hook on `bprm_check_security` blocks binary execution from /tmp, /dev/shm, /var/tmp. Policy-gated, off by default, auto-enables on high-severity threats.
- **XDP allowlist** - operator IPs never dropped, checked before blocklist in kernel.
- **Layered blocking** - single block decision triggers XDP + firewall + Cloudflare + AbuseIPDB in one action.
- **Cross-detector correlation** - same IP in multiple detectors boosts AI confidence (1.15x for 2, 1.30x for 3, 1.50x for 4+).
- **LSM auto-enable** - agent automatically activates kernel execution blocking when it detects download+execute or reverse shell incidents.
- **Smart honeypot routing** - suspicious_login attackers (brute-force followed by success) redirected to honeypot; 20% of new attackers sampled; rest blocked via XDP.
- **AbuseIPDB delayed reporting** - reports queued 5 minutes before sending to allow false-positive correction.
- **Block rate limiter** - max 20 blocks per minute to prevent false-positive cascades.
- **XDP TTL** - blocked IPs auto-expire after 24 hours.
- **LSM process allowlist** - package managers (dpkg, apt, dnf), compilers (gcc, cargo), and system processes always allowed to execute from /tmp.
- **Sensor HUD dashboard** - new default home page with Chart.js area timeline, threat gauge, polar area detector chart. Design matches innerwarden.com (surface-card, cyber-gradient-text, JetBrains Mono).
- **Removed legacy runtime-security integration** - superseded by native eBPF (kprobe + LSM deeper than tracepoint-based approaches).
- **Deprecated Fail2ban** - native detectors + XDP firewall are faster and smarter.

19 detectors, 11 skills, 6 eBPF kernel programs, 692 tests.

---

## [0.2.0] - 2026-03-21

### Phase 2 - eBPF Deep Visibility

- **eBPF kernel tracing** - 3 tracepoints running in production (execve, connect, openat) via Aya framework on kernel 6.8
- **Container awareness** - `cgroup_id` captured in kernel space via `bpf_get_current_cgroup_id()`, container IDs resolved from `/proc/<pid>/cgroup` (Docker, Podman, k8s)
- **Process tree tracking** - ppid resolved via `/proc/<pid>/status`, full parent-child chain in event details
- **C2 callback detector** - beaconing analysis (coefficient of variation), C2 port monitoring, data exfiltration detection (10+ unique IPs from one process)
- **Process tree detector** - 26 suspicious lineage patterns: web server → shell, database → shell, Java/Node.js RCE, container runtime escape
- **Container escape detector** - nsenter, chroot, mount, modprobe from containers; Docker socket access, /proc/kcore reads, host sensitive file access
- **File access monitoring** - real-time sensitive path monitoring via openat tracepoint with kernel-space filtering (/etc/, /root/.ssh/, /home/*/.ssh/)
- **18 detectors** total (up from 14), 699 tests passing, sensor at 29MB RAM with all tracepoints active

---

## [0.1.6] - 2026-03-20

### Telegram personality overhaul

- **Hacker-partner voice** - all Telegram messages now speak with the personality of a skilled security operator, not a robotic monitoring system
- **Guard mode quips** - incident alerts in GUARD and DRY-RUN modes now include context-aware one-liners per threat type
- **Action reports** - post-kill messages use confidence-scaled quips: "Clean kill. Zero doubt." / "Textbook containment."
- **Mode descriptions** - GUARD: "Threats get neutralized on sight. You get the report." / WATCH: "I flag everything, you make the call."
- **/threats** - visual severity icons, relative time (3h ago), cleaner spacing
- **/decisions** - action-specific icons (block/suspend/honeypot/monitor/kill), confidence + mode display
- **/blocked** - "Kill list" header with count
- **AbuseIPDB auto-block** - "Instant kill - AbuseIPDB reputation gate" / "Dropped on sight - known threat, no AI needed."
- **Honeypot** - "Live target acquired" / "trap them or drop them?" / session debrief with "Their playbook:" heading

### Fixed

- **CrowdSec rate-limit** - cap new blocks per sync to 50 (configurable via `max_per_sync`), preventing OOM when CAPI returns 10k+ IPs. Trim `known_ips` at 10k to prevent unbounded memory growth.
- **Last Portuguese strings removed** - honeypot buttons (Bloquear/Monitorar/Ignorar), toast messages, and monitoring callback all translated to English

---

## [0.1.5] - 2026-03-20

### Security hardening (red team response)

- **Config self-monitoring** - integrity detector always monitors `/etc/innerwarden/*`, detects config tampering
- **Protected IP ranges** - AI can never block RFC1918/loopback IPs, decisions downgraded to ignore
- **Hash-chained audit trail** - each decision includes SHA-256 of the previous, tampering breaks the chain
- **Minimal sudoers** - ufw/iptables/nftables rules restricted to deny/delete/status only (no disable, flush, or reset)
- **Dashboard blocks actions over insecure HTTP** - operator actions disabled when auth is configured on non-localhost without TLS
- **Telegram destructive command warnings** - `/enable` and `/disable` show warning before execution
- **Prompt sanitization on all AI providers** - Anthropic provider now sanitizes attacker-controlled fields (was OpenAI/Ollama only)
- **Disk exhaustion protection** - events file capped at 200MB/day
- **Constant-time auth** - dashboard username comparison prevents timing attacks
- **Ed25519 binary signatures** - `innerwarden upgrade` verifies release signatures when `.sig` sidecars are present
- **Minimal sudoers** - ufw/iptables/nftables restricted to deny/delete/status only (no disable, flush, or reset)
- **Dashboard blocks actions over insecure HTTP** - operator actions disabled when auth configured on non-localhost without TLS

---

## [0.1.4] - 2026-03-19

### New commands
- **`innerwarden backup`** - archive configs to tar.gz for safe upgrades
- **`innerwarden metrics`** - events per collector, incidents per detector, AI latency, uptime

### Security hardening
- **Disk exhaustion protection** - events file capped at 200MB/day, auto-pauses writes
- **Constant-time auth** - dashboard username comparison prevents timing attacks
- **Prompt sanitization on all providers** - Anthropic provider now sanitizes attacker-controlled strings (was OpenAI/Ollama only)

### Performance
- **Dashboard 15x faster** - overview loads in 0.2s instead of 3s by counting lines instead of parsing 165MB of events JSON

### New detector
- **External config-drift anomaly** - promotes High/Critical events around sudoers, SUID, authorized_keys, and crontab changes to incidents

### Fixes
- **install.sh preserves configs** - detects existing installation and skips config overwrite on upgrade
- **Dashboard protection-first UX** - hero shows "Server Protected" with containment rate, resolved incidents faded

---

## [0.1.3] - 2026-03-19

### Security hardening

- **Dashboard login rate limiting** - after 5 failed login attempts within 15 minutes, the IP is blocked from trying again. Returns HTTP 429. Prevents brute-force on the dashboard itself.
- **Ban escalation for repeat offenders** - when an IP is blocked more than once, the decision reason is annotated with "repeat offender (blocked N times)". Flows through to Telegram, audit trail, and AbuseIPDB reports.
- **Dashboard HTTPS warning** - warns when the dashboard runs with auth on a non-localhost address over HTTP. Credentials would be sent in plaintext.
- **AI prompt injection sanitization** - attacker-controlled strings (usernames, paths, summaries) are sanitized before injection into the AI prompt. Control characters stripped, whitespace normalized.

### CrowdSec integration

- CrowdSec installed and enrolled on production server. Community blocklist flowing - known bad IPs are blocked preventively before they attack.

### Other

- Data retention enabled (7-day auto-cleanup of JSONL files)
- Watchdog cron (10-min health check, auto-restart + Telegram alert)
- OpenClaw skill published on ClawHub (innerwarden-security v1.0.3, "Benign" verdict)

---

## [0.1.2] - 2026-03-19

### NPM log support
- **Nginx Proxy Manager format** - the nginx_access collector now auto-detects and parses NPM log format (`[Client IP]` style). Sites behind Docker NPM are now protected by search_abuse, user_agent_scanner, and web_scan detectors.

### Bot detection
- **Known good bot whitelist** - 25+ legitimate crawlers (Google, Bing, DuckDuckGo, etc.) excluded from abuse detection.
- **rDNS verification** - for major search engine bots, the sensor verifies the IP via reverse DNS. Fake Googlebots (spoofed user-agent) are tagged `bot:spoofed` and treated as attackers.

### OpenClaw integration
- **innerwarden-security skill** - OpenClaw skill that installs Inner Warden, validates commands, monitors health, and fixes issues. Auto-detects AI provider. Prompt injection defense built in.

### Fixes
- **All strings in English** - removed all Portuguese from dashboard, Telegram, and agent messages.
- **max_completion_tokens** - auto-detects newer OpenAI models (gpt-5.x, o1, o3) that require the new parameter.
- **systemd dependency** - agent no longer dies when sensor restarts (Requires → Wants).

---

## [0.1.1] - 2026-03-18

### New detectors

- **Network IDS detector** - repeated alerts from same source IP → incident → block-ip
- **Docker anomaly detector** - rapid container restarts / OOM kills → incident → block-container
- **File integrity detector** - any change to monitored files (passwd, shadow, sudoers) → Critical incident

### Telegram follow-up

- **Fail2ban block notifications** - when fail2ban blocks an IP, Telegram now sends a follow-up message confirming the block or reporting failures. Previously only the initial "Live threat" alert was sent.

### Dashboard

- **Incident outcome field** - API now returns `outcome` (blocked/suspended/open) and `action_taken` for each incident by cross-referencing decisions.

### Fixes

- **install.sh: remove NoNewPrivileges from agent service** - the flag prevented sudo from working, breaking all response skills (ufw, iptables, sudoers). Sensor keeps the restriction.
- **Legacy external-tool docs** - honest "Current Limitations" sections explaining they provide context but don't trigger automated actions yet.

---

## [0.1.0] - 2026-03-18

First public release.

### Detection (8 detectors)

- SSH brute-force, credential stuffing, port scan, sudo abuse, search abuse
- `execution_guard` - shell command AST analysis via tree-sitter-bash
- `web_scan` - HTTP error floods per IP
- `user_agent_scanner` - 20+ known scanner signatures (Nikto, sqlmap, Nuclei, etc.)

### Collection (15 collectors)

- auth_log, journald, Docker, file integrity, nginx access/error, exec audit
- macOS unified log, syslog/kern.log firewall
- Legacy runtime, IDS, config-audit, and HIDS alerts
- AWS CloudTrail (IAM changes, root usage, audit tampering)

### Response skills (8 skills)

- Block IP (ufw / iptables / nftables / pf)
- Suspend user sudo (TTL-based, auto-cleanup)
- Rate limit nginx (HTTP 403 deny with TTL)
- Monitor IP (bounded tcpdump capture)
- Kill process (pkill by user, TTL metadata)
- Block container (docker pause with auto-unpause)
- Honeypot - SSH/HTTP decoy with LLM-powered shell, always-on mode, IOC extraction

### AI decision engine

- 12 providers: OpenAI, Anthropic, Groq, DeepSeek, Mistral, xAI/Grok, Google Gemini, Ollama, Together, MiniMax, Fireworks, OpenRouter - plus any OpenAI-compatible API
- Dynamic model discovery - wizard fetches available models from the provider API
- `innerwarden configure ai` - interactive wizard or direct CLI
- Algorithm gate, decision cooldown, confidence threshold, blocklist
- DDoS protection: auto-block threshold, max AI calls per tick, circuit breaker

### Collective defense

- AbuseIPDB enrichment + report-back - blocked IPs reported to global database
- Cloudflare WAF - blocks pushed to edge automatically
- GeoIP enrichment
- Fail2ban sync
- CrowdSec community threat intel

### Operator tools

- Telegram bot: alerts + approve/deny + conversational AI (/status, /incidents, /blocked, /ask)
- Slack notifications, webhook, browser push (VAPID/RFC 8291)
- Dashboard: investigation UI, SSE live push, operator actions, entity search, honeypot tab, attacker path viewer
- `innerwarden test` - pipeline test (synthetic incident → decision verification)

### Agent API for AI agents

- `GET /api/agent/security-context` - threat level and recommendation
- `GET /api/agent/check-ip?ip=X` - IP reputation check
- `POST /api/agent/check-command` - command safety analysis (reverse shells, download+execute, obfuscation, persistence, destructive ops)

### Control plane CLI

- enable/disable, setup wizard, doctor diagnostics, self-upgrade (SHA-256)
- scan advisor, incidents, decisions, entity timeline, block/unblock, export, tail, report, tune, watchdog
- Structured allowlists (IP/CIDR + users)
- `innerwarden configure ai` / `innerwarden configure responder`

### Module system

- 20 built-in modules with manifest, validate, install/uninstall, publish
- `openclaw-protection` module for AI agent environments

### Security CI

- cargo-deny: dependency advisories + license compliance
- gitleaks: secrets scanning
- Dependabot: weekly dependency updates

### Platform

- Linux (x86_64 + arm64) + macOS (x86_64 + arm64)
- 577 tests across four crates
