# InnerWarden — Testing & Coverage Map

> Single source of truth for everything that should fire in InnerWarden:
> collectors, eBPF programs, detectors, correlation rules, response skills,
> and runtime paths. Used to drive `scripts/smoke-all.sh` and the Caldera
> validation matrix.
>
> Last updated 2026-05-17 after spec 050 (PR0–PR7) shipped.

---

## 1. Service topology (what runs on a host)

```
┌──────────────────────────────────────────────────────────────────────┐
│  innerwarden-sensor.service  (PID 1 child, CAP_BPF + CAP_NET_RAW)     │
│  └─ eBPF subsystem (44 programs, see §4)                              │
│  └─ Collectors (29, see §3) — host inventory, log readers, AF_PACKET  │
│  └─ Detectors (~70, see §5) — pure functions over the event stream    │
│  └─ Sinks (4) — jsonl + sqlite + state + syslog_cef                   │
│         │                                                             │
│         ▼ /var/lib/innerwarden/{events,incidents}-*.jsonl (+ sqlite)  │
│                                                                       │
│  innerwarden-agent.service   (or via watchdog on prod)                │
│  └─ Reader: byte-offset cursors on JSONL (or Redis Streams)           │
│  └─ Pipeline: enrichment → AI → MITRE map → skill exec → audit        │
│  └─ Correlation engine (68 rules, see §7)                             │
│  └─ Skills (12 response actions, see §6)                              │
│  └─ Dashboard SPA on :8787                                            │
│                                                                       │
│  innerwarden-watchdog.service (prod only)                             │
│  └─ Crash recovery + telegram alerts + integrity SHA-256 pin          │
└──────────────────────────────────────────────────────────────────────┘
```

Reference: §"Architecture Summary" in `.claude/CLAUDE.md`.

---

## 2. Runtime paths (operator-relevant locations)

| Path | What | Owner |
|---|---|---|
| `/usr/local/bin/innerwarden-{sensor,agent,ctl,watchdog}` | binaries | root |
| `/etc/innerwarden/config.toml` | main config | root |
| `/etc/innerwarden/allowlist.toml` | dynamic allowlist (`[detectors.<name>]` per-detector sections) | root |
| `/var/lib/innerwarden/events-YYYY-MM-DD.jsonl` | rolling event sink (raw observations) | sensor |
| `/var/lib/innerwarden/incidents-YYYY-MM-DD.jsonl` | rolling incident sink (detector hits) | sensor |
| `/var/lib/innerwarden/state/` | sqlite + dedup + cursor offsets | sensor + agent |
| `/var/lib/innerwarden/baseline.json` | learned per-host baseline | agent |
| `/var/lib/innerwarden/attacker-profiles.json` | per-IP intel profiles | agent |
| `/var/lib/innerwarden/campaigns.json` | DNA+IOC campaign clusters | agent |
| `/var/lib/innerwarden/threat-feeds.json` | external feed cache | agent |
| `/var/lib/innerwarden/datasets/` | downloaded threat-intel datasets | sensor |
| `/var/lib/innerwarden/models/classifier/` | Local Warden ONNX model (out-of-band install) | agent |
| `/var/lib/innerwarden/models/autoencoder.bin` | nightly-trained anomaly model | agent |
| `/var/lib/innerwarden/pcap/` | selective pcap captures per high-severity incident | agent |
| `/var/lib/innerwarden/audit.jsonl` | hash-chained skill execution audit | agent |
| `rules/atr/` | 71 ATR YAML rules (vendored) | sensor |
| `rules/sigma/` | community Sigma rules (208) | sensor |
| `rules/yara/` | YARA binary scan rules | sensor |

---

## 3. Collectors (29) — `crates/sensor/src/collectors/`

Pure event producers. Each emits `Event { source, kind, details, … }` into the `mpsc::channel`. **All collectors are fail-open** — they log and continue, never crash the sensor.

| Collector | Source | Emits `kind=` | Triggered by |
|---|---|---|---|
| `auth_log` | `/var/log/auth.log` (Debian) / `/var/log/secure` (RHEL) | `ssh.login_failed`, `ssh.login_success`, `sudo.*`, `useradd.*` | new lines |
| `cloudtrail` | AWS CloudTrail S3 (optional) | `aws.api_call_*` | poll cycle |
| `dns_capture` | AF_PACKET UDP:53 (raw socket) | `dns.query`, `dns.response` | packet capture (needs CAP_NET_RAW) |
| `docker` | Docker Engine API | `container.create`, `container.die`, `container.oom` | API events stream |
| `ebpf_syscall` | eBPF ring buffer | `shell.command_exec`, `process.exec`, `network.outbound_connect`, `file.write_access`, `file.read_access`, `privilege.escalation`, `privilege.setuid`, `kernel_module_load`, `mprotect`, `ioperm`, `iopl`, `firmware.msr_write`, `acpi.evaluate`, `lsm.exec_blocked`, `lsm.file_open_denied`, `lsm.bpf_load`, `dup.fd_redirect`, `prctl.set_name`, `clone.*`, `unlink.*`, `rename.*`, `kill.signal`, `accept.*`, `io_uring.*`, `mount.*`, `memfd_create.*`, `init_module.*`, `listen.*`, `setuid.*`, `bind.*`, `ptrace.*`, `openat.*`, `connect.*`, `process_exit.*` | kernel hook |
| `exec_audit` | execve audit | `shell.command_exec` (low-cost fallback) | process exec |
| `fanotify_watch` | fanotify (CAP_SYS_ADMIN) | `file.changed`, `file.write_burst` | filesystem event |
| `file_extract` | extracted-file pipeline | `file.extracted` | sensor pipeline |
| `firmware_integrity` | SMBIOS / EFI vars | `firmware.*` | sweep cycle |
| `http_capture` | AF_PACKET TCP:80/8080/… | `http.request` | packet capture |
| `integrity` | hash of sensitive files | `file.changed` | sweep cycle |
| `journald` | systemd journal | various `journald.*` + service kinds | new entries |
| `kernel_integrity` | `/proc/kallsyms`, bpftool, `/proc/modules` | `rootkit.*`, `ebpf.unauthorized_load`, `kernel.module_inventory_drift` | sweep cycle |
| `log_state` | log offset book-keeper | (internal) | per-collector |
| `macos_log` | macOS unified log | `macos_log.*` | log stream (macOS only) |
| `net_snapshot` | `/proc/net/{tcp,udp,unix}` | `network.connection_inventory` | sweep |
| `nginx_access` | `/var/log/nginx/access.log` | `http.error`, `http.request` | new lines |
| `nginx_error` | `/var/log/nginx/error.log` | `http.error` | new lines |
| `proc_maps` | `/proc/PID/maps` scan | `memory.rwx_map`, `memory.anon_exec`, `memory.deleted_mapping`, `memory.exec_stack`, `memory.ld_preload` | per-suspect-pid |
| `proto_http` | HTTP captured payloads (assembler) | `http.*` | tcp_stream feed |
| `proto_smb` | SMB protocol decoder | `smb.*` | tcp_stream feed |
| `proto_ssh` | SSH protocol decoder | `ssh.*` | tcp_stream feed |
| `suid_inventory` | scan SUID binaries at boot | `host.suid_inventory_snapshot` | boot |
| `sysctl_drift` | `sysctl -a` snapshot vs. baseline | `host.sysctl_drift` | sweep |
| `syslog_firewall` | iptables / ufw logs | `firewall.block` | new lines |
| `systemd_inventory` | running unit list | `host.systemd_inventory_snapshot` | sweep |
| `tcp_stream` | AF_PACKET reassembler | (internal feed to proto_*) | packet capture |
| `tls_fingerprint` | AF_PACKET TLS ClientHello | `tls.ja3`, `tls.ja4`, `tls.malicious_match` | packet capture |
| `usb_monitor` | `/sys/bus/usb/devices/` | `usb.attach`, `usb.detach` | uevent |

---

## 4. eBPF programs (44) — `crates/sensor-ebpf/src/main.rs`

| Type | Count | Hooks |
|---|---|---|
| `tracepoint` | 23 | execve, connect, openat, process_exit, ptrace, setuid, bind, mount, memfd_create, init_module, dup, listen, mprotect, clone, unlink, rename, kill, prctl, accept, io_uring_submit, io_uring_create, ioperm, iopl |
| `kprobe` | 10 | commit_creds (privesc), native_write_msr (firmware), acpi_evaluate_object (ACPI rootkit), and more from spec-029 / spec-040 wave |
| `lsm` | 3 | `bprm_check_security` (exec block + kill chain), `file_open` (sensitive path write protection), `bpf` (eBPF program load / VoidLink defense) |
| `raw_tracepoint` | 7 | `sys_enter` dispatch points (tail-call chain via ProgramArray) |
| `xdp` | 1 | wire-speed IP block at the NIC |

CO-RE/BTF relocations for cross-kernel portability. Compiled `#![no_std]` for `bpfel-unknown-none`, loaded via Aya. Capability-based guard mode via `CGROUP_CAPABILITIES` + `COMM_CAPABILITIES` BPF maps with 10 capability bits.

---

## 5. Detectors (74 — `crates/sensor/src/detectors/`)

The 4 infrastructure modules (`allowlists`, `datasets`, `exec_context`, `mod.rs` helpers) are not user-facing detectors. The remaining ~70 are grouped by MITRE tactic.

### Initial Access (TA0001)

| Detector | MITRE | Trigger | File |
|---|---|---|---|
| `ssh_bruteforce` | T1110.001 | N failed `ssh.login_failed` from same IP in window | `ssh_bruteforce.rs` |
| `credential_stuffing` | T1110.004 | distinct usernames against `ssh.login_failed` from same IP | `credential_stuffing.rs` |
| `distributed_ssh` | T1110 | N IPs hitting `ssh.login_failed` for the same user | `distributed_ssh.rs` |
| `web_scan` | T1595 | repeated `http.error` 404/403 patterns | `web_scan.rs` |
| `web_shell` | T1505.003 | upload + exec pattern via nginx/apache logs + eBPF | `web_shell.rs` |
| `user_agent_scanner` | T1595/T1595.002 | known scanner UA strings | `user_agent_scanner.rs` |

### Execution (TA0002)

| Detector | MITRE | Trigger | File |
|---|---|---|---|
| `reverse_shell` | T1059 | exec of shell with stdin/stdout/stderr redirected to socket | `reverse_shell.rs` |
| `fileless` | T1620 | exec of `memfd_create` fd | `fileless.rs` |
| `process_injection` | T1055 | mprotect to RWX in another process / proc_maps anomaly | `process_injection.rs` |
| `execution_guard` | — | exec of explicitly-blocked binaries from allowlist | `execution_guard.rs` |
| `crypto_miner` | T1496 | sustained CPU spike via cgroup + known miner argv | `crypto_miner.rs` |

### Persistence (TA0003)

| Detector | MITRE | Trigger | File |
|---|---|---|---|
| `crontab_persistence` | T1053.003 | write to `/etc/crontab` / `/var/spool/cron/` | `crontab_persistence.rs` |
| `systemd_persistence` | T1543.002 | new systemd unit file written | `systemd_persistence.rs` |
| `ssh_key_injection` | T1098.004 | write to `~/.ssh/authorized_keys` | `ssh_key_injection.rs` |
| `keylogger_bash_trap` | T1056.004 / T1546.004 | write to shell startup files OR `trap … DEBUG` exec | `keylogger_bash_trap.rs` |
| `user_creation` | T1136.001 | useradd/adduser exec from non-pkg-mgr parent | `user_creation.rs` |
| **`pam_module_change`** | **T1556.003** | write to `/etc/pam.d/` or `pam_*.so` (PR5) | `pam_module_change.rs` |
| **`startup_script_persistence`** | **T1037.004** | write to `/etc/rc.local`, `/etc/init.d/`, etc. (PR5) | `startup_script_persistence.rs` |

### Privilege Escalation (TA0004)

| Detector | MITRE | Trigger | File |
|---|---|---|---|
| `privesc` | T1548 / T1078 | privesc events from eBPF | `privesc.rs` |
| `sudo_abuse` | T1548.003 | sudo with abnormal targets | `sudo_abuse.rs` |
| **`setuid_exploit_pattern`** | **T1548.001** | non-baseline SUID exec by non-root (PR4) | `setuid_exploit_pattern.rs` |
| **`capabilities_abuse`** | **T1068 / T1548.005** | non-root + dangerous cap + exploit argv (PR4) | `capabilities_abuse.rs` |

### Defense Evasion (TA0005)

| Detector | MITRE | Trigger | File |
|---|---|---|---|
| `log_tampering` | T1070.002 | clearing/deletion/truncate of `/var/log/*` | `log_tampering.rs` |
| `sandbox_evasion` | T1497.* | timing checks, VM artifacts | `sandbox_evasion.rs` |
| `data_encoding` | T1132 / T1132.001 | base64/hex blobs in argv | `data_encoding.rs` |
| `rootkit` | T1014 | kernel syscall table change / hidden ebpf prog | `rootkit.rs` |
| **`auditd_disable`** | **T1562.001** | `systemctl stop auditd`, `auditctl -e 0`, `pkill auditd`, audit.rules write (PR5) | `auditd_disable.rs` |
| **`selinux_apparmor_disable`** | **T1562.001** | `setenforce 0`, `aa-disable`, `aa-teardown`, `/etc/selinux/config` write (PR5) | `selinux_apparmor_disable.rs` |
| `host_drift` | — | drift from baseline host snapshot | `host_drift.rs` |
| `integrity_alert` | — | hash mismatch on protected file | `integrity_alert.rs` |
| `process_tree` | — | unexpected parent → child (nginx → sh, etc.) | `process_tree.rs` |
| `container_drift` | — | overlayfs upper layer write outside expected paths | `container_drift.rs` |
| `mitre_hunt` | T1036.005 T1040 T1053.002 T1090 T1219 T1222.002 T1489 T1529 T1560 T1564.001 | catch-all MITRE technique mapper | `mitre_hunt.rs` |

### Credential Access (TA0006)

| Detector | MITRE | Trigger | File |
|---|---|---|---|
| `credential_harvest` | T1003 | reads against `/etc/shadow`, `/etc/sudoers`, etc. | `credential_harvest.rs` |
| `search_abuse` | T1552.001 | mass `grep -r password` style search | `search_abuse.rs` |
| `sensitive_write` | — | write to sensitive paths | `sensitive_write.rs` |

### Discovery (TA0007)

| Detector | MITRE | Trigger | File |
|---|---|---|---|
| `port_scan` | T1046 | many `network.inbound_connect`/`accept` against distinct ports | `port_scan.rs` |
| `discovery_burst` | T1016 T1049 T1057 T1082 T1083 T1087 | rapid discovery commands from same comm | `discovery_burst.rs` |
| **`discovery_anomaly`** | **T1016 T1018 T1033 T1049 T1057 T1082 T1083 T1087 T1135 T1518** | argv[0]-driven discovery via `exec_context` gate (PR1) | `discovery_anomaly.rs` |
| **`nmap_scan`** | **T1046 T1595.001** | `nmap` argv[0] outside pkg-mgr context (PR1) | `nmap_scan.rs` |
| **`wordlist_scan`** | **T1595.003** | `gobuster`/`ffuf`/`feroxbuster`/`dirb`/etc. (PR1) | `wordlist_scan.rs` |
| `suspicious_login` | — | login from unusual time/source | `suspicious_login.rs` |

### Lateral Movement (TA0008)

| Detector | MITRE | Trigger | File |
|---|---|---|---|
| `lateral_movement` | T1021 | generic lateral signals | `lateral_movement.rs` |
| **`lateral_egress_ssh`** | **T1021.004** | outbound `ssh` from non-operator-shell tree (PR4) | `lateral_egress_ssh.rs` |
| **`lateral_egress_scp_rsync`** | **T1029 / T1048.001** | scp/rsync/sftp staging user-data → remote (PR4) | `lateral_egress_scp_rsync.rs` |

### Collection (TA0009)

| Detector | MITRE | Trigger | File |
|---|---|---|---|
| **`clipboard_read`** | **T1115** | exec of clipboard tools (`xclip`, `xsel`, `wl-paste`) (PR2) | `clipboard_read.rs` |
| **`screen_capture`** | **T1113** | exec of `gnome-screenshot`/`scrot`/`maim`/etc. (PR2) | `screen_capture.rs` |
| **`archive_pwd_protected`** | **T1560.001** | password-protected archive creation (PR2) | `archive_pwd_protected.rs` |
| **`automated_file_collection`** | **T1119** | mass tar/zip/find-and-collect (PR2) | `automated_file_collection.rs` |
| **`keylogger_bash_trap`** | T1056.004 / T1546.004 | (also Persistence, see above) | `keylogger_bash_trap.rs` |

### Command and Control (TA0011)

| Detector | MITRE | Trigger | File |
|---|---|---|---|
| `c2_callback` | T1071 | beaconing patterns | `c2_callback.rs` |
| `dns_tunneling` | T1071.004 | long random DNS subdomains, high query volume | `dns_tunneling.rs` |
| `dns_c2` | T1071.004 | DNS TXT/A patterns matching known C2 | `dns_c2.rs` |
| `proto_anomaly` | — | unexpected protocol on port (HTTP on :22, etc.) | `proto_anomaly.rs` |
| `outbound_anomaly` | — | outbound to unseen destination | `outbound_anomaly.rs` |
| **`c2_web_tunnel`** | **T1090.003 / T1572** | ngrok/cloudflared/bore + tunnel DNS (PR3) | `c2_web_tunnel.rs` |
| **`c2_protocol_tunneling`** | **T1071.004 / T1572** | DNS/ICMP/SSH-forward tunneling (PR3) | `c2_protocol_tunneling.rs` |
| **`c2_non_standard_port`** | **T1571** | listener outside well-known port set (PR3) | `c2_non_standard_port.rs` |
| `stego_detect` | T1001.002 | LSB encoding / image-payload patterns | `stego_detect.rs` |

### Exfiltration (TA0010)

| Detector | MITRE | Trigger | File |
|---|---|---|---|
| `data_exfiltration` | T1041 | size + destination heuristic | `data_exfiltration.rs` |
| `data_exfil_ebpf` | T1041 | eBPF outbound volume tracking | `data_exfil_ebpf.rs` |

### Impact (TA0040)

| Detector | MITRE | Trigger | File |
|---|---|---|---|
| `ransomware` | T1486 | write entropy burst + file rename pattern | `ransomware.rs` |
| **`data_destruction_pattern`** | **T1485 / T1561.001 / T1486** | 5 sub-shapes: rm_rf_user_data, disk_wipe, shred_burst, mkfs_on_running_volume, cryptsetup_luksformat (PR6) | `data_destruction_pattern.rs` |
| `packet_flood` | T1498.001 | SYN flood / amplification | `packet_flood.rs` |

### Cross-tactic / Infra

| Detector | What | File |
|---|---|---|
| `sigma_rule` | runs 8 built-in Sigma rules + `rules/sigma/*.yml` | `sigma_rule.rs` |
| `yara_scan` | 8 built-in YARA rules + `rules/yara/*.yml` | `yara_scan.rs` |
| `threat_intel` | hash check vs VirusTotal + IOC feeds | `threat_intel.rs` |
| `docker_anomaly` | container.oom, container.die heuristics | `docker_anomaly.rs` |
| `container_escape` | overlayfs escape + privileged-container indicators | `container_escape.rs` |
| `cgroup_abuse` | sustained CPU/memory abuse | `cgroup_abuse.rs` |
| `io_uring_anomaly` | io_uring abuse (Aya-detected) | `io_uring_anomaly.rs` |
| `kernel_module_load` | new kmod load post-baseline | `kernel_module_load.rs` |

---

## 6. Response skills (12) — `crates/agent/src/skills/builtin/`

| Skill | Action |
|---|---|
| `block_ip_xdp` | drop traffic at NIC via eBPF XDP map (wire-speed) |
| `block_ip_nftables` | nftables rule insertion |
| `block_ip_iptables` | iptables rule insertion |
| `block_ip_ufw` | ufw deny |
| `block_ip_pf` | macOS pf rule |
| `firewall_target` | abstraction over the above 5 |
| `block_container` | docker pause / stop |
| `suspend_user_sudo` | revoke sudo group + lock user |
| `kill_process` | SIGKILL by pid |
| `monitor_ip` | escalate observation without blocking |
| `rate_limit_nginx` | install nginx limit_req block |
| `kill_chain_response` | composite for high-severity chain incidents |

---

## 7. Correlation rules (67) — `crates/agent/src/correlation_engine.rs`

CL-001 → CL-047 are the legacy ruleset (firmware/hypervisor/kernel chains + baseline/neural/DNA rules). CL-048/049/050 are reserved.

### Spec 050-PR7 — Cross-tactic chains (CL-051 → CL-070)

Wires PR1-6 detectors into MITRE attack chains. See the dedicated table:

| ID | Chain | Severity | Window | Conf |
|---|---|---|---|---|
| CL-051 | Discovery → Privesc | Critical | 30m | 0.85 |
| CL-052 | Privesc → Lateral | Critical | 30m | 0.85 |
| CL-053 | Collection → Exfil | Critical | 30m | 0.85 |
| CL-054 | Web Shell → C2 | Critical | 30m | 0.85 |
| CL-055 | Persistence → Defense Evasion | Critical | 30m | 0.85 |
| CL-056 | Defense Evasion → Impact (wiper shape) | Critical | 60m | 0.90 |
| CL-057 | Discovery Burst → Collection | High | 30m | 0.80 |
| CL-058 | Initial Access → Foothold | Critical | 30m | 0.85 |
| CL-059 | Foothold → Persistence | Critical | 60m | 0.85 |
| CL-060 | C2 → Internal Discovery | High | 30m | 0.85 |
| CL-061 | Discovery → C2 Callout | High | 30m | 0.80 |
| CL-062 | Reverse Shell → Privesc | Critical | 30m | 0.85 |
| CL-063 | Privesc → Persistence | Critical | 60m | 0.85 |
| CL-064 | Persistence → Lateral | High | 60m | 0.80 |
| CL-065 | Lateral → Collection | High | 30m | 0.80 |
| CL-066 | Collection → Lateral Exfil | Critical | 30m | 0.85 |
| **CL-067** | **Full Kill Chain (5-stage)** | **Critical** | **2h** | **0.95** |
| CL-068 | Wiper Precursor (evasion + discovery + impact) | Critical | 30m | 0.85 |
| CL-069 | Insider Exfiltration | High | 60m | 0.80 |
| CL-070 | PAM Credential Theft → Lateral Pivot | Critical | 60m | 0.85 |

---

## 8. Datasets the sensor consumes at runtime

Lives under `/var/lib/innerwarden/datasets/` after first run, refreshed every 60 min by `datasets.rs`:

| File | Source | Used by |
|---|---|---|
| `malicious_ips.txt` | abuseIPDB + community feeds | `outbound_anomaly`, `c2_callback`, `threat_intel` |
| `malicious_domains.txt` | community feeds | `dns_c2`, `c2_*` |
| `ja3_blacklist.txt` | curated | `tls_fingerprint` |
| `known_hashes.txt` | VT-style hash blacklist | `yara_scan`, `threat_intel` |
| `c2_urls.txt` | community URL feeds | `c2_callback`, `outbound_anomaly` |

---

## 9. Test sandbox plan for `scripts/smoke-all.sh`

The smoke harness creates these disposable resources on test001:

| Resource | Path | Used for |
|---|---|---|
| Sandbox user | `iw_smoke_test:iw_smoke_test` + home `/home/iw_smoke_test/` | rm_rf_user_data, ssh_key_injection, shell-profile writes |
| Loop device | backed by `/var/tmp/iw_smoke_loop.img` (100MB sparse) | dd disk_wipe, mkfs, cryptsetup luksFormat |
| Scratch dir | `/tmp/iw_smoke_sandbox/` | every other safe trigger |
| Log | `/tmp/iw_smoke_log_*.log` | per-run results |

Teardown reverses everything: `losetup -d`, `userdel -r`, `rm -rf`.

**What the harness cannot directly test (skipped with reason):**
- Real kernel rootkit (would require building a malicious kmod)
- Real KVM-escape / hypervisor anomaly (no VM nesting on test001)
- Real macOS log (Linux-only host)
- CloudTrail collector (no AWS creds)
- Caldera-only chains (CL-067 full kill chain — too many stages to fake cleanly)

These get covered by the next stage: Caldera adversary replay.

---

## 10. How to use this document

1. **Adding a new detector**: append a row to the right §5 sub-table with MITRE ID + trigger + file path.
2. **Adding a new correlation rule**: append to §7 with ID + chain + severity + window + confidence.
3. **Adding a new collector or sink**: append to §3 with source + emitted `kind` + trigger.
4. **Wiring a new test in `smoke-all.sh`**: cross-reference the §5 row when picking the synthetic trigger to issue.
5. **Caldera validation**: this file is the matrix the Caldera profile must hit. Anything that says `Critical` and is not in the Caldera coverage report after a run = gap.
