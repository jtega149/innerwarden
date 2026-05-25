mod boot;
mod collector_health;
mod collectors;
mod config;
mod detectors;
mod event_dispatch;
mod incident_builders;
mod main_helpers;
mod seccomp;
mod sinks;
mod tracing_init;

use incident_builders::build_devnode_watchlist;
use main_helpers::{
    choose_syslog_protocol, parse_syslog_port, should_enable_syslog_sink,
    should_spawn_integrity_collector, state_path_for,
};

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::Result;
use clap::Parser;
use collectors::{
    auth_log::AuthLogCollector, cloudtrail::CloudTrailCollector, docker::DockerCollector,
    exec_audit::ExecAuditCollector, integrity::IntegrityCollector, journald::JournaldCollector,
    macos_log::MacosLogCollector, nginx_access::NginxAccessCollector,
    nginx_error::NginxErrorCollector, syslog_firewall::SyslogFirewallCollector,
};
use detectors::c2_callback::C2CallbackDetector;
use detectors::container_escape::ContainerEscapeDetector;
use detectors::credential_harvest::CredentialHarvestDetector;
use detectors::credential_stuffing::CredentialStuffingDetector;
use detectors::crontab_persistence::CrontabPersistenceDetector;
use detectors::crypto_miner::CryptoMinerDetector;
use detectors::data_exfiltration::DataExfiltrationDetector;
use detectors::distributed_ssh::DistributedSshDetector;
use detectors::dns_tunneling::DnsTunnelingDetector;
use detectors::docker_anomaly::DockerAnomalyDetector;
use detectors::execution_guard::ExecutionGuardDetector;
use detectors::fileless::FilelessDetector;
use detectors::integrity_alert::IntegrityAlertDetector;
use detectors::kernel_module_load::KernelModuleLoadDetector;
use detectors::lateral_movement::LateralMovementDetector;
use detectors::log_tampering::LogTamperingDetector;
use detectors::outbound_anomaly::OutboundAnomalyDetector;
use detectors::packet_flood::PacketFloodDetector;
use detectors::port_scan::PortScanDetector;
use detectors::privesc::PrivescDetector;
use detectors::process_injection::ProcessInjectionDetector;
use detectors::process_tree::ProcessTreeDetector;
use detectors::ransomware::RansomwareDetector;
use detectors::reverse_shell::ReverseShellDetector;
use detectors::rootkit::RootkitDetector;
use detectors::search_abuse::SearchAbuseDetector;
use detectors::ssh_bruteforce::SshBruteforceDetector;
use detectors::ssh_key_injection::SshKeyInjectionDetector;
use detectors::sudo_abuse::SudoAbuseDetector;
use detectors::suspicious_login::SuspiciousLoginDetector;
use detectors::systemd_persistence::SystemdPersistenceDetector;
use detectors::user_agent_scanner::UserAgentScannerDetector;
use detectors::user_creation::UserCreationDetector;
use detectors::web_scan::WebScanDetector;
use detectors::web_shell::WebShellDetector;
use sinks::{sqlite::SqliteWriter, state::State};
use tokio::sync::mpsc;
#[allow(unused_imports)]
use tracing::{info, warn};

#[derive(Parser)]
#[command(
    name = "innerwarden-sensor",
    version,
    about = "Lightweight host observability sensor"
)]
struct Cli {
    #[arg(long, default_value = "config.toml")]
    config: String,
}

pub(crate) struct DetectorSet {
    /// Dynamic allowlist loaded from /etc/innerwarden/allowlist.toml.
    /// Checked before all detectors -- if a process/IP is allowlisted,
    /// the event is still logged but no incident is generated.
    pub(crate) dynamic_allowlist: detectors::allowlists::DynamicAllowlist,
    /// Last time we checked the allowlist file for changes.
    pub(crate) allowlist_last_check: std::time::Instant,

    /// IPs blocked by the agent. Loaded from blocked-ips.txt and
    /// reloaded every 60s. Events from these IPs skip detection.
    pub(crate) blocked_ips: HashSet<String>,
    /// Last time we reloaded blocked-ips.txt.
    pub(crate) blocked_ips_last_check: std::time::Instant,

    pub(crate) ssh: Option<SshBruteforceDetector>,
    pub(crate) credential_stuffing: Option<CredentialStuffingDetector>,
    pub(crate) port_scan: Option<PortScanDetector>,
    pub(crate) sudo_abuse: Option<SudoAbuseDetector>,
    pub(crate) search_abuse: Option<SearchAbuseDetector>,
    pub(crate) web_scan: Option<WebScanDetector>,
    pub(crate) user_agent_scanner: Option<UserAgentScannerDetector>,
    pub(crate) execution_guard: Option<ExecutionGuardDetector>,
    pub(crate) docker_anomaly: Option<DockerAnomalyDetector>,
    pub(crate) integrity_alert: Option<IntegrityAlertDetector>,
    pub(crate) log_tampering: Option<LogTamperingDetector>,
    pub(crate) distributed_ssh: Option<DistributedSshDetector>,
    pub(crate) suspicious_login: Option<SuspiciousLoginDetector>,
    pub(crate) c2_callback: Option<C2CallbackDetector>,
    pub(crate) process_tree: Option<ProcessTreeDetector>,
    pub(crate) container_escape: Option<ContainerEscapeDetector>,
    pub(crate) privesc: Option<PrivescDetector>,
    pub(crate) fileless: Option<FilelessDetector>,
    pub(crate) dns_tunneling: Option<DnsTunnelingDetector>,
    pub(crate) lateral_movement: Option<LateralMovementDetector>,
    pub(crate) crypto_miner: Option<CryptoMinerDetector>,
    pub(crate) outbound_anomaly: Option<OutboundAnomalyDetector>,
    pub(crate) rootkit: Option<RootkitDetector>,
    pub(crate) reverse_shell: Option<ReverseShellDetector>,
    pub(crate) ssh_key_injection: Option<SshKeyInjectionDetector>,
    pub(crate) web_shell: Option<WebShellDetector>,
    pub(crate) kernel_module_load: Option<KernelModuleLoadDetector>,
    pub(crate) crontab_persistence: Option<CrontabPersistenceDetector>,
    pub(crate) data_exfiltration: Option<DataExfiltrationDetector>,
    pub(crate) process_injection: Option<ProcessInjectionDetector>,
    pub(crate) user_creation: Option<UserCreationDetector>,
    pub(crate) systemd_persistence: Option<SystemdPersistenceDetector>,
    pub(crate) ransomware: Option<RansomwareDetector>,
    pub(crate) credential_harvest: Option<CredentialHarvestDetector>,
    pub(crate) packet_flood: Option<PacketFloodDetector>,
    pub(crate) sensitive_write: Option<detectors::sensitive_write::SensitiveWriteDetector>,
    pub(crate) discovery_burst: Option<detectors::discovery_burst::DiscoveryBurstDetector>,
    pub(crate) io_uring_anomaly: Option<detectors::io_uring_anomaly::IoUringAnomalyDetector>,
    pub(crate) container_drift: Option<detectors::container_drift::ContainerDriftDetector>,
    pub(crate) host_drift: Option<detectors::host_drift::HostDriftDetector>,
    pub(crate) data_exfil_ebpf: Option<detectors::data_exfil_ebpf::DataExfilEbpfDetector>,
    pub(crate) imds_ssrf: Option<detectors::imds_ssrf::ImdsSsrfDetector>,
    pub(crate) yara_scan: Option<detectors::yara_scan::YaraScanDetector>,
    pub(crate) sigma_rule: Option<detectors::sigma_rule::SigmaRuleDetector>,
    pub(crate) mitre_hunt: Option<detectors::mitre_hunt::MitreHuntDetector>,
    pub(crate) dns_c2: Option<detectors::dns_c2::DnsC2Detector>,
    pub(crate) data_encoding: Option<detectors::data_encoding::DataEncodingDetector>,
    pub(crate) sandbox_evasion: Option<detectors::sandbox_evasion::SandboxEvasionDetector>,
    pub(crate) threat_intel: Option<detectors::threat_intel::ThreatIntelDetector>,
    pub(crate) proto_anomaly: Option<detectors::proto_anomaly::ProtoAnomalyDetector>,
    // spec 050-PR1 — Reconnaissance
    pub(crate) nmap_scan: Option<detectors::nmap_scan::NmapScanDetector>,
    pub(crate) wordlist_scan: Option<detectors::wordlist_scan::WordlistScanDetector>,
    pub(crate) discovery_anomaly: Option<detectors::discovery_anomaly::DiscoveryAnomalyDetector>,
    // spec 050-PR2 — Collection
    pub(crate) clipboard_read: Option<detectors::clipboard_read::ClipboardReadDetector>,
    pub(crate) screen_capture: Option<detectors::screen_capture::ScreenCaptureDetector>,
    pub(crate) keylogger_bash_trap:
        Option<detectors::keylogger_bash_trap::KeyloggerBashTrapDetector>,
    pub(crate) archive_pwd_protected:
        Option<detectors::archive_pwd_protected::ArchivePwdProtectedDetector>,
    pub(crate) automated_file_collection:
        Option<detectors::automated_file_collection::AutomatedFileCollectionDetector>,
    // spec 050-PR3 — C2 variants
    pub(crate) c2_web_tunnel: Option<detectors::c2_web_tunnel::C2WebTunnelDetector>,
    pub(crate) c2_protocol_tunneling:
        Option<detectors::c2_protocol_tunneling::C2ProtocolTunnelingDetector>,
    pub(crate) c2_non_standard_port:
        Option<detectors::c2_non_standard_port::C2NonStandardPortDetector>,
    // spec 050-PR4 — Privilege Escalation + Lateral Movement
    pub(crate) setuid_exploit_pattern:
        Option<detectors::setuid_exploit_pattern::SetuidExploitPatternDetector>,
    pub(crate) capabilities_abuse: Option<detectors::capabilities_abuse::CapabilitiesAbuseDetector>,
    pub(crate) lateral_egress_ssh: Option<detectors::lateral_egress_ssh::LateralEgressSshDetector>,
    pub(crate) lateral_egress_scp_rsync:
        Option<detectors::lateral_egress_scp_rsync::LateralEgressScpRsyncDetector>,
    // spec 050-PR5 — Persistence + Defense Evasion
    pub(crate) pam_module_change: Option<detectors::pam_module_change::PamModuleChangeDetector>,
    pub(crate) auditd_disable: Option<detectors::auditd_disable::AuditdDisableDetector>,
    pub(crate) selinux_apparmor_disable:
        Option<detectors::selinux_apparmor_disable::SelinuxApparmorDisableDetector>,
    pub(crate) startup_script_persistence:
        Option<detectors::startup_script_persistence::StartupScriptPersistenceDetector>,
    // spec 050-PR6 — Impact
    pub(crate) data_destruction_pattern:
        Option<detectors::data_destruction_pattern::DataDestructionPatternDetector>,
    // 2026-05-17 wave — gap closers
    pub(crate) symlink_hijack: Option<detectors::symlink_hijack::SymlinkHijackDetector>,
    pub(crate) system_user_interactive:
        Option<detectors::system_user_interactive::SystemUserInteractiveDetector>,
}

#[derive(Default)]
pub(crate) struct WriteStats {
    pub(crate) events_written: u64,
    pub(crate) incidents_written: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_init::init_tracing()?;

    let cli = Cli::parse();
    let cfg = config::load(&cli.config)?;

    info!(
        host = %cfg.agent.host_id,
        data_dir = %cfg.output.data_dir,
        "innerwarden-sensor v{} starting",
        env!("CARGO_PKG_VERSION")
    );

    let data_dir = Path::new(&cfg.output.data_dir);
    let state_path = state_path_for(data_dir);

    let mut state = State::load(&state_path)?;
    info!(cursors = state.cursors.len(), "state loaded");

    let write_events = cfg.output.write_events;

    // SQLite is the primary and only event/incident sink.
    let sqlite_writer = SqliteWriter::new(data_dir, write_events)?;
    info!(path = %data_dir.join("innerwarden.db").display(), "sqlite sink enabled");
    // Optional syslog CEF output (configured via env or future config section)
    let mut syslog_writer: Option<sinks::syslog_cef::SyslogCefWriter> = {
        let syslog_host = std::env::var("INNERWARDEN_SYSLOG_HOST").unwrap_or_default();
        if !should_enable_syslog_sink(&syslog_host) {
            None
        } else {
            let syslog_port = std::env::var("INNERWARDEN_SYSLOG_PORT").ok();
            let port = parse_syslog_port(syslog_port.as_deref());
            let protocol = choose_syslog_protocol(std::env::var("INNERWARDEN_SYSLOG_TCP").is_ok());
            info!(host = %syslog_host, port, "Syslog CEF output enabled");
            Some(sinks::syslog_cef::SyslogCefWriter::new(
                sinks::syslog_cef::SyslogCefConfig {
                    host: syslog_host,
                    port,
                    protocol,
                },
                env!("CARGO_PKG_VERSION"),
            ))
        }
    };
    let (tx, mut rx) = mpsc::channel(1024);

    // Shared state - updated by collectors, read on shutdown for persistence.
    let shared_auth_offset = Arc::new(AtomicU64::new(0));
    let shared_integrity_hashes: Arc<Mutex<HashMap<String, String>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let shared_journald_cursor: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let shared_docker_since: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let shared_exec_audit_offset = Arc::new(AtomicU64::new(0));
    let shared_nginx_offset = Arc::new(AtomicU64::new(0));
    let shared_nginx_error_offset = Arc::new(AtomicU64::new(0));
    let shared_syslog_firewall_offset = Arc::new(AtomicU64::new(0));

    // Build the full DetectorSet (every per-detector cfg.enabled.then(...)
    // block + dynamic allowlist load + blocked-IP feedback file). Moved
    // to crates/sensor/src/boot/build_detectors.rs in PR5b1 (2026-05-25).
    let mut detectors = boot::build_detectors::build_detector_set(&cfg, data_dir);

    // Load threat intelligence datasets (IPs, domains, JA3, hashes, URLs).
    // Downloads public feeds on first run, reloads from disk every 60 min.
    let datasets_dir = data_dir.join("datasets");
    let mut threat_datasets = detectors::datasets::Datasets::load(&datasets_dir, 3600);
    if !threat_datasets.is_loaded() {
        info!("downloading threat intelligence feeds for the first time...");
        let (ok, total) = detectors::datasets::update_all_feeds(&datasets_dir);
        info!(
            feeds_updated = ok,
            total_entries = total,
            "initial feed download complete"
        );
        threat_datasets.reload();
    }

    // Spawn auth_log collector
    if cfg.collectors.auth_log.enabled {
        let offset = state
            .get_cursor("auth_log")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        shared_auth_offset.store(offset, Ordering::Relaxed);

        let collector =
            AuthLogCollector::new(&cfg.collectors.auth_log.path, &cfg.agent.host_id, offset);
        info!(path = %cfg.collectors.auth_log.path, offset, "starting auth_log collector");
        let tx2 = tx.clone();
        let shared = Arc::clone(&shared_auth_offset);
        tokio::spawn(async move {
            if let Err(e) = collector.run(tx2, shared).await {
                tracing::error!("auth_log collector error: {e:#}");
            }
        });
    }

    // Spawn integrity collector
    if should_spawn_integrity_collector(
        cfg.collectors.integrity.enabled,
        &cfg.collectors.integrity.paths,
    ) {
        let ic = &cfg.collectors.integrity;
        let known_hashes: HashMap<String, String> = state
            .get_cursor("integrity")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default();

        // Seed shared hashes with whatever we loaded from state
        *shared_integrity_hashes.lock().unwrap() = known_hashes.clone();

        // Always monitor Inner Warden's own config files for tampering,
        // regardless of user configuration.
        let self_monitor_paths = [
            "/etc/innerwarden/config.toml",
            "/etc/innerwarden/agent.toml",
            "/etc/innerwarden/agent.env",
        ];
        let mut all_paths: Vec<std::path::PathBuf> =
            ic.paths.iter().map(|p| Path::new(p).to_owned()).collect();
        for sp in &self_monitor_paths {
            let p = Path::new(sp).to_owned();
            if !all_paths.contains(&p) {
                all_paths.push(p);
            }
        }

        let collector = IntegrityCollector::new(
            all_paths.clone(),
            &cfg.agent.host_id,
            ic.poll_seconds,
            known_hashes,
        );
        info!(
            paths = all_paths.len(),
            poll_secs = ic.poll_seconds,
            "starting integrity collector (includes self-monitoring)"
        );
        let tx3 = tx.clone();
        let shared = Arc::clone(&shared_integrity_hashes);
        tokio::spawn(async move {
            if let Err(e) = collector.run(tx3, shared).await {
                tracing::error!("integrity collector error: {e:#}");
            }
        });
    }

    // Spawn journald collector
    if cfg.collectors.journald.enabled {
        let jc = &cfg.collectors.journald;
        let cursor: Option<String> = state
            .get_cursor("journald")
            .and_then(|v| serde_json::from_value(v.clone()).ok());
        *shared_journald_cursor.lock().unwrap() = cursor.clone();
        let collector = JournaldCollector::new(&cfg.agent.host_id, jc.units.clone(), cursor);
        info!(units = ?jc.units, "starting journald collector");
        let tx4 = tx.clone();
        let shared = Arc::clone(&shared_journald_cursor);
        tokio::spawn(async move {
            if let Err(e) = collector.run(tx4, shared).await {
                tracing::error!("journald collector error: {e:#}");
            }
        });
    }

    // Spawn docker collector
    if cfg.collectors.docker.enabled {
        let since: Option<String> = state
            .get_cursor("docker")
            .and_then(|v| v.as_str().map(str::to_string));
        *shared_docker_since.lock().unwrap() = since.clone();
        let collector = DockerCollector::new(&cfg.agent.host_id, since);
        info!("starting docker collector");
        let tx5 = tx.clone();
        let shared = Arc::clone(&shared_docker_since);
        tokio::spawn(async move {
            if let Err(e) = collector.run(tx5, shared).await {
                tracing::error!("docker collector error: {e:#}");
            }
        });
    }

    // Spawn exec_audit collector
    if cfg.collectors.exec_audit.enabled {
        let ec = &cfg.collectors.exec_audit;
        let offset = state
            .get_cursor("exec_audit")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        shared_exec_audit_offset.store(offset, Ordering::Relaxed);
        let collector =
            ExecAuditCollector::new(&ec.path, &cfg.agent.host_id, offset, ec.include_tty);
        info!(
            path = %ec.path,
            include_tty = ec.include_tty,
            offset,
            "starting exec_audit collector"
        );
        let tx6 = tx.clone();
        let shared = Arc::clone(&shared_exec_audit_offset);
        tokio::spawn(async move {
            if let Err(e) = collector.run(tx6, shared).await {
                tracing::error!("exec_audit collector error: {e:#}");
            }
        });
    }

    // Spawn nginx_access collector
    if cfg.collectors.nginx_access.enabled {
        let nc = &cfg.collectors.nginx_access;
        let offset = state
            .get_cursor("nginx_access")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        shared_nginx_offset.store(offset, Ordering::Relaxed);
        let collector = NginxAccessCollector::new(&nc.path, &cfg.agent.host_id, offset);
        info!(path = %nc.path, offset, "starting nginx_access collector");
        let tx7 = tx.clone();
        let shared = Arc::clone(&shared_nginx_offset);
        tokio::spawn(async move {
            if let Err(e) = collector.run(tx7, shared).await {
                tracing::error!("nginx_access collector error: {e:#}");
            }
        });
    }

    // Spawn nginx_error collector
    if cfg.collectors.nginx_error.enabled {
        let nec = &cfg.collectors.nginx_error;
        let offset = state
            .get_cursor("nginx_error")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        shared_nginx_error_offset.store(offset, Ordering::Relaxed);
        let collector = NginxErrorCollector::new(&nec.path, &cfg.agent.host_id, offset);
        info!(path = %nec.path, offset, "starting nginx_error collector");
        let tx_nginx_error = tx.clone();
        let shared = Arc::clone(&shared_nginx_error_offset);
        tokio::spawn(async move {
            if let Err(e) = collector.run(tx_nginx_error, shared).await {
                tracing::error!("nginx_error collector error: {e:#}");
            }
        });
    }

    // Spawn macos_log collector
    if cfg.collectors.macos_log.enabled {
        let collector = MacosLogCollector::new(&cfg.agent.host_id);
        info!("starting macos_log collector");
        let tx_macos = tx.clone();
        tokio::spawn(async move {
            if let Err(e) = collector.run(tx_macos).await {
                tracing::error!("macos_log collector error: {e:#}");
            }
        });
    }

    // Spawn syslog_firewall collector
    if cfg.collectors.syslog_firewall.enabled {
        let sc = &cfg.collectors.syslog_firewall;
        let offset = state
            .get_cursor("syslog_firewall")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        shared_syslog_firewall_offset.store(offset, Ordering::Relaxed);
        let collector = SyslogFirewallCollector::new(&sc.path, &cfg.agent.host_id, offset);
        info!(path = %sc.path, offset, "starting syslog_firewall collector");
        let tx_syslog = tx.clone();
        let shared = Arc::clone(&shared_syslog_firewall_offset);
        tokio::spawn(async move {
            if let Err(e) = collector.run(tx_syslog, shared).await {
                tracing::error!("syslog_firewall collector error: {e:#}");
            }
        });
    }

    // Spawn cloudtrail collector
    if cfg.collectors.cloudtrail.enabled {
        let cc = &cfg.collectors.cloudtrail;
        let collector = CloudTrailCollector::new(&cc.dir, &cfg.agent.host_id);
        info!(dir = %cc.dir, "starting cloudtrail collector");
        let tx_cloudtrail = tx.clone();
        tokio::spawn(async move {
            if let Err(e) = collector.run(tx_cloudtrail).await {
                tracing::error!("cloudtrail collector error: {e:#}");
            }
        });
    }

    // Spawn eBPF collector (optional - requires Linux 5.8+, CAP_BPF)
    {
        let tx_ebpf = tx.clone();
        let host_id = cfg.agent.host_id.clone();
        tokio::spawn(async move {
            collectors::ebpf_syscall::run(tx_ebpf, host_id).await;
        });
    }

    // Spawn firmware integrity collector (monitors ESP, UEFI vars, ACPI, DMI, tainted)
    {
        let tx_firmware = tx.clone();
        let host_id = cfg.agent.host_id.clone();
        tokio::spawn(async move {
            collectors::firmware_integrity::run(tx_firmware, host_id).await;
        });
    }

    // Spawn proc_maps collector (memory forensics: RWX, deleted files, LD_PRELOAD)
    {
        let tx_maps = tx.clone();
        let host_id = cfg.agent.host_id.clone();
        tokio::spawn(async move {
            collectors::proc_maps::run(tx_maps, host_id, 60).await;
        });
    }

    // Spawn fanotify filesystem monitor (real-time file modification + ransomware detection)
    {
        let tx_fan = tx.clone();
        let host_id = cfg.agent.host_id.clone();
        let watch_paths = cfg
            .collectors
            .integrity
            .paths
            .iter()
            .map(|p| p.to_string())
            .collect();
        tokio::spawn(async move {
            collectors::fanotify_watch::run(tx_fan, host_id, watch_paths, 5).await;
        });
    }

    // Spawn kernel integrity monitor (syscall table + eBPF inventory + module baseline)
    {
        let tx_kern = tx.clone();
        let host_id = cfg.agent.host_id.clone();
        tokio::spawn(async move {
            collectors::kernel_integrity::run(tx_kern, host_id, 120).await;
        });
    }

    // Spawn cgroup resource abuse detector (CPU/memory abuse, cryptominer detection)
    {
        let tx_cg = tx.clone();
        let host_id = cfg.agent.host_id.clone();
        tokio::spawn(async move {
            detectors::cgroup_abuse::run(tx_cg, host_id, 30).await;
        });
    }

    // Spawn TLS fingerprint collector (JA3/JA4 — requires CAP_NET_RAW + libc)
    #[cfg(feature = "ebpf")]
    {
        let tx_tls = tx.clone();
        let host_id = cfg.agent.host_id.clone();
        tokio::spawn(async move {
            collectors::tls_fingerprint::run(tx_tls, host_id, 0).await;
        });
    }

    // DNS query capture (AF_PACKET raw socket, captures UDP:53)
    {
        let tx_dns = tx.clone();
        let host_id = cfg.agent.host_id.clone();
        tokio::spawn(async move {
            collectors::dns_capture::run(tx_dns, host_id).await;
        });
    }

    // HTTP request capture (AF_PACKET raw socket, captures TCP:80/8080/8787/etc.)
    {
        let tx_http = tx.clone();
        let host_id = cfg.agent.host_id.clone();
        tokio::spawn(async move {
            collectors::http_capture::run(tx_http, host_id).await;
        });
    }

    // Network snapshot: periodic /proc/net/tcp scan with PID resolution
    {
        let tx_net = tx.clone();
        let host_id = cfg.agent.host_id.clone();
        tokio::spawn(async move {
            collectors::net_snapshot::run(tx_net, host_id, 30).await;
        });
    }

    // USB device monitoring: detects BadUSB, rubber ducky, unauthorized storage
    {
        let tx_usb = tx.clone();
        let host_id = cfg.agent.host_id.clone();
        tokio::spawn(async move {
            collectors::usb_monitor::run(tx_usb, host_id, 5).await;
        });
    }

    // SUID binary inventory: baseline + drift detection
    {
        let tx_suid = tx.clone();
        let host_id = cfg.agent.host_id.clone();
        tokio::spawn(async move {
            collectors::suid_inventory::run(tx_suid, host_id, 300).await;
        });
    }

    // Sysctl drift: monitors 20 security-critical kernel parameters
    {
        let tx_sysctl = tx.clone();
        let host_id = cfg.agent.host_id.clone();
        tokio::spawn(async move {
            collectors::sysctl_drift::run(tx_sysctl, host_id, 60).await;
        });
    }

    // SUID page-cache integrity: detects Copy Fail / Dirty Frag / Fragnesia-style
    // page-cache poisoning by comparing cached reads with direct-I/O disk reads.
    if cfg.detectors.suid_page_cache_integrity.enabled {
        let d = &cfg.detectors.suid_page_cache_integrity;
        let tx_suid_cache = tx.clone();
        let host_id = cfg.agent.host_id.clone();
        let allowlist: Vec<PathBuf> = d.allowlist.iter().map(PathBuf::from).collect();
        let poll_interval_secs = d.poll_interval_secs;
        info!(
            paths = allowlist.len(),
            poll_interval_secs, "starting suid_page_cache_integrity detector"
        );
        tokio::spawn(async move {
            detectors::suid_page_cache_integrity::run(
                tx_suid_cache,
                host_id,
                poll_interval_secs,
                allowlist,
            )
            .await;
        });
    }

    // Kernel devnode exposure: catches sensitive /dev/* nodes whose
    // permissions are more permissive than the documented safe-default.
    // Motivated by Azure mana_ib shipping `/dev/infiniband/uverbs*` mode
    // 0666 by default — see crates/sensor/src/detectors/kernel_devnode_exposed.rs
    // for the full architectural reasoning.
    if cfg.detectors.kernel_devnode_exposed.enabled {
        let d = &cfg.detectors.kernel_devnode_exposed;
        let tx_devnode = tx.clone();
        let host_id = cfg.agent.host_id.clone();
        let poll_interval_secs = d.poll_interval_secs;
        let allowlist = d.allowlist.clone();
        let watchlist = build_devnode_watchlist(&d.overrides);
        info!(
            patterns = watchlist.len(),
            poll_interval_secs, "starting kernel_devnode_exposed detector"
        );
        tokio::spawn(async move {
            detectors::kernel_devnode_exposed::run(
                tx_devnode,
                host_id,
                poll_interval_secs,
                watchlist,
                allowlist,
            )
            .await;
        });
    }

    // Systemd unit inventory: detects new/suspicious services
    {
        let tx_sysd = tx.clone();
        let host_id = cfg.agent.host_id.clone();
        tokio::spawn(async move {
            collectors::systemd_inventory::run(tx_sysd, host_id, 300).await;
        });
    }

    // TCP stream reassembly engine (AF_PACKET, all TCP traffic)
    // Reassembles bidirectional streams, detects protocols on any port,
    // enables deep packet inspection for HTTP, SSH, SMB, etc.
    {
        let tx_tcp = tx.clone();
        let host_id = cfg.agent.host_id.clone();
        tokio::spawn(async move {
            collectors::tcp_stream::run(tx_tcp, host_id).await;
        });
    }

    // Drop the original tx - each collector holds its own clone.
    // When all collector tasks finish, all senders drop and rx.recv() returns None.
    drop(tx);

    // Apply seccomp profile if configured (Active Defence feature).
    // MUST be after all eBPF programs are loaded and sockets are opened,
    // since seccomp restricts future syscalls. The profile blocks execve,
    // connect, and other syscalls the sensor doesn't need post-startup.
    #[cfg(target_os = "linux")]
    {
        let seccomp_path = data_dir.join("sensor.seccomp.json");
        if seccomp_path.exists() {
            match seccomp::apply_seccomp_profile(&seccomp_path) {
                Ok(count) => info!(
                    syscalls_allowed = count,
                    "seccomp profile applied — sensor hardened"
                ),
                Err(e) => warn!("seccomp profile failed to apply: {e:#} — continuing without"),
            }
        }
    }

    // SIGTERM listener (Unix only)
    #[cfg(unix)]
    let mut sigterm = {
        use tokio::signal::unix::{signal, SignalKind};
        signal(SignalKind::terminate())?
    };

    // PR29 — write the boot-time collector health snapshot. Probes
    // each file-backed collector's source path, records whether the
    // path exists / is stale / is missing, and writes the result to
    // `<data_dir>/collector-health.json` for the agent dashboard to
    // read. Errors are logged and swallowed: a missing health file
    // means the dashboard shows the legacy view (per-collector count
    // only), not a crash.
    {
        let now = chrono::Utc::now();
        let statuses = vec![
            collector_health::build_status(
                "auth_log",
                cfg.collectors.auth_log.enabled,
                Some(&cfg.collectors.auth_log.path),
                now,
            ),
            collector_health::build_status("journald", cfg.collectors.journald.enabled, None, now),
            collector_health::build_status(
                "exec_audit",
                cfg.collectors.exec_audit.enabled,
                Some(&cfg.collectors.exec_audit.path),
                now,
            ),
            collector_health::build_status("docker", cfg.collectors.docker.enabled, None, now),
            collector_health::build_status(
                "integrity",
                cfg.collectors.integrity.enabled,
                None,
                now,
            ),
            collector_health::build_status(
                "syslog_firewall",
                cfg.collectors.syslog_firewall.enabled,
                Some(&cfg.collectors.syslog_firewall.path),
                now,
            ),
            collector_health::build_status(
                "nginx_access",
                cfg.collectors.nginx_access.enabled,
                Some(&cfg.collectors.nginx_access.path),
                now,
            ),
            collector_health::build_status(
                "nginx_error",
                cfg.collectors.nginx_error.enabled,
                Some(&cfg.collectors.nginx_error.path),
                now,
            ),
            // NOTE: suricata_eve and osquery_log appear in some
            // operator config files but are NOT in the sensor's
            // CollectorsConfig struct. serde silently ignores those
            // keys, so the sensor never spawns them. Don't include
            // them in the probe; they aren't collectors this binary
            // runs. The right operator action is to remove those
            // sections from config.toml (or open a tracking PR to
            // add proper Suricata/Osquery collectors).
        ];
        if let Err(e) = collector_health::write_status_file(data_dir, &cfg.agent.host_id, &statuses)
        {
            tracing::warn!(error = %e, "failed to write collector-health.json");
        } else {
            info!("collector-health.json written ({} entries)", statuses.len());
        }
    }

    // Main loop: drain events, run detectors, write output
    let mut stats = WriteStats::default();

    // Cross-detector dedup cache: PID -> (last_incident_ts, severity_rank).
    // Prevents multiple detectors from emitting incidents for the same PID
    // within a 10-second window. Only the highest severity is kept.
    let mut dedup_cache: HashMap<u32, (chrono::DateTime<chrono::Utc>, u8)> = HashMap::new();

    'main: loop {
        // Receive next event or signal
        #[cfg(unix)]
        let received = tokio::select! {
            event = rx.recv() => event,
            _ = tokio::signal::ctrl_c() => {
                info!("SIGINT received - shutting down");
                break 'main;
            }
            _ = sigterm.recv() => {
                info!("SIGTERM received - shutting down");
                break 'main;
            }
        };

        #[cfg(not(unix))]
        let received = tokio::select! {
            event = rx.recv() => event,
            _ = tokio::signal::ctrl_c() => {
                info!("SIGINT received - shutting down");
                break 'main;
            }
        };

        let Some(ev) = received else {
            info!("all collectors stopped");
            break 'main;
        };

        // Periodic dataset reload (every hour)
        threat_datasets.maybe_reload();

        event_dispatch::process_event(
            ev,
            &sqlite_writer,
            &mut detectors,
            &mut stats,
            &mut syslog_writer,
            &mut dedup_cache,
            &threat_datasets,
        );
    }

    info!(
        events_written = stats.events_written,
        incidents_written = stats.incidents_written,
        "sensor stopped"
    );

    // Persist collector state using the latest values from the shared Arcs
    let auth_offset = shared_auth_offset.load(Ordering::Relaxed);
    state.set_cursor("auth_log", serde_json::json!(auth_offset));

    let integrity_hashes = shared_integrity_hashes.lock().unwrap().clone();
    if !integrity_hashes.is_empty() {
        state.set_cursor("integrity", serde_json::to_value(&integrity_hashes)?);
    }

    if let Some(cursor) = shared_journald_cursor.lock().unwrap().clone() {
        state.set_cursor("journald", serde_json::json!(cursor));
    }

    if let Some(since) = shared_docker_since.lock().unwrap().clone() {
        state.set_cursor("docker", serde_json::json!(since));
    }

    let exec_audit_offset = shared_exec_audit_offset.load(Ordering::Relaxed);
    state.set_cursor("exec_audit", serde_json::json!(exec_audit_offset));

    let nginx_offset = shared_nginx_offset.load(Ordering::Relaxed);
    state.set_cursor("nginx_access", serde_json::json!(nginx_offset));

    let nginx_error_offset = shared_nginx_error_offset.load(Ordering::Relaxed);
    state.set_cursor("nginx_error", serde_json::json!(nginx_error_offset));

    let syslog_firewall_offset = shared_syslog_firewall_offset.load(Ordering::Relaxed);
    state.set_cursor("syslog_firewall", serde_json::json!(syslog_firewall_offset));

    state.save(&state_path)?;
    info!(auth_offset, "state saved");

    Ok(())
}

// 11 small helpers (load_blocked_ips, state_path_for, blocked_ips_path_for,
// parse_blocked_ips, should_spawn_integrity_collector, should_enable_syslog_sink,
// parse_syslog_port, choose_syslog_protocol, severity_rank, is_passthrough_source,
// should_use_blocked_ip_hint) moved to crates/sensor/src/main_helpers.rs as part
// of the 2026-05-25 main.rs decomposition PR2. The previous `/// Load blocked
// IPs from the file written by the agent.` doc comment moved with `load_blocked_ips`
// — its body is in main_helpers.rs.

// apply_seccomp_profile + bpf_stmt + bpf_jump + syscall_name_to_nr
// moved to crates/sensor/src/seccomp.rs as part of the 2026-05-25
// main.rs decomposition PR3. The whole module is Linux-gated and
// carries byte-level anchor tests for the `struct sock_filter`
// packing that ARE the seccomp policy.

#[cfg(test)]
mod tests {
    use super::*;
    use innerwarden_core::event::Severity;

    // (parse_blocked_ips / helper_paths_resolve_inside_data_dir /
    //  should_spawn_integrity_collector / parse_syslog_port /
    //  choose_syslog_protocol / severity_rank anchors moved to
    //  crates/sensor/src/main_helpers.rs as part of the 2026-05-25
    //  main.rs decomposition PR2.)

    // (6 incident-builder anchors moved to
    //  crates/sensor/src/incident_builders.rs as part of the 2026-05-25
    //  main.rs decomposition PR4 — page_cache_mismatch_event_promotes_to_critical_incident,
    //  devnode_exposed_event_promotes_to_medium_incident, and the four
    //  build_devnode_watchlist_* tests.)

    // (passthrough_sources_are_disabled_by_default moved to main_helpers.rs
    //  as `is_passthrough_source_returns_false_for_all_known_sources` — same
    //  contract, broader source coverage.)

    #[test]
    fn cli_parses_default_and_custom_config_path() {
        let default_cli =
            Cli::try_parse_from(["innerwarden-sensor"]).expect("default CLI should parse");
        assert_eq!(default_cli.config, "config.toml");

        let custom_cli = Cli::try_parse_from([
            "innerwarden-sensor",
            "--config",
            "/etc/innerwarden/sensor.toml",
        ])
        .expect("custom config CLI should parse");
        assert_eq!(custom_cli.config, "/etc/innerwarden/sensor.toml");
    }

    // (5 helper unit tests moved to main_helpers.rs as part of PR2:
    //  parse_blocked_ips_deduplicates_and_keeps_comment_lines_as_tokens,
    //  load_blocked_ips_returns_empty_for_missing_feedback_file,
    //  load_blocked_ips_reads_agent_feedback_file,
    //  should_enable_syslog_sink_requires_non_empty_host,
    //  parse_syslog_port_rejects_out_of_range_values.)

    // ── Wave 9f anchors (2026-05-04) — journald-detection contract ───────
    //
    // AUDIT-009 root: tracing-subscriber writes plain text to stdout which
    // journald captures with no `PRIORITY=` field. `journalctl -p warning`
    // then silently drops every WARN this crate emits. The fix routes
    // tracing through `tracing-journald` when the binary runs under
    // systemd (detected via JOURNAL_STREAM env var). These anchors pin
    // the detection logic so a future refactor that breaks the env-var
    // contract is caught at test time rather than by the operator one
    // morning when their `journalctl -p warning` query goes silent.

    // (use_journald_layer anchors moved to crates/sensor/src/tracing_init.rs
    //  as part of the 2026-05-25 main.rs decomposition PR1.)

    // (blocked_ip_hint_returns_true_but_does_not_imply_skip + its 2026-05-23
    //  early-return-removal anchor moved to crates/sensor/src/event_dispatch.rs
    //  as part of the 2026-05-25 main.rs decomposition PR5a, alongside
    //  process_event itself. The `include_str!` source-grep target moved
    //  with it from "main.rs" to "event_dispatch.rs".)

    // (build_tracing_env_filter anchor moved to crates/sensor/src/tracing_init.rs
    //  as part of the 2026-05-25 main.rs decomposition PR1.)
}
