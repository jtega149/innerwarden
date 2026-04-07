//! InnerWarden SMM — Ring -2 firmware security monitoring.
//!
//! Provides read-only visibility into firmware, SMM, MSR, TPM, UEFI, and
//! ACPI state. All operations are non-destructive — they observe and report
//! without modifying hardware or firmware state.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────┐
//! │  Application (Ring 3)                   │
//! │  └─ InnerWarden agent-guard, ATR rules  │
//! ├─────────────────────────────────────────┤
//! │  Kernel (Ring 0)                        │
//! │  └─ InnerWarden eBPF (25 hooks)         │
//! ├─────────────────────────────────────────┤
//! │  Firmware / SMM (Ring -2)          ← US │
//! │  └─ innerwarden-smm                     │
//! │     ├─ MSR read (SMI count, SMRR lock)  │
//! │     ├─ SPI flash integrity              │
//! │     ├─ UEFI Secure Boot attestation     │
//! │     ├─ TPM PCR verification             │
//! │     ├─ ACPI table integrity             │
//! │     └─ SMI anomaly detection            │
//! └─────────────────────────────────────────┘
//! ```

pub mod acpi;
pub mod baseline;
pub mod correlator;
pub mod cpu_features;
pub mod ebpf_audit;
pub mod kintegrity;
pub mod ktext;
pub mod measurement_chain;
pub mod microcode;
pub mod msr;
pub mod smi;
pub mod spi;
pub mod timing;
pub mod tpm;
pub mod trace_of_times;
pub mod uefi;

use serde::Serialize;

/// Overall firmware health report.
#[derive(Debug, Clone, Serialize)]
pub struct FirmwareReport {
    pub ts: ::chrono::DateTime<::chrono::Utc>,
    pub arch: Arch,
    /// Weighted firmware trust score (0.0 = fully compromised, 1.0 = fully trusted).
    pub trust_score: f64,
    pub checks: Vec<CheckResult>,
    /// Correlated threats (signals combined for higher-confidence detection).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub correlated_threats: Vec<correlator::CorrelatedThreat>,
}

/// CPU architecture — determines which checks are available.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Arch {
    X86_64,
    Aarch64,
    Unknown,
}

impl Arch {
    pub fn current() -> Self {
        if cfg!(target_arch = "x86_64") {
            Arch::X86_64
        } else if cfg!(target_arch = "aarch64") {
            Arch::Aarch64
        } else {
            Arch::Unknown
        }
    }
}

/// Result of a single firmware check.
#[derive(Debug, Clone, Serialize)]
pub struct CheckResult {
    pub id: &'static str,
    pub name: &'static str,
    pub status: CheckStatus,
    /// How confident we are in this finding (0.0–1.0).
    ///
    /// Combines two dimensions:
    /// - **impact**: how bad is it if this is compromised (SMRAM unlock = 1.0, TPM missing = 0.3)
    /// - **certainty**: how sure we are the reading is accurate (MSR read = 1.0, heuristic = 0.6)
    ///
    /// `confidence = impact × certainty`
    pub confidence: f64,
    pub detail: String,
}

/// Status of a firmware check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum CheckStatus {
    /// Hardware/firmware is in expected secure state.
    Secure,
    /// Potential issue detected — needs investigation.
    Warning,
    /// Definite security problem — firmware may be compromised.
    Critical,
    /// Check could not run (missing permissions, unsupported hardware).
    Unavailable,
}

/// Build a confidence score from impact and certainty.
///
/// - `impact`: 0.0–1.0, how severe the finding is (1.0 = total compromise)
/// - `certainty`: 0.0–1.0, how reliable the reading is (1.0 = hardware register)
pub fn confidence(impact: f64, certainty: f64) -> f64 {
    (impact * certainty).clamp(0.0, 1.0)
}

/// Run all available firmware checks for the current architecture.
pub fn full_audit() -> FirmwareReport {
    let arch = Arch::current();
    let mut checks = Vec::new();

    // MSR checks (x86_64 only).
    checks.push(msr::check_smram_lock());
    checks.push(msr::check_smi_count());

    // UEFI checks.
    checks.push(uefi::check_secure_boot());
    checks.push(uefi::check_bios_info());

    // TPM checks.
    checks.push(tpm::check_tpm_present());
    checks.push(tpm::check_pcr_values());

    // ACPI checks.
    checks.push(acpi::check_table_integrity());

    // SPI flash checks.
    checks.push(spi::check_flash_baseline());

    // Chronomancy — timing-based attestation (universal, no hardware needed).
    checks.push(timing::check_timing_attestation());
    checks.push(timing::check_hwlat());
    checks.push(timing::check_ima_log());

    // SMI anomaly.
    checks.push(smi::check_smi_rate());

    // CPU microcode verification.
    checks.push(microcode::check_microcode());

    // Kernel integrity.
    checks.push(kintegrity::check_modules());
    checks.push(kintegrity::check_kallsyms());
    checks.push(kintegrity::check_kernel_version());

    // Software measurement chain (PCR-like, no TPM needed).
    checks.push(measurement_chain::check_measurement_chain());

    // Kernel text integrity (rootkit inline hook detection).
    checks.push(ktext::check_kernel_text());

    // eBPF program audit (VoidLink defense).
    checks.push(ebpf_audit::check_ebpf_inventory());

    // CPU feature flags + hypervisor detection (Blue Pill defense).
    checks.push(cpu_features::check_cpu_security_features());
    checks.push(cpu_features::check_hypervisor());

    // Load baseline for drift detection + correlation.
    let baseline_path = baseline::FirmwareBaseline::default_path();
    let drift = baseline::FirmwareBaseline::load(&baseline_path)
        .ok()
        .map(|b| baseline::detect_drift(&b));

    // Temporary report for correlation (trust_score updated below).
    let mut report = FirmwareReport {
        ts: ::chrono::Utc::now(),
        arch,
        trust_score: 1.0,
        checks,
        correlated_threats: Vec::new(),
    };

    // Run correlation engine.
    report.correlated_threats = correlator::correlate(&report, drift.as_ref());

    // Trust score: the worst signal wins (check or correlated threat).
    let worst_check = report
        .checks
        .iter()
        .filter(|c| c.status == CheckStatus::Critical)
        .map(|c| c.confidence)
        .fold(0.0f64, f64::max);
    let worst_correlated = report
        .correlated_threats
        .iter()
        .map(|t| t.confidence)
        .fold(0.0f64, f64::max);
    let worst = worst_check.max(worst_correlated);
    report.trust_score = (1.0 - worst).clamp(0.0, 1.0);

    report
}
