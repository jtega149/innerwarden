// Migrated from standalone repo — suppress cosmetic clippy lints.
#![allow(clippy::all, dead_code, unused_variables)]

//! InnerWarden Hypervisor — Ring -1 security monitoring.
//!
//! Monitors and inspects the hypervisor layer without being a hypervisor.
//! Detects hidden hypervisors, monitors KVM operations, analyzes VM exits,
//! and provides Virtual Machine Introspection capabilities.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────┐
//! │  Ring 3 — Application                   │
//! │  └─ InnerWarden agent-guard             │
//! ├─────────────────────────────────────────┤
//! │  Ring 0 — Kernel                        │
//! │  └─ InnerWarden eBPF (40 hooks)         │
//! ├─────────────────────────────────────────┤
//! │  Ring -1 — Hypervisor            ← US   │
//! │  └─ innerwarden-hypervisor              │
//! │     ├─ Deep hypervisor detection        │
//! │     ├─ CPUID fingerprinting             │
//! │     ├─ KVM perf event monitoring        │
//! │     ├─ VM exit analysis                 │
//! │     ├─ Timing-based VM detection        │
//! │     └─ Hypervisor integrity checks      │
//! ├─────────────────────────────────────────┤
//! │  Ring -2 — Firmware                     │
//! │  └─ innerwarden-smm (21 checks)        │
//! └─────────────────────────────────────────┘
//! ```

pub mod cpuid;
pub mod descriptor_tables;
pub mod detect;
pub mod kvm;
pub mod memory_probe;
pub mod probes;
pub mod timing;
pub mod vmexit;

use serde::Serialize;

/// Overall hypervisor security report.
#[derive(Debug, Clone, Serialize)]
pub struct HypervisorReport {
    pub ts: chrono::DateTime<chrono::Utc>,
    pub environment: Environment,
    /// Trust score (0.0 = compromised, 1.0 = trusted).
    pub trust_score: f64,
    pub checks: Vec<CheckResult>,
    /// VM detection verdict from comprehensive probe scoring.
    pub vm_verdict: probes::VmVerdict,
    /// Individual probe results (evidence chain).
    pub probe_results: Vec<probes::ProbeResult>,
}

/// Execution environment type.
#[derive(Debug, Clone, Serialize)]
pub enum Environment {
    /// Running directly on hardware (no hypervisor detected).
    BareMetal,
    /// Running inside a known hypervisor.
    VirtualMachine { hypervisor: String },
    /// Running as a hypervisor host (KVM host).
    HypervisorHost { vm_count: usize },
    /// Hypervisor detected but unidentified (suspicious).
    UnknownHypervisor,
}

/// Result of a single check.
#[derive(Debug, Clone, Serialize)]
pub struct CheckResult {
    pub id: &'static str,
    pub name: &'static str,
    pub status: CheckStatus,
    pub confidence: f64,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum CheckStatus {
    Secure,
    Warning,
    Critical,
    Unavailable,
}

pub fn confidence(impact: f64, certainty: f64) -> f64 {
    (impact * certainty).clamp(0.0, 1.0)
}

/// Run all hypervisor checks.
pub fn full_audit() -> HypervisorReport {
    let mut checks = Vec::new();

    // CPUID-based hypervisor detection.
    checks.push(cpuid::check_hypervisor_cpuid());
    checks.push(cpuid::check_cpuid_consistency());

    // Deep detection via timing.
    checks.push(timing::check_timing_detection());

    // KVM host monitoring.
    checks.push(kvm::check_kvm_host());
    checks.push(kvm::check_kvm_modules());

    // VM exit analysis (if KVM host).
    checks.push(vmexit::check_vm_exit_stats());

    // Memory-based VM detection (EPT/stage-2 overhead).
    checks.push(memory_probe::check_memory_vm_detection());

    // Interrupt delivery analysis.
    checks.push(descriptor_tables::check_interrupt_analysis());

    // Descriptor table check (x86 SIDT/SGDT Red Pill).
    checks.push(descriptor_tables::check_descriptor_tables());

    // Run comprehensive VM detection probes (20 probes).
    let probe_results = probes::run_all_probes();
    let vm_verdict = probes::compute_verdict(&probe_results);

    // Determine environment from probes + checks.
    let environment = if vm_verdict.is_vm {
        match &vm_verdict.brand {
            Some(brand) => Environment::VirtualMachine {
                hypervisor: brand.clone(),
            },
            None => Environment::UnknownHypervisor,
        }
    } else {
        detect::determine_environment(&checks)
    };

    // Trust score.
    let worst = checks
        .iter()
        .filter(|c| c.status == CheckStatus::Critical)
        .map(|c| c.confidence)
        .fold(0.0f64, f64::max);
    let trust_score = (1.0 - worst).clamp(0.0, 1.0);

    HypervisorReport {
        ts: chrono::Utc::now(),
        environment,
        trust_score,
        checks,
        vm_verdict,
        probe_results,
    }
}
