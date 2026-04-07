//! Environment determination — combine all signals to classify the system.

use crate::{CheckResult, CheckStatus, Environment};

/// Determine the execution environment from check results.
pub fn determine_environment(checks: &[CheckResult]) -> Environment {
    let hv_cpuid = checks.iter().find(|c| c.id == "HV-001");
    let kvm_host = checks.iter().find(|c| c.id == "KVM-001");

    // KVM host running VMs.
    if let Some(kvm) = kvm_host {
        if kvm.status == CheckStatus::Secure {
            let vm_count = kvm
                .detail
                .split("running")
                .nth(1)
                .and_then(|s| s.trim().split_whitespace().next())
                .and_then(|n| n.parse::<usize>().ok())
                .unwrap_or(0);
            return Environment::HypervisorHost { vm_count };
        }
    }

    // VM guest.
    if let Some(hv) = hv_cpuid {
        if hv.detail.contains("hypervisor detected:") {
            let name = hv
                .detail
                .split("hypervisor detected: ")
                .nth(1)
                .and_then(|s| s.split('.').next())
                .unwrap_or("unknown")
                .to_string();
            return Environment::VirtualMachine { hypervisor: name };
        }
        if hv.status == CheckStatus::Warning && hv.detail.contains("UNRECOGNIZED") {
            return Environment::UnknownHypervisor;
        }
    }

    Environment::BareMetal
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bare_metal_when_no_hypervisor() {
        let checks = vec![CheckResult {
            id: "HV-001",
            name: "test",
            status: CheckStatus::Secure,
            confidence: 0.5,
            detail: "no hypervisor flag".into(),
        }];
        assert!(matches!(
            determine_environment(&checks),
            Environment::BareMetal
        ));
    }

    #[test]
    fn vm_when_hypervisor_detected() {
        let checks = vec![CheckResult {
            id: "HV-001",
            name: "test",
            status: CheckStatus::Secure,
            confidence: 0.5,
            detail: "hypervisor detected: KVM/QEMU. Vendor: QEMU".into(),
        }];
        assert!(matches!(
            determine_environment(&checks),
            Environment::VirtualMachine { .. }
        ));
    }
}
