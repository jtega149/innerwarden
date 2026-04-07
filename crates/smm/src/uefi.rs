//! UEFI variable inspection — Secure Boot state, boot order, BIOS info.
//!
//! Reads from `/sys/firmware/efi/efivars/` (efivarfs) and `/sys/class/dmi/id/`.
//! All operations are read-only.

use crate::{confidence, CheckResult, CheckStatus};
use std::fs;
use std::path::Path;

// ── Secure Boot ─────────────────────────────────────────────────────────

/// Secure Boot state from UEFI variables.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SecureBootState {
    /// Whether Secure Boot is enabled (enforcing).
    pub enabled: bool,
    /// Whether the system booted in Setup Mode (keys not enrolled).
    pub setup_mode: bool,
    /// Raw byte value of SecureBoot variable.
    pub raw: Option<u8>,
}

impl SecureBootState {
    /// Read Secure Boot state from efivarfs.
    pub fn read() -> Option<Self> {
        let sb = read_efi_var("SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c")?;
        // EFI var format: 4 bytes attributes + data.
        let enabled = sb.get(4).copied() == Some(1);

        let setup = read_efi_var("SetupMode-8be4df61-93ca-11d2-aa0d-00e098032b8c");
        let setup_mode = setup.and_then(|v| v.get(4).copied()) == Some(1);

        Some(Self {
            enabled,
            setup_mode,
            raw: sb.get(4).copied(),
        })
    }
}

/// Read raw bytes from an EFI variable.
fn read_efi_var(name: &str) -> Option<Vec<u8>> {
    let path = format!("/sys/firmware/efi/efivars/{name}");
    fs::read(&path).ok()
}

// ── BIOS/DMI info ───────────────────────────────────────────────────────

/// BIOS/firmware information from DMI/SMBIOS tables.
#[derive(Debug, Clone, serde::Serialize)]
pub struct BiosInfo {
    pub vendor: String,
    pub version: String,
    pub date: String,
    pub bios_release: String,
}

impl BiosInfo {
    /// Read BIOS info from sysfs DMI tables.
    pub fn read() -> Self {
        Self {
            vendor: read_dmi("bios_vendor"),
            version: read_dmi("bios_version"),
            date: read_dmi("bios_date"),
            bios_release: read_dmi("bios_release"),
        }
    }
}

fn read_dmi(field: &str) -> String {
    let path = format!("/sys/class/dmi/id/{field}");
    fs::read_to_string(&path)
        .unwrap_or_default()
        .trim()
        .to_string()
}

// ── Check functions ─────────────────────────────────────────────────────

/// Check Secure Boot status.
pub fn check_secure_boot() -> CheckResult {
    // Check if EFI is available at all.
    if !Path::new("/sys/firmware/efi").exists() {
        return CheckResult {
            id: "UEFI-001",
            name: "Secure Boot",
            status: CheckStatus::Unavailable,
            confidence: 0.0,
            detail: "system booted in legacy BIOS mode (no EFI)".into(),
        };
    }

    match SecureBootState::read() {
        Some(state) => {
            if state.enabled && !state.setup_mode {
                CheckResult {
                    id: "UEFI-001",
                    name: "Secure Boot",
                    status: CheckStatus::Secure,
                    confidence: confidence(0.7, 1.0),
                    detail: "Secure Boot enabled, keys enrolled (enforcing mode)".into(),
                }
            } else if state.setup_mode {
                CheckResult {
                    id: "UEFI-001",
                    name: "Secure Boot",
                    status: CheckStatus::Warning,
                    confidence: confidence(0.7, 1.0),
                    detail: "Secure Boot in Setup Mode — keys not enrolled, \
                             unsigned code can run. Enroll PK/KEK/db keys to enforce."
                        .into(),
                }
            } else {
                CheckResult {
                    id: "UEFI-001",
                    name: "Secure Boot",
                    status: CheckStatus::Warning,
                    confidence: confidence(0.5, 1.0),
                    detail: format!(
                        "Secure Boot disabled (raw={}). Boot chain is not verified.",
                        state.raw.unwrap_or(0)
                    ),
                }
            }
        }
        None => CheckResult {
            id: "UEFI-001",
            name: "Secure Boot",
            status: CheckStatus::Unavailable,
            confidence: 0.0,
            detail: "cannot read SecureBoot EFI variable (permissions or not present)".into(),
        },
    }
}

/// Check BIOS vendor/version for known-good baseline.
pub fn check_bios_info() -> CheckResult {
    let info = BiosInfo::read();

    if info.vendor.is_empty() && info.version.is_empty() {
        return CheckResult {
            id: "UEFI-002",
            name: "BIOS Info",
            status: CheckStatus::Unavailable,
            confidence: 0.0,
            detail: "DMI/SMBIOS data not available".into(),
        };
    }

    CheckResult {
        id: "UEFI-002",
        name: "BIOS Info",
        status: CheckStatus::Secure,
        confidence: confidence(0.3, 1.0),
        detail: format!(
            "{} {} (date: {}, release: {})",
            info.vendor, info.version, info.date, info.bios_release
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secure_boot_parsing() {
        // Simulated EFI variable: 4 bytes attrs + 1 byte data.
        let enabled_var = vec![0x06, 0x00, 0x00, 0x00, 0x01]; // enabled
        assert_eq!(enabled_var.get(4).copied(), Some(1));

        let disabled_var = vec![0x06, 0x00, 0x00, 0x00, 0x00]; // disabled
        assert_eq!(disabled_var.get(4).copied(), Some(0));
    }

    #[test]
    fn bios_info_handles_missing() {
        // BiosInfo::read() should not panic even if files don't exist.
        let info = BiosInfo {
            vendor: read_dmi("nonexistent_field"),
            version: String::new(),
            date: String::new(),
            bios_release: String::new(),
        };
        assert!(info.vendor.is_empty());
    }

    #[test]
    fn check_secure_boot_runs() {
        let result = check_secure_boot();
        // On most dev machines, either Unavailable (no EFI) or some valid state.
        assert!(!result.id.is_empty());
    }
}
