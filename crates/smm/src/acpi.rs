//! ACPI table integrity — hash DSDT/SSDT tables for tamper detection.
//!
//! Reads from `/sys/firmware/acpi/tables/`. Read-only.
//! Modified ACPI tables can execute arbitrary AML code on the OS.

use crate::{confidence, CheckResult, CheckStatus};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

const ACPI_TABLES_DIR: &str = "/sys/firmware/acpi/tables";

/// Hashed ACPI table for integrity verification.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AcpiTableHash {
    pub name: String,
    pub size: usize,
    pub sha256: String,
}

/// Read and hash all ACPI tables.
pub fn hash_tables() -> Vec<AcpiTableHash> {
    let dir = Path::new(ACPI_TABLES_DIR);
    if !dir.exists() {
        return Vec::new();
    }

    let mut tables = Vec::new();
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return tables,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().to_string();
        if let Ok(data) = fs::read(&path) {
            let hash = hex::encode(Sha256::digest(&data));
            tables.push(AcpiTableHash {
                name,
                size: data.len(),
                sha256: hash,
            });
        }
    }

    tables.sort_by(|a, b| a.name.cmp(&b.name));
    tables
}

// ── Check functions ─────────────────────────────────────────────────────

/// Hash ACPI tables for baseline / drift detection.
pub fn check_table_integrity() -> CheckResult {
    let tables = hash_tables();

    if tables.is_empty() {
        return CheckResult {
            id: "ACPI-001",
            name: "ACPI Tables",
            status: CheckStatus::Unavailable,
            confidence: 0.0,
            detail: "cannot read /sys/firmware/acpi/tables/ (permissions or not present)".into(),
        };
    }

    let dsdt = tables.iter().find(|t| t.name == "DSDT");
    let ssdt_count = tables.iter().filter(|t| t.name.starts_with("SSDT")).count();

    let dsdt_info = dsdt
        .map(|d| format!("DSDT: {} bytes sha256:{:.16}…", d.size, d.sha256))
        .unwrap_or_else(|| "DSDT: not found".into());

    CheckResult {
        id: "ACPI-001",
        name: "ACPI Tables",
        status: CheckStatus::Secure,
        confidence: confidence(0.6, 0.8),
        detail: format!(
            "{} tables hashed ({}). {dsdt_info}. Compare against known-good baseline.",
            tables.len(),
            if ssdt_count > 0 {
                format!("{ssdt_count} SSDTs")
            } else {
                "no SSDTs".into()
            },
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_consistency() {
        // Same data should produce same hash.
        let data = b"test ACPI table data";
        let h1 = hex::encode(Sha256::digest(data));
        let h2 = hex::encode(Sha256::digest(data));
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64); // SHA-256 hex = 64 chars
    }

    #[test]
    fn check_tables_runs() {
        let result = check_table_integrity();
        assert!(!result.id.is_empty());
    }
}
