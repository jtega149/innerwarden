//! `innerwarden chain-break` subcommands.
//!
//! Operator-facing CLI for the decisions hash-chain audit (PR #357
//! `chain_break_audit` table). Two subcommands:
//!
//!   - `register` — document an intentional break range so the
//!     hourly maintenance verifier stops alerting. Used after manual
//!     SQL recovery, bulk imports, schema rewrites — any operation
//!     that inserts decision rows without going through the
//!     `Store::insert_decision` API.
//!
//!   - `list` — show every registered break with the operator,
//!     reason, and rowid range. Mirrors `Store::list_chain_breaks`
//!     for command-line audit.

use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result};
use innerwarden_store::Store;

use super::circuit::resolve_store_dir;

/// Register an intentional break in the decisions hash chain.
///
/// Forwards to `Store::register_chain_break`. The store rejects
/// inverted ranges; the verifier reads the table on every hourly
/// tick (no agent restart needed). Output is the new break record's
/// id so an operator script can reference it later.
pub(crate) fn cmd_chain_break_register(
    agent_config: &Path,
    data_dir: &Path,
    rowid_start: i64,
    rowid_end: i64,
    operator: &str,
    reason: &str,
    json: bool,
) -> Result<()> {
    let dir = resolve_store_dir(agent_config, data_dir);
    let store =
        Store::open(&dir).with_context(|| format!("open sqlite store at {}", dir.display()))?;
    let id = store
        .register_chain_break(rowid_start, rowid_end, operator, reason, None)
        .with_context(|| {
            format!("register chain break for rowid range [{rowid_start}, {rowid_end}]")
        })?;
    let mut out = std::io::stdout();
    if json {
        writeln!(
            out,
            "{}",
            serde_json::json!({
                "id": id,
                "rowid_start": rowid_start,
                "rowid_end": rowid_end,
                "operator": operator,
                "reason": reason,
                "rows_documented": rowid_end - rowid_start + 1,
            })
        )?;
    } else {
        writeln!(
            out,
            "Registered chain break #{id}: rows {rowid_start}..{rowid_end} ({} rows) by {operator}",
            rowid_end - rowid_start + 1
        )?;
        writeln!(out, "Reason: {reason}")?;
        writeln!(
            out,
            "The hourly hash-chain verifier will skip this range on the next tick."
        )?;
    }
    Ok(())
}

/// List every registered chain break.
///
/// Pretty-print by default; `--json` for machine-readable output.
pub(crate) fn cmd_chain_break_list(agent_config: &Path, data_dir: &Path, json: bool) -> Result<()> {
    let dir = resolve_store_dir(agent_config, data_dir);
    let store =
        Store::open(&dir).with_context(|| format!("open sqlite store at {}", dir.display()))?;
    let records = store
        .list_chain_breaks()
        .context("read chain_break_audit table")?;
    let mut out = std::io::stdout();
    if json {
        let arr: Vec<_> = records
            .iter()
            .map(|r| {
                serde_json::json!({
                    "id": r.id,
                    "rowid_start": r.rowid_start,
                    "rowid_end": r.rowid_end,
                    "rows_documented": r.rowid_end - r.rowid_start + 1,
                    "registered_at": r.registered_at,
                    "operator": r.operator,
                    "reason": r.reason,
                    "prev_chain_end_hash": r.prev_chain_end_hash,
                })
            })
            .collect();
        writeln!(out, "{}", serde_json::Value::Array(arr))?;
    } else if records.is_empty() {
        writeln!(
            out,
            "No chain breaks registered. Hash chain is fully verified."
        )?;
    } else {
        writeln!(out, "{} registered chain break(s):", records.len())?;
        writeln!(out)?;
        for r in &records {
            writeln!(
                out,
                "#{}  rows {}..{} ({} rows)",
                r.id,
                r.rowid_start,
                r.rowid_end,
                r.rowid_end - r.rowid_start + 1
            )?;
            writeln!(out, "    registered: {}", r.registered_at)?;
            writeln!(out, "    operator:   {}", r.operator)?;
            writeln!(out, "    reason:     {}", r.reason)?;
            if let Some(h) = &r.prev_chain_end_hash {
                writeln!(out, "    prev hash:  {h}")?;
            }
            writeln!(out)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn temp_paths() -> (TempDir, std::path::PathBuf) {
        let td = TempDir::new().unwrap();
        let cfg = td.path().join("agent.toml");
        (td, cfg)
    }

    fn assert_single_record(
        dir: &Path,
        rowid_start: i64,
        rowid_end: i64,
        operator: &str,
        reason: &str,
    ) {
        let store = Store::open(dir).unwrap();
        let records = store.list_chain_breaks().unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].rowid_start, rowid_start);
        assert_eq!(records[0].rowid_end, rowid_end);
        assert_eq!(records[0].operator, operator);
        assert_eq!(records[0].reason, reason);
    }

    #[test]
    fn register_then_list_round_trip() {
        let (td, cfg) = temp_paths();
        cmd_chain_break_register(
            &cfg,
            td.path(),
            100,
            199,
            "test-op",
            "regression test",
            false,
        )
        .unwrap();
        // List must include the registered range.
        assert_single_record(td.path(), 100, 199, "test-op", "regression test");
    }

    #[test]
    fn register_json_mode_persists_same_record() {
        let (td, cfg) = temp_paths();

        cmd_chain_break_register(
            &cfg,
            td.path(),
            7,
            7,
            "json-op",
            "single row recovery",
            true,
        )
        .unwrap();

        assert_single_record(td.path(), 7, 7, "json-op", "single row recovery");
    }

    #[test]
    fn register_multiple_ranges_then_list_succeeds_in_both_modes() {
        let (td, cfg) = temp_paths();

        cmd_chain_break_register(&cfg, td.path(), 1, 2, "alice", "manual import", false).unwrap();
        cmd_chain_break_register(&cfg, td.path(), 10, 12, "bob", "schema repair", true).unwrap();

        cmd_chain_break_list(&cfg, td.path(), false).unwrap();
        cmd_chain_break_list(&cfg, td.path(), true).unwrap();

        let store = Store::open(td.path()).unwrap();
        let records = store.list_chain_breaks().unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].rowid_start, 1);
        assert_eq!(records[0].rowid_end, 2);
        assert_eq!(records[0].operator, "alice");
        assert_eq!(records[1].rowid_start, 10);
        assert_eq!(records[1].rowid_end, 12);
        assert_eq!(records[1].operator, "bob");
    }

    #[test]
    fn register_rejects_inverted_range() {
        let (td, cfg) = temp_paths();
        let err =
            cmd_chain_break_register(&cfg, td.path(), 500, 100, "test-op", "should fail", false)
                .unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("invalid range") || msg.contains("rowid_end"),
            "expected invalid-range error, got: {msg}"
        );
    }

    #[test]
    fn list_empty_database_has_no_records() {
        let (td, cfg) = temp_paths();
        // Just calling list on a fresh DB should not error.
        cmd_chain_break_list(&cfg, td.path(), true).unwrap();
        let store = Store::open(td.path()).unwrap();
        let records = store.list_chain_breaks().unwrap();
        assert_eq!(records.len(), 0);
    }
}
