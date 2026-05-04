//! Symlink rejection on the agent binary path.
//!
//! Refusing to spawn from a symlink prevents a trivial swap-in-place attack
//! (`ln -sf /tmp/malicious /usr/local/bin/innerwarden-agent`). The free
//! supervisor performs this check at construction AND before every spawn,
//! so attackers who introduce the symlink after boot are caught on the next
//! restart cycle.
//!
//! This intentionally does NOT compute a content hash. Hash-based integrity
//! lives in the proprietary supervisor wrapper, where it gates the restart
//! via `RestartHook` rather than by replacing this check.

use std::path::Path;

use anyhow::{bail, Context, Result};

/// Returns `Ok(())` if `path` is a regular file (or non-existent - that is
/// the spawner's job to surface), `Err` if it is a symlink.
pub fn ensure_not_symlink(path: &Path) -> Result<()> {
    let meta =
        std::fs::symlink_metadata(path).with_context(|| format!("stat: {}", path.display()))?;
    if meta.file_type().is_symlink() {
        bail!(
            "agent binary is a symlink - refusing to spawn from it: {}",
            path.display()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_regular_file() {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("real");
        std::fs::write(&bin, b"content").unwrap();
        assert!(ensure_not_symlink(&bin).is_ok());
    }

    #[test]
    fn rejects_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        let link = dir.path().join("link");
        std::fs::write(&real, b"content").unwrap();
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let err = ensure_not_symlink(&link).unwrap_err();
        assert!(format!("{:#}", err).contains("symlink"));
    }

    #[test]
    fn surfaces_missing_path() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("nope");
        assert!(ensure_not_symlink(&missing).is_err());
    }
}
