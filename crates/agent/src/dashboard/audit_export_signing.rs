//! Spec 049 PR12 — detached ed25519 signing for the audit export.
//!
//! Operator clicks Export Audit CSV → the response is signed with
//! a local ed25519 key that the agent generates on first use and
//! stores at `<data_dir>/audit-signing.{key,pub}` with 0600 / 0644
//! permissions respectively. The MSSP shares the `.pub` once with
//! the client; every export carries a `# Signature` metadata line
//! the client verifies with stock tooling (openssl, cosign).
//!
//! Design choices:
//!
//! - **Key on disk, 0600 perms.** Operator can rotate by deleting
//!   the file; next export regenerates. Pre-PR12 there was no key,
//!   so no migration concern. Audit log lines record key generation.
//! - **Signature in the CSV metadata header**, not a sidecar
//!   `.sig` file. Operator emails ONE attachment; client verifies
//!   from that single file. Verification: strip the signature line,
//!   hash the remaining bytes, verify with the public key.
//! - **Public key surfaced via `/api/audit-signing/public-key`.**
//!   Shared ONCE between MSSP and client; the fingerprint is also
//!   embedded in every export's metadata so the client can detect
//!   key rotation by comparison.
//! - **ed25519-dalek v2** — already in workspace deps; no new
//!   supply-chain entry.

use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey, SECRET_KEY_LENGTH};
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

/// 32-byte ed25519 signing key file (operator-private).
pub(super) const KEY_FILE_NAME: &str = "audit-signing.key";
/// Public key file (sharable with the audit recipient).
pub(super) const PUB_FILE_NAME: &str = "audit-signing.pub";

/// Owned signing material — built once per `/api/export` call.
#[derive(Debug)]
pub(super) struct AuditSigner {
    pub(super) keypair: SigningKey,
}

impl AuditSigner {
    /// Load the persisted keypair from `<data_dir>/audit-signing.key`.
    /// Generates a fresh keypair on first use (file absent) and
    /// writes BOTH the private key (`.key`, 0600) and the public
    /// key (`.pub`, 0644). Returns `Err` only when filesystem I/O
    /// fails irrecoverably — the API handler treats `Err` as "skip
    /// signing this export, document the reason" so a corrupt key
    /// file does not break the audit export path entirely.
    pub(super) fn load_or_generate(data_dir: &Path) -> std::io::Result<Self> {
        let key_path = data_dir.join(KEY_FILE_NAME);
        if let Ok(bytes) = fs::read(&key_path) {
            if bytes.len() == SECRET_KEY_LENGTH {
                let arr: [u8; SECRET_KEY_LENGTH] = bytes
                    .as_slice()
                    .try_into()
                    .expect("len == SECRET_KEY_LENGTH checked above");
                return Ok(Self {
                    keypair: SigningKey::from_bytes(&arr),
                });
            }
            // Wrong length on disk: regenerate. Old key is moved
            // aside with a .bak suffix so the operator can recover
            // it manually if needed (e.g. they had a legitimate
            // 64-byte format from a different scheme).
            let bak = data_dir.join(format!("{KEY_FILE_NAME}.bak"));
            let _ = fs::rename(&key_path, bak);
        }
        // Fresh keypair.
        let keypair = SigningKey::generate(&mut OsRng);
        write_keypair_files(data_dir, &keypair)?;
        Ok(Self { keypair })
    }

    /// Sign `bytes` with the operator's private key. Returns a
    /// base64 (standard, no-padding) string suitable for embedding
    /// in a CSV `# Signature` metadata line.
    pub(super) fn sign_base64(&self, bytes: &[u8]) -> String {
        let sig = self.keypair.sign(bytes);
        STANDARD_NO_PAD.encode(sig.to_bytes())
    }

    /// Public key fingerprint — first 16 hex chars of SHA-256(pubkey).
    /// Embedded in every export so the client can detect key
    /// rotation by comparison against the `.pub` they have on file.
    pub(super) fn public_key_fingerprint(&self) -> String {
        let pk: VerifyingKey = self.keypair.verifying_key();
        let mut hasher = Sha256::new();
        hasher.update(pk.as_bytes());
        let digest = hasher.finalize();
        let hex: String = digest.iter().take(8).map(|b| format!("{b:02x}")).collect();
        hex
    }

    /// Raw public key bytes (32 bytes). The `/api/audit-signing/public-key`
    /// endpoint streams these as `application/octet-stream` so the
    /// client can save them as a file and feed directly to
    /// openssl / cosign.
    pub(super) fn public_key_bytes(&self) -> [u8; 32] {
        self.keypair.verifying_key().to_bytes()
    }

    /// Public key, base64-encoded one-line form (matches the `.pub`
    /// file written to disk). Convenience for endpoint handlers
    /// that want to inline the key in JSON.
    #[allow(dead_code)]
    pub(super) fn public_key_base64(&self) -> String {
        STANDARD_NO_PAD.encode(self.public_key_bytes())
    }
}

fn write_keypair_files(data_dir: &Path, keypair: &SigningKey) -> std::io::Result<()> {
    fs::create_dir_all(data_dir)?;

    // Private key: 32 bytes, 0600 perms on Unix. On Windows fall
    // back to default ACLs — the data dir itself should be locked
    // down by the operator anyway.
    let key_path = data_dir.join(KEY_FILE_NAME);
    let secret_bytes = keypair.to_bytes();
    fs::write(&key_path, secret_bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&key_path)?.permissions();
        perms.set_mode(0o600);
        fs::set_permissions(&key_path, perms)?;
    }

    // Public key: base64 line (matches the audit-signing.pub format
    // documented in the export's verification recipe).
    let pub_path = data_dir.join(PUB_FILE_NAME);
    let pub_b64 = STANDARD_NO_PAD.encode(keypair.verifying_key().to_bytes());
    let pub_content = format!("ed25519 {pub_b64} innerwarden-audit-export\n");
    fs::write(&pub_path, pub_content)?;

    Ok(())
}

/// Build the verification recipe lines embedded in the CSV
/// metadata header. Kept as a single helper so a future change to
/// the recipe touches one place and the anchor test catches it.
pub(super) fn verification_recipe_lines() -> Vec<String> {
    vec![
        "# To verify: strip the `# Signature` line, base64-decode the value,".to_string(),
        "# obtain the operator's audit-signing.pub (from /api/audit-signing/public-key),"
            .to_string(),
        "# verify with `openssl pkeyutl -verify -pubin -inkey <pubkey.pem> ...`".to_string(),
        "# or `cosign verify-blob --key <pubkey> --signature <sig.bin> <unsigned.csv>`."
            .to_string(),
    ]
}

/// Resolve the path to the persisted public-key file. Used by the
/// `/api/audit-signing/public-key` endpoint to stream the file.
pub(super) fn pub_key_path(data_dir: &Path) -> PathBuf {
    data_dir.join(PUB_FILE_NAME)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn load_or_generate_creates_both_files_on_first_use() {
        let dir = tempdir().expect("tempdir");
        let _signer = AuditSigner::load_or_generate(dir.path()).expect("signer");
        assert!(
            dir.path().join(KEY_FILE_NAME).exists(),
            "private key must be written to disk on first use"
        );
        assert!(
            dir.path().join(PUB_FILE_NAME).exists(),
            "public key must be written to disk on first use"
        );
    }

    #[test]
    fn load_or_generate_reuses_existing_key() {
        let dir = tempdir().expect("tempdir");
        let signer1 = AuditSigner::load_or_generate(dir.path()).expect("first");
        let signer2 = AuditSigner::load_or_generate(dir.path()).expect("second");
        // Public keys must match — same private key was reused.
        assert_eq!(
            signer1.public_key_bytes(),
            signer2.public_key_bytes(),
            "second call must reuse the persisted private key, not regenerate"
        );
    }

    #[cfg(unix)]
    #[test]
    fn private_key_file_has_0600_permissions_on_unix() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().expect("tempdir");
        let _signer = AuditSigner::load_or_generate(dir.path()).expect("signer");
        let meta = fs::metadata(dir.path().join(KEY_FILE_NAME)).expect("metadata");
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "private key MUST be 0600 (operator-only read)");
    }

    #[test]
    fn malformed_key_file_is_moved_aside_and_regenerated() {
        let dir = tempdir().expect("tempdir");
        // Write a deliberately-wrong-length key file.
        fs::write(dir.path().join(KEY_FILE_NAME), b"garbage").expect("seed");
        let _signer = AuditSigner::load_or_generate(dir.path()).expect("signer");
        // .bak file should now exist; new key file regenerated.
        assert!(
            dir.path().join(format!("{KEY_FILE_NAME}.bak")).exists(),
            "malformed key MUST be moved to .bak for operator recovery"
        );
        let new_key = fs::read(dir.path().join(KEY_FILE_NAME)).expect("new key");
        assert_eq!(new_key.len(), SECRET_KEY_LENGTH);
    }

    #[test]
    fn sign_base64_roundtrips_through_dalek_verification() {
        // Sanity check: the operator's claim is "sig over these
        // bytes verifies with the public key." Anchor the loop end
        // to end so a future refactor that emits a different
        // signature scheme is caught.
        use ed25519_dalek::Verifier;
        let dir = tempdir().expect("tempdir");
        let signer = AuditSigner::load_or_generate(dir.path()).expect("signer");
        let payload = b"the quick brown fox jumps over the lazy dog";
        let sig_b64 = signer.sign_base64(payload);
        let sig_bytes = STANDARD_NO_PAD
            .decode(&sig_b64)
            .expect("base64 decodes cleanly");
        let sig: ed25519_dalek::Signature =
            sig_bytes.as_slice().try_into().expect("sig is 64 bytes");
        signer
            .keypair
            .verifying_key()
            .verify(payload, &sig)
            .expect("ed25519 verify must succeed");
    }

    #[test]
    fn signature_differs_per_input() {
        let dir = tempdir().expect("tempdir");
        let signer = AuditSigner::load_or_generate(dir.path()).expect("signer");
        let s1 = signer.sign_base64(b"input a");
        let s2 = signer.sign_base64(b"input b");
        assert_ne!(s1, s2, "different inputs MUST produce different signatures");
    }

    #[test]
    fn public_key_fingerprint_is_16_hex_chars() {
        let dir = tempdir().expect("tempdir");
        let signer = AuditSigner::load_or_generate(dir.path()).expect("signer");
        let fp = signer.public_key_fingerprint();
        assert_eq!(fp.len(), 16, "fingerprint must be 16 hex chars");
        assert!(
            fp.chars().all(|c| c.is_ascii_hexdigit()),
            "fingerprint must be lowercase hex"
        );
    }

    #[test]
    fn public_key_bytes_are_32_bytes() {
        let dir = tempdir().expect("tempdir");
        let signer = AuditSigner::load_or_generate(dir.path()).expect("signer");
        let pk = signer.public_key_bytes();
        assert_eq!(pk.len(), 32, "ed25519 public key is 32 bytes");
    }

    #[test]
    fn pub_key_file_contains_base64_marker() {
        // The .pub file format is documented as `ed25519 <b64> innerwarden-audit-export`.
        // Anchor the format so a future change doesn't silently
        // break the verification recipe operators run on the client side.
        let dir = tempdir().expect("tempdir");
        let _signer = AuditSigner::load_or_generate(dir.path()).expect("signer");
        let content = fs::read_to_string(dir.path().join(PUB_FILE_NAME)).expect("pub file");
        assert!(
            content.starts_with("ed25519 "),
            "pub file must start with `ed25519 `"
        );
        assert!(
            content.trim_end().ends_with("innerwarden-audit-export"),
            "pub file must carry the agent identifier (comment field)"
        );
    }

    #[test]
    fn verification_recipe_lines_carry_both_toolings() {
        // The recipe should mention BOTH openssl and cosign so the
        // operator's MSSP client can pick whichever they have.
        let lines = verification_recipe_lines();
        let joined: String = lines.join(" ");
        assert!(joined.contains("openssl"));
        assert!(joined.contains("cosign"));
    }
}
