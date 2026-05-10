# Supply Chain Security

Inner Warden is a Linux security daemon that runs with root privileges. The install path matters as much as the runtime. This page documents what every release ships, how to verify it, and what is and is not guaranteed.

The framing principle: do not say "signed" anywhere unless the path actually verifies a signature. Trust is built by closing the gap between claim and check.

---

## How Inner Warden is built

- Releases are cut from protected tags (`vX.Y.Z`).
- The release workflow is `.github/workflows/release.yml`. GitHub Actions referenced from that workflow are pinned by SHA, not by tag.
- Each release builds Linux (`x86_64`, `aarch64`) and macOS (`x86_64`, `aarch64`) binaries. Linux builds include a Zig-based static linker pass for portability.
- The workflow runs `cargo test --workspace` and the security workflow gates (cargo-deny, secret scan, dep audit) before publishing artifacts.
- Every release attaches a [GitHub Artifact Attestation](https://docs.github.com/en/actions/security-guides/using-artifact-attestations-to-establish-provenance-for-builds) to the **6 Linux binaries** (sensor + agent + ctl × x86_64/aarch64). The attestation is a SLSA v1 provenance record signed by GitHub's keyless identity through Sigstore. macOS binaries and the sidecar files (`.sha256`, `.sig`, `SHA256SUMS`, `install.sh`) are not currently attested individually — extending attestation to them is on the deferred roadmap.

---

## What every stable release ships

| Artifact | Purpose |
|---|---|
| `innerwarden-{sensor,agent,ctl}-linux-{x86_64,aarch64}` | The release binaries |
| `…<binary>.sha256` | Per-binary SHA-256, signed-channel guarantee on download integrity |
| `…<binary>.sig` | Per-binary Ed25519 signature against the embedded release public key (Spec 048) |
| `SHA256SUMS` | Aggregate manifest of every release artifact's SHA-256 |
| `SHA256SUMS.sig` | GPG signature over `SHA256SUMS` (manual verification path) |
| `install.sh` | The convenience installer |
| GitHub Artifact Attestation | SLSA v1 provenance for the 6 Linux binaries, verifiable via `gh attestation verify` (sidecars not individually attested) |

If you see a stable release missing the `.sig` files, treat it as a release-pipeline regression and report it. Spec 048 made the installer and the `innerwarden upgrade` command fail-closed when stable releases lack signatures.

---

## The release public key

Inner Warden uses an Ed25519 key for raw-binary signing. The key is embedded in two places that must agree:

- `crates/ctl/src/upgrade.rs::RELEASE_PUBLIC_KEY_B64`
- `install.sh::INNERWARDEN_RELEASE_PEM`

Active key:

```text
SHA-256 fingerprint:    9cba21f2d6a45e7f58edd9b840e152b5c7d0ee6e511bb6835037088c6a89143f
Base64 (raw 32 bytes):  yf58o+MQluj7MwTlW+hB9tfLQk9df0iUeGxPbmAIFM8=
PEM (standard SPKI):    -----BEGIN PUBLIC KEY-----
                        MCowBQYDK2VwAyEAyf58o+MQluj7MwTlW+hB9tfLQk9df0iUeGxPbmAIFM8=
                        -----END PUBLIC KEY-----
```

If a future release rotates this key, the active fingerprint here changes and the prior key is moved to a "Retired keys" section. A rotation requires a coordinated installer + ctl release; the existence of two embedding sites is intentional.

The key currently lives in the `RELEASE_SIGNING_KEY` GitHub Actions secret, restricted to the release workflow environment. The corresponding private key has not yet been moved to hardware-backed signing or split-custody. That is a known limit, captured in "Current limits" below.

### GPG release key (signs `SHA256SUMS.sig`)

A separate GPG identity signs the aggregate `SHA256SUMS` manifest for the manual-verification path. Generated 2026-05-10 alongside the Spec 048 release pipeline.

```text
GPG identity:        InnerWarden Release Signing <release@innerwarden.com>
Algorithm:           RSA 4096
Key fingerprint:     503A ACC7 8B1F E274 7B1F  1935 22D0 44AC 0848 6799
Long key id:         22D044AC08486799
Created:             2026-05-10
Expires:             2031-05-09 (5 years)
```

To verify `SHA256SUMS.sig` manually, import the public key from this repository or from a public keyserver and run `gpg --verify SHA256SUMS.sig SHA256SUMS`. The exported public key block is published alongside this doc once the first stable release post-Spec-048 ships.

The private key lives in the `RELEASE_GPG_KEY` GitHub Actions secret and is used only by the release workflow's "Sign SHA256SUMS with GPG" step (gated to stable tags). Like the Ed25519 key, it has not yet been moved to hardware-backed signing.

---

## Manual verification recipe

This is the path a cautious operator follows before installing.

```bash
VERSION=v0.13.1
ARCH=x86_64

# 1. Download the binary, the SHA sidecar, and the signature sidecar.
curl -LO "https://github.com/InnerWarden/innerwarden/releases/download/${VERSION}/innerwarden-ctl-linux-${ARCH}"
curl -LO "https://github.com/InnerWarden/innerwarden/releases/download/${VERSION}/innerwarden-ctl-linux-${ARCH}.sha256"
curl -LO "https://github.com/InnerWarden/innerwarden/releases/download/${VERSION}/innerwarden-ctl-linux-${ARCH}.sig"

# 2. Verify SHA-256 (catches corruption + truncation + redirected download).
sha256sum -c "innerwarden-ctl-linux-${ARCH}.sha256"

# 3. Verify the Ed25519 signature against the release key.
cat <<'EOF' > /tmp/innerwarden-release.pem
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAyf58o+MQluj7MwTlW+hB9tfLQk9df0iUeGxPbmAIFM8=
-----END PUBLIC KEY-----
EOF

base64 -d "innerwarden-ctl-linux-${ARCH}.sig" > /tmp/innerwarden-ctl.sigbin
openssl pkeyutl -verify -pubin -inkey /tmp/innerwarden-release.pem \
    -rawin -in "innerwarden-ctl-linux-${ARCH}" \
    -sigfile /tmp/innerwarden-ctl.sigbin

# 4. Verify GitHub Artifact Attestation (SLSA v1 provenance, signed by
#    GitHub's keyless OIDC identity through Sigstore).
gh attestation verify "innerwarden-ctl-linux-${ARCH}" \
    --repo InnerWarden/innerwarden

# 5. (Optional) Verify the aggregate manifest signature.
curl -LO "https://github.com/InnerWarden/innerwarden/releases/download/${VERSION}/SHA256SUMS"
curl -LO "https://github.com/InnerWarden/innerwarden/releases/download/${VERSION}/SHA256SUMS.sig"
gpg --verify SHA256SUMS.sig SHA256SUMS
```

If steps 2-4 all succeed, the binary is the one InnerWarden published. Step 5 adds an out-of-band check via a separate GPG identity for the aggregate manifest.

---

## How `curl | sudo bash` verifies

The convenience installer at `install.sh` runs the same checks as the manual recipe, automatically:

1. SHA-256 against the per-binary `.sha256` sidecar.
2. Ed25519 signature against the embedded `INNERWARDEN_RELEASE_PEM`, using `openssl pkeyutl -verify -rawin`.
3. Aborts on missing or invalid signatures for stable releases. There are two override env vars (deliberately named to be scary) for emergencies:

| Env var | Behaviour |
|---|---|
| `INNERWARDEN_INSECURE_SKIP_SIG_VERIFY=1` | Bypass Ed25519 verification entirely. Use only during migration from a pre-Spec-048 release. The installer prints a noisy warning when this is set. |
| `INNERWARDEN_ALLOW_UNSIGNED_CANARY=1` | Required for canary releases (which currently ship without signatures). Stable releases ignore this flag. |

The installer requires `openssl >= 3.0` for the Ed25519 verification path. Ubuntu 22.04+, Rocky 9+, Fedora 36+, and Debian 12+ all ship a compatible openssl in the base system. Older distros (notably Ubuntu 20.04 with stock openssl 1.1.x) hit a precondition error with actionable guidance rather than silently degrading to SHA-only.

---

## How `innerwarden upgrade` verifies

The Rust updater (`crates/ctl/src/commands/update.rs`) verifies signatures using the same embedded key (`RELEASE_PUBLIC_KEY_B64` in `upgrade.rs`). Stable releases are fail-closed: the update aborts before any binary is replaced if the `.sig` is missing or invalid.

Two operator-visible escape-hatch flags exist:

| Flag | Behaviour |
|---|---|
| `--allow-unsigned-stable` | Allow stable releases that ship without a `.sig`. Use only when migrating from a pre-Spec-048 release or in air-gapped scenarios. The updater prints a noisy warning and the override is captured in CI release-anchor reviews. |
| `--allow-unsigned-canary` | Required to install any canary release (canary signing is on the follow-up roadmap; until then canary is opt-in unsafe). |

Pre-Spec-048 the updater warned-and-continued on missing signatures. The new fail-closed contract is anchored by `update_fails_closed_when_stable_release_has_no_sig` in the test suite.

---

## Current limits (honesty section)

These are intentional gaps. They are documented here because hiding them would be the exact kind of dishonesty Spec 048 is built to close.

- **Reproducible builds**: not yet implemented. Two CI runs for the same tag may produce different binary bytes (linker timestamps, dependency rebuild order). The signatures still bind a single attestation chain to the artifact, but byte-for-byte rebuild from source is not yet possible.
- **Hardware-backed release key**: the Ed25519 release private key is stored in a GitHub Actions secret. A compromised release workflow could sign a malicious artifact with the active key. Mitigation: the workflow is pinned by SHA, runs in a protected environment, and the key is set to a separate scope; but it is not split-custody and not in an HSM.
- **Reactive key rotation**: there is no scheduled rotation cadence. The key rotates when there is a reason to rotate (compromise, periodic refresh, or a new contributor with signing authority). When that happens, the prior key moves to a "Retired keys" section and the current installer + ctl ship with the new key embedded.
- **No `.deb` / `.rpm` packages**: every install is raw binary today. Native packages, signed APT/RPM repositories, official distro submissions, and reproducible builds are the next phases of the supply-chain trust roadmap. They land when there is concrete pull (an enterprise customer or a contributor shipping the work). Tracked as deferred from the external trust review (2026-05-10).
- **No SBOM today**: the `Cargo.lock` is the dependency manifest. A CycloneDX SBOM per release is on the deferred roadmap.
- **No Sigstore/Cosign artifact signing on releases**: only the GitHub Artifact Attestation flow uses Sigstore today. Cosign over the release archives + container images is on the deferred roadmap.
- **GitHub Artifact Attestation proves the artifact came from the release workflow**, not that the workflow could not be compromised. A workflow compromise is mitigated by the SHA-pinned actions, protected environments, and code review on the release path, but no provenance system survives an active CI compromise.
- **`curl | sudo bash` is still the recommended quick path** for labs and demos. It is not the only path; the manual recipe above and the `innerwarden upgrade` updater both verify signatures. The decision to keep `curl | sh` as the default install is pragmatic: Tailscale, Docker, Rust/Rustup, Bun, Caddy, Cloudflared, k3s, mise, and fly.io all use the same convention. Spec 048 closes the dishonesty around it (the script now actually verifies signatures), not the convention itself.

---

## Reporting a supply-chain issue

If you observe any of the following, report it as a security issue (`SECURITY.md` lists the channel):

- A stable release missing `.sig` files, `SHA256SUMS`, or the `SHA256SUMS.sig`.
- A signature verification failure on a release downloaded from the canonical URLs.
- A discrepancy between the embedded fingerprint in `crates/ctl/src/upgrade.rs::RELEASE_PUBLIC_KEY_B64` and the fingerprint listed on this page.
- A release that did not run the full release workflow (no GitHub Artifact Attestation).
- Suspected compromise of the release private key.

For non-security-critical drift (e.g., this page is out of date with a recent release), open an issue on the public tracker.

---

## Deferred roadmap (external trust review, 2026-05-10)

The supply-chain trust review proposed 12 phases. Spec 048 implemented the four highest-impact items. The remaining items are deferred until concrete demand exists:

| External review | Status | Trigger to start |
|---|---|---|
| `.deb` / `.rpm` packaging (SEC-DIST-004) | Deferred | First enterprise customer asking, or external contributor shipping the PR |
| APT / RPM signed repositories (SEC-DIST-005, 006) | Deferred | After packaging has been stable for ≥ 2 releases |
| SBOM generation (SEC-DIST-007) | Deferred | First security review request |
| Sigstore / Cosign for release artifacts (SEC-DIST-008) | Deferred | Same as SBOM |
| Hardware-backed signing key + rotation runbook (SEC-DIST-011) | Deferred | Before the first key rotation event |
| Module installer hardening (SEC-DIST-012) | Mostly done | Documented separately in module manifests |
| Reproducible builds, official distro repos, TUF (Phase 4) | Deferred | Enterprise contract or specific contributor pull |

Contributors are welcome to pick up any of these without renegotiating scope; the spec doc at `.specify/features/048-supply-chain-honesty/spec.md` references each external review item.
