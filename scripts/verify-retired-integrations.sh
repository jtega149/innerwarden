#!/usr/bin/env bash
# verify-retired-integrations.sh — guard against stale vendor names
# leaking back into the agent source tree.
#
# Inner Warden is a clean-room implementation in Rust: eBPF/Aya for
# kernel telemetry, 53 native detectors, Sigma rules (the open
# community standard), an ATR rule engine for AI agent threats, and
# 49 cross-layer correlation rules — all written from scratch in
# this repo.
#
# Earlier waves of the project shipped *optional* one-way adapters
# that consumed third-party tools' output as additional input
# streams (the same shape as the auditd/journald log readers). One
# of those adapters was retired during Wave 8b/8c when the native
# eBPF + detector layer covered the same surface without an
# external dependency. The internal docstrings that called that
# adapter's deployment idiom by the vendor's name were renamed in
# Wave 8f to the vendor-neutral term "rules-only mode" (the agent
# can run with detection rules only and no LLM — a shape that has
# nothing to do with any specific vendor; Wazuh, OSSEC, Suricata
# all support the same idea).
#
# This script keeps that cleanup honest: a CI check ensures the
# retired vendor name does not creep back into crates/agent/src/
# by accident. It is NOT a statement about the codebase being a
# copy of anything — it is the opposite, a hygiene guard against
# accidental re-introduction.
#
# Allowed callouts (outside scope of this scan):
# - CHANGELOG.md, history files
# - .claude/personas.md (operator-local, gitignored)
# - .claude-local/ (gitignored)
# - benchmark-reports/ + similar fixture data
#
# Distro/shell-portable: POSIX-y bash, no GNU-only flags. Works on
# macOS (BSD coreutils) and Linux (GNU coreutils) the same way.
#
# Usage:
#   ./scripts/verify-retired-integrations.sh
#
# Exit codes:
#   0 — clean, no retired vendor mentions in scoped paths
#   1 — drift detected; offending lines printed to stderr

set -eu

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# Scope: agent source code only. Other crates and docs may reference
# retired tools for historical / comparative / interoperability
# reasons (Sigma rules referencing other engines, integration recipe
# docs listing alternatives, etc.).
SCOPE="$REPO_ROOT/crates/agent/src"

if [ ! -d "$SCOPE" ]; then
  echo "verify-retired-integrations: $SCOPE not found" >&2
  exit 1
fi

# Single retired vendor name guarded today. Adding entries here is
# easy: append a new -e pattern. Keep the list short — false
# positives on common words would defeat the guard.
PATTERNS='-e falco'

# Use grep -r with -I (binary skip) and case-insensitive match. Print
# every offender on its own line so the operator can see exactly which
# file + line + context to fix.
hits="$(grep -rIni $PATTERNS "$SCOPE" || true)"

if [ -n "$hits" ]; then
  echo "verify-retired-integrations: retired vendor mention(s) detected in agent source:" >&2
  echo "$hits" | sed 's/^/  /' >&2
  cat >&2 <<EOF

A retired one-way input adapter's vendor name should not appear in
crates/agent/src/ — Wave 8f renamed every internal "<vendor>-mode" /
"<vendor>-like" reference to the vendor-neutral "rules-only mode"
because the adapter no longer exists. New mentions re-introduce the
anachronism. If the new reference is intentional (e.g. you are
re-introducing the adapter or comparing against the tool in a
review-only context), update this script and ANCHOR_TESTS.md to
relax the gate.
EOF
  exit 1
fi

echo "verify-retired-integrations: clean (0 retired vendor mentions in $SCOPE)."
