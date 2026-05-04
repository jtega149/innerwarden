#!/usr/bin/env bash
# verify-doc-vs-source.sh — keeps `.claude/CLAUDE.md` honest about what
# the sensor actually ships.
#
# Wave 8c (2026-05-04): the previous version of `.claude/CLAUDE.md` listed
# four collectors (`falco_log`, `suricata_eve`, `wazuh_alerts`,
# `osquery_log`) and two detectors (`osquery_anomaly`, `suricata_alert`)
# that NEVER existed in the source tree, while ten real collectors
# (file_extract, net_snapshot, proto_*, suid_inventory, sysctl_drift,
# systemd_inventory, tcp_stream, usb_monitor) were not documented at all.
# This script makes that drift fail CI.
#
# Distro/shell-portable: POSIX-y bash, no GNU-only flags. Works on macOS
# (BSD coreutils) and Linux (GNU coreutils) the same way.
#
# Usage:
#   ./scripts/verify-doc-vs-source.sh           # check, exit non-zero on drift
#   ./scripts/verify-doc-vs-source.sh --update  # not yet implemented (TODO)
#
# Exit codes:
#   0 — docs and source agree
#   1 — drift detected; specifics printed to stderr

set -eu

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DOC="$REPO_ROOT/.claude/CLAUDE.md"
COLLECTORS_DIR="$REPO_ROOT/crates/sensor/src/collectors"
DETECTORS_DIR="$REPO_ROOT/crates/sensor/src/detectors"

if [ ! -f "$DOC" ]; then
  # `.claude/CLAUDE.md` is operator-local (gitignored). Forks, CI runners
  # and other contributors will not have it. Skip cleanly so this script
  # is safe to wire into CI without forcing every checkout to carry the
  # handbook. The gate still catches drift on machines where the file
  # exists, which is the population that benefits from it.
  echo "verify-doc-vs-source: $DOC not found — skipping (dev tool only)."
  exit 0
fi

# List .rs files in a directory minus mod.rs, strip extension, sort.
list_modules() {
  local dir="$1"
  if [ ! -d "$dir" ]; then
    echo "verify-doc-vs-source: $dir not found" >&2
    exit 1
  fi
  # `find` is POSIX; `-print0` is GNU-only so use plain `-print` then `sort`.
  find "$dir" -maxdepth 1 -name '*.rs' -type f \
    | sed -E 's|.*/||; s|\.rs$||' \
    | grep -v '^mod$' \
    | sort -u
}

# Extract module names listed in CLAUDE.md within the named code block.
# We bracket the block by its leading `<section>/  (...)` line and the
# closing ``` fence.
#
# The block format we authored looks like:
#   collectors/  (...)
#     name1, name2, name3,
#     name4, ...
#
# Strategy: pull lines between `^<section>/` and the next `^[a-z]+/` or
# triple backtick, drop the header, split by commas/whitespace.
list_documented() {
  local section="$1"
  awk -v section="$section/" '
    BEGIN { inblock = 0 }
    {
      if (index($0, section) == 1) { inblock = 1; next }
      if (inblock) {
        # Stop at the next section header (e.g. "detectors/" or "sinks/").
        # Section headers either include a count in parens (`detectors/  (52 modules — ...)`)
        # or are bare (`sinks/`). Both must reset the inblock flag.
        if ($0 ~ /^[a-z_]+\/([[:space:]]*\(|[[:space:]]*$)/) { inblock = 0; next }
        # Closing code fence also resets.
        if ($0 ~ /^```/) { inblock = 0; next }
        # Strip leading whitespace and split on commas.
        line = $0
        gsub(/^[[:space:]]+/, "", line)
        n = split(line, parts, /[[:space:]]*,[[:space:]]*/)
        for (i = 1; i <= n; i++) {
          name = parts[i]
          # Tolerate trailing punctuation/whitespace.
          gsub(/[[:space:]]+$/, "", name)
          if (length(name) > 0 && name ~ /^[a-z][a-z0-9_]*$/) {
            print name
          }
        }
      }
    }
  ' "$DOC" | sort -u
}

# Compare two sorted lists. Print drift to stderr.
diff_lists() {
  local kind="$1" disk="$2" docs="$3"
  local missing phantoms
  missing=$(comm -23 "$disk" "$docs" || true)
  phantoms=$(comm -13 "$disk" "$docs" || true)
  local rc=0
  if [ -n "$missing" ]; then
    echo "verify-doc-vs-source: $kind on disk but NOT in .claude/CLAUDE.md:" >&2
    echo "$missing" | sed 's/^/  - /' >&2
    rc=1
  fi
  if [ -n "$phantoms" ]; then
    echo "verify-doc-vs-source: $kind in .claude/CLAUDE.md but NOT on disk (phantoms):" >&2
    echo "$phantoms" | sed 's/^/  - /' >&2
    rc=1
  fi
  return $rc
}

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

list_modules    "$COLLECTORS_DIR" > "$TMP_DIR/collectors.disk"
list_modules    "$DETECTORS_DIR"  > "$TMP_DIR/detectors.disk"
list_documented collectors        > "$TMP_DIR/collectors.docs"
list_documented detectors         > "$TMP_DIR/detectors.docs"

drift=0
diff_lists collectors "$TMP_DIR/collectors.disk" "$TMP_DIR/collectors.docs" || drift=1
diff_lists detectors  "$TMP_DIR/detectors.disk"  "$TMP_DIR/detectors.docs"  || drift=1

if [ "$drift" -ne 0 ]; then
  cat >&2 <<EOF

To fix: open $DOC and update the "Sensor source layout" code block so
the collectors/ and detectors/ entries match the disk. Then re-run:
  ./scripts/verify-doc-vs-source.sh
EOF
  exit 1
fi

n_coll=$(wc -l < "$TMP_DIR/collectors.disk" | tr -d ' ')
n_det=$(wc -l < "$TMP_DIR/detectors.disk" | tr -d ' ')
echo "verify-doc-vs-source: docs and source agree (${n_coll} collectors, ${n_det} detectors)."
