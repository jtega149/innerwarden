#!/usr/bin/env bash
# verify-readme-counts.sh - keeps README.md count claims honest.
#
# Why this exists: a 2026-06-07 doc-vs-code audit found 96 stale-count
# inconsistencies across the docs. README was the ONLY surface kept current,
# but even it had internal contradictions ("54 kernel programs" vs "45 loaded";
# "+8 built-in" Sigma vs "9 built-in"). Counts were hardcoded as prose in ~10
# surfaces and never re-derived. This gate makes README the single pinned
# source: it must agree with itself, and the cleanly code-derivable counts must
# match the source tree. CI runs it on every PR, so a count cannot silently
# drift again.
#
# Two layers:
#   Part A - README internal consistency. Every place README states a metric
#            (badge + prose) must show the SAME number. Fully robust: README vs
#            itself, no code derivation.
#   Part B - README vs source, for counts that are DETERMINISTICALLY derivable
#            from a file/grep: detectors, collectors, Sigma community corpus,
#            and eBPF programs COMPILED. README's (already self-consistent)
#            value must equal the source-derived value.
#
# eBPF has TWO distinct numbers and the gate keeps them separate:
#   - "compiled" = program macros in crates/sensor-ebpf/src/main.rs. Static,
#     so it IS code-pinned (Part B).
#   - "loaded in prod" = the kernel-dependent runtime subset (<= compiled).
#     A deploy fact, not a build fact, so it is self-consistency only.
#
# Intentionally NOT code-pinned (documented, not an oversight):
#   - eBPF "loaded": runtime/kernel-dependent (see above).
#   - Correlation rules: the builtin YAML carries one more `- id:` than the
#     loader registers (a template), so a naive grep yields 70 vs the real 69.
#     The authoritative count is pinned by the Rust `rule_count() == 69` unit
#     test; here we only enforce README self-consistency.
#   - MITRE "90+": a marketing floor across 14 tactics, not the canonical
#     mitre.rs table size (~55). Self-consistency only.
#
# Distro/shell-portable: POSIX-y bash, -oE/-i grep only (works on macOS BSD and
# Linux GNU coreutils identically).
#
# Usage:   ./scripts/verify-readme-counts.sh
# Exit:    0 = README agrees with itself and with source
#          1 = drift detected; specifics printed to stderr

set -eu

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
README="$REPO_ROOT/README.md"
DETECTORS_MOD="$REPO_ROOT/crates/sensor/src/detectors/mod.rs"
COLLECTORS_MOD="$REPO_ROOT/crates/sensor/src/collectors/mod.rs"
SIGMA_DIR="$REPO_ROOT/rules/sigma"
EBPF_MAIN="$REPO_ROOT/crates/sensor-ebpf/src/main.rs"

# Failures are recorded in a temp file, not a variable: the consistency checks
# run inside $(...) command substitutions (subshells), so a parent-scope
# variable assignment would be lost. A file write is visible across subshells.
FAIL_FILE="$(mktemp)"
trap 'rm -f "$FAIL_FILE"' EXIT
note() { printf '%s\n' "$*" >&2; }
mark_fail() { printf 'x' >> "$FAIL_FILE"; }

if [ ! -f "$README" ]; then
  note "verify-readme-counts: $README not found"
  exit 1
fi

# digits_in <text>: strip URL %-escapes (badges encode spaces as %20, which
# would otherwise leak a phantom "20"), then print every integer, one per line.
digits_in() {
  printf '%s\n' "$1" | sed 's/%[0-9A-Fa-f][0-9A-Fa-f]/ /g' | grep -oE '[0-9]+' || true
}

# single_value <label> <newline-separated-numbers>: assert exactly one distinct
# value. Echoes it on stdout (empty on warn/fail). Logs OK/WARN/FAIL to stderr.
single_value() {
  label="$1"
  vals="$(printf '%s\n' "$2" | grep -E '[0-9]' | sort -un || true)"
  n="$(printf '%s\n' "$vals" | grep -c '[0-9]' || true)"
  if [ "$n" -eq 0 ]; then
    note "WARN  $label: no mention found in README (pattern may need updating)"
    echo ""; return 0
  fi
  if [ "$n" -gt 1 ]; then
    note "FAIL  $label: README is self-inconsistent, found: $(printf '%s ' $vals)"
    mark_fail; echo ""; return 0
  fi
  note "OK    $label: README consistent at $vals"
  echo "$vals"
}

# consistent <label> <ere>: collect every README token matching <ere> and
# require they all carry the same number.
consistent() {
  single_value "$1" "$(digits_in "$(grep -oiE "$2" "$README" 2>/dev/null || true)")"
}

# vs_code <label> <readme_value> <code_value>
vs_code() {
  [ -z "$2" ] && return 0   # already warned/failed in Part A
  if [ "$2" != "$3" ]; then
    note "FAIL  $1: README says $2 but source has $3"; mark_fail
  else
    note "OK    $1: README $2 == source $3"
  fi
}

note "== Part A: README internal consistency =="
DET="$(consistent  'detectors'         '(detectors-[0-9]+)|([0-9]+ (stateful )?detectors)')"
COL="$(consistent  'collectors'        '[0-9]+ collectors')"
COR="$(consistent  'correlation rules' '(correlation%20rules-[0-9]+)|([0-9]+ cross-layer( correlation)? rules)')"
SIGC="$(consistent 'Sigma community'   '([0-9]+ (community )?Sigma)|([0-9]+ Sigma community)')"
SIGB="$(consistent 'Sigma built-in'    '(\(\+[0-9]+ built-in\))|([0-9]+ built-in Sigma)')"
YARA="$(consistent 'YARA rules'        '[0-9]+ YARA')"
MITRE="$(consistent 'MITRE techniques' '[0-9]+\+ (unique )?MITRE')"

# eBPF: "compiled" and "loaded" are different metrics, split by keyword.
EBPF_COMPILED="$(single_value 'eBPF compiled' \
  "$(digits_in "$(grep -iE 'compiled|live in a single file' "$README" | grep -oiE '([0-9]+ kernel programs)|([0-9]+ compiled)' || true)")")"
EBPF_LOADED="$(single_value 'eBPF loaded' \
  "$(digits_in "$(grep -iE 'ebpf|kernel programs' "$README" | grep -viE 'compiled|live in a single file' \
       | grep -oiE '(ebpf%20programs-[0-9]+)|([0-9]+ ebpf kernel programs)|([0-9]+ kernel programs)' || true)")")"

note ""
note "== Part B: README vs source (deterministic counts) =="
DET_CODE="$(grep -cE '^pub mod ' "$DETECTORS_MOD")"
COL_CODE="$(grep -cE '^pub mod ' "$COLLECTORS_MOD")"
SIGC_CODE="$(find "$SIGMA_DIR" -type f \( -name '*.yml' -o -name '*.yaml' \) 2>/dev/null | wc -l | tr -d ' ')"
EBPF_CODE="$(grep -cE '^[[:space:]]*#\[(kprobe|kretprobe|tracepoint|raw_tracepoint|lsm|fentry|fexit|uprobe|xdp)' "$EBPF_MAIN")"
vs_code 'detectors'       "$DET"           "$DET_CODE"
vs_code 'collectors'      "$COL"           "$COL_CODE"
vs_code 'Sigma community' "$SIGC"          "$SIGC_CODE"
vs_code 'eBPF compiled'   "$EBPF_COMPILED" "$EBPF_CODE"

note ""
if [ -s "$FAIL_FILE" ]; then
  note "verify-readme-counts: DRIFT DETECTED. Make README.md (or the source) agree."
  exit 1
fi
note "verify-readme-counts: all README counts agree with themselves and with source."
exit 0
