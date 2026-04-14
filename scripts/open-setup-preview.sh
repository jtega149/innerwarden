#!/usr/bin/env bash
set -euo pipefail

SVG_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/docs/internal/setup-flow-preview.svg"

if [[ ! -f "$SVG_PATH" ]]; then
  echo "Preview file not found: $SVG_PATH"
  exit 1
fi

if command -v open >/dev/null 2>&1; then
  open "$SVG_PATH"
  echo "Opened: $SVG_PATH"
else
  echo "$SVG_PATH"
fi
