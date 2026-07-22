#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if [[ -x ".venv/bin/python" ]]; then
  PY=".venv/bin/python"
else
  PY="${PYTHON:-python3}"
fi

"$PY" -m cyberdeck.cli doctor --verbose
"$PY" -m pytest -q
echo "Healthcheck OK"
