#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if [[ -x ".venv/bin/cyberdeck" ]]; then
  CYBERDECK=".venv/bin/cyberdeck"
elif command -v cyberdeck >/dev/null 2>&1; then
  CYBERDECK="cyberdeck"
else
  CYBERDECK="python -m cyberdeck.cli"
fi

$CYBERDECK frameworks sync --all --verbose
$CYBERDECK run \
  --org config/orgs/example_organization.yml \
  --mode snapshot \
  --lookback-days 30 \
  --html reports/example_organization_executive.html \
  --real-only \
  --verbose

echo "Demo report generated: reports/example_organization_executive.html"
