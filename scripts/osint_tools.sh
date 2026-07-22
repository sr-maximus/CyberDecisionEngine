#!/usr/bin/env bash
set -euo pipefail

cmd="${1:-status}"
target="${2:-}"

case "$cmd" in
  start)
    docker compose --profile osint up -d osint-tools
    ;;
  stop)
    docker compose --profile osint stop osint-tools >/dev/null || true
    ;;
  logs)
    docker compose --profile osint logs -f osint-tools
    ;;
  test)
    docker compose --profile osint exec -T osint-tools python - <<'PY'
import json
import urllib.request
print(json.dumps(json.load(urllib.request.urlopen("http://127.0.0.1:7001/health", timeout=8)), indent=2))
PY
    ;;
  search)
    if [[ -z "$target" ]]; then
      echo "Uso: scripts/osint_tools.sh search <usuario-o-marca>"
      exit 2
    fi
    docker compose --profile osint exec -T osint-tools python - "$target" <<'PY'
import json
import sys
import urllib.request
payload = json.dumps({"targets": [sys.argv[1]], "max_results": 20, "timeout_seconds": 45}).encode()
req = urllib.request.Request("http://127.0.0.1:7001/username-search", data=payload, headers={"Content-Type": "application/json"}, method="POST")
print(json.dumps(json.load(urllib.request.urlopen(req, timeout=70)), indent=2)[:6000])
PY
    ;;
  status)
    docker compose --profile osint ps osint-tools
    ;;
  *)
    echo "Uso: scripts/osint_tools.sh {start|stop|logs|test|search|status}"
    exit 2
    ;;
esac
