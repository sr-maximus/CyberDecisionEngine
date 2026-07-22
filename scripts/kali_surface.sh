#!/usr/bin/env bash
set -euo pipefail

cmd="${1:-status}"
domain="${2:-}"

case "$cmd" in
  start)
    docker compose --profile surface up -d kali-surface
    ;;
  stop)
    docker compose --profile surface stop kali-surface >/dev/null || true
    ;;
  logs)
    docker compose --profile surface logs -f kali-surface
    ;;
  test)
    docker compose --profile surface exec -T kali-surface python - <<'PY'
import json
import urllib.request
print(json.dumps(json.load(urllib.request.urlopen("http://127.0.0.1:7010/health", timeout=8)), indent=2))
PY
    ;;
  scan)
    if [[ -z "$domain" ]]; then
      echo "Uso: scripts/kali_surface.sh scan <dominio>"
      exit 2
    fi
    docker compose --profile surface exec -T kali-surface python - "$domain" <<'PY'
import json
import sys
import urllib.request
payload = json.dumps({"domains": [sys.argv[1]], "mode": "light", "max_hosts": 25, "timeout_seconds": 120}).encode()
req = urllib.request.Request("http://127.0.0.1:7010/surface-scan", data=payload, headers={"Content-Type": "application/json"}, method="POST")
print(json.dumps(json.load(urllib.request.urlopen(req, timeout=160)), indent=2)[:10000])
PY
    ;;
  status)
    docker compose --profile surface ps kali-surface
    ;;
  *)
    echo "Uso: scripts/kali_surface.sh {start|stop|logs|test|scan|status}"
    exit 2
    ;;
esac
