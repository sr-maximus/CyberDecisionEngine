#!/usr/bin/env bash
set -euo pipefail

cmd="${1:-status}"
domain="${2:-example.com}"

case "$cmd" in
  start)
    docker compose up -d spiderfoot
    ;;
  stop)
    docker compose stop spiderfoot >/dev/null || true
    ;;
  logs)
    docker compose logs -f spiderfoot
    ;;
  health|test)
    docker compose exec -T spiderfoot python - <<'PY'
import json
import urllib.request

with urllib.request.urlopen("http://127.0.0.1:7020/health", timeout=10) as response:
    print(json.dumps(json.loads(response.read().decode()), indent=2))
PY
    ;;
  scan)
    docker compose exec -T spiderfoot python - "$domain" <<'PY'
import json
import sys
import urllib.request

domain = sys.argv[1]
payload = json.dumps({
    "domains": [domain],
    "use_case": "passive",
    "depth": "deep",
    "timeout_seconds": 900,
    "max_records": 40,
    "max_threads": 4,
    "include_raw": False,
}).encode()
request = urllib.request.Request(
    "http://127.0.0.1:7020/scan",
    data=payload,
    headers={"Content-Type": "application/json"},
    method="POST",
)
with urllib.request.urlopen(request, timeout=960) as response:
    print(json.dumps(json.loads(response.read().decode()), indent=2)[:12000])
PY
    ;;
  status)
    docker compose ps spiderfoot
    ;;
  *)
    echo "Uso: scripts/spiderfoot_sidecar.sh {start|stop|logs|health|test|scan <dominio>|status}"
    exit 2
    ;;
esac
