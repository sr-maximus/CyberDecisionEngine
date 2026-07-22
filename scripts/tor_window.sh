#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

ACTION="${1:-status}"
SERVICE="tor-proxy"

case "$ACTION" in
  start)
    docker compose --profile tor up -d "$SERVICE"
    docker compose ps "$SERVICE"
    ;;
  stop|down)
    docker compose stop "$SERVICE" >/dev/null 2>&1 || true
    docker compose rm -f "$SERVICE" >/dev/null 2>&1 || true
    docker compose ps "$SERVICE"
    ;;
  restart)
    "$0" stop
    "$0" start
    ;;
  status)
    docker compose ps "$SERVICE"
    ;;
  test)
    docker compose exec -T "$SERVICE" sh -lc 'nc -z 127.0.0.1 9050 && echo "TOR SOCKS ready on internal port 9050"'
    ;;
  logs)
    docker compose logs --tail 80 "$SERVICE"
    ;;
  *)
    echo "Usage: $0 {start|stop|restart|status|test|logs}" >&2
    exit 2
    ;;
esac
