#!/bin/sh
set -eu

TOKEN_FILE="${OPENCLAW_GATEWAY_TOKEN_FILE:-/run/openclaw/gateway-token}"
mkdir -p "$(dirname "$TOKEN_FILE")"
if [ ! -s "$TOKEN_FILE" ]; then
  umask 077
  node -e "process.stdout.write(require('crypto').randomBytes(32).toString('hex'))" > "$TOKEN_FILE"
fi
export OPENCLAW_GATEWAY_TOKEN="$(cat "$TOKEN_FILE")"

exec node dist/index.js gateway --bind lan --port 18789
