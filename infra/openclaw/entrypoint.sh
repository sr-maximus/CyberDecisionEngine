#!/bin/sh
set -eu

TOKEN_FILE="${OPENCLAW_GATEWAY_TOKEN_FILE:-/run/openclaw/gateway-token}"
CONFIG_DIR="/home/node/.openclaw"
CONFIG_FILE="$CONFIG_DIR/openclaw.json"
WORKSPACE_DIR="$CONFIG_DIR/workspace-cyberdecision"
mkdir -p "$CONFIG_DIR"
cp /opt/cyberdecision/openclaw.json "$CONFIG_FILE"
chmod 600 "$CONFIG_FILE"
mkdir -p "$WORKSPACE_DIR"
# This analysis agent is preconfigured and must not enter the conversational
# first-run workflow.
rm -f "$WORKSPACE_DIR/BOOTSTRAP.md"
mkdir -p "$(dirname "$TOKEN_FILE")"
if [ ! -s "$TOKEN_FILE" ]; then
  umask 077
  node -e "process.stdout.write(require('crypto').randomBytes(32).toString('hex'))" > "$TOKEN_FILE"
fi
export OPENCLAW_GATEWAY_TOKEN="$(cat "$TOKEN_FILE")"

exec node dist/index.js gateway --bind lan --port 18789
