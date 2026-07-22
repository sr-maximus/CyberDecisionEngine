#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PID_DIR="$ROOT_DIR/.local-pids"
UID_VALUE="$(id -u)"
LAUNCH_DIR="$HOME/Library/LaunchAgents"
API_LABEL="com.cyberdecisionengine.api"
WEB_LABEL="com.cyberdecisionengine.web"

if command -v launchctl >/dev/null 2>&1; then
  launchctl bootout "gui/${UID_VALUE}" "$LAUNCH_DIR/${API_LABEL}.plist" >/dev/null 2>&1 || true
  launchctl bootout "gui/${UID_VALUE}" "$LAUNCH_DIR/${WEB_LABEL}.plist" >/dev/null 2>&1 || true
  rm -f "$LAUNCH_DIR/${API_LABEL}.plist" "$LAUNCH_DIR/${WEB_LABEL}.plist"
fi

stop_pid() {
  local name="$1"
  local pid_file="$PID_DIR/${name}.pid"
  if [[ -f "$pid_file" ]]; then
    local pid
    pid="$(cat "$pid_file")"
    if kill -0 "$pid" >/dev/null 2>&1; then
      kill "$pid"
      echo "Stopped $name (pid $pid)."
    fi
    rm -f "$pid_file"
  fi
}

stop_pid api
stop_pid web
echo "Local web services stopped."
