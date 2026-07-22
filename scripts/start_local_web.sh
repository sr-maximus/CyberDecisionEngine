#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

API_PORT="${API_PORT:-8000}"
WEB_PORT="${WEB_PORT:-8080}"
PID_DIR="$ROOT_DIR/.local-pids"
LOG_DIR="$ROOT_DIR/.local-logs"
mkdir -p "$PID_DIR" "$LOG_DIR" data reports

if [[ ! -x "$ROOT_DIR/.venv/bin/python" ]]; then
  echo "Missing .venv. Create it first with: python3 -m venv .venv && .venv/bin/python -m pip install -e ."
  exit 1
fi

"$ROOT_DIR/.venv/bin/python" - <<'PY'
import importlib.util
import subprocess
import sys

missing = [pkg for pkg in ("fastapi", "uvicorn") if importlib.util.find_spec(pkg) is None]
if missing:
    subprocess.check_call([
        sys.executable,
        "-m",
        "pip",
        "install",
        "fastapi>=0.115.0",
        "uvicorn[standard]>=0.32.0",
    ])
PY

if command -v node >/dev/null 2>&1; then
  NODE_BIN="$(command -v node)"
elif [[ -x "$HOME/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/bin/node" ]]; then
  NODE_BIN="$HOME/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/bin/node"
else
  echo "node not found. Install Node.js or run through Codex with bundled dependencies."
  exit 1
fi

if command -v pnpm >/dev/null 2>&1; then
  PNPM_BIN="$(command -v pnpm)"
elif [[ -x "$HOME/.cache/codex-runtimes/codex-primary-runtime/dependencies/bin/pnpm" ]]; then
  export PATH="$HOME/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/bin:$HOME/.cache/codex-runtimes/codex-primary-runtime/dependencies/bin:$PATH"
  PNPM_BIN="$HOME/.cache/codex-runtimes/codex-primary-runtime/dependencies/bin/pnpm"
else
  echo "pnpm not found. Install Node.js/pnpm or run through Codex with bundled dependencies."
  exit 1
fi

if [[ ! -d "$ROOT_DIR/web/node_modules" ]]; then
  (cd "$ROOT_DIR/web" && "$PNPM_BIN" install)
fi

if ! command -v launchctl >/dev/null 2>&1; then
  echo "launchctl not found. This local launcher currently supports macOS."
  exit 1
fi

UID_VALUE="$(id -u)"
LAUNCH_DIR="$HOME/Library/LaunchAgents"
API_LABEL="com.cyberdecisionengine.api"
WEB_LABEL="com.cyberdecisionengine.web"
API_PLIST="$LAUNCH_DIR/${API_LABEL}.plist"
WEB_PLIST="$LAUNCH_DIR/${WEB_LABEL}.plist"
mkdir -p "$LAUNCH_DIR"

launchctl bootout "gui/${UID_VALUE}" "$API_PLIST" >/dev/null 2>&1 || true
launchctl bootout "gui/${UID_VALUE}" "$WEB_PLIST" >/dev/null 2>&1 || true

cat > "$API_PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>${API_LABEL}</string>
  <key>ProgramArguments</key>
  <array>
    <string>${ROOT_DIR}/.venv/bin/python</string>
    <string>-m</string>
    <string>uvicorn</string>
    <string>cyberdeck_api.main:app</string>
    <string>--host</string>
    <string>127.0.0.1</string>
    <string>--port</string>
    <string>${API_PORT}</string>
  </array>
  <key>WorkingDirectory</key>
  <string>${ROOT_DIR}</string>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardOutPath</key>
  <string>${LOG_DIR}/api.log</string>
  <key>StandardErrorPath</key>
  <string>${LOG_DIR}/api.log</string>
</dict>
</plist>
EOF

cat > "$WEB_PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>${WEB_LABEL}</string>
  <key>ProgramArguments</key>
  <array>
    <string>${NODE_BIN}</string>
    <string>${ROOT_DIR}/web/node_modules/vite/bin/vite.js</string>
    <string>--host</string>
    <string>127.0.0.1</string>
    <string>--port</string>
    <string>${WEB_PORT}</string>
  </array>
  <key>WorkingDirectory</key>
  <string>${ROOT_DIR}/web</string>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardOutPath</key>
  <string>${LOG_DIR}/web.log</string>
  <key>StandardErrorPath</key>
  <string>${LOG_DIR}/web.log</string>
</dict>
</plist>
EOF

launchctl bootstrap "gui/${UID_VALUE}" "$API_PLIST"
launchctl bootstrap "gui/${UID_VALUE}" "$WEB_PLIST"
launchctl kickstart -k "gui/${UID_VALUE}/${API_LABEL}"
launchctl kickstart -k "gui/${UID_VALUE}/${WEB_LABEL}"

echo "Waiting for API..."
for _ in {1..30}; do
  if "$ROOT_DIR/.venv/bin/python" - <<PY >/dev/null 2>&1
import urllib.request
urllib.request.urlopen("http://127.0.0.1:${API_PORT}/api/health", timeout=1).read()
PY
  then
    break
  fi
  sleep 1
done

echo "Waiting for web..."
for _ in {1..30}; do
  if "$ROOT_DIR/.venv/bin/python" - <<PY >/dev/null 2>&1
import urllib.request
urllib.request.urlopen("http://127.0.0.1:${WEB_PORT}", timeout=1).read()
PY
  then
    break
  fi
  sleep 1
done

if ! "$ROOT_DIR/.venv/bin/python" - <<PY >/dev/null 2>&1
import urllib.request
urllib.request.urlopen("http://127.0.0.1:${API_PORT}/api/health", timeout=2).read()
urllib.request.urlopen("http://127.0.0.1:${WEB_PORT}", timeout=2).read()
PY
then
  echo "Local services did not start correctly."
  echo "--- API log ---"
  tail -40 "$LOG_DIR/api.log" || true
  echo "--- Web log ---"
  tail -40 "$LOG_DIR/web.log" || true
  exit 1
fi

echo "CyberDecisionEngine web is running:"
echo "  Web: http://127.0.0.1:${WEB_PORT}"
echo "  API: http://127.0.0.1:${API_PORT}/docs"
echo "  Logs: $LOG_DIR"
