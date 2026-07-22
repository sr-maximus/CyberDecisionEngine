#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

echo "CyberDecisionEngine installer for macOS Intel"

ARCH="$(uname -m)"
if [[ "$ARCH" != "x86_64" ]]; then
  echo "ERROR: This installer targets macOS Intel x86_64. Detected: $ARCH"
  exit 1
fi

if ! xcode-select -p >/dev/null 2>&1; then
  echo "Xcode Command Line Tools are missing."
  read -r -p "Install Xcode Command Line Tools now? [y/N] " answer
  if [[ "$answer" =~ ^[Yy]$ ]]; then
    xcode-select --install || true
    echo "Re-run this installer after Xcode tools finish installing."
  fi
  exit 1
fi

if ! command -v brew >/dev/null 2>&1; then
  echo "Homebrew is missing. Install it from https://brew.sh/ and re-run this script."
  exit 1
fi

if ! command -v python3.13 >/dev/null 2>&1; then
  echo "Python 3.13+ is required and python3.13 was not found."
  read -r -p "Install python@3.13 with Homebrew? [y/N] " answer
  if [[ "$answer" =~ ^[Yy]$ ]]; then
    brew install python@3.13
  else
    echo "Install Python 3.13+ manually and re-run this installer."
    exit 1
  fi
fi

python3.13 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
cyberdeck doctor --verbose

echo "Installation complete."
