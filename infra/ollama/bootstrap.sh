#!/bin/sh
set -eu

BASE_MODEL="${OLLAMA_BASE_MODEL:-qwen3:1.7b}"
MODEL_NAME="${OLLAMA_MODEL_NAME:-cyberdecision-cti}"
CHAT_BASE_MODEL="${OLLAMA_CHAT_BASE_MODEL:-qwen3:0.6b}"
CHAT_MODEL_NAME="${OLLAMA_CHAT_MODEL_NAME:-cyberdecision-cti-chat}"
export OLLAMA_HOST="${OLLAMA_HOST:-http://ollama:11434}"

attempt=0
until ollama list >/dev/null 2>&1; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 60 ]; then
    echo "Ollama did not become ready." >&2
    exit 1
  fi
  sleep 2
done

if ! ollama list | awk 'NR > 1 {print $1}' | grep -Fxq "${BASE_MODEL}"; then
  ollama pull "${BASE_MODEL}"
fi

ollama create "${MODEL_NAME}" --file /config/Modelfile
ollama show "${MODEL_NAME}" >/dev/null

if ! ollama list | awk 'NR > 1 {print $1}' | grep -Fxq "${CHAT_BASE_MODEL}"; then
  ollama pull "${CHAT_BASE_MODEL}"
fi

ollama create "${CHAT_MODEL_NAME}" --file /config/Modelfile.chat
ollama show "${CHAT_MODEL_NAME}" >/dev/null
