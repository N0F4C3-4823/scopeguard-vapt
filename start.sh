#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
[ -x "$ROOT_DIR/.venv/bin/python" ] || { echo "Virtual environment missing. Run ./install.sh first." >&2; exit 1; }
source "$ROOT_DIR/.venv/bin/activate"

HOST="${SCOPEGUARD_HOST:-127.0.0.1}"
PORT="${SCOPEGUARD_PORT:-8000}"
NEXT_IS_HOST=0
NEXT_IS_PORT=0
for arg in "$@"; do
  case "$arg" in
    --host) NEXT_IS_HOST=1 ;;
    --port) NEXT_IS_PORT=1 ;;
    --host=*) HOST="${arg#*=}" ;;
    --port=*) PORT="${arg#*=}" ;;
    *)
      if [ "$NEXT_IS_HOST" = 1 ]; then HOST="$arg"; NEXT_IS_HOST=0; fi
      if [ "$NEXT_IS_PORT" = 1 ]; then PORT="$arg"; NEXT_IS_PORT=0; fi
      ;;
  esac
done

BASE_URL="http://$HOST:$PORT"
OLLAMA_BIN="${SCOPEGUARD_OLLAMA_BIN:-}"
if [ -z "$OLLAMA_BIN" ] || [ "$OLLAMA_BIN" = "./.tools/ollama/bin/ollama" ]; then
  if [ -x "$ROOT_DIR/.tools/ollama/bin/ollama" ]; then OLLAMA_BIN="$ROOT_DIR/.tools/ollama/bin/ollama"
  else OLLAMA_BIN="$(command -v ollama 2>/dev/null || true)"
  fi
fi
OLLAMA_URL="${SCOPEGUARD_OLLAMA_URL:-http://127.0.0.1:11434}"
SERVER_PID=""
OLLAMA_PID=""
mkdir -p "$ROOT_DIR/data/logs"

health_check() {
  if command -v curl >/dev/null 2>&1; then
    curl --fail --silent --show-error --max-time 2 "$BASE_URL/api/health" >/dev/null
  else
    BASE_URL="$BASE_URL" python - <<'PY'
import os, urllib.request
with urllib.request.urlopen(os.environ["BASE_URL"] + "/api/health", timeout=2) as response:
    raise SystemExit(0 if response.status == 200 else 1)
PY
  fi
}

ollama_health() {
  command -v curl >/dev/null 2>&1 && curl --fail --silent --max-time 1 "$OLLAMA_URL/api/tags" >/dev/null 2>&1
}

cleanup() {
  if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill -TERM "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  if [ -n "$OLLAMA_PID" ] && kill -0 "$OLLAMA_PID" 2>/dev/null; then
    kill -TERM "$OLLAMA_PID" 2>/dev/null || true
    wait "$OLLAMA_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

if health_check 2>/dev/null; then
  echo "A ScopeGuard instance is already serving at $BASE_URL; refusing to start a duplicate." >&2
  exit 1
fi

if [ -n "$OLLAMA_BIN" ] && [ -x "$OLLAMA_BIN" ] && ! ollama_health; then
  mkdir -p "${OLLAMA_MODELS:-$ROOT_DIR/data/ollama}"
  OLLAMA_HOST="$OLLAMA_URL" OLLAMA_MODELS="${OLLAMA_MODELS:-$ROOT_DIR/data/ollama}" \
    OLLAMA_NUM_PARALLEL=1 OLLAMA_MAX_LOADED_MODELS=1 "$OLLAMA_BIN" serve >"$ROOT_DIR/data/logs/ollama.log" 2>&1 &
  OLLAMA_PID=$!
  for _ in $(seq 1 60); do ollama_health && break; sleep 0.5; done
  if ! ollama_health; then
    echo "Ollama did not become ready; continuing without optional local AI." >&2
    kill -TERM "$OLLAMA_PID" 2>/dev/null || true
    wait "$OLLAMA_PID" 2>/dev/null || true
    OLLAMA_PID=""
  fi
fi

SCOPEGUARD_HOST="$HOST" SCOPEGUARD_PORT="$PORT" python -m app.cli serve "$@" >"$ROOT_DIR/data/logs/application.log" 2>&1 &
SERVER_PID=$!
for _ in $(seq 1 60); do
  if health_check 2>/dev/null; then
    echo "ScopeGuard VAPT is ready: $BASE_URL"
    echo "Press Ctrl-C to stop the local server."
    wait "$SERVER_PID"
    exit $?
  fi
  if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    echo "ScopeGuard failed to start. Inspect data/logs/application.log." >&2
    exit 1
  fi
  sleep 0.25
done
echo "ScopeGuard did not become healthy at $BASE_URL. Inspect data/logs/application.log." >&2
exit 1
