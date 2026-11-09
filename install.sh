#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_BIN="${PYTHON_BIN:-python3}"
OLLAMA_MODEL="${SCOPEGUARD_OLLAMA_MODEL:-qwen2.5:1.5b-instruct}"
OLLAMA_PID=""
OLLAMA_STARTED=0
LIMITED_MODE="${SCOPEGUARD_LIMITED_MODE:-0}"

say() { printf '[ScopeGuard] %s\n' "$*"; }
warn() { printf '[ScopeGuard] WARNING: %s\n' "$*" >&2; }
die() { printf '[ScopeGuard] ERROR: %s\n' "$*" >&2; exit 1; }
interactive() { [ -t 0 ] && [ -t 1 ]; }
confirm() {
  local answer
  interactive || return 1
  read -r -p "$1 [y/N] " answer
  case "${answer,,}" in y|yes) return 0 ;; *) return 1 ;; esac
}

cleanup() {
  if [ "$OLLAMA_STARTED" = 1 ] && [ -n "$OLLAMA_PID" ] && kill -0 "$OLLAMA_PID" 2>/dev/null; then
    kill -TERM "$OLLAMA_PID" 2>/dev/null || true
    wait "$OLLAMA_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

detect_platform() {
  DISTRO_ID=unknown
  DISTRO_NAME="$(uname -s)"
  DISTRO_VERSION=unknown
  if [ -r /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    DISTRO_ID="${ID:-unknown}"
    DISTRO_VERSION="${VERSION_ID:-unknown}"
    DISTRO_NAME="${PRETTY_NAME:-$DISTRO_ID}"
  fi
  ARCH="$(uname -m)"
  PACKAGE_MANAGER=""
  for candidate in apt-get dnf yum pacman zypper; do
    if command -v "$candidate" >/dev/null 2>&1; then PACKAGE_MANAGER="$candidate"; break; fi
  done
  WSL=0
  if grep -qi microsoft /proc/version 2>/dev/null || grep -qi microsoft /proc/sys/kernel/osrelease 2>/dev/null; then WSL=1; fi
  SYSTEMD=0
  if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then SYSTEMD=1; fi
}

print_environment() {
  say "ScopeGuard VAPT installer (v1.0.0-beta.1)"
  say "Distribution: $DISTRO_NAME ($DISTRO_ID $DISTRO_VERSION)"
  say "Architecture: $ARCH"
  say "Package manager: ${PACKAGE_MANAGER:-not detected}"
  say "WSL: $([ "$WSL" = 1 ] && echo detected || echo not-detected)"
  say "systemd: $([ "$SYSTEMD" = 1 ] && echo available || echo unavailable)"
  if command -v "$PYTHON_BIN" >/dev/null 2>&1; then say "Python: $($PYTHON_BIN --version 2>&1)"; else say "Python: not found"; fi
  if [ -r /proc/meminfo ]; then say "Memory available: $(awk '/MemAvailable:/ { printf "%.0f MiB", $2 / 1024 }' /proc/meminfo)"; fi
  say "Disk available: $(df -h "$ROOT_DIR" | awk 'NR==2 {print $4}')"
  say "Node.js is not required: the frontend is shipped as static assets."
}

package_names() {
  case "$PACKAGE_MANAGER" in
    apt-get) printf '%s\n' python3 python3-venv python3-pip curl ca-certificates nmap openssl dnsutils zstd ;;
    dnf|yum) printf '%s\n' python3 python3-pip python3-virtualenv curl ca-certificates nmap openssl bind-utils zstd ;;
    pacman) printf '%s\n' python python-pip curl ca-certificates nmap openssl bind zstd ;;
    zypper) printf '%s\n' python311 python311-pip python311-virtualenv curl ca-certificates nmap openssl bind-utils zstd ;;
    *) return 1 ;;
  esac
}

run_privileged() {
  if [ "$(id -u)" -eq 0 ]; then "$@"
  elif command -v sudo >/dev/null 2>&1; then sudo "$@"
  else die "Root or sudo is required to install system packages."; fi
}

install_system_packages() {
  [ -n "$PACKAGE_MANAGER" ] || die "No supported package manager was detected. Install Python 3.11+, curl, nmap, openssl, dig, and zstd using your distribution."
  mapfile -t packages < <(package_names)
  say "Requested system packages: ${packages[*]}"
  if [ "${SCOPEGUARD_INSTALL_SYSTEM_PACKAGES:-0}" != 1 ] && ! confirm "Install missing system packages now?"; then
    die "System dependencies are missing. Re-run with SCOPEGUARD_INSTALL_SYSTEM_PACKAGES=1 or install them manually."
  fi
  case "$PACKAGE_MANAGER" in
    apt-get) run_privileged apt-get update; run_privileged apt-get install -y "${packages[@]}" ;;
    dnf|yum) run_privileged "$PACKAGE_MANAGER" install -y "${packages[@]}" ;;
    pacman) run_privileged pacman -Sy --needed --noconfirm "${packages[@]}" ;;
    zypper) run_privileged zypper --non-interactive install --no-confirm "${packages[@]}" ;;
  esac
}

ensure_python() {
  if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then install_system_packages; fi
  command -v "$PYTHON_BIN" >/dev/null 2>&1 || die "Python 3.11 or newer is required."
  "$PYTHON_BIN" - <<'PY' || die "Python 3.11 or newer is required."
import sys
raise SystemExit(0 if sys.version_info >= (3, 11) else 1)
PY
  if ! "$PYTHON_BIN" -m venv --help >/dev/null 2>&1; then
    warn "Python venv support is missing."
    install_system_packages
  fi
}

check_optional_tools() {
  local missing=()
  for tool in curl nmap openssl dig zstd; do command -v "$tool" >/dev/null 2>&1 || missing+=("$tool"); done
  if [ "${#missing[@]}" -gt 0 ]; then
    warn "Scanner-support tools missing: ${missing[*]}"
    if [ "${SCOPEGUARD_INSTALL_SYSTEM_PACKAGES:-0}" = 1 ] || confirm "Install scanner-support tools now?"; then
      install_system_packages
    else
      warn "Checks requiring missing tools will remain INCONCLUSIVE or unavailable."
    fi
  fi
}

ollama_binary() {
  local configured="${SCOPEGUARD_OLLAMA_BIN:-}"
  if [ -n "$configured" ]; then
    if [[ "$configured" != /* ]]; then configured="$ROOT_DIR/$configured"; fi
    if [ -x "$configured" ]; then printf '%s\n' "$configured"; return 0; fi
  fi
  if [ -x "$ROOT_DIR/.tools/ollama/bin/ollama" ]; then printf '%s\n' "$ROOT_DIR/.tools/ollama/bin/ollama"
  else command -v ollama 2>/dev/null || true
  fi
}

install_local_ollama() {
  command -v curl >/dev/null 2>&1 || die "curl is required for project-local Ollama installation."
  command -v zstd >/dev/null 2>&1 || die "zstd is required for project-local Ollama installation."
  local url tmp archive
  case "$ARCH" in
    x86_64|amd64) url=https://ollama.com/download/ollama-linux-amd64.tar.zst ;;
    aarch64|arm64) url=https://ollama.com/download/ollama-linux-arm64.tar.zst ;;
    *) die "Project-local Ollama is not packaged for $ARCH; install a compatible runtime separately." ;;
  esac
  tmp="$(mktemp -d)"
  archive="$tmp/ollama.tar.zst"
  say "Downloading official Ollama runtime for $ARCH."
  curl --fail --show-error --location --proto '=https' --tlsv1.2 --progress-bar "$url" -o "$archive"
  mkdir -p "$ROOT_DIR/.tools/ollama"
  zstd -d -c "$archive" | tar -xf - -C "$ROOT_DIR/.tools/ollama"
  chmod 0755 "$ROOT_DIR/.tools/ollama/bin/ollama"
  find "$tmp" -depth -delete
}

ollama_health() {
  curl --fail --silent --show-error --max-time 2 "${SCOPEGUARD_OLLAMA_URL:-http://127.0.0.1:11434}/api/tags" >/dev/null 2>&1
}

ollama_models_dir() {
  local configured="${OLLAMA_MODELS:-$ROOT_DIR/data/ollama}"
  if [[ "$configured" = /* ]]; then printf '%s\n' "$configured"; else printf '%s\n' "$ROOT_DIR/$configured"; fi
}

ollama_cpu_library() {
  if grep -qm1 'avx2' /proc/cpuinfo 2>/dev/null; then printf '%s\n' 'cpu_avx2'; else printf '%s\n' 'cpu'; fi
}

start_ollama() {
  local binary="$1"
  if ollama_health; then return 0; fi
  mkdir -p "$(ollama_models_dir)" "$ROOT_DIR/data/logs"
  OLLAMA_HOST="${SCOPEGUARD_OLLAMA_URL:-http://127.0.0.1:11434}" \
    OLLAMA_MODELS="$(ollama_models_dir)" \
    OLLAMA_LLM_LIBRARY="${SCOPEGUARD_OLLAMA_LLM_LIBRARY:-$(ollama_cpu_library)}" \
    OLLAMA_CONTEXT_LENGTH=2048 OLLAMA_NUM_PARALLEL=1 OLLAMA_MAX_LOADED_MODELS=1 \
    OLLAMA_MAX_QUEUE=2 OLLAMA_NO_CLOUD=1 "$binary" serve >"$ROOT_DIR/data/logs/ollama-install.log" 2>&1 &
  OLLAMA_PID=$!
  OLLAMA_STARTED=1
  for _ in $(seq 1 60); do ollama_health && return 0; sleep 0.5; done
  die "Ollama did not become ready; inspect data/logs/ollama-install.log."
}

verify_ollama_model() {
  MODEL="$1" URL="${SCOPEGUARD_OLLAMA_URL:-http://127.0.0.1:11434}/api/generate" "$PYTHON_BIN" - <<'PY'
import json, os, urllib.request
payload = json.dumps({"model": os.environ["MODEL"], "prompt": "Return the single word READY.", "stream": False, "options": {"num_ctx": 512, "temperature": 0}}).encode()
request = urllib.request.Request(os.environ["URL"], data=payload, headers={"Content-Type": "application/json"})
with urllib.request.urlopen(request, timeout=120) as response: body = json.load(response)
if not isinstance(body.get("response"), str) or not body["response"].strip(): raise SystemExit("Ollama returned no inference text")
print("Ollama inference validation passed")
PY
}

prepare_ollama() {
  local binary
  binary="$(ollama_binary)"
  if [ "$LIMITED_MODE" = 1 ]; then
    if [ "${SCOPEGUARD_INSTALL_OLLAMA:-0}" = 1 ] || [ "${SCOPEGUARD_INSTALL_OLLAMA_MODEL:-0}" = 1 ]; then
      die "SCOPEGUARD_LIMITED_MODE=1 conflicts with explicit Ollama installation flags."
    fi
    warn "Limited installation requested: Ollama and Qwen will not be installed or verified."
    return 0
  fi
  if [ -z "$binary" ] && { [ "${SCOPEGUARD_INSTALL_OLLAMA:-0}" = 1 ] || [ "${SCOPEGUARD_INSTALL_OLLAMA_MODEL:-0}" = 1 ]; }; then
    install_local_ollama
    binary="$(ollama_binary)"
  elif [ -z "$binary" ] && interactive && confirm "Install project-local Ollama and configure local AI now?"; then
    install_local_ollama
    binary="$(ollama_binary)"
  fi
  if [ -z "$binary" ]; then
    die "Ollama is required for a complete installation. Approve local AI setup, or explicitly choose limited mode with SCOPEGUARD_LIMITED_MODE=1."
  fi
  say "Ollama runtime: $binary"
  start_ollama "$binary"
  if ! MODEL="$OLLAMA_MODEL" URL="${SCOPEGUARD_OLLAMA_URL:-http://127.0.0.1:11434}/api/tags" "$PYTHON_BIN" - <<'PY'
import json, os, urllib.request
with urllib.request.urlopen(os.environ["URL"], timeout=5) as response:
    names = {item.get("name", "") for item in json.load(response).get("models", [])}
if os.environ["MODEL"] not in names:
    raise SystemExit(1)
PY
  then
    if [ "${SCOPEGUARD_INSTALL_OLLAMA_MODEL:-0}" = 1 ] || { interactive && confirm "Download $OLLAMA_MODEL now?"; }; then
      say "Pulling model $OLLAMA_MODEL."
      OLLAMA_MODELS="$(ollama_models_dir)" "$binary" pull "$OLLAMA_MODEL"
    else
      die "The exact Qwen model $OLLAMA_MODEL is missing. Approve the model download or choose explicit limited mode."
    fi
  fi
  if ! verify_ollama_model "$OLLAMA_MODEL"; then
    die "The Ollama model did not pass inference validation; inspect data/logs/ollama-install.log."
  fi
}

prepare_scopeguard_ai() {
  [ "$LIMITED_MODE" = 1 ] && return 0
  say "Verifying ScopeGuard's structured local-AI integration with a real inference request."
  SCOPEGUARD_OLLAMA_URL="${SCOPEGUARD_OLLAMA_URL:-http://127.0.0.1:11434}" \
    SCOPEGUARD_OLLAMA_MODEL="$OLLAMA_MODEL" \
    "$ROOT_DIR/.venv/bin/python" -m app.cli ai-self-test
}

install_python_environment() {
  if [ ! -d "$ROOT_DIR/.venv" ]; then
    say "Creating isolated Python environment."
    "$PYTHON_BIN" -m venv "$ROOT_DIR/.venv"
  fi
  source "$ROOT_DIR/.venv/bin/activate"
  python -m pip install --upgrade pip
  python -m pip install --requirement "$ROOT_DIR/requirements.txt"
  if [ "${SCOPEGUARD_INSTALL_DEV:-0}" = 1 ]; then python -m pip install --requirement "$ROOT_DIR/requirements-dev.txt"; fi
  python -m pip install --no-deps --editable "$ROOT_DIR"
}

detect_platform
print_environment
ensure_python
check_optional_tools
install_python_environment
prepare_ollama
prepare_scopeguard_ai
mkdir -p "$ROOT_DIR/data"
if [ ! -f "$ROOT_DIR/.env" ]; then cp "$ROOT_DIR/.env.example" "$ROOT_DIR/.env"; fi
python -m app.cli self-test
if [ "$LIMITED_MODE" = 1 ]; then
  say "Installation completed in LIMITED MODE without Ollama/Qwen."
  say "To complete local-AI setup later: SCOPEGUARD_INSTALL_OLLAMA=1 SCOPEGUARD_INSTALL_OLLAMA_MODEL=1 ./install.sh"
else
  say "Installation Successful: Ollama, Qwen, ScopeGuard AI integration, dependencies, and self-tests passed."
fi
say "Start with ./start.sh"
