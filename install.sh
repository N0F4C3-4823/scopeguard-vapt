#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_BIN="${PYTHON_BIN:-python3}"
OLLAMA_MODEL="${SCOPEGUARD_OLLAMA_MODEL:-qwen2.5:1.5b-instruct}"
OLLAMA_PID=""
OLLAMA_STARTED=0

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
    DISTRO_NAME="${PRETTY_NAME:-\$DISTRO_ID}"
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

start_ollama() {
  local binary="$1"
  if ollama_health; then return 0; fi
  mkdir -p "${OLLAMA_MODELS:-$ROOT_DIR/data/ollama}" "$ROOT_DIR/data/logs"
  OLLAMA_HOST="${SCOPEGUARD_OLLAMA_URL:-http://127.0.0.1:11434}" \
    OLLAMA_MODELS="${OLLAMA_MODELS:-$ROOT_DIR/data/ollama}" \
    OLLAMA_NUM_PARALLEL=1 OLLAMA_MAX_LOADED_MODELS=1 "$binary" serve >"$ROOT_DIR/data/logs/ollama-install.log" 2>&1 &
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
  if [ -z "$binary" ] && { [ "${SCOPEGUARD_INSTALL_OLLAMA:-0}" = 1 ] || [ "${SCOPEGUARD_INSTALL_OLLAMA_MODEL:-0}" = 1 ]; }; then
    install_local_ollama
    binary="$(ollama_binary)"
  elif [ -z "$binary" ] && interactive && confirm "Install project-local Ollama for optional local AI?"; then
    install_local_ollama
    binary="$(ollama_binary)"
  fi
  if [ -z "$binary" ]; then warn "Ollama is not installed; continuing without optional local AI."; return 0; fi
  say "Ollama runtime: $binary"
  if [ "${SCOPEGUARD_INSTALL_OLLAMA_MODEL:-0}" = 1 ] || { interactive && confirm "Download $OLLAMA_MODEL?"; }; then
    start_ollama "$binary"
    say "Pulling model $OLLAMA_MODEL."
    OLLAMA_MODELS="${OLLAMA_MODELS:-$ROOT_DIR/data/ollama}" "$binary" pull "$OLLAMA_MODEL"
    verify_ollama_model "$OLLAMA_MODEL"
  fi
}

detect_platform
print_environment
ensure_python
check_optional_tools
prepare_ollama

if [ ! -d "$ROOT_DIR/.venv" ]; then
  say "Creating isolated Python environment."
  "$PYTHON_BIN" -m venv "$ROOT_DIR/.venv"
fi
source "$ROOT_DIR/.venv/bin/activate"
python -m pip install --upgrade pip
python -m pip install --requirement "$ROOT_DIR/requirements.txt"
if [ "${SCOPEGUARD_INSTALL_DEV:-0}" = 1 ]; then python -m pip install --requirement "$ROOT_DIR/requirements-dev.txt"; fi
python -m pip install --no-deps --editable "$ROOT_DIR"
mkdir -p "$ROOT_DIR/data"
if [ ! -f "$ROOT_DIR/.env" ]; then cp "$ROOT_DIR/.env.example" "$ROOT_DIR/.env"; fi
python -m app.cli self-test
say "Installation completed. Start with ./start.sh"
