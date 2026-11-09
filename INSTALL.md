# Installing ScopeGuard VAPT

## Supported path

The supported workflow is a local Linux checkout:

~~~bash
git clone https://github.com/N0F4C3-4823/scopeguard-vapt.git
cd scopeguard-vapt
./install.sh
./start.sh
~~~

The installer is idempotent. It creates .venv, installs the exact runtime pins in requirements.txt, installs the editable package, creates .env from .env.example, initializes the database, and runs the registry self-test. It asks before installing system packages. A complete installation also installs or detects Ollama, downloads `qwen2.5:1.5b-instruct`, starts the local API, and performs a real ScopeGuard structured-inference check; it fails closed if any of those required AI checks fail.

## System dependencies

The installer detects Debian/Kali apt, Fedora/RHEL dnf/yum, Arch pacman, and openSUSE zypper. If required packages are absent, review the displayed list and either approve the interactive prompt or run:

~~~bash
SCOPEGUARD_INSTALL_SYSTEM_PACKAGES=1 ./install.sh
~~~

The package list includes Python/venv support, curl, CA certificates, nmap, openssl, DNS utilities, and zstd. Distribution package names differ; unsupported distributions receive a clear diagnostic instead of an unsafe guessed command.

## Development installation

Install test tools in the isolated environment with:

~~~bash
SCOPEGUARD_INSTALL_DEV=1 ./install.sh
~~~

Then run:

~~~bash
.venv/bin/pytest -q
.venv/bin/ruff check app tests
node --check static/app.js
~~~

The browser suite requires a running application and the connected Playwright browser:

~~~bash
./start.sh --port 8001
SCOPEGUARD_E2E=1 SCOPEGUARD_BASE_URL=http://127.0.0.1:8001 .venv/bin/pytest -q tests/e2e/test_gui_smoke.py
~~~

## Ollama and Qwen

Ollama remains local-only. On x86_64 and arm64 Linux, the complete installer downloads the official project-local runtime after explicit approval when it is not already available:

~~~bash
SCOPEGUARD_INSTALL_OLLAMA=1 \
SCOPEGUARD_INSTALL_OLLAMA_MODEL=1 \
./install.sh
~~~

The default model is `qwen2.5:1.5b-instruct`. The installer starts a temporary local server, reuses or pulls the model into `data/ollama`, performs a raw inference check, then performs ScopeGuard's real schema/evidence-reference AI self-test. CPU-only settings limit concurrency and loaded models. It does not expose Ollama beyond localhost. Large models are not supported by the recommended low-memory profile.

If AI cannot be installed, use the explicit limited path:

~~~bash
SCOPEGUARD_LIMITED_MODE=1 ./install.sh
~~~

Limited mode is clearly reported and the rest of the deterministic assessment engine remains available; it must not be confused with a complete AI-ready installation. A later `SCOPEGUARD_INSTALL_OLLAMA=1 SCOPEGUARD_INSTALL_OLLAMA_MODEL=1 ./install.sh` resumes the complete path without deleting assessment data.

## Startup and shutdown

~~~bash
./start.sh
~~~

The launcher checks for duplicate local instances, starts a project-local Ollama only when present, starts the backend, polls /api/health, prints the actual URL, and cleans up only child processes it started. Use Ctrl-C for a clean shutdown.

## Data location

Runtime data is stored only under data/. Do not commit it. Back up this directory before upgrades or deletion. It contains assessment scope, evidence, reports, and optional model data.

## WSL

WSL is suitable for controlled fixture assessments and many TCP/external checks. Wireless, Layer-2, some ICMP, and privileged network operations may be unavailable. The capability engine records those constraints; it does not claim that WSL is equivalent to a native internal sensor.
