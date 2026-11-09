from __future__ import annotations

import os
import shutil
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    root_dir: Path
    data_dir: Path
    host: str = "127.0.0.1"
    port: int = 8000
    max_cidr_hosts: int = 256
    max_workers: int = 1
    # Live timeouts are deliberately independent from controlled-fixture
    # timing. Nmap service detection can spend longer than its host timeout
    # finishing NSE/version work, so the subprocess grace period is explicit.
    live_command_timeout: float = 45.0
    live_limited_command_timeout: float = 45.0
    scanner_host_timeout_seconds: int = 30
    scanner_command_grace_seconds: int = 15
    scanner_max_retries: int = 2
    tcp_connect_timeout_seconds: int = 5
    protocol_timeout_seconds: int = 15
    nmap_script_timeout_seconds: int = 30
    assessment_deadline_seconds: int = 3600
    ollama_url: str = "http://127.0.0.1:11434"
    ollama_model: str = "qwen2.5:1.5b-instruct"
    ollama_binary: Path | None = None
    ollama_models_dir: Path | None = None

    @property
    def db_path(self) -> Path:
        return self.data_dir / "scopeguard.sqlite3"

    def ensure_dirs(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)


def load_settings(root_dir: Path | None = None) -> Settings:
    root = (root_dir or Path(__file__).resolve().parent.parent).resolve()
    data_value = os.getenv("SCOPEGUARD_DATA_DIR", str(root / "data"))
    data_dir = Path(data_value)
    if not data_dir.is_absolute():
        data_dir = (root / data_dir).resolve()
    bundled_ollama = root / ".tools" / "ollama" / "bin" / "ollama"
    configured_ollama = os.getenv("SCOPEGUARD_OLLAMA_BIN", "").strip()
    if configured_ollama:
        ollama_binary = Path(configured_ollama).expanduser()
        if not ollama_binary.is_absolute():
            ollama_binary = (root / ollama_binary).resolve()
    elif bundled_ollama.exists():
        ollama_binary = bundled_ollama
    else:
        ollama_binary = Path(shutil.which("ollama") or "ollama")
    models_value = os.getenv("OLLAMA_MODELS", str(data_dir / "ollama"))
    models_dir = Path(models_value)
    if not models_dir.is_absolute():
        models_dir = (root / models_dir).resolve()
    return Settings(
        root_dir=root,
        data_dir=data_dir,
        host=os.getenv("SCOPEGUARD_HOST", "127.0.0.1"),
        port=int(os.getenv("SCOPEGUARD_PORT", "8000")),
        max_cidr_hosts=int(os.getenv("SCOPEGUARD_MAX_CIDR_HOSTS", "256")),
        max_workers=max(1, int(os.getenv("SCOPEGUARD_MAX_WORKERS", "1"))),
        live_command_timeout=max(1.0, float(os.getenv("SCOPEGUARD_LIVE_COMMAND_TIMEOUT", "45"))),
        live_limited_command_timeout=max(1.0, float(os.getenv("SCOPEGUARD_LIVE_LIMITED_COMMAND_TIMEOUT", "45"))),
        scanner_host_timeout_seconds=max(1, int(os.getenv("SCOPEGUARD_SCANNER_HOST_TIMEOUT", "30"))),
        scanner_command_grace_seconds=max(1, int(os.getenv("SCOPEGUARD_SCANNER_COMMAND_GRACE", "15"))),
        scanner_max_retries=max(0, int(os.getenv("SCOPEGUARD_SCANNER_MAX_RETRIES", "2"))),
        tcp_connect_timeout_seconds=max(1, int(os.getenv("SCOPEGUARD_TCP_CONNECT_TIMEOUT", "5"))),
        protocol_timeout_seconds=max(1, int(os.getenv("SCOPEGUARD_PROTOCOL_TIMEOUT", "15"))),
        nmap_script_timeout_seconds=max(1, int(os.getenv("SCOPEGUARD_NMAP_SCRIPT_TIMEOUT", "30"))),
        assessment_deadline_seconds=max(60, int(os.getenv("SCOPEGUARD_ASSESSMENT_DEADLINE", "3600"))),
        ollama_url=os.getenv("SCOPEGUARD_OLLAMA_URL", "http://127.0.0.1:11434").rstrip("/"),
        ollama_model=os.getenv("SCOPEGUARD_OLLAMA_MODEL", "qwen2.5:1.5b-instruct"),
        ollama_binary=ollama_binary,
        ollama_models_dir=models_dir,
    )
