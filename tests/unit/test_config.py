from __future__ import annotations

from pathlib import Path

from app.config import load_settings


def test_live_timeout_settings_are_independent_from_fixture_timing(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("SCOPEGUARD_LIVE_COMMAND_TIMEOUT", "23")
    monkeypatch.setenv("SCOPEGUARD_LIVE_LIMITED_COMMAND_TIMEOUT", "17")
    monkeypatch.setenv("SCOPEGUARD_SCANNER_HOST_TIMEOUT", "11")
    settings = load_settings(tmp_path)
    assert settings.live_command_timeout == 23
    assert settings.live_limited_command_timeout == 17
    assert settings.scanner_host_timeout_seconds == 11
