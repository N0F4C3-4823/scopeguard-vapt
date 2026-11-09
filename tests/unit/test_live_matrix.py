from __future__ import annotations

import json
from pathlib import Path

from app.live_adapters import build_command, capability_matrix


def test_checked_in_live_capability_matrix_covers_registry_without_drift():
    path = Path("docs/live_capability_matrix.json")
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["schema_version"] == "scopeguard-live-capability-v1"
    assert [entry["id"] for entry in payload["entries"]] == [f"{index:02d}" for index in range(1, 41)]
    source = capability_matrix()
    for checked, runtime in zip(payload["entries"], source, strict=True):
        assert checked["id"] == runtime["testcase"]["id"]
        assert checked["condition"] == runtime["testcase"]["condition"]
        for field in (
            "live_status",
            "required_tools",
            "required_vantage",
            "required_permissions",
            "required_capabilities",
            "requires_credentials",
            "execution_adapter",
            "evidence_parser",
            "verification_logic",
            "supported_profiles",
            "coverage",
            "controlled_validation",
        ):
            assert checked[field] == runtime["live"][field]


def test_live_nmap_host_timeout_is_configurable():
    command = build_command("02", "127.0.0.1", nmap_host_timeout_seconds=19)
    assert command is not None
    assert command[command.index("--host-timeout") + 1] == "19s"
