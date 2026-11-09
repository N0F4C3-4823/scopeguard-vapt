from __future__ import annotations

import json
from pathlib import Path

from app.commands import CommandResult
from app.live_adapters import build_command, capability_matrix, parse_live_result


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


def _nmap_result(text: str) -> CommandResult:
    return CommandResult(
        id="parser-test",
        argv=("nmap", "-Pn", "127.0.0.1"),
        displayed_command="nmap -Pn 127.0.0.1",
        cwd=str(Path.cwd()),
        started_at="2026-01-01T00:00:00+00:00",
        ended_at="2026-01-01T00:00:01+00:00",
        exit_code=0,
        timed_out=False,
        stdout=text.encode(),
        stderr=b"",
        status="COMPLETED",
        tool_version="nmap test",
    )


def test_filtered_reason_is_protocol_specific_and_never_generic_udp():
    tcp = _nmap_result("23/tcp filtered telnet\nNmap done: 1 IP address (1 host up) scanned in 0.01 seconds\n")
    udp = _nmap_result("123/udp open|filtered ntp\nNmap done: 1 IP address (1 host up) scanned in 0.01 seconds\n")
    tcp_result = parse_live_result("10", tcp)
    udp_result = parse_live_result("01", udp)
    assert "TCP filtering" in (tcp_result.reason or "")
    assert "UDP" in (udp_result.reason or "")
    assert "UDP silence" not in (tcp_result.reason or "")


def test_tool_exit_codes_are_explained_without_negative_verdicts():
    curl = _nmap_result("curl: operation timed out\n")
    curl = CommandResult(**{**curl.__dict__, "argv": ("curl", "--max-time", "1", "http://127.0.0.1"), "exit_code": 28, "status": "FAILED"})
    dns = CommandResult(**{**curl.__dict__, "argv": ("dig", "+time=1", "@127.0.0.1", ".", "NS"), "exit_code": 9, "stderr": b"no servers could be reached", "status": "FAILED"})
    assert parse_live_result("27", curl).status == "INCONCLUSIVE"
    assert "curl exited 28" in (parse_live_result("27", curl).reason or "")
    assert "dig exited 9" in (parse_live_result("40", dns).reason or "")
