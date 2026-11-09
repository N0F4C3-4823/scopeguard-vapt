from __future__ import annotations

import json
from pathlib import Path

from app.live_adapters import capability_matrix


def test_security_engine_validation_matrix_is_explicit_and_fail_closed():
    payload = json.loads(Path("docs/security_engine_validation_matrix.json").read_text(encoding="utf-8"))
    entries = payload["entries"]
    assert payload["registered_testcases"] == 40
    assert len(entries) == 40
    assert sum(entry["command_path_exercised"] for entry in entries) == 34
    assert sum(entry["controlled_service_validated"] for entry in entries) == 16
    assert sum(entry["live_status"] == "CAPABILITY_ONLY" for entry in entries) == 6
    assert [entry["id"] for entry in entries] == [f"{index:02d}" for index in range(1, 41)]
    runtime = {entry["testcase"]["id"]: entry["live"] for entry in capability_matrix()}
    for entry in entries:
        live = runtime[entry["id"]]
        assert entry["live_status"] == live["live_status"]
        assert entry["live_adapter"] == live["execution_adapter"]
        assert entry["command_path_exercised"] is live["has_live_execution"]
        for state in ("positive_result", "negative_result", "inconclusive_result", "malformed_result"):
            assert entry[state]
        if live["live_status"] == "CAPABILITY_ONLY":
            assert entry["controlled_service_validated"] is False
            assert entry["evidence_verification"].startswith("Not applicable")
