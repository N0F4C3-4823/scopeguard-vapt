from __future__ import annotations

import resource
import time

from app.models import AssessmentCreate
from app.registry import TESTCASES


def _wait_for_terminal(manager, database, assessment_id: str):
    for _ in range(1800):
        row = database.get_assessment(assessment_id)
        if row and row["status"] in {"COMPLETED", "FAILED", "CANCELLED"}:
            thread = manager._threads.get(assessment_id)
            if thread:
                thread.join(timeout=5)
            return row
        time.sleep(0.1)
    raise AssertionError("live local assessment did not reach a terminal state")


def test_authorized_local_target_runs_production_live_adapter_path(manager, database, settings):
    started = time.monotonic()
    assessment = manager.create(
        AssessmentCreate(
            name="Authorized local live adapter audit",
            targets=["127.0.0.1"],
            authorized=True,
            authorization_note="Controlled local loopback service authorization for automated testing",
            profile="authorized_external",
            assessment_type="external_unauthenticated",
        )
    )
    manager.start(assessment["id"])
    final = _wait_for_terminal(manager, database, assessment["id"])
    assert final["status"] == "COMPLETED"
    results = database.list_results(assessment["id"])
    assert len(results) == len(TESTCASES) == 40
    assert all(row["command"] is not None for row in results if row["status"] not in {"NA"})
    assert any(row["status"] == "FOUND" for row in results)
    assert any(row["status"] == "INCONCLUSIVE" for row in results)
    root = settings.data_dir / "assessments" / assessment["id"]
    assert (root / "manifest.json").exists()
    assert (settings.data_dir / "exports" / f"{assessment['id']}.zip").exists()
    elapsed = time.monotonic() - started
    peak_rss_mb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024
    assert elapsed < 360, f"controlled live assessment exceeded 6 minutes: {elapsed:.1f}s"
    assert manager.max_active_commands == 1
    assert manager.active_commands == 0
    discovery_executions = [
        execution for execution in database.list_executions(assessment["id"])
        if execution["testcase_id"].startswith("DISCOVERY_")
    ]
    adapter_executions = [
        execution for execution in database.list_executions(assessment["id"])
        if not execution["testcase_id"].startswith("DISCOVERY_")
    ]
    assert len(discovery_executions) == 2
    # A filtered/externally inaccessible result may use the immutable shared
    # discovery command as its applicability POC.  That is deliberate evidence
    # reuse, not a second network execution for every testcase.  Count only
    # result commands that are not one of the two shared discovery commands
    # when checking subprocess provenance.
    discovery_commands = {row["displayed_command"] for row in discovery_executions}
    adapter_result_rows = [
        row for row in results
        if row["command"] is not None and row["command"] not in discovery_commands
    ]
    assert len(adapter_executions) == len(adapter_result_rows)
    assert {row["command"] for row in adapter_result_rows} >= {
        execution["displayed_command"]
        for execution in adapter_executions
        if execution["testcase_id"] not in {"DISCOVERY_TCP", "DISCOVERY_UDP"}
    }
    assert manager.executed_commands == len(discovery_executions) + len(adapter_executions)
    print(f"LIVE_PERFORMANCE elapsed_seconds={elapsed:.2f} peak_rss_mb={peak_rss_mb:.1f} max_active_commands={manager.max_active_commands} executed_commands={manager.executed_commands}")
