from __future__ import annotations

import time

from app.models import AssessmentCreate
from app.registry import TESTCASES


def _wait_for_terminal(database, assessment_id: str) -> dict:
    for _ in range(1200):
        assessment = database.get_assessment(assessment_id)
        if assessment and assessment["status"] in {"COMPLETED", "FAILED", "CANCELLED"}:
            return assessment
        time.sleep(0.05)
    raise AssertionError("parallel controlled assessment did not reach a terminal state")


def test_target_workers_execute_concurrently_and_remain_isolated(manager, database):
    target_values = [
        "fixture://positive",
        "fixture://negative",
        "fixture://mixed",
        "fixture://na",
        "fixture://failure",
    ]
    assessment = manager.create(
        AssessmentCreate(
            name="Parallel target scheduler",
            targets=target_values,
            authorized=True,
            profile="controlled_fixture",
            llm_enabled=False,
        )
    )
    manager.start(assessment["id"])
    final = _wait_for_terminal(database, assessment["id"])

    assert final["status"] == "COMPLETED"
    results = database.list_results(assessment["id"])
    assert len(results) == len(target_values) * len(TESTCASES)
    assert len({(row["target_id"], row["testcase_id"]) for row in results}) == len(results)
    scheduler = [event for event in database.list_events(assessment["id"]) if event["event"] == "target_scheduler_started"]
    assert scheduler
    assert scheduler[-1]["payload_json"]["max_target_workers"] == 5
    assert manager.max_active_commands > 1
