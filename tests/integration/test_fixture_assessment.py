import time

from app.models import AssessmentCreate
from app.registry import TESTCASES


def wait_for_terminal(manager, database, assessment_id):
    thread = None
    for _ in range(1200):
        row = database.get_assessment(assessment_id)
        if row and row["status"] in {"COMPLETED", "FAILED", "CANCELLED"}:
            thread = manager._threads.get(assessment_id)
            if thread:
                thread.join(timeout=5)
            return row
        time.sleep(0.05)
    raise AssertionError("assessment did not reach a terminal state")


def test_complete_mixed_fixture_has_40_rows_and_exports(manager, database, settings):
    assessment = manager.create(
        AssessmentCreate(
            name="Mixed fixture",
            targets=["fixture://mixed"],
            authorized=True,
            assessment_type="external_unauthenticated",
        )
    )
    manager.start(assessment["id"])
    final = wait_for_terminal(manager, database, assessment["id"])
    assert final["status"] == "COMPLETED"
    results = database.list_results(assessment["id"])
    assert len(results) == len(TESTCASES) == 40
    assert {row["status"] for row in results} == {"FOUND", "NOT_FOUND", "NA", "INCONCLUSIVE"}
    assert final["na_count"] > 0
    assert final["inconclusive_count"] > 0
    assert final["applicable_count"] == 34
    assert (settings.data_dir / "exports" / f"{assessment['id']}.zip").exists()
