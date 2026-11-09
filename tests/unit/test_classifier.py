import sys
from pathlib import Path

from app.classifier import classify
from app.commands import run_command
from app.registry import TESTCASE_BY_ID


def run_fixture(tmp_path: Path, scenario: str, testcase_id: str = "01"):
    return run_command(
        [sys.executable, "-m", "app.fixture_command", "--testcase-id", testcase_id, "--scenario", scenario, "--target", f"fixture://{scenario}"],
        timeout_seconds=0.4 if scenario == "timeout" else 3,
        cwd=Path.cwd(),
    )


def test_classifier_distinguishes_found_negative_na_and_inconclusive(tmp_path):
    assert classify(TESTCASE_BY_ID["01"], run_fixture(tmp_path, "positive")).status == "FOUND"
    assert classify(TESTCASE_BY_ID["01"], run_fixture(tmp_path, "negative")).status == "NOT_FOUND"
    assert classify(TESTCASE_BY_ID["01"], run_fixture(tmp_path, "na")).status == "NA"
    assert classify(TESTCASE_BY_ID["01"], run_fixture(tmp_path, "na"), allow_na=False).status == "INCONCLUSIVE"
    assert classify(TESTCASE_BY_ID["01"], run_fixture(tmp_path, "failure")).status == "INCONCLUSIVE"
    assert classify(TESTCASE_BY_ID["01"], run_fixture(tmp_path, "timeout")).status == "INCONCLUSIVE"
