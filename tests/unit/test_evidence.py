import json
from pathlib import Path

from app.classifier import classify
from app.commands import run_command
from app.evidence import png_has_text_metadata, write_testcase_evidence
from app.registry import TESTCASE_BY_ID


def test_evidence_preserves_raw_output_and_exact_poc_layout(tmp_path: Path):
    command = run_command(
        ["python", "-m", "app.fixture_command", "--testcase-id", "01", "--scenario", "positive", "--target", "fixture://positive"],
        timeout_seconds=3,
        cwd=Path.cwd(),
    )
    classification = classify(TESTCASE_BY_ID["01"], command)
    artifact = write_testcase_evidence(
        tmp_path,
        "target-001_fixture_positive",
        TESTCASE_BY_ID["01"],
        command,
        classification,
        target_value="fixture://positive",
        target_id="target-001",
        fixture_id="fixture://positive",
    )
    testcase_dir = tmp_path / "target-001_fixture_positive" / "testcases" / "01_NTP_Open_Reflection_Amplification"
    assert (testcase_dir / "POCs" / "FOUND").is_dir()
    assert (testcase_dir / "POCs" / "NOT_FOUND").is_dir()
    assert (testcase_dir / "evidence" / "stdout.bin").read_bytes() == command.stdout
    png = Path(tmp_path, artifact["poc_paths"][0])
    assert png.exists()
    assert not png_has_text_metadata(png)
    payload = png.with_name("payload.txt")
    assert payload.read_text(encoding="utf-8").startswith(command.displayed_command + "\n\n")
    assert "STATUS=" not in payload.read_text(encoding="utf-8")
    assert "FOUND" in json.loads((testcase_dir / "result.json").read_text()) ["status"]
