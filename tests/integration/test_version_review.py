from __future__ import annotations

import json
from pathlib import Path

from app.commands import sha256_bytes
from app.models import AssessmentCreate
from app.orchestrator import AssessmentManager
from app.registry import TESTCASES


def test_manual_version_review_persists_decision_and_genuine_poc(manager, database, settings):
    assessment = manager.create(
        AssessmentCreate(
            name="Manual version review",
            targets=["fixture://mixed"],
            authorized=True,
            profile="controlled_fixture",
        )
    )
    assessment_id = assessment["id"]
    target = database.get_targets(assessment_id)[0]
    testcase = next(item for item in TESTCASES if item.id == "11")
    root = settings.data_dir / "assessments" / assessment_id
    testcase_dir = root / AssessmentManager._target_dir_name(target) / "testcases" / f"11_{testcase.condition}"
    evidence_dir = testcase_dir / "evidence"
    evidence_dir.mkdir(parents=True)
    stdout = b"21/tcp open ftp vsftpd 2.0.8 or later\n80/tcp open http Apache httpd 2.4.58\n"
    stderr = b""
    (evidence_dir / "stdout.txt").write_bytes(stdout)
    (evidence_dir / "stderr.txt").write_bytes(stderr)
    (testcase_dir / "result.json").write_text(
        json.dumps({"status": "INCONCLUSIVE", "final_verdict": None, "poc_paths": []}),
        encoding="utf-8",
    )
    execution_id = "version-review-execution"
    database.add_execution(
        {
            "id": execution_id,
            "assessment_id": assessment_id,
            "target_id": target["id"],
            "testcase_id": "11",
            "command_json": json.dumps(["nmap", "-sV", "-p", "21,80", target["value"]]),
            "displayed_command": f"nmap -sV -p 21,80 {target['value']}",
            "cwd": str(Path.cwd()),
            "started_at": "2026-01-01T00:00:00+00:00",
            "ended_at": "2026-01-01T00:00:01+00:00",
            "exit_code": 0,
            "timed_out": 0,
            "tool_version": "Nmap fixture",
            "stdout_path": str((evidence_dir / "stdout.txt").relative_to(root)),
            "stderr_path": str((evidence_dir / "stderr.txt").relative_to(root)),
            "stdout_sha256": sha256_bytes(stdout),
            "stderr_sha256": sha256_bytes(stderr),
            "combined_sha256": sha256_bytes(stdout + stderr),
            "execution_status": "COMPLETED",
        }
    )
    result_id = database.add_result(
        {
            "assessment_id": assessment_id,
            "target_id": target["id"],
            "target": target["value"],
            "target_label": target["label"],
            "testcase_id": "11",
            "testcase_name": testcase.name,
            "status": "INCONCLUSIVE",
            "final_verdict": None,
            "coverage_status": "INSUFFICIENT_EVIDENCE",
            "coverage_reason": "Operator review required",
            "observation_type": "vulnerability",
            "reportable_finding": 0,
            "description_line_1": "",
            "description_line_2": "",
            "applicability": "applicable",
            "conditions_tested_json": [testcase.condition],
            "conditions_confirmed_json": [],
            "conditions_not_found_json": [],
            "inconclusive_conditions_json": [testcase.condition],
            "severity": "informational",
            "finding_ids_json": [],
            "evidence_paths_json": [],
            "poc_paths_json": [],
            "tools_used_json": ["nmap"],
            "validation_state": "INCOMPLETE",
            "failure_reason": "Operator review required",
            "evidence_id": execution_id,
            "command": f"nmap -sV -p 21,80 {target['value']}",
            "output_preview": stdout.decode(),
            "created_at": "2026-01-01T00:00:01+00:00",
        }
    )
    for other in TESTCASES:
        if other.id == "11":
            continue
        database.add_result(
            {
                "assessment_id": assessment_id,
                "target_id": target["id"],
                "target": target["value"],
                "target_label": target["label"],
                "testcase_id": other.id,
                "testcase_name": other.name,
                "status": "NA",
                "final_verdict": "NA",
                "coverage_status": "COMPLETED",
                "coverage_reason": "Controlled review fixture",
                "observation_type": "informational",
                "reportable_finding": 0,
                "description_line_1": "The controlled review fixture does not include this condition.",
                "description_line_2": "This result is limited to the explicitly configured fixture scope.",
                "applicability": "not_applicable",
                "conditions_tested_json": [],
                "conditions_confirmed_json": [],
                "conditions_not_found_json": [],
                "inconclusive_conditions_json": [],
                "severity": "informational",
                "finding_ids_json": [],
                "evidence_paths_json": [],
                "poc_paths_json": [],
                "tools_used_json": [],
                "validation_state": "VALIDATED",
                "failure_reason": None,
                "evidence_id": None,
                "command": None,
                "output_preview": None,
                "created_at": "2026-01-01T00:00:01+00:00",
            }
        )

    review = manager.version_review(assessment_id, target["id"])
    assert review["review_required"] is True
    assert [entry["port"] for entry in review["entries"]] == [21, 80]
    assert review["poc_paths"]
    assert all((root / path).is_file() for path in review["poc_paths"])

    reviewable = [entry["entry_id"] for entry in review["entries"] if entry["reviewable"]]
    finalized = manager.submit_version_review(
        assessment_id,
        target["id"],
        decision="none_outdated",
        selected_entry_ids=[],
        reviewed_entry_ids=reviewable,
        unidentified_acknowledged=True,
    )
    assert finalized["review_required"] is False
    stored = next(item for item in database.list_results(assessment_id) if item["id"] == result_id)
    assert stored["final_verdict"] == "NOT_FOUND"
    assert len(stored["description_line_1"]) > 0
    assert stored["description_line_2"]
    assert stored["poc_paths_json"]
    result_payload = json.loads((testcase_dir / "result.json").read_text(encoding="utf-8"))
    assert result_payload["final_verdict"] == "NOT_FOUND"
    assert result_payload["poc_paths"]
    assert database.list_version_reviews(assessment_id, target["id"])
