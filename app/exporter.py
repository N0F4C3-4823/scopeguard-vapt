from __future__ import annotations

import csv
import io
import json
import os
import stat
import tempfile
import zipfile
from pathlib import Path
from typing import Any

from .db import Database
from .live_adapters import adapter_for
from .registry import TESTCASES

CSV_HEADERS = [
    "assessment_id",
    "target",
    "target_label",
    "testcase_id",
    "testcase_name",
    "status",
    "applicability",
    "conditions_tested",
    "conditions_confirmed",
    "conditions_not_found",
    "inconclusive_conditions",
    "severity",
    "finding_ids",
    "evidence_paths",
    "poc_paths",
    "tools_used",
    "validation_state",
    "failure_reason",
]


class ExportError(RuntimeError):
    pass


def _csv_text(headers: list[str], rows: list[list[str]]) -> str:
    stream = io.StringIO(newline="")
    writer = csv.writer(stream, lineterminator="\n")
    writer.writerow(headers)
    writer.writerows(rows)
    return stream.getvalue()


def _join(value: Any) -> str:
    if isinstance(value, list):
        return "; ".join(str(item) for item in value)
    return "" if value is None else str(value)


def _validate_relative(path: Path) -> None:
    if path.is_symlink():
        raise ExportError(f"Symlink is not allowed in export: {path}")
    if path.is_absolute() or ".." in path.parts:
        raise ExportError(f"Unsafe export path: {path}")


def _zip_tree(root: Path, archive_path: Path) -> None:
    with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(root.rglob("*")):
            relative = path.relative_to(root)
            _validate_relative(relative)
            if path.is_dir():
                archive.writestr(relative.as_posix().rstrip("/") + "/", "")
                continue
            if path.is_symlink() or stat.S_ISLNK(path.stat(follow_symlinks=False).st_mode):
                raise ExportError(f"Symlink is not allowed in export: {path}")
            archive.write(path, relative.as_posix())
    if zipfile.ZipFile(archive_path).testzip() is not None:
        raise ExportError("ZIP integrity check failed")


def export_assessment(
    db: Database,
    assessment_id: str,
    data_dir: Path,
    *,
    status_override: str | None = None,
) -> dict[str, Path]:
    assessment = db.get_assessment(assessment_id)
    if not assessment:
        raise ExportError("Assessment not found")
    if status_override:
        assessment["status"] = status_override
    targets = db.get_targets(assessment_id)
    results = db.list_results(assessment_id)
    if len(results) != len(targets) * len(TESTCASES):
        raise ExportError("Export refused: testcase result coverage is incomplete")
    assessment_root = data_dir / "assessments" / assessment_id
    if not assessment_root.exists():
        raise ExportError("Evidence root is missing")
    for result in results:
        for relative in result["evidence_paths_json"] + result["poc_paths_json"]:
            path = assessment_root / relative
            if not path.exists() or path.is_dir():
                raise ExportError(f"Required evidence is missing: {relative}")
    result_rows = [
        [
            result["assessment_id"],
            result["target"],
            result["target_label"],
            result["testcase_id"],
            result["testcase_name"],
            result["status"],
            result["applicability"],
            _join(result["conditions_tested_json"]),
            _join(result["conditions_confirmed_json"]),
            _join(result["conditions_not_found_json"]),
            _join(result["inconclusive_conditions_json"]),
            result["severity"],
            _join(result["finding_ids_json"]),
            _join(result["evidence_paths_json"]),
            _join(result["poc_paths_json"]),
            _join(result["tools_used_json"]),
            result["validation_state"],
            result["failure_reason"] or "",
        ]
        for result in results
    ]
    (assessment_root / "testcase_results.csv").write_text(
        _csv_text(CSV_HEADERS, result_rows), encoding="utf-8", newline=""
    )
    findings_headers = [
        "finding_id", "target", "testcase_id", "finding_name", "status", "severity",
        "description", "technical_evidence", "validation_method", "remediation", "references",
        "poc_paths", "confidence_basis",
    ]
    finding_rows = []
    for result in results:
        for finding_id in result["finding_ids_json"]:
            finding_rows.append([
                finding_id,
                result["target"],
                result["testcase_id"],
                result["testcase_name"],
                result["status"],
                result["severity"],
                "Deterministic evidence-backed observation; validate the precise predicate against the attached raw command output.",
                result["output_preview"] or "",
                result["validation_state"],
                "Review the precise configuration represented by the evidence before remediation.",
                "",
                _join(result["poc_paths_json"]),
                "Command exit status, predicate token, observation ID, and SHA-256 evidence hashes.",
            ])
    (assessment_root / "findings.csv").write_text(
        _csv_text(findings_headers, finding_rows), encoding="utf-8", newline=""
    )
    executions = db.list_executions(assessment_id)
    tool_rows = [["python", "runtime", "available", assessment.get("profile", "")]]
    seen_tools: set[str] = set()
    for execution in executions:
        executable = Path(json.loads(execution["command_json"])[0]).name
        if executable in seen_tools:
            continue
        seen_tools.add(executable)
        tool_rows.append([
            executable,
            "live adapter executable",
            execution["execution_status"],
            f"version={execution['tool_version']}; exit_code={execution['exit_code']}; timed_out={bool(execution['timed_out'])}",
        ])
    tool_rows.append(["ollama", "optional local LLM", "enabled" if assessment["llm_enabled"] else "disabled", "secondary evidence analysis only"])
    (assessment_root / "tool_status.csv").write_text(
        _csv_text(["tool", "capability", "status", "details"], tool_rows), encoding="utf-8", newline=""
    )
    llm_rows = [[
        item["result_id"], item["model"], item["prompt_version"], item["validation_state"],
        json.dumps(item["response_json"], ensure_ascii=False),
    ] for item in db.list_llm_triage(assessment_id)]
    (assessment_root / "llm_triage.csv").write_text(
        _csv_text(["result_id", "model", "prompt_version", "validation_state", "response"], llm_rows),
        encoding="utf-8",
        newline="",
    )
    coverage = {
        "registry_ids": [test.id for test in TESTCASES],
        "expected_rows": len(targets) * len(TESTCASES),
        "actual_rows": len(results),
        "targets": [target["value"] for target in targets],
        "entries": [
            {
                "testcase_id": result["testcase_id"],
                "target_id": result["target_id"],
                "status": result["status"],
                "live_adapter": adapter_for(result["testcase_id"]).as_dict(),
                "fixture_id": result["target"],
                "evidence_paths": result["evidence_paths_json"],
                "poc_paths": result["poc_paths_json"],
            }
            for result in results
        ],
    }
    (assessment_root / "manifest.json").write_text(json.dumps(coverage, indent=2), encoding="utf-8")
    (assessment_root / "assessment.json").write_text(
        json.dumps({"assessment": assessment, "targets": targets, "results": results}, indent=2),
        encoding="utf-8",
    )
    counts = {status: sum(1 for result in results if result["status"] == status) for status in (
        "FOUND", "NOT_FOUND", "NA", "INCONCLUSIVE"
    )}
    summary = "\n".join([
        f"Assessment identifier: {assessment_id}",
        f"Assessment name: {assessment['name']}",
        f"Authorized scope: {assessment['authorization_note']}",
        f"Targets: {len(targets)}",
        f"Expected testcase rows: {len(targets) * len(TESTCASES)}",
        f"Actual testcase rows: {len(results)}",
        f"FOUND: {counts['FOUND']}",
        f"NOT_FOUND: {counts['NOT_FOUND']}",
        f"NA: {counts['NA']}",
        f"INCONCLUSIVE: {counts['INCONCLUSIVE']}",
        f"Command execution records: {len(executions)}",
        f"Completed command executions: {sum(item['execution_status'] == 'COMPLETED' for item in executions)}",
        f"Failed or timed-out command executions: {sum(item['execution_status'] != 'COMPLETED' for item in executions)}",
        f"Final execution status: {assessment['status']}",
        f"Output directory: {assessment_root}",
        "No result is inferred from a failed or incomplete execution.",
    ])
    (assessment_root / "assessment_summary.txt").write_text(summary + "\n", encoding="utf-8")
    (assessment_root / "execution.log").write_text(
        "\n".join(f"{result['target']} {result['testcase_id']} {result['status']}" for result in results) + "\n",
        encoding="utf-8",
    )
    (assessment_root / "errors.log").write_text(
        "\n".join(
            f"{result['target']} {result['testcase_id']}: {result['failure_reason']}"
            for result in results
            if result["failure_reason"]
        ) + "\n",
        encoding="utf-8",
    )
    archive_path = data_dir / "exports" / f"{assessment_id}.zip"
    archive_path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(prefix=f"{assessment_id}-", suffix=".zip", dir=archive_path.parent, delete=False) as temp:
        temp_path = Path(temp.name)
    try:
        _zip_tree(assessment_root, temp_path)
        os.replace(temp_path, archive_path)
    except Exception:
        temp_path.unlink(missing_ok=True)
        raise
    return {
        "root": assessment_root,
        "csv": assessment_root / "testcase_results.csv",
        "zip": archive_path,
        "manifest": assessment_root / "manifest.json",
    }
