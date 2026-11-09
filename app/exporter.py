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
from .descriptions import two_line_description, validate_two_line_description
from .evidence import safe_name
from .live_adapters import adapter_for
from .registry import TESTCASES

CSV_HEADERS = [
    "assessment_id",
    "target",
    "target_label",
    "testcase_id",
    "testcase_name",
    "status",
    "final_verdict",
    "coverage_status",
    "coverage_reason",
    "observation_type",
    "reportable_finding",
    "description_line_1",
    "description_line_2",
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


def target_dir_name(target: dict[str, Any]) -> str:
    return f"{target['id']}_{safe_name(target['label'])[:80]}"


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


def _description(result: dict[str, Any]) -> tuple[str, str]:
    line_1 = str(result.get("description_line_1") or "")
    line_2 = str(result.get("description_line_2") or "")
    verdict = result.get("final_verdict")
    target_identifiers = tuple(
        str(value)
        for value in (result.get("target"), result.get("target_label"))
        if value
    )
    if validate_two_line_description(line_1, line_2, target_identifiers=target_identifiers):
        return line_1, line_2
    if verdict not in {"FOUND", "NOT_FOUND", "NA"}:
        return "", ""
    return two_line_description(
        testcase_id=str(result["testcase_id"]),
        testcase_name=str(result["testcase_name"]),
        condition=str(result["testcase_name"]),
        verdict=verdict,
        observation_type=str(result.get("observation_type") or "vulnerability"),
        target=str(result.get("target_label") or result.get("target") or "the authorized target"),
        applicability=str(result.get("applicability") or "the required access or capability"),
    )


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
            if path.is_symlink() or stat.S_ISLNK(path.stat(follow_symlinks=False).st_mode):
                raise ExportError(f"Symlink is not allowed in export: {path}")
            if path.is_dir():
                archive.writestr(relative.as_posix().rstrip("/") + "/", "")
                continue
            archive.write(path, relative.as_posix())
    if zipfile.ZipFile(archive_path).testzip() is not None:
        raise ExportError("ZIP integrity check failed")


def _validate_result_coverage(results: list[dict[str, Any]], targets: list[dict[str, Any]]) -> None:
    expected = {(target["id"], testcase.id) for target in targets for testcase in TESTCASES}
    actual = {(result["target_id"], result["testcase_id"]) for result in results}
    if actual != expected or len(results) != len(expected):
        raise ExportError("Export refused: testcase result coverage is incomplete or duplicated")


def _validate_finalized_artifacts(assessment_root: Path, results: list[dict[str, Any]]) -> None:
    """Fail closed if a certified result lacks the required evidence artifact."""
    for result in results:
        verdict = result.get("final_verdict")
        pocs = result.get("poc_paths_json") or []
        if verdict in {"FOUND", "NOT_FOUND"}:
            if not pocs:
                raise ExportError(
                    f"Export refused: finalized {verdict} result {result['target_id']}/{result['testcase_id']} has no POC"
                )
            for relative in pocs:
                path = assessment_root / relative
                if path.suffix.lower() != ".png" or path.is_symlink() or not path.is_file() or path.stat().st_size == 0:
                    raise ExportError(f"Export refused: invalid POC artifact {relative}")
        elif verdict == "NA":
            # NA is an accessibility/applicability verdict, but it still
            # requires a genuine command/output POC when the applicability
            # decision was supported by recorded evidence.
            for relative in pocs:
                path = assessment_root / relative
                if path.suffix.lower() != ".png" or path.is_symlink() or not path.is_file() or path.stat().st_size == 0:
                    raise ExportError(f"Export refused: invalid NA POC artifact {relative}")
        if verdict in {"FOUND", "NOT_FOUND", "NA"}:
            line_1, line_2 = _description(result)
            target_identifiers = tuple(
                str(value)
                for value in (result.get("target"), result.get("target_label"))
                if value
            )
            if not validate_two_line_description(line_1, line_2, target_identifiers=target_identifiers):
                raise ExportError(
                    f"Export refused: finalized result {result['target_id']}/{result['testcase_id']} lacks two-line explanation"
                )


def _result_row(result: dict[str, Any]) -> list[str]:
    description_line_1, description_line_2 = _description(result)
    return [
        result["assessment_id"],
        result["target"],
        result["target_label"],
        result["testcase_id"],
        result["testcase_name"],
        result["status"],
        result.get("final_verdict") or "",
        result.get("coverage_status") or "INSUFFICIENT_EVIDENCE",
        result.get("coverage_reason") or "",
        result.get("observation_type") or "vulnerability",
        "true" if result.get("reportable_finding") else "false",
        description_line_1,
        description_line_2,
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


def _finding_rows(results: list[dict[str, Any]]) -> list[list[str]]:
    rows: list[list[str]] = []
    for result in results:
        if not result.get("reportable_finding"):
            continue
        for finding_id in result["finding_ids_json"]:
            description_line_1, description_line_2 = _description(result)
            rows.append([
                finding_id,
                result["target"],
                result["testcase_id"],
                result["testcase_name"],
                result.get("final_verdict") or "",
                result["severity"],
                f"{description_line_1} {description_line_2}".strip(),
                description_line_1,
                description_line_2,
                result["output_preview"] or "",
                result["validation_state"],
                "Review the precise configuration represented by the evidence before remediation.",
                "",
                _join(result["poc_paths_json"]),
                "Command exit status, predicate, observation ID, and SHA-256 evidence hashes.",
            ])
    return rows


FINDINGS_HEADERS = [
    "finding_id", "target", "testcase_id", "finding_name", "status", "severity",
    "description", "description_line_1", "description_line_2", "technical_evidence", "validation_method", "remediation", "references",
    "poc_paths", "confidence_basis",
]


def _write_target_exports(
    assessment_root: Path,
    target: dict[str, Any],
    results: list[dict[str, Any]],
) -> Path:
    target_root = assessment_root / target_dir_name(target)
    if target_root.is_symlink() or not target_root.is_dir():
        raise ExportError(f"Target evidence root is missing or unsafe: {target['id']}")
    target_rows = [result for result in results if result["target_id"] == target["id"]]
    if len(target_rows) != len(TESTCASES):
        raise ExportError(f"Target export refused: incomplete testcase coverage for {target['id']}")
    prefix = target_dir_name(target)
    for result in target_rows:
        for relative in result["evidence_paths_json"] + result["poc_paths_json"]:
            relative_path = Path(relative)
            if relative_path.is_absolute() or ".." in relative_path.parts or not relative_path.parts or relative_path.parts[0] != prefix:
                raise ExportError(f"Target evidence path is unsafe: {relative}")
            path = assessment_root / relative_path
            if path.is_symlink() or not path.is_file():
                raise ExportError(f"Target evidence is missing: {relative}")
    (target_root / "testcase_results.csv").write_text(
        _csv_text(CSV_HEADERS, [_result_row(result) for result in target_rows]),
        encoding="utf-8",
        newline="",
    )
    (target_root / "findings.csv").write_text(
        _csv_text(FINDINGS_HEADERS, _finding_rows(target_rows)),
        encoding="utf-8",
        newline="",
    )
    unresolved = [result for result in target_rows if not result.get("final_verdict")]
    findings = [result for result in target_rows if result.get("reportable_finding")]
    explanations = [
        f"{result['testcase_id']} {result.get('final_verdict')}:\n{line_1}\n{line_2}"
        for result in target_rows
        if result.get("final_verdict") and (line_1 := _description(result)[0]) and (line_2 := _description(result)[1])
    ]
    summary = "\n".join([
        f"Target: {target['value']}",
        f"Target label: {target['label']}",
        f"Assessment ID: {target['assessment_id']}",
        f"Testcase rows: {len(target_rows)}",
        f"Confirmed vulnerabilities: {len(findings)}",
        f"Unresolved checks: {len(unresolved)}",
        "No unresolved check is represented as NOT_FOUND or NA.",
        "Finalized explanations:",
        *explanations,
    ])
    (target_root / "target_summary.txt").write_text(summary + "\n", encoding="utf-8")
    return target_root


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
    _validate_result_coverage(results, targets)
    assessment_root = data_dir / "assessments" / assessment_id
    if assessment_root.is_symlink() or not assessment_root.is_dir():
        raise ExportError("Evidence root is missing")
    _validate_finalized_artifacts(assessment_root, results)
    for result in results:
        expected_prefix = target_dir_name(next(target for target in targets if target["id"] == result["target_id"]))
        for relative in result["evidence_paths_json"] + result["poc_paths_json"]:
            relative_path = Path(relative)
            if relative_path.is_absolute() or ".." in relative_path.parts or not relative_path.parts or relative_path.parts[0] != expected_prefix:
                raise ExportError(f"Evidence path is not isolated to its target: {relative}")
            path = assessment_root / relative
            if path.is_symlink() or not path.exists() or path.is_dir():
                raise ExportError(f"Required evidence is missing: {relative}")
    result_rows = [_result_row(result) for result in results]
    (assessment_root / "testcase_results.csv").write_text(
        _csv_text(CSV_HEADERS, result_rows), encoding="utf-8", newline=""
    )
    (assessment_root / "findings.csv").write_text(
        _csv_text(FINDINGS_HEADERS, _finding_rows(results)), encoding="utf-8", newline=""
    )
    for target in targets:
        _write_target_exports(assessment_root, target, results)
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
                "final_verdict": result.get("final_verdict"),
                "coverage_status": result.get("coverage_status"),
                "coverage_reason": result.get("coverage_reason"),
                "observation_type": result.get("observation_type"),
                "reportable_finding": bool(result.get("reportable_finding")),
                "description_line_1": result.get("description_line_1", ""),
                "description_line_2": result.get("description_line_2", ""),
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
        json.dumps(
            {
                "assessment": assessment,
                "targets": targets,
                "results": results,
                "ai_recovery": db.list_ai_recovery(assessment_id),
                "llm_triage": db.list_llm_triage(assessment_id),
            },
            indent=2,
        ),
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
        f"Confirmed vulnerabilities: {sum(1 for result in results if result.get('reportable_finding'))}",
        f"Informational observations: {sum(1 for result in results if result.get('final_verdict') == 'FOUND' and result.get('observation_type') in {'informational', 'exposure_inventory'})}",
        f"Unresolved checks: {sum(1 for result in results if not result.get('final_verdict'))}",
        f"Completion outcome: {'COMPLETED_WITH_LIMITATIONS' if any(not result.get('final_verdict') for result in results) else 'COMPLETED'}",
        f"Command execution records: {len(executions)}",
        f"Completed command executions: {sum(item['execution_status'] == 'COMPLETED' for item in executions)}",
        f"Failed or timed-out command executions: {sum(item['execution_status'] != 'COMPLETED' for item in executions)}",
        f"Final execution status: {assessment['status']}",
        f"Output directory: {assessment_root}",
        "No result is inferred from a failed or incomplete execution.",
        "Finalized two-line explanations:",
        *[
            f"{result['target']} {result['testcase_id']} {result.get('final_verdict')}:\n{line_1}\n{line_2}"
            for result in results
            if result.get("final_verdict") and (line_1 := _description(result)[0]) and (line_2 := _description(result)[1])
        ],
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
    (assessment_root / "assessment_summary.csv").write_text(
        _csv_text(
            ["target_id", "target", "target_label", "confirmed_vulnerabilities", "informational_observations", "verified_negatives", "not_applicable", "unresolved_checks"],
            [
                [
                    target["id"],
                    target["value"],
                    target["label"],
                    str(sum(1 for result in results if result["target_id"] == target["id"] and result.get("reportable_finding"))),
                    str(sum(1 for result in results if result["target_id"] == target["id"] and result.get("final_verdict") == "FOUND" and result.get("observation_type") in {"informational", "exposure_inventory"})),
                    str(sum(1 for result in results if result["target_id"] == target["id"] and result.get("final_verdict") == "NOT_FOUND")),
                    str(sum(1 for result in results if result["target_id"] == target["id"] and result.get("final_verdict") == "NA")),
                    str(sum(1 for result in results if result["target_id"] == target["id"] and not result.get("final_verdict"))),
                ]
                for target in targets
            ],
        ),
        encoding="utf-8",
        newline="",
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


def export_target(
    db: Database,
    assessment_id: str,
    target_id: str,
    data_dir: Path,
) -> dict[str, Path]:
    assessment = db.get_assessment(assessment_id)
    target = db.get_target(assessment_id, target_id)
    if not assessment or not target:
        raise ExportError("Assessment target not found")
    results = db.list_results(assessment_id, target_id)
    if len(results) != len(TESTCASES):
        raise ExportError("Target export refused: testcase result coverage is incomplete")
    assessment_root = data_dir / "assessments" / assessment_id
    _validate_finalized_artifacts(assessment_root, results)
    target_root = _write_target_exports(assessment_root, target, results)
    archive_path = data_dir / "exports" / f"{assessment_id}-{target_id}.zip"
    archive_path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(prefix=f"{assessment_id}-{target_id}-", suffix=".zip", dir=archive_path.parent, delete=False) as temp:
        temp_path = Path(temp.name)
    try:
        _zip_tree(target_root, temp_path)
        os.replace(temp_path, archive_path)
    except Exception:
        temp_path.unlink(missing_ok=True)
        raise
    return {"root": target_root, "csv": target_root / "testcase_results.csv", "zip": archive_path}
