from __future__ import annotations

import json
import re
import textwrap
from pathlib import Path
from typing import Any

from PIL import Image, ImageDraw, ImageFont

from .commands import CommandResult, sha256_bytes
from .registry import TestcaseDefinition

_UNSAFE = re.compile(r"[^A-Za-z0-9._-]+")


def safe_name(value: str) -> str:
    cleaned = _UNSAFE.sub("_", value).strip("._")
    return cleaned[:100] or "condition"


def _font(size: int) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    candidates = (
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
        "/usr/share/fonts/truetype/liberation2/LiberationMono-Regular.ttf",
    )
    for candidate in candidates:
        if Path(candidate).exists():
            return ImageFont.truetype(candidate, size)
    return ImageFont.load_default()


def render_poc_pngs(
    command: str,
    stdout: bytes,
    stderr: bytes,
    output_dir: Path,
    *,
    max_lines: int = 72,
    max_columns: int = 128,
) -> list[Path]:
    """Render exactly command + captured output; no labels or metadata are added."""
    output_dir.mkdir(parents=True, exist_ok=True)
    output_text = stdout.decode("utf-8", errors="replace") + stderr.decode("utf-8", errors="replace")
    payload = f"{command}\n\n{output_text}"
    lines: list[str] = []
    for original_line in payload.splitlines() or [""]:
        wrapped = textwrap.wrap(
            original_line,
            width=max_columns,
            replace_whitespace=False,
            drop_whitespace=False,
            break_long_words=True,
            break_on_hyphens=False,
        )
        lines.extend(wrapped or [""])
    line_font = _font(16)
    line_height = 22
    pages: list[Path] = []
    for page_index in range(0, len(lines), max_lines):
        page_lines = lines[page_index : page_index + max_lines]
        width = 1450
        height = max(80, 28 + len(page_lines) * line_height)
        image = Image.new("RGB", (width, height), "#fbfcfe")
        draw = ImageDraw.Draw(image)
        for line_index, line in enumerate(page_lines):
            draw.text((20, 14 + line_index * line_height), line, font=line_font, fill="#14213d")
        path = output_dir / f"poc_{page_index // max_lines + 1:03d}.png"
        image.save(path, format="PNG", optimize=False)
        pages.append(path)
    (output_dir / "payload.txt").write_text(payload, encoding="utf-8", newline="")
    return pages


def png_has_text_metadata(path: Path) -> bool:
    payload = path.read_bytes()
    return any(chunk in payload for chunk in (b"tEXt", b"iTXt", b"zTXt"))


def write_testcase_evidence(
    assessment_root: Path,
    target_dir_name: str,
    testcase: TestcaseDefinition,
    command_result: CommandResult,
    classification: Any,
    *,
    target_value: str,
    target_id: str,
    fixture_id: str | None,
    create_screenshots: bool = True,
    recovery_attempts: list[CommandResult] | None = None,
) -> dict[str, Any]:
    testcase_dir = assessment_root / target_dir_name / "testcases" / (
        f"{testcase.id}_{safe_name(testcase.condition)}"
    )
    evidence_dir = testcase_dir / "evidence"
    found_dir = testcase_dir / "POCs" / "FOUND"
    not_found_dir = testcase_dir / "POCs" / "NOT_FOUND"
    found_dir.mkdir(parents=True, exist_ok=True)
    not_found_dir.mkdir(parents=True, exist_ok=True)
    evidence_dir.mkdir(parents=True, exist_ok=True)
    stdout_path = evidence_dir / "stdout.txt"
    stderr_path = evidence_dir / "stderr.txt"
    stdout_bytes_path = evidence_dir / "stdout.bin"
    stderr_bytes_path = evidence_dir / "stderr.bin"
    stdout_path.write_bytes(command_result.stdout)
    stderr_path.write_bytes(command_result.stderr)
    stdout_bytes_path.write_bytes(command_result.stdout)
    stderr_bytes_path.write_bytes(command_result.stderr)
    commands = {
        "command_id": command_result.id,
        "argv": list(command_result.argv),
        "displayed_command": command_result.displayed_command,
        "cwd": command_result.cwd,
        "started_at": command_result.started_at,
        "ended_at": command_result.ended_at,
        "exit_code": command_result.exit_code,
        "timed_out": command_result.timed_out,
        "tool_version": command_result.tool_version,
        "execution_status": command_result.status,
        "target_id": target_id,
        "target": target_value,
        "testcase_id": testcase.id,
        "fixture_id": fixture_id,
    }
    (evidence_dir / "commands.json").write_text(json.dumps(commands, indent=2), encoding="utf-8")
    hashes = {
        "stdout_sha256": sha256_bytes(command_result.stdout),
        "stderr_sha256": sha256_bytes(command_result.stderr),
        "combined_sha256": sha256_bytes(command_result.combined_output),
    }
    (evidence_dir / "hashes.json").write_text(json.dumps(hashes, indent=2), encoding="utf-8")
    supplemental_paths: list[str] = []
    for index, attempt in enumerate(recovery_attempts or (), start=1):
        attempt_dir = evidence_dir / f"recovery_attempt_{index:03d}"
        attempt_dir.mkdir(parents=True, exist_ok=True)
        attempt_stdout = attempt_dir / "stdout.bin"
        attempt_stderr = attempt_dir / "stderr.bin"
        attempt_stdout.write_bytes(attempt.stdout)
        attempt_stderr.write_bytes(attempt.stderr)
        (attempt_dir / "commands.json").write_text(
            json.dumps(
                {
                    "command_id": attempt.id,
                    "argv": list(attempt.argv),
                    "displayed_command": attempt.displayed_command,
                    "exit_code": attempt.exit_code,
                    "timed_out": attempt.timed_out,
                    "execution_status": attempt.status,
                    "stdout_sha256": attempt.stdout_sha256,
                    "stderr_sha256": attempt.stderr_sha256,
                    "combined_sha256": attempt.combined_sha256,
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        supplemental_paths.extend(
            str(path.relative_to(assessment_root))
            for path in (attempt_stdout, attempt_stderr, attempt_dir / "commands.json")
        )
    poc_paths: list[str] = []
    final_verdict = getattr(classification, "final_verdict", None)
    if final_verdict in {"FOUND", "NOT_FOUND"} and create_screenshots:
        parent = found_dir if final_verdict == "FOUND" else not_found_dir
        condition_dir = parent / safe_name(testcase.condition)
        pages = render_poc_pngs(
            command_result.displayed_command,
            command_result.stdout,
            command_result.stderr,
            condition_dir,
        )
        poc_paths = [str(path.relative_to(assessment_root)) for path in pages]
    evidence_paths = [str(path.relative_to(assessment_root)) for path in (
        stdout_path,
        stderr_path,
        evidence_dir / "commands.json",
        evidence_dir / "hashes.json",
    )] + supplemental_paths
    result_payload = {
        "testcase_id": testcase.id,
        "testcase_name": testcase.name,
        "condition": testcase.condition,
        "status": classification.status,
        "final_verdict": getattr(classification, "final_verdict", None),
        "coverage_status": getattr(classification, "coverage_status", "COMPLETED"),
        "coverage_reason": getattr(classification, "coverage_reason", None),
        "observation_type": getattr(classification, "observation_type", "vulnerability"),
        "description_line_1": getattr(classification, "description_line_1", ""),
        "description_line_2": getattr(classification, "description_line_2", ""),
        "applicability": classification.applicability,
        "command_id": command_result.id,
        "evidence_paths": evidence_paths,
        "poc_paths": poc_paths,
        "hashes": hashes,
        "provenance": {
            "assessment_root": str(assessment_root),
            "target_id": target_id,
            "target": target_value,
            "fixture_id": fixture_id,
        },
        "failure_reason": classification.failure_reason,
    }
    (testcase_dir / "result.json").write_text(json.dumps(result_payload, indent=2), encoding="utf-8")
    (testcase_dir / "result.txt").write_text(
        f"{testcase.id} {testcase.name}\nSTATUS={classification.status}\n"
        f"APPLICABILITY={classification.applicability}\n",
        encoding="utf-8",
    )
    return {
        "root": testcase_dir,
        "evidence_paths": evidence_paths,
        "poc_paths": poc_paths,
        "hashes": hashes,
        "commands": commands,
        "stdout_preview": command_result.stdout.decode("utf-8", errors="replace")[:1200],
    }


def write_applicability_evidence(
    assessment_root: Path,
    target_dir_name: str,
    testcase: TestcaseDefinition,
    *,
    target_value: str,
    target_id: str,
    state: str,
    reason: str,
    missing: tuple[str, ...] = (),
    description_line_1: str = "",
    description_line_2: str = "",
    related_evidence_paths: tuple[str, ...] = (),
) -> dict[str, Any]:
    testcase_dir = assessment_root / target_dir_name / "testcases" / (
        f"{testcase.id}_{safe_name(testcase.condition)}"
    )
    evidence_dir = testcase_dir / "evidence"
    (testcase_dir / "POCs" / "FOUND").mkdir(parents=True, exist_ok=True)
    (testcase_dir / "POCs" / "NOT_FOUND").mkdir(parents=True, exist_ok=True)
    evidence_dir.mkdir(parents=True, exist_ok=True)
    for relative in related_evidence_paths:
        relative_path = Path(relative)
        if relative_path.is_absolute() or ".." in relative_path.parts:
            raise ValueError(f"Unsafe related evidence path: {relative}")
        path = assessment_root / relative_path
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"Missing related evidence path: {relative}")
    payload = {
        "testcase_id": testcase.id,
        "condition": testcase.condition,
        "status": "NA" if state == "NA" else "INCONCLUSIVE",
        "final_verdict": "NA" if state == "NA" else None,
        "coverage_status": "COMPLETED" if state == "NA" else "BLOCKED",
        "coverage_reason": reason,
        "description_line_1": description_line_1,
        "description_line_2": description_line_2,
        "applicability_state": state,
        "reason": reason,
        "missing": list(missing),
        "target_id": target_id,
        "target": target_value,
        "command_executed": False,
        "related_evidence_paths": list(related_evidence_paths),
    }
    path = evidence_dir / "applicability.json"
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    (testcase_dir / "result.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")
    (testcase_dir / "result.txt").write_text(
        f"{testcase.id} {testcase.name}\nSTATUS={payload['status']}\nAPPLICABILITY={reason}\n",
        encoding="utf-8",
    )
    return {
        "root": testcase_dir,
        "evidence_paths": [str(path.relative_to(assessment_root))] + list(related_evidence_paths),
        "poc_paths": [],
        "hashes": {"applicability_sha256": sha256_bytes(path.read_bytes())},
        "commands": payload,
        "stdout_preview": reason,
    }
