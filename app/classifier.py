from __future__ import annotations

from dataclasses import dataclass

from .commands import CommandResult
from .live_adapters import parse_live_result
from .registry import TestcaseDefinition


@dataclass(frozen=True)
class Classification:
    status: str
    applicability: str
    conditions_tested: tuple[str, ...]
    conditions_confirmed: tuple[str, ...]
    conditions_not_found: tuple[str, ...]
    inconclusive_conditions: tuple[str, ...]
    severity: str
    failure_reason: str | None
    observation_ids: tuple[str, ...]
    validation_state: str


def classify_live(testcase: TestcaseDefinition, result: CommandResult) -> Classification:
    """Classify raw output from a registered live adapter.

    Unlike the controlled fixture parser, this path never reads generated
    ``STATUS=`` tokens.  The adapter parser inspects only the bytes captured
    from the actual allowlisted command and emits a structured decision.
    """
    parsed = parse_live_result(testcase.id, result)
    return Classification(
        parsed.status,
        parsed.applicability,
        (testcase.condition,),
        (testcase.condition,) if parsed.status == "FOUND" else (),
        (testcase.condition,) if parsed.status == "NOT_FOUND" else (),
        (testcase.condition,) if parsed.status == "INCONCLUSIVE" else (),
        parsed.severity,
        parsed.reason,
        parsed.observation_ids,
        parsed.validation_state,
    )


def classify(
    testcase: TestcaseDefinition,
    result: CommandResult,
    *,
    allow_na: bool = True,
) -> Classification:
    output = (result.stdout + result.stderr).decode("utf-8", errors="replace")
    status_line = next(
        (line.removeprefix("STATUS=").strip() for line in output.splitlines() if line.startswith("STATUS=")),
        None,
    )
    # Controlled fixtures carry their deterministic scenario in the explicit
    # argv that was executed, not in stdout.  This keeps fixture POCs free of
    # generated status labels while retaining a reproducible parser contract.
    if "app.fixture_command" in result.argv:
        try:
            scenario = result.argv[result.argv.index("--scenario") + 1]
            if scenario == "positive":
                status_line = "FOUND"
            elif scenario == "negative":
                status_line = "NOT_FOUND"
            elif scenario == "na":
                status_line = "NA"
            elif scenario == "mixed":
                status_line = {0: "INCONCLUSIVE", 1: "FOUND", 2: "NOT_FOUND", 3: "NA"}[int(testcase.id) % 4]
        except (ValueError, IndexError):
            status_line = None
    observation_ids = tuple(
        line.removeprefix("OBSERVATION_ID=").strip()
        for line in output.splitlines()
        if line.startswith("OBSERVATION_ID=")
    )
    condition = testcase.condition
    if result.timed_out:
        return Classification(
            "INCONCLUSIVE", "execution incomplete", (condition,), (), (), (condition,), "unknown",
            "bounded command timeout", observation_ids, "INCOMPLETE",
        )
    if result.exit_code != 0 or result.status != "COMPLETED":
        return Classification(
            "INCONCLUSIVE", "execution incomplete", (condition,), (), (), (condition,), "unknown",
            f"command exited with status {result.exit_code}", observation_ids, "INCOMPLETE",
        )
    if status_line == "FOUND" and observation_ids:
        return Classification(
            "FOUND", "applicable", (condition,), (condition,), (), (), "medium", None,
            observation_ids, "VALIDATED",
        )
    if status_line == "NOT_FOUND" and observation_ids:
        return Classification(
            "NOT_FOUND", "applicable", (condition,), (), (condition,), (), "informational", None,
            observation_ids, "VALIDATED",
        )
    if status_line == "NA" and allow_na:
        return Classification(
            "NA", testcase.na_reason, (condition,), (), (), (), "informational", None,
            observation_ids, "APPLICABILITY_CONFIRMED",
        )
    if status_line == "NA":
        return Classification(
            "INCONCLUSIVE", "applicable check returned an inapplicability token", (condition,), (), (),
            (condition,), "unknown", "applicable execution did not establish a positive or negative predicate",
            observation_ids, "INSUFFICIENT",
        )
    return Classification(
        "INCONCLUSIVE", "evidence insufficient", (condition,), (), (), (condition,), "unknown",
        "completed command did not establish a supported predicate", observation_ids, "INSUFFICIENT",
    )
