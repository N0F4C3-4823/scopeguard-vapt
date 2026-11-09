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
    final_verdict: str | None = None
    coverage_status: str = "INSUFFICIENT_EVIDENCE"
    coverage_reason: str | None = None
    observation_type: str = "vulnerability"
    reportable_finding: bool = False
    description_line_1: str = ""
    description_line_2: str = ""


_INFORMATIONAL_TESTCASES = {"02", "12", "22", "35", "38"}
_EXPOSURE_TESTCASES = {"19"}
_MISCONFIGURATION_TESTCASES = {"08", "15", "21", "27", "33", "34", "39"}


def observation_type_for(testcase_id: str, status: str) -> str:
    if status == "NA":
        return "coverage"
    if testcase_id in _EXPOSURE_TESTCASES:
        return "exposure_inventory"
    if testcase_id in _INFORMATIONAL_TESTCASES:
        return "informational"
    if testcase_id in _MISCONFIGURATION_TESTCASES:
        return "misconfiguration"
    return "vulnerability"


def classification_metadata(
    testcase_id: str,
    status: str,
    *,
    result: CommandResult | None = None,
    reason: str | None = None,
) -> dict[str, object]:
    final_verdict = status if status in {"FOUND", "NOT_FOUND", "NA"} else None
    if status in {"FOUND", "NOT_FOUND", "NA"}:
        coverage_status = "COMPLETED"
    elif result is not None and (result.timed_out or result.status != "COMPLETED" or result.exit_code != 0):
        coverage_status = "FAILED"
    else:
        coverage_status = "INSUFFICIENT_EVIDENCE"
    kind = observation_type_for(testcase_id, status)
    return {
        "final_verdict": final_verdict,
        "coverage_status": coverage_status,
        "coverage_reason": reason,
        "observation_type": kind,
        "reportable_finding": status == "FOUND" and kind in {"vulnerability", "misconfiguration"},
    }


def classify_live(testcase: TestcaseDefinition, result: CommandResult) -> Classification:
    """Classify raw output from a registered live adapter.

    Unlike the controlled fixture parser, this path never reads generated
    ``STATUS=`` tokens.  The adapter parser inspects only the bytes captured
    from the actual allowlisted command and emits a structured decision.
    """
    parsed = parse_live_result(testcase.id, result)
    metadata = classification_metadata(testcase.id, parsed.status, result=result, reason=parsed.reason)
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
        **metadata,
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
            **classification_metadata(testcase.id, "INCONCLUSIVE", result=result, reason="bounded command timeout"),
        )
    if result.exit_code != 0 or result.status != "COMPLETED":
        reason = f"command exited with status {result.exit_code}"
        return Classification(
            "INCONCLUSIVE", "execution incomplete", (condition,), (), (), (condition,), "unknown",
            reason, observation_ids, "INCOMPLETE",
            **classification_metadata(testcase.id, "INCONCLUSIVE", result=result, reason=reason),
        )
    if status_line == "FOUND" and observation_ids:
        return Classification(
            "FOUND", "applicable", (condition,), (condition,), (), (), "medium", None,
            observation_ids, "VALIDATED",
            **classification_metadata(testcase.id, "FOUND", result=result),
        )
    if status_line == "NOT_FOUND" and observation_ids:
        return Classification(
            "NOT_FOUND", "applicable", (condition,), (), (condition,), (), "informational", None,
            observation_ids, "VALIDATED",
            **classification_metadata(testcase.id, "NOT_FOUND", result=result),
        )
    if status_line == "NA" and allow_na:
        return Classification(
            "NA", testcase.na_reason, (condition,), (), (), (), "informational", None,
            observation_ids, "APPLICABILITY_CONFIRMED",
            **classification_metadata(testcase.id, "NA", result=result, reason=testcase.na_reason),
        )
    if status_line == "NA":
        reason = "applicable check returned an inapplicability token"
        return Classification(
            "INCONCLUSIVE", "applicable check returned an inapplicability token", (condition,), (), (),
            (condition,), "unknown", "applicable execution did not establish a positive or negative predicate",
            observation_ids, "INSUFFICIENT",
            **classification_metadata(testcase.id, "INCONCLUSIVE", result=result, reason=reason),
        )
    reason = "completed command did not establish a supported predicate"
    return Classification(
        "INCONCLUSIVE", "evidence insufficient", (condition,), (), (), (condition,), "unknown",
        reason, observation_ids, "INSUFFICIENT",
        **classification_metadata(testcase.id, "INCONCLUSIVE", result=result, reason=reason),
    )
