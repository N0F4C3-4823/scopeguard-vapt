from __future__ import annotations

from typing import Any


def _sentence(value: str) -> str:
    value = " ".join(value.strip().split())
    if not value:
        return ""
    return value if value.endswith((".", "!", "?")) else f"{value}."


def _target(result: dict[str, Any]) -> str:
    return str(result.get("target_label") or result.get("target") or "the authorized target")


def two_line_description(
    *,
    testcase_id: str,
    testcase_name: str,
    condition: str,
    verdict: str | None,
    observation_type: str,
    target: str,
    applicability: str,
) -> tuple[str, str]:
    """Return exactly two evidence-bounded sentences for a finalized result."""
    if verdict not in {"FOUND", "NOT_FOUND", "NA"}:
        return "", ""
    subject = target or "the authorized target"
    if verdict == "NA":
        line1 = _sentence(f"The {condition} check requires {applicability}")
        line2 = _sentence(f"That access or capability was not part of the authorized assessment for {subject}, so this condition does not apply")
        return line1, line2
    if verdict == "NOT_FOUND":
        line1 = _sentence(f"The completed {condition} check did not establish the tested condition on {subject}")
        line2 = _sentence("The recorded command output supports this negative conclusion only for the tested scope and method")
        return line1, line2

    special = {
        "02": (
            f"The completed fingerprinting check captured a validated service observation for {subject}",
            "This identifies observed service evidence and does not prove an origin IP or compromise",
        ),
        "12": (
            f"The completed TCP scan recorded a filtered port on {subject}",
            "This is an informational filtering observation and is not by itself a vulnerability",
        ),
        "19": (
            f"The completed inventory recorded reachable service exposure on {subject}",
            "Reachability is retained for exposure review and does not by itself prove a vulnerability",
        ),
        "22": (
            f"The completed banner check captured a validated service identity for {subject}",
            "The identity is an informational observation and does not by itself prove exploitability",
        ),
        "35": (
            f"The completed discovery check confirmed that {subject} responded to an allowed reachability signal",
            "Reachability is an informational observation and does not by itself prove compromise",
        ),
        "38": (
            f"The completed ICMP check captured the configured response from {subject}",
            "This records an information-disclosure observation without claiming protection or compromise beyond the response",
        ),
    }
    if testcase_id in special:
        return tuple(_sentence(line) for line in special[testcase_id])  # type: ignore[return-value]
    significance = {
        "vulnerability": "This establishes the tested security condition within the recorded authorized scope",
        "misconfiguration": "This identifies a configuration weakness within the recorded authorized scope",
    }.get(observation_type, "This records the verified condition within the recorded authorized scope")
    return (
        _sentence(f"The completed {condition} check positively established the tested condition on {subject}"),
        _sentence(significance),
    )


def validate_two_line_description(line_1: str, line_2: str) -> bool:
    """Require two non-empty, single-sentence lines with no hidden line breaks."""
    if not line_1 or not line_2 or "\n" in line_1 or "\n" in line_2:
        return False
    return all(line.rstrip()[-1:] in {".", "!", "?"} for line in (line_1, line_2))
