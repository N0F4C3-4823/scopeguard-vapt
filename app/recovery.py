from __future__ import annotations

from dataclasses import dataclass

from .config import Settings
from .live_adapters import build_command

SAFE_ACTIONS = {
    "retry_safe_probe",
    "collect_safe_banner",
    "inspect_existing_evidence",
}


@dataclass(frozen=True)
class RecoveryPlan:
    action_id: str | None
    argv: list[str] | None
    reason: str


def plan_recovery(
    *,
    action_id: str | None,
    testcase_id: str,
    target: str,
    settings: Settings,
    attempt: int,
) -> RecoveryPlan:
    if action_id not in SAFE_ACTIONS:
        return RecoveryPlan(None, None, "LLM action was not in the approved recovery registry")
    if action_id == "inspect_existing_evidence":
        return RecoveryPlan(action_id, None, "Existing evidence was inspected without executing another command")
    if target.lower().startswith("fixture://"):
        return RecoveryPlan(action_id, None, "Controlled fixture evidence is deterministic; no live corrective command is permitted")
    if attempt >= settings.scanner_max_retries:
        return RecoveryPlan(action_id, None, "Bounded recovery retry limit was reached")
    # A retry changes the scanner strategy: it gives Nmap more time and one
    # additional bounded retry, rather than repeating identical argv.
    if action_id == "collect_safe_banner" and testcase_id not in {"02", "04", "05", "11", "22"}:
        return RecoveryPlan(action_id, None, "Banner collection is not an approved alternate for this testcase")
    argv = build_command(
        testcase_id,
        target,
        nmap_host_timeout_seconds=min(settings.scanner_host_timeout_seconds * 2, 120),
        nmap_max_retries=min(settings.scanner_max_retries + attempt + 1, 5),
        tcp_connect_timeout_seconds=min(settings.tcp_connect_timeout_seconds * 2, 15),
        protocol_timeout_seconds=min(settings.protocol_timeout_seconds * 2, 30),
        nmap_script_timeout_seconds=min(settings.nmap_script_timeout_seconds * 2, 60),
    )
    if argv is None:
        return RecoveryPlan(action_id, None, "No live command is registered for this capability-dependent testcase")
    return RecoveryPlan(action_id, argv, "Approved bounded retry with increased protocol deadline")
