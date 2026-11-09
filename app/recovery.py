from __future__ import annotations

from dataclasses import dataclass

from .config import Settings
from .discovery import protocol_for_testcase, required_ports
from .live_adapters import build_command

ACTION_REGISTRY = {
    "retry_safe_probe": {
        "parameters": {"port"},
        "description": "Repeat the registered adapter once with a larger bounded deadline.",
    },
    "collect_safe_banner": {
        "parameters": {"port"},
        "description": "Collect an allowlisted service banner for a registered service testcase.",
    },
    "verify_discovered_tcp_service": {
        "parameters": {"port"},
        "description": "Re-run the registered TCP adapter for an explicitly discovered approved port.",
    },
    "verify_discovered_udp_service": {
        "parameters": {"port"},
        "description": "Re-run the registered UDP adapter for an explicitly discovered approved port.",
    },
    "inspect_existing_evidence": {
        "parameters": set(),
        "description": "Inspect existing evidence without executing a command.",
    },
    "reparse_raw_output": {
        "parameters": set(),
        "description": "Re-run the deterministic parser over preserved raw output.",
    },
}
SAFE_ACTIONS = frozenset(ACTION_REGISTRY)


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
    parameters: dict[str, object] | None = None,
) -> RecoveryPlan:
    if action_id not in SAFE_ACTIONS:
        return RecoveryPlan(None, None, "LLM action was not in the approved recovery registry")
    parameters = parameters or {}
    allowed_parameters = ACTION_REGISTRY[action_id]["parameters"]
    if set(parameters) - allowed_parameters:
        return RecoveryPlan(None, None, "LLM action contained unsupported parameters")
    port = parameters.get("port")
    if port is not None:
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            return RecoveryPlan(None, None, "LLM action contained an invalid port")
        approved = {item[1] for item in required_ports(testcase_id)}
        if not approved or port not in approved:
            return RecoveryPlan(None, None, "LLM action requested a port outside the testcase contract")
    if action_id == "inspect_existing_evidence":
        return RecoveryPlan(action_id, None, "Existing evidence was inspected without executing another command")
    if action_id == "reparse_raw_output":
        return RecoveryPlan(action_id, None, "Preserved raw output will be reprocessed by the deterministic parser")
    if target.lower().startswith("fixture://"):
        return RecoveryPlan(action_id, None, "Controlled fixture evidence is deterministic; no live corrective command is permitted")
    if attempt >= settings.scanner_max_retries:
        return RecoveryPlan(action_id, None, "Bounded recovery retry limit was reached")
    # A retry changes the scanner strategy: it gives Nmap more time and one
    # additional bounded retry, rather than repeating identical argv.
    if action_id == "collect_safe_banner" and testcase_id not in {"02", "04", "05", "11", "22"}:
        return RecoveryPlan(action_id, None, "Banner collection is not an approved alternate for this testcase")
    if action_id == "verify_discovered_tcp_service" and protocol_for_testcase(testcase_id) not in {"tcp", "other"}:
        return RecoveryPlan(action_id, None, "TCP verification is not registered for this testcase")
    if action_id == "verify_discovered_udp_service" and protocol_for_testcase(testcase_id) != "udp":
        return RecoveryPlan(action_id, None, "UDP verification is not registered for this testcase")
    if action_id == "collect_safe_banner" and port is not None and protocol_for_testcase(testcase_id) == "udp":
        return RecoveryPlan(action_id, None, "A TCP banner action cannot be used for a UDP testcase")
    port_overrides: dict[str, int] = {}
    if port is not None:
        key = f"{port}/udp" if protocol_for_testcase(testcase_id) == "udp" else str(port)
        port_overrides[key] = port
    argv = build_command(
        testcase_id,
        target,
        port_overrides=port_overrides or None,
        nmap_host_timeout_seconds=min(settings.scanner_host_timeout_seconds * 2, 120),
        nmap_max_retries=min(settings.scanner_max_retries + attempt + 1, 5),
        tcp_connect_timeout_seconds=min(settings.tcp_connect_timeout_seconds * 2, 15),
        protocol_timeout_seconds=min(settings.protocol_timeout_seconds * 2, 30),
        nmap_script_timeout_seconds=min(settings.nmap_script_timeout_seconds * 2, 60),
    )
    if argv is None:
        return RecoveryPlan(action_id, None, "No live command is registered for this capability-dependent testcase")
    return RecoveryPlan(action_id, argv, "Approved bounded retry with increased protocol deadline")
