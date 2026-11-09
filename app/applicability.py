from __future__ import annotations

import platform
from dataclasses import dataclass
from pathlib import Path

from .registry import TestcaseDefinition

ASSESSMENT_TYPES = {
    "external_unauthenticated": "External Network Pentest — Unauthenticated",
    "internal_unauthenticated": "Internal Network Pentest — Unauthenticated",
    "internal_authenticated": "Internal Network Pentest — Authenticated",
    "custom_hybrid": "Custom / Hybrid Network Pentest",
}


@dataclass(frozen=True)
class CapabilitySnapshot:
    requested: frozenset[str]
    detected: frozenset[str]
    permissions: frozenset[str]
    credentials_available: bool
    controlled_fixture: bool = False


@dataclass(frozen=True)
class ApplicabilityDecision:
    state: str  # APPLICABLE, NA, or INCONCLUSIVE
    reason: str
    missing: tuple[str, ...] = ()
    condition: str = ""


def detect_capabilities() -> set[str]:
    detected = {"external_vantage", "tcp", "ipv4", "ipv6"}
    interfaces = Path("/sys/class/net")
    if interfaces.exists() and any((path / "wireless").exists() for path in interfaces.iterdir()):
        detected.add("wireless_adapter")
    release = platform.release().lower()
    if "microsoft" not in release and "microsoft" not in platform.version().lower():
        detected.add("layer2_access")
    return detected


def evaluate_applicability(
    testcase: TestcaseDefinition,
    assessment_type: str,
    capabilities: CapabilitySnapshot,
) -> ApplicabilityDecision:
    condition = testcase.condition
    if assessment_type not in ASSESSMENT_TYPES:
        return ApplicabilityDecision("NA", "Unknown assessment type; condition cannot be authorized", condition=condition)
    required_vantage = set(testcase.required_vantage)
    if assessment_type in {"internal_unauthenticated", "internal_authenticated"} and "internal_vantage" not in capabilities.requested and "internal" not in required_vantage:
        return ApplicabilityDecision(
            "INCONCLUSIVE",
            "An internal assessment was selected but an internal vantage point was not declared; service reachability cannot be established",
            ("internal_vantage",),
            condition,
        )
    if "wireless" in required_vantage:
        if assessment_type == "external_unauthenticated" or assessment_type == "internal_unauthenticated" and "wireless_adapter" not in capabilities.requested:
            return ApplicabilityDecision("NA", "Wireless security requires explicitly authorized wireless proximity and an adapter", condition=condition)
    if "internal" in required_vantage:
        if assessment_type == "external_unauthenticated":
            return ApplicabilityDecision("NA", "External unauthenticated vantage cannot establish internal network access", condition=condition)
        if "internal_vantage" not in capabilities.requested:
            return ApplicabilityDecision("NA", "An internal vantage point was not declared in the authorized scope", condition=condition)
    missing_capabilities = [cap for cap in testcase.required_capabilities if cap not in capabilities.requested]
    if missing_capabilities:
        return ApplicabilityDecision(
            "NA",
            "Required authorized capability is not available: " + ", ".join(missing_capabilities),
            tuple(missing_capabilities),
            condition,
        )
    unavailable = [cap for cap in testcase.required_capabilities if cap not in capabilities.detected]
    if unavailable and not capabilities.controlled_fixture:
        return ApplicabilityDecision(
            "INCONCLUSIVE",
            "Authorized capability was requested but is unavailable on this host: " + ", ".join(unavailable),
            tuple(unavailable),
            condition,
        )
    if testcase.requires_credentials:
        if assessment_type in {"external_unauthenticated", "internal_unauthenticated"}:
            return ApplicabilityDecision("NA", "This condition requires credentials, but the selected assessment is unauthenticated", condition=condition)
        if not capabilities.credentials_available:
            return ApplicabilityDecision("INCONCLUSIVE", "Credentials were required but are not available for this run", ("credentials",), condition)
    missing_permissions = [permission for permission in testcase.required_permissions if permission not in capabilities.permissions]
    if missing_permissions:
        return ApplicabilityDecision(
            "NA",
            "Required explicit permission is missing: " + ", ".join(missing_permissions),
            tuple(missing_permissions),
            condition,
        )
    return ApplicabilityDecision("APPLICABLE", "Condition is applicable under the authorized assessment capabilities", condition=condition)


def snapshot_for(
    *,
    requested: list[str],
    permissions: list[str],
    credentials_available: bool,
    controlled_fixture: bool,
) -> CapabilitySnapshot:
    detected = detect_capabilities()
    if controlled_fixture:
        detected |= set(requested)
    return CapabilitySnapshot(
        requested=frozenset(requested),
        detected=frozenset(detected),
        permissions=frozenset(permissions),
        credentials_available=credentials_available,
        controlled_fixture=controlled_fixture,
    )
