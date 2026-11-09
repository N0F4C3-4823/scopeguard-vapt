"""Deterministic parsing and validation for Testcase 11 operator review."""

from __future__ import annotations

import hashlib
import re
from typing import Any

_NMAP_SERVICE = re.compile(
    r"^\s*(?P<port>\d+)/(tcp|udp)\s+open\s+(?P<service>\S+)\s*(?P<detail>.*?)\s*$",
    re.IGNORECASE | re.MULTILINE,
)
_TARGET_IDENTIFIER = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b|\b[a-z0-9-]+\.[a-z]{2,}\b", re.IGNORECASE)


def _entry_id(port: int, protocol: str, service: str, detail: str) -> str:
    digest = hashlib.sha256(f"{port}/{protocol}/{service}/{detail}".encode()).hexdigest()[:12]
    return f"version-{port}-{protocol}-{digest}"


def _version_text(detail: str) -> tuple[str, str, bool]:
    value = " ".join(detail.split())
    if not value or value.casefold() in {"unknown", "tcpwrapped", "?"}:
        return "Version not identified", "unavailable", False
    ambiguous = bool(re.search(r"\?|\bor later\b|\bor earlier\b|\bpossible\b|\bunknown\b", value, re.I))
    return value, "ambiguous" if ambiguous else "observed", not ambiguous


def _product_name(service: str, detail: str) -> str:
    value = " ".join(detail.split())
    if value:
        return value.split()[0]
    return service


def parse_version_observations(output: bytes | str) -> list[dict[str, Any]]:
    text = output.decode("utf-8", errors="replace") if isinstance(output, bytes) else output
    entries: list[dict[str, Any]] = []
    for match in _NMAP_SERVICE.finditer(text):
        port = int(match.group("port"))
        protocol = "tcp" if "/tcp" in match.group(0).lower() else "udp"
        service = match.group("service")
        detail = " ".join(match.group("detail").split())
        product = _product_name(service, detail)
        version_detail = detail[len(product):].strip() if detail.casefold().startswith(product.casefold()) else detail
        version, confidence, reviewable = _version_text(version_detail)
        entries.append(
            {
                "entry_id": _entry_id(port, protocol, service, version),
                "port": port,
                "protocol": protocol,
                "service": service,
                "product": product,
                "version": version,
                "confidence": confidence,
                "reviewable": reviewable,
            }
        )
    return entries


def sanitize_review_text(value: str, *, max_length: int = 140) -> str:
    value = " ".join(str(value).replace("\n", " ").replace("\r", " ").split())
    value = _TARGET_IDENTIFIER.sub("identified host", value)
    return value[:max_length].strip()


def validate_review_entries(entries: list[dict[str, Any]], selected: list[str], reviewed: list[str]) -> None:
    known = {str(entry["entry_id"]): entry for entry in entries}
    if not entries:
        raise ValueError("No software/version observations are available for manual review")
    if not set(selected).issubset(known):
        raise ValueError("The review selected an unknown software entry")
    if not set(reviewed).issubset(known):
        raise ValueError("The review referenced an unknown software entry")
    if any(not known[item]["reviewable"] for item in selected):
        raise ValueError("An entry without reliable version evidence cannot be marked outdated")
    required_reviewable = {item_id for item_id, item in known.items() if item["reviewable"]}
    if set(reviewed) != required_reviewable:
        raise ValueError("Review every entry with usable version information before finalizing the review")


def review_descriptions(decision: str, selected: list[dict[str, Any]], unidentified: list[dict[str, Any]]) -> tuple[str, str]:
    if decision == "outdated":
        labels = ", ".join(
            f"{sanitize_review_text(str(item['product']))} {sanitize_review_text(str(item['version']))}"
            for item in selected
        )
        line1 = f"The reviewed software inventory contains an outdated version entry: {labels}."
        line2 = "These versions should be updated to supported releases to reduce potential security risks."
        return line1, line2
    line1 = "No outdated versions were identified among the software entries reviewed."
    line2 = "This conclusion is based on the available version information and the completed manual review."
    if unidentified:
        line2 = "The conclusion applies only to reviewable entries; unidentified versions remain a coverage limitation."
    return line1, line2
