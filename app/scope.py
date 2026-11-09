from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

_FQDN_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
_FIXTURES = {"positive", "negative", "mixed", "na", "failure", "timeout"}


@dataclass(frozen=True)
class NormalizedTarget:
    id: str
    value: str
    label: str
    kind: str
    host_count: int


class ScopeError(ValueError):
    pass


def _validate_hostname(value: str) -> None:
    if len(value) > 253 or value.endswith("."):
        raise ScopeError(f"Invalid hostname: {value}")
    labels = value.split(".")
    if not labels or any(not _FQDN_LABEL.fullmatch(label) for label in labels):
        raise ScopeError(f"Invalid hostname: {value}")


def normalize_target(value: str, index: int, max_cidr_hosts: int) -> NormalizedTarget:
    raw = value.strip()
    if not raw:
        raise ScopeError("Targets cannot contain blank entries")
    if raw.lower().startswith("fixture://"):
        scenario = raw.split("://", 1)[1].lower()
        if scenario not in _FIXTURES:
            raise ScopeError(f"Unknown controlled fixture: {scenario}")
        normalized = f"fixture://{scenario}"
        return NormalizedTarget(f"target-{index:03d}", normalized, normalized, "fixture", 1)
    try:
        address = ipaddress.ip_address(raw)
    except ValueError:
        try:
            network = ipaddress.ip_network(raw, strict=False)
        except ValueError:
            _validate_hostname(raw.lower())
            return NormalizedTarget(f"target-{index:03d}", raw.lower(), raw.lower(), "fqdn", 1)
        host_count = network.num_addresses
        if host_count > max_cidr_hosts:
            raise ScopeError(
                f"CIDR {raw} contains {host_count} addresses; maximum is {max_cidr_hosts}"
            ) from None
        return NormalizedTarget(f"target-{index:03d}", str(network), str(network), "cidr", host_count)
    return NormalizedTarget(f"target-{index:03d}", str(address), str(address), "ip", 1)


def parse_scope(
    targets: list[str], excludes: list[str], max_cidr_hosts: int, labels: dict[str, str] | None = None
) -> list[NormalizedTarget]:
    if not targets:
        raise ScopeError("At least one target is required")
    normalized: list[NormalizedTarget] = []
    seen: set[str] = set()
    for index, raw in enumerate(targets, start=1):
        target = normalize_target(raw, index, max_cidr_hosts)
        if target.value in seen:
            continue
        seen.add(target.value)
        normalized.append(target)
    normalized_excludes = {
        normalize_target(raw, index, max_cidr_hosts).value
        for index, raw in enumerate(excludes, start=1)
    }
    filtered = [target for target in normalized if target.value not in normalized_excludes]
    if not filtered:
        raise ScopeError("All targets were excluded")
    label_map = {key.strip().lower(): value.strip() for key, value in (labels or {}).items()}
    for target in filtered:
        if target.value in label_map and label_map[target.value]:
            object.__setattr__(target, "label", label_map[target.value][:120])
    return filtered
