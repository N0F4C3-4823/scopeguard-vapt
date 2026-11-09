"""Shared, protocol-aware discovery for live assessments.

Discovery is deliberately narrower than a full vulnerability scan.  It records
which explicitly requested TCP and UDP ports were observed and keeps protocol,
state, service and completion provenance together so downstream adapters cannot
reuse a UDP observation as evidence about a TCP service.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import asdict, dataclass

from .commands import CommandResult

TCP_DISCOVERY_PORTS = (
    21,
    22,
    23,
    53,
    80,
    135,
    139,
    389,
    443,
    445,
    1433,
    1521,
    1883,
    27017,
    3306,
    3389,
    5432,
    5900,
    6379,
    8080,
    8883,
    9200,
)
UDP_DISCOVERY_PORTS = (53, 69, 123, 137, 138, 161, 162, 500, 4500)

_PORT_LINE = re.compile(
    r"^\s*(\d+)/(tcp|udp)\s+(open|closed|filtered|open\|filtered)(?:\s+(.*?))?\s*$",
    re.MULTILINE | re.IGNORECASE,
)


@dataclass(frozen=True)
class PortObservation:
    port: int
    protocol: str
    state: str
    service: str
    scanner: str = "nmap"

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class DiscoverySnapshot:
    target: str
    tcp: tuple[PortObservation, ...]
    udp: tuple[PortObservation, ...]
    tcp_complete: bool
    udp_complete: bool
    host_state: str
    tcp_command_id: str | None = None
    udp_command_id: str | None = None
    tcp_failure: str | None = None
    udp_failure: str | None = None

    def observations(self, protocol: str | None = None) -> tuple[PortObservation, ...]:
        values = self.tcp + self.udp
        return tuple(item for item in values if protocol is None or item.protocol == protocol)

    def as_dict(self) -> dict[str, object]:
        return {
            "target": self.target,
            "tcp": [item.as_dict() for item in self.tcp],
            "udp": [item.as_dict() for item in self.udp],
            "tcp_complete": self.tcp_complete,
            "udp_complete": self.udp_complete,
            "host_state": self.host_state,
            "tcp_command_id": self.tcp_command_id,
            "udp_command_id": self.udp_command_id,
            "tcp_failure": self.tcp_failure,
            "udp_failure": self.udp_failure,
        }


def _nmap_complete(text: str) -> bool:
    lower = text.lower()
    return bool(
        re.search(r"nmap done:", lower)
        and not re.search(r"skipping host|host timeout|scan timed out", lower)
    )


def _failure(result: CommandResult) -> str | None:
    if result.timed_out:
        return "discovery command timed out"
    if result.status != "COMPLETED" or result.exit_code != 0:
        detail = (result.stderr or result.stdout).decode("utf-8", errors="replace").strip()
        suffix = f": {detail[:240]}" if detail else ""
        return f"discovery command failed with exit status {result.exit_code}{suffix}"
    return None


def _parse_observations(result: CommandResult) -> tuple[PortObservation, ...]:
    text = (result.stdout + result.stderr).decode("utf-8", errors="replace")
    return tuple(
        PortObservation(
            port=int(port),
            protocol=protocol.lower(),
            state=state.lower(),
            service=(service or "").strip(),
        )
        for port, protocol, state, service in _PORT_LINE.findall(text)
    )


def parse_discovery_result(result: CommandResult, protocol: str) -> tuple[tuple[PortObservation, ...], bool, str | None]:
    """Parse one actual nmap discovery result without inferring missing ports."""
    text = (result.stdout + result.stderr).decode("utf-8", errors="replace")
    failure = _failure(result)
    complete = failure is None and _nmap_complete(text)
    observations = tuple(item for item in _parse_observations(result) if item.protocol == protocol)
    if not complete and failure is None:
        failure = "nmap output did not contain a trustworthy completion record"
    return observations, complete, failure


def build_discovery_commands(
    target: str,
    *,
    host_timeout_seconds: int,
    max_retries: int,
    script_timeout_seconds: int,
    tcp_ports: Iterable[int] | None = None,
    udp_ports: Iterable[int] | None = None,
) -> tuple[list[str], list[str]]:
    """Build separate TCP and UDP argv so protocol provenance is explicit."""
    common = [
        "nmap",
        "-Pn",
        "--reason",
        "--host-timeout",
        f"{max(1, int(host_timeout_seconds))}s",
        "--max-retries",
        str(max(0, int(max_retries))),
        "--script-timeout",
        f"{max(1, int(script_timeout_seconds))}s",
    ]
    selected_tcp = tuple(tcp_ports or TCP_DISCOVERY_PORTS)
    selected_udp = tuple(udp_ports or UDP_DISCOVERY_PORTS)
    tcp = [*common, "-sT", "-p", f"T:{','.join(map(str, selected_tcp))}", target]
    udp = [*common, "-sU", "-p", f"U:{','.join(map(str, selected_udp))}", target]
    return tcp, udp


_TCP_REQUIRED: dict[str, tuple[int, ...]] = {
    "06": (389,),
    "08": (443,),
    "10": (23,),
    "12": (22, 80, 443),
    "15": (80, 443, 8080),
    "16": (139, 445),
    "18": (21,),
    "20": (1883, 8883),
    "21": (139, 445),
    "23": (3389,),
    "24": (6379,),
    "25": (1433,),
    "27": (80,),
    "33": (80,),
    "34": (22,),
    "36": (135, 593),
    "37": (5900,),
    "39": (22,),
}
_UDP_REQUIRED: dict[str, tuple[int, ...]] = {
    "01": (123,),
    "07": (137, 138),
    "09": (69,),
    "13": (161,),
    "17": (161, 162),
    "30": (500, 4500),
    "40": (53,),
}
_GENERIC_TCP = {"02", "04", "05", "11", "22"}
_TCP_FILTER_BLOCK = {
    "06", "10", "15", "16", "18", "20", "21", "23", "24", "25", "27", "33", "34", "36", "37", "39",
}


def service_gate(
    testcase_id: str,
    snapshot: DiscoverySnapshot,
    *,
    assessment_type: str = "external_unauthenticated",
) -> tuple[str, str] | None:
    """Return an applicability/coverage override from complete discovery.

    Explicitly closed required ports are NA.  For an external unauthenticated
    assessment, a complete scan that positively reports every required TCP
    endpoint as ``filtered`` establishes an accessibility limitation and is
    therefore NA under the external-vantage policy.  It is not a negative
    security result.  Missing, failed, or timed-out observations never become
    NA.
    """
    if testcase_id in _GENERIC_TCP:
        if not snapshot.tcp_complete:
            return None
        if snapshot.tcp and all(item.state == "closed" for item in snapshot.tcp):
            return "NA", "The complete TCP discovery scan explicitly closed every tested TCP service port"
        return None

    required_tcp = _TCP_REQUIRED.get(testcase_id, ())
    required_udp = _UDP_REQUIRED.get(testcase_id, ())
    if required_tcp:
        if not snapshot.tcp_complete:
            return None
        observations = {item.port: item for item in snapshot.tcp}
        if not all(port in observations for port in required_tcp):
            return None
        if all(observations[port].state == "closed" for port in required_tcp):
            return "NA", f"The complete TCP discovery scan explicitly closed the required service ports: {', '.join(map(str, required_tcp))}"
        if testcase_id in _TCP_FILTER_BLOCK and all(
            observations[port].state == "filtered" for port in required_tcp
        ):
            reason = (
                "NA_UNTESTABLE_FROM_EXTERNAL_VANTAGE: the complete TCP discovery scan observed "
                f"all required service ports as filtered ({', '.join(map(str, required_tcp))}); "
                "the service-dependent check could not be performed from this external position"
            )
            if assessment_type == "external_unauthenticated":
                return "NA", reason
            return "INCONCLUSIVE", reason
        return None
    if required_udp:
        if not snapshot.udp_complete:
            return None
        observations = {item.port: item for item in snapshot.udp}
        if not all(port in observations for port in required_udp):
            return None
        if all(observations[port].state == "closed" for port in required_udp):
            return "NA", f"The complete UDP discovery scan explicitly closed the required service ports: {', '.join(map(str, required_udp))}"
    return None


def external_udp_accessibility_gate(
    testcase_id: str,
    snapshot: DiscoverySnapshot,
    *,
    assessment_type: str,
) -> tuple[str, str] | None:
    """Return an external accessibility NA only after the service check ran.

    ``open|filtered`` is deliberately not treated as confirmed filtering.  The
    caller must first attempt the protocol-specific check and bounded recovery;
    this helper only supplies the final accessibility policy decision when the
    completed discovery still contains no usable UDP response.
    """
    if assessment_type != "external_unauthenticated" or not snapshot.udp_complete:
        return None
    required_udp = _UDP_REQUIRED.get(testcase_id, ())
    observations = {item.port: item for item in snapshot.udp}
    if not required_udp or not all(port in observations for port in required_udp):
        return None
    if all(observations[port].state == "open|filtered" for port in required_udp) and all(
        "no-response" in observations[port].service.casefold() for port in required_udp
    ):
        return (
            "NA",
            "NA_UNTESTABLE_FROM_EXTERNAL_VANTAGE: the completed UDP checks returned "
            "open|filtered with no usable protocol response on every required endpoint; "
            "the service-dependent check could not be assessed from this external position",
        )
    return None


def protocol_for_testcase(testcase_id: str) -> str:
    if testcase_id in _UDP_REQUIRED:
        return "udp"
    if testcase_id in _GENERIC_TCP or testcase_id in _TCP_REQUIRED:
        return "tcp"
    return "other"


def required_ports(testcase_id: str) -> tuple[tuple[str, int], ...]:
    return tuple(("tcp", port) for port in _TCP_REQUIRED.get(testcase_id, ())) + tuple(
        ("udp", port) for port in _UDP_REQUIRED.get(testcase_id, ())
    )


def observations_for_ports(snapshot: DiscoverySnapshot, ports: Iterable[tuple[str, int]]) -> list[PortObservation]:
    wanted = {(protocol, port) for protocol, port in ports}
    return [item for item in snapshot.observations() if (item.protocol, item.port) in wanted]
