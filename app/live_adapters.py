"""Allowlisted, non-destructive live execution adapters.

The adapter registry is deliberately conservative.  A live adapter may collect a
service response or a protocol configuration observation, but it may not turn
mere reachability into a vulnerability finding.  Classification is derived from
the captured command result by :func:`parse_live_result`; no status tokens are
written into the command's stdout.
"""

from __future__ import annotations

import re
import sys
from dataclasses import asdict, dataclass

from .commands import CommandResult
from .registry import TESTCASES

COMMON_TCP_PORTS = "21,22,23,53,80,135,139,389,443,445,1433,1521,1883,27017,3306,3389,5432,5900,6379,8080,8883,9200"


@dataclass(frozen=True)
class LiveAdapterDefinition:
    testcase_id: str
    live_status: str
    required_tools: tuple[str, ...]
    required_vantage: tuple[str, ...]
    required_permissions: tuple[str, ...]
    required_capabilities: tuple[str, ...]
    requires_credentials: bool
    execution_adapter: str
    evidence_parser: str
    verification_logic: str
    supported_profiles: tuple[str, ...]
    coverage: tuple[str, ...]
    command_scope: str

    @property
    def has_live_execution(self) -> bool:
        return self.live_status in {"LIVE", "LIVE_LIMITED"}

    def as_dict(self) -> dict[str, object]:
        value = asdict(self)
        for key in (
            "required_tools",
            "required_vantage",
            "required_permissions",
            "required_capabilities",
            "supported_profiles",
            "coverage",
        ):
            value[key] = list(value[key])
        value["has_live_execution"] = self.has_live_execution
        value["controlled_validation"] = list(_CONTROLLED_VALIDATION.get(self.testcase_id, ()))
        return value


_PROFILE_SET = (
    "external_unauthenticated",
    "internal_unauthenticated",
    "internal_authenticated",
    "custom_hybrid",
)


def _definition(
    testcase_id: str,
    *,
    status: str,
    tools: tuple[str, ...],
    adapter: str,
    parser: str,
    verification: str,
    coverage: tuple[str, ...],
    profiles: tuple[str, ...] = _PROFILE_SET,
    command_scope: str = "safe, rate-limited, read-only network observation",
) -> LiveAdapterDefinition:
    testcase = next(item for item in TESTCASES if item.id == testcase_id)
    return LiveAdapterDefinition(
        testcase_id=testcase_id,
        live_status=status,
        required_tools=tools,
        required_vantage=testcase.required_vantage,
        required_permissions=testcase.required_permissions,
        required_capabilities=testcase.required_capabilities,
        requires_credentials=testcase.requires_credentials,
        execution_adapter=adapter,
        evidence_parser=parser,
        verification_logic=verification,
        supported_profiles=profiles,
        coverage=coverage,
        command_scope=command_scope,
    )


_ADAPTERS: dict[str, LiveAdapterDefinition] = {
    "01": _definition("01", status="LIVE_LIMITED", tools=("nmap",), adapter="nmap_ntp_info", parser="nmap_ntp", verification="NTP exposure is observed, but amplification is never asserted without a bounded, protocol-specific positive predicate.", coverage=("command_execution", "udp_service_state")),
    "02": _definition("02", status="LIVE", tools=("nmap",), adapter="nmap_service_fingerprint", parser="nmap_service_fingerprint", verification="A validated service/version line is an informational observation; origin-IP claims are never inferred.", coverage=("command_execution", "service_fingerprint")),
    "03": _definition("03", status="CAPABILITY_ONLY", tools=(), adapter="authorized_internal_sensor_required", parser="none", verification="External or host-only execution cannot establish VLAN isolation; requires an authorized internal vantage and segmentation fixture.", coverage=("applicability_only",), profiles=("internal_unauthenticated", "internal_authenticated", "custom_hybrid")),
    "04": _definition("04", status="LIVE_LIMITED", tools=("nmap",), adapter="nmap_database_inventory", parser="database_service_inventory", verification="Database exposure alone is not anonymous access; an unauthenticated read predicate must be independently established.", coverage=("command_execution", "service_inventory")),
    "05": _definition("05", status="LIVE", tools=("nmap",), adapter="nmap_service_fingerprint", parser="legacy_service_fingerprint", verification="Only reliably identified deprecated protocol/service names are reported.", coverage=("command_execution", "service_fingerprint")),
    "06": _definition("06", status="LIVE", tools=("nmap",), adapter="nmap_ldap_rootdse", parser="ldap_rootdse", verification="RootDSE data is FOUND only when the safe LDAP script captures it; access denial is a completed negative for unauthenticated disclosure.", coverage=("command_execution", "unauthenticated_directory_query")),
    "07": _definition("07", status="LIVE_LIMITED", tools=("nmap",), adapter="nmap_nbstat", parser="netbios_nbstat", verification="NetBIOS data is reported only from an actual nbstat response; UDP silence remains inconclusive.", coverage=("command_execution", "udp_service_state")),
    "08": _definition("08", status="LIVE", tools=("nmap",), adapter="nmap_ssl_enum_ciphers", parser="tls_cipher_inventory", verification="Deprecated protocol support is FOUND only when the TLS script enumerates it; a complete modern-only enumeration supports NOT_FOUND for that condition.", coverage=("command_execution", "tls_protocol_inventory")),
    "09": _definition("09", status="LIVE_LIMITED", tools=("nmap",), adapter="nmap_tftp_state", parser="udp_service_state", verification="TFTP exposure is observed without uploading, overwriting, or claiming file-read access.", coverage=("command_execution", "udp_service_state")),
    "10": _definition("10", status="LIVE", tools=("nmap",), adapter="nmap_telnet_banner", parser="telnet_banner", verification="Plaintext Telnet behavior is FOUND only from a captured Telnet/banner response; no credentials are attempted.", coverage=("command_execution", "plaintext_banner")),
    "11": _definition("11", status="LIVE_LIMITED", tools=("nmap",), adapter="nmap_service_fingerprint", parser="version_corroboration", verification="Nmap service/version evidence is preserved for operator review; no online CVE research or exploitability claim is performed by this testcase.", coverage=("command_execution", "version_observation")),
    "12": _definition("12", status="LIVE", tools=("nmap",), adapter="nmap_tcp_state", parser="tcp_port_state", verification="Only an explicit filtered/closed/open state for a port included in the completed scan is classified.", coverage=("command_execution", "tcp_state")),
    "13": _definition("13", status="LIVE", tools=("nmap",), adapter="nmap_snmp_info", parser="snmp_info", verification="FOUND requires a real SNMP information response to the safe public-community probe; UDP silence is inconclusive.", coverage=("command_execution", "snmp_query")),
    "14": _definition("14", status="CAPABILITY_ONLY", tools=(), adapter="authorized_layer2_sensor_required", parser="none", verification="ARP/MAC protections require an authorized local Layer-2 vantage; no poisoning or MITM action is implemented.", coverage=("applicability_only",), profiles=("internal_unauthenticated", "internal_authenticated", "custom_hybrid")),
    "15": _definition("15", status="LIVE_LIMITED", tools=("nmap",), adapter="nmap_http_management_surface", parser="management_surface", verification="Management exposure is reported only for an observed management marker in an actual HTTP response; no credential attack occurs.", coverage=("command_execution", "http_metadata")),
    "16": _definition("16", status="LIVE", tools=("nmap",), adapter="nmap_smb_enum_shares", parser="smb_share_access", verification="FOUND requires an actual unauthenticated share/file-access observation; access denial supports NOT_FOUND for that tested condition.", coverage=("command_execution", "share_enumeration")),
    "17": _definition("17", status="LIVE_LIMITED", tools=("nmap",), adapter="nmap_snmp_info", parser="snmp_version_posture", verification="SNMP version observations are retained, but a version alone is not called a vulnerability.", coverage=("command_execution", "snmp_query")),
    "18": _definition("18", status="LIVE", tools=("python",), adapter="python_ftp_anonymous", parser="ftp_anonymous_response", verification="FOUND requires a real FTP 230 response to the anonymous login probe; an explicit 530 denial supports NOT_FOUND.", coverage=("command_execution", "anonymous_login_check")),
    "19": _definition("19", status="LIVE_LIMITED", tools=("nmap",), adapter="nmap_tcp_inventory", parser="reachability_observation_only", verification="Reachability is preserved as evidence only; this adapter never turns port reachability alone into FOUND or NOT_FOUND.", coverage=("command_execution", "tcp_inventory")),
    "20": _definition("20", status="LIVE_LIMITED", tools=("nmap",), adapter="nmap_messaging_inventory", parser="messaging_inventory", verification="Endpoint exposure alone is not an unauthenticated data/action finding; no messages are published or changed.", coverage=("command_execution", "service_inventory")),
    "21": _definition("21", status="LIVE", tools=("nmap",), adapter="nmap_smb_security", parser="smb_security_posture", verification="SMB signing/dialect posture is classified only from the safe NSE output; no relay, MITM, or exploit is attempted.", coverage=("command_execution", "smb_security")),
    "22": _definition("22", status="LIVE", tools=("nmap",), adapter="nmap_service_fingerprint", parser="banner_identity", verification="A banner/service identity is FOUND only when nmap captures a non-unknown service identity.", coverage=("command_execution", "service_fingerprint")),
    "23": _definition("23", status="LIVE", tools=("nmap",), adapter="nmap_rdp_encryption", parser="rdp_nla", verification="RDP NLA posture is classified from rdp-enum-encryption output; no credentials are guessed.", coverage=("command_execution", "rdp_security")),
    "24": _definition("24", status="LIVE", tools=("python",), adapter="python_redis_info_probe", parser="redis_auth", verification="FOUND requires a real Redis INFO response without an authentication barrier; an explicit -NOAUTH response supports NOT_FOUND. Keys and configuration are never modified.", coverage=("command_execution", "redis_safe_query")),
    "25": _definition("25", status="LIVE_LIMITED", tools=("nmap",), adapter="nmap_mssql_info", parser="mssql_info", verification="MS-SQL pre-auth observations are retained; no password spraying or login guessing is performed.", coverage=("command_execution", "mssql_safe_query")),
    "26": _definition("26", status="CAPABILITY_ONLY", tools=(), adapter="approved_authenticated_policy_sensor_required", parser="none", verification="Brute-force resistance is not tested in unauthenticated mode; approved authenticated policy evidence is required.", coverage=("applicability_only",), profiles=("internal_authenticated", "custom_hybrid"), command_scope="no automated credential guessing; requires approved authenticated policy evidence"),
    "27": _definition("27", status="LIVE", tools=("curl",), adapter="curl_http_headers", parser="specific_version_header", verification="A numeric product version in an actual response header is FOUND; a completed response without a version is NOT_FOUND for disclosure.", coverage=("command_execution", "http_headers")),
    "28": _definition("28", status="CAPABILITY_ONLY", tools=(), adapter="authorized_internal_egress_sensor_required", parser="none", verification="External-only execution cannot prove internal egress controls; requires an approved internal source and destination fixture.", coverage=("applicability_only",), profiles=("internal_unauthenticated", "internal_authenticated", "custom_hybrid")),
    "29": _definition("29", status="LIVE_LIMITED", tools=("nmap",), adapter="nmap_ipv6_discovery", parser="ipv6_discovery", verification="Only an actual authorized IPv6 response is recorded; remote router-advertisement security is not inferred.", coverage=("command_execution", "ipv6_discovery")),
    "30": _definition("30", status="LIVE_LIMITED", tools=("nmap",), adapter="nmap_ike_version", parser="vpn_negotiation_observation", verification="IKE/SSL-VPN negotiation data is captured without destructive negotiation or credential attempts; weakness claims remain limited.", coverage=("command_execution", "vpn_observation")),
    "31": _definition("31", status="CAPABILITY_ONLY", tools=(), adapter="authorized_inventory_sensor_required", parser="none", verification="Rogue-device status requires an authorized asset inventory; a host observed on a network is never guessed to be rogue.", coverage=("applicability_only",), profiles=("internal_unauthenticated", "internal_authenticated", "custom_hybrid")),
    "32": _definition("32", status="CAPABILITY_ONLY", tools=(), adapter="authorized_wireless_sensor_required", parser="none", verification="Wireless posture requires authorized proximity and suitable hardware; WSL limitations are reported rather than bypassed.", coverage=("applicability_only",), profiles=("internal_unauthenticated", "internal_authenticated", "custom_hybrid")),
    "33": _definition("33", status="LIVE", tools=("nmap",), adapter="nmap_http_security_checks", parser="nmap_http_security_headers_and_methods", verification="Each supported HTTP condition is evaluated from safe Nmap script output; one present header never establishes broad HTTP security.", coverage=("command_execution", "http_security_headers", "http_methods")),
    "34": _definition("34", status="LIVE", tools=("nmap",), adapter="nmap_ssh_algorithms", parser="ssh_algorithm_posture", verification="Weak SSH algorithms are FOUND only when enumerated by ssh2-enum-algos; a complete algorithm list without the tested weak algorithms supports NOT_FOUND.", coverage=("command_execution", "ssh_configuration")),
    "35": _definition("35", status="LIVE", tools=("nmap",), adapter="nmap_host_discovery", parser="host_reachability", verification="Host-up is FOUND from a completed multi-signal discovery response; lack of a response remains INCONCLUSIVE.", coverage=("command_execution", "host_discovery")),
    "36": _definition("36", status="LIVE", tools=("nmap",), adapter="nmap_rpcinfo", parser="rpc_mapping", verification="RPC mapping is FOUND only when an actual rpcinfo response discloses a program/endpoint.", coverage=("command_execution", "rpc_mapping")),
    "37": _definition("37", status="LIVE", tools=("nmap",), adapter="nmap_vnc_info", parser="vnc_authentication", verification="VNC no-auth is FOUND only from vnc-info output; an explicit authentication type supports NOT_FOUND.", coverage=("command_execution", "vnc_configuration")),
    "38": _definition("38", status="LIVE_LIMITED", tools=("nmap",), adapter="nmap_icmp_information_queries", parser="icmp_information_response", verification="Echo reachability is not disclosure; only explicit timestamp/address-mask information responses are evaluated.", coverage=("command_execution", "icmp_information_queries")),
    "39": _definition("39", status="LIVE", tools=("nmap",), adapter="nmap_ssh_algorithms", parser="ssh_vulnerability_posture", verification="Specific SSH cryptographic weaknesses require an actual weak algorithm listing; no duplicate network work is required beyond the valid scan.", coverage=("command_execution", "ssh_configuration")),
    "40": _definition("40", status="LIVE_LIMITED", tools=("dig", "nmap"), adapter="dig_dns_udp_tcp_and_nmap", parser="dns_response_flags", verification="UDP/TCP response behavior and DNS flags are preserved independently; recursion or transfer conclusions require matching authorized evidence.", coverage=("command_execution", "dns_udp", "dns_tcp", "dns_flags")),
}


# This is intentionally separate from the execution contract.  It records
# what a controlled local service can prove, rather than implying that every
# safe adapter has a synthetic positive vulnerability fixture.
_CONTROLLED_VALIDATION: dict[str, tuple[str, ...]] = {
    "01": ("NTP response -> INCONCLUSIVE; silence/malformed response -> INCONCLUSIVE",),
    "02": ("HTTP/SSH fingerprint -> FOUND informational; closed ports -> NA",),
    "03": ("capability-only; no live sensor",),
    "04": ("database banner -> INCONCLUSIVE; no database service -> NA",),
    "05": ("Telnet/FTP legacy service -> FOUND; modern HTTP inventory -> NOT_FOUND",),
    "06": ("LDAP RootDSE response -> FOUND; auth denial/malformed response -> NOT_FOUND or INCONCLUSIVE",),
    "07": ("NetBIOS response -> FOUND; UDP silence/malformed response -> INCONCLUSIVE",),
    "08": ("modern TLS-only service -> NOT_FOUND; weak/deprecated protocol if supported -> FOUND",),
    "09": ("TFTP state response -> INCONCLUSIVE; UDP silence -> INCONCLUSIVE",),
    "10": ("Telnet plaintext banner -> FOUND; closed port -> NA",),
    "11": ("version inventory -> AWAITING_OPERATOR_REVIEW; explicit outdated selection -> FOUND; reviewed none outdated -> NOT_FOUND; unidentified entries remain a limitation",),
    "12": ("closed/open tested ports -> NOT_FOUND for filtering; filtered state -> FOUND",),
    "13": ("SNMP public response -> FOUND; denied/malformed response -> INCONCLUSIVE",),
    "14": ("capability-only; no Layer-2 sensor",),
    "15": ("management-title HTTP response -> FOUND; complete non-management response -> NOT_FOUND",),
    "16": ("SMB share service -> FOUND/NOT_FOUND only with real SMB evidence; no SMB -> NA",),
    "17": ("SNMP version response -> INCONCLUSIVE observation",),
    "18": ("anonymous FTP read -> FOUND; explicit anonymous denial -> NOT_FOUND",),
    "19": ("any port inventory -> INCONCLUSIVE; reachability is never a finding",),
    "20": ("MQTT/WebSocket exposure -> INCONCLUSIVE without auth/data predicate",),
    "21": ("SMB signing posture -> FOUND/NOT_FOUND only with real SMB NSE output",),
    "22": ("validated service identity -> FOUND; closed ports -> NA",),
    "23": ("RDP NLA posture -> FOUND/NOT_FOUND only with real RDP NSE output",),
    "24": ("unauthenticated Redis INFO -> FOUND; NOAUTH response -> NOT_FOUND",),
    "25": ("MS-SQL info -> INCONCLUSIVE; no authentication attempts",),
    "26": ("capability-only; no credential guessing",),
    "27": ("versioned HTTP header -> FOUND; complete header without version -> NOT_FOUND",),
    "28": ("capability-only; requires authorized internal egress sensor",),
    "29": ("IPv6 response -> INCONCLUSIVE observation; no response -> INCONCLUSIVE",),
    "30": ("IKE response -> INCONCLUSIVE observation; no response -> INCONCLUSIVE",),
    "31": ("capability-only; requires authorized asset inventory",),
    "32": ("capability-only; requires authorized wireless hardware/proximity",),
    "33": ("missing X-Content-Type-Options -> FOUND; nosniff present -> NOT_FOUND",),
    "34": ("weak SSH algorithm listing -> FOUND; modern algorithm list -> NOT_FOUND",),
    "35": ("completed host-up discovery -> FOUND; no response -> INCONCLUSIVE",),
    "36": ("RPC mapping response -> FOUND; no mapper -> NA/INCONCLUSIVE",),
    "37": ("VNC security type None -> FOUND; VNC authentication type -> NOT_FOUND",),
    "38": ("ICMP response -> INCONCLUSIVE observation; no response -> INCONCLUSIVE",),
    "39": ("weak SSH algorithm listing -> FOUND; modern algorithm list -> NOT_FOUND",),
    "40": ("DNS response without authorized zone predicate -> INCONCLUSIVE",),
}


def adapter_for(testcase_id: str) -> LiveAdapterDefinition:
    try:
        return _ADAPTERS[testcase_id]
    except KeyError as error:
        raise ValueError(f"No live adapter is registered for testcase {testcase_id}") from error


def capability_matrix() -> list[dict[str, object]]:
    return [
        {"testcase": testcase.as_dict(), "live": adapter_for(testcase.id).as_dict()}
        for testcase in TESTCASES
    ]


def _nmap(
    target: str,
    ports: str,
    *,
    scripts: tuple[str, ...] = (),
    service_detection: bool = False,
    udp: bool = False,
    extra: tuple[str, ...] = (),
    host_timeout_seconds: int = 8,
    max_retries: int = 1,
    script_timeout_seconds: int = 30,
) -> list[str]:
    argv = [
        "nmap", "-Pn", "--host-timeout", f"{host_timeout_seconds}s",
        "--max-retries", str(max(0, int(max_retries))), "--script-timeout", f"{max(1, int(script_timeout_seconds))}s", "--reason",
    ]
    if udp:
        argv.append("-sU")
    if service_detection:
        argv.extend(("-sV", "--version-light"))
    if scripts:
        argv.extend(("--script", ",".join(scripts)))
    argv.extend(extra)
    argv.extend(("-p", ports, target))
    return argv


def _selected_ports(port_overrides: dict[str, int], keys: tuple[str, ...]) -> str | None:
    """Return only explicitly overridden ports for controlled local services.

    Production calls do not provide overrides and retain the normal coverage
    set.  The controlled-service harness supplies an ephemeral port for one
    service; narrowing that one command keeps validation bounded and prevents
    unrelated service probes from obscuring the adapter's actual evidence.
    """
    selected = [str(port_overrides[key]) for key in keys if key in port_overrides]
    return ",".join(selected) if selected else None


def build_command(
    testcase_id: str,
    target: str,
    *,
    port_overrides: dict[str, int] | None = None,
    nmap_host_timeout_seconds: int = 8,
    nmap_max_retries: int = 1,
    tcp_connect_timeout_seconds: int = 5,
    protocol_timeout_seconds: int = 15,
    nmap_script_timeout_seconds: int = 30,
    dns_transport: str | None = None,
) -> list[str] | None:
    """Build one explicit argv for a testcase; never interpolate a shell command."""
    adapter = adapter_for(testcase_id)
    if not adapter.has_live_execution:
        return None
    ports = port_overrides or {}
    host_timeout = max(1, int(nmap_host_timeout_seconds))

    def nmap(*args, **kwargs):
        return _nmap(
            *args,
            host_timeout_seconds=host_timeout,
            max_retries=nmap_max_retries,
            script_timeout_seconds=nmap_script_timeout_seconds,
            **kwargs,
        )

    if testcase_id in {"02", "04", "05", "11", "22"}:
        keys = tuple(COMMON_TCP_PORTS.split(","))
        selected = _selected_ports(ports, keys)
        return nmap(target, selected or ",".join(keys), service_detection=True)
    if testcase_id == "19":
        keys = tuple(COMMON_TCP_PORTS.split(","))
        selected = _selected_ports(ports, keys)
        return nmap(target, selected or ",".join(keys), extra=("-sT",))
    if testcase_id == "01":
        return nmap(target, str(ports.get("123/udp", 123)), scripts=("ntp-info",), udp=True)
    if testcase_id == "06":
        return nmap(target, str(ports.get("389", 389)), scripts=("ldap-rootdse",))
    if testcase_id == "07":
        return nmap(target, ",".join(str(ports.get(f"{item}/udp", item)) for item in (137, 138)), scripts=("nbstat",), udp=True)
    if testcase_id == "08":
        return nmap(target, str(ports.get("443", 443)), scripts=("ssl-enum-ciphers",))
    if testcase_id == "09":
        return nmap(target, str(ports.get("69/udp", 69)), udp=True)
    if testcase_id == "10":
        return nmap(target, str(ports.get("23", 23)), service_detection=True)
    if testcase_id == "12":
        keys = ("22", "80", "443")
        selected = _selected_ports(ports, keys)
        return nmap(target, selected or ",".join(keys), extra=("-sT",))
    if testcase_id == "13":
        return nmap(target, str(ports.get("161/udp", 161)), scripts=("snmp-info",), udp=True)
    if testcase_id == "15":
        keys = ("80", "443", "8080")
        selected = _selected_ports(ports, keys)
        return nmap(target, selected or ",".join(keys), scripts=("http-title", "http-headers"), service_detection=True)
    if testcase_id == "16":
        keys = ("139", "445")
        selected = _selected_ports(ports, keys)
        return nmap(target, selected or ",".join(keys), scripts=("smb-enum-shares",))
    if testcase_id == "17":
        return nmap(target, ",".join(str(ports.get(f"{item}/udp", item)) for item in (161, 162)), scripts=("snmp-info",), udp=True)
    if testcase_id == "18":
        port = ports.get("21", 21)
        return [
            sys.executable, "-m", "app.ftp_probe", "--target", target,
            "--port", str(port), "--timeout", str(max(1, int(protocol_timeout_seconds))),
        ]
    if testcase_id == "20":
        keys = ("1883", "8883")
        selected = _selected_ports(ports, keys)
        return nmap(target, selected or ",".join(keys), service_detection=True)
    if testcase_id == "21":
        keys = ("139", "445")
        selected = _selected_ports(ports, keys)
        return nmap(target, selected or ",".join(keys), scripts=("smb2-security-mode", "smb-protocols"))
    if testcase_id == "23":
        return nmap(target, str(ports.get("3389", 3389)), scripts=("rdp-enum-encryption",))
    if testcase_id == "24":
        return [
            sys.executable, "-m", "app.protocol_probe", "redis-info",
            "--target", target, "--port", str(ports.get("6379", 6379)),
            "--timeout", str(max(1, int(protocol_timeout_seconds))),
        ]
    if testcase_id == "25":
        return nmap(target, str(ports.get("1433", 1433)), scripts=("ms-sql-info",))
    if testcase_id == "27":
        port = ports.get("80", 80)
        return ["curl", "--silent", "--show-error", "--include", "--connect-timeout", str(max(1, int(tcp_connect_timeout_seconds))), "--max-time", str(max(1, int(protocol_timeout_seconds))), "--url", f"http://{target}:{port}/"]
    if testcase_id == "29":
        return ["nmap", "-6", "-sn", "--host-timeout", f"{host_timeout}s", "--max-retries", str(max(0, int(nmap_max_retries))), "--reason", target]
    if testcase_id == "30":
        return nmap(target, ",".join(str(ports.get(f"{item}/udp", item)) for item in (500, 4500)), scripts=("ike-version",), udp=True)
    if testcase_id == "33":
        port = ports.get("80", 80)
        return nmap(
            target,
            str(port),
            scripts=("http-security-headers", "http-methods", "http-title", "http-headers"),
            service_detection=True,
        )
    if testcase_id in {"34", "39"}:
        return nmap(target, str(ports.get("22", 22)), scripts=("ssh2-enum-algos",), service_detection=True)
    if testcase_id == "35":
        return ["nmap", "-sn", "-PE", "-PS22,80,443", "--host-timeout", f"{host_timeout}s", "--max-retries", str(max(0, int(nmap_max_retries))), "--reason", target]
    if testcase_id == "36":
        keys = ("135", "593")
        selected = _selected_ports(ports, keys)
        return nmap(target, selected or ",".join(keys), scripts=("rpcinfo",))
    if testcase_id == "37":
        return nmap(target, str(ports.get("5900", 5900)), scripts=("vnc-info",), service_detection=True)
    if testcase_id == "38":
        return ["nmap", "-sn", "-PP", "-PM", "--host-timeout", f"{host_timeout}s", "--max-retries", str(max(0, int(nmap_max_retries))), "--reason", target]
    if testcase_id == "40":
        transport = dns_transport or "udp"
        if transport not in {"tcp", "udp"}:
            raise ValueError(f"Unsupported DNS transport: {transport}")
        return [
            "dig",
            f"+time={max(1, int(protocol_timeout_seconds))}",
            "+tries=1",
            "+comments",
            "+answer",
            "+stats",
            *(["+tcp"] if transport == "tcp" else []),
            f"@{target}",
            ".",
            "NS",
        ]
    raise ValueError(f"No command builder for testcase {testcase_id}")


@dataclass(frozen=True)
class LiveParse:
    status: str
    applicability: str
    reason: str | None
    observation_ids: tuple[str, ...] = ()
    severity: str = "unknown"
    validation_state: str = "INSUFFICIENT"


_PORT_LINE = re.compile(
    r"^\s*(\d+)/(tcp|udp)\s+(open|closed|filtered|open\|filtered)(?:\s+(.*?))?\s*$",
    re.MULTILINE | re.IGNORECASE,
)


def _text(result: CommandResult) -> str:
    return (result.stdout + result.stderr).decode("utf-8", errors="replace")


def _states(text: str) -> list[tuple[int, str, str, str]]:
    """Return port, protocol, state and service as separate facts."""
    return [
        (int(port), protocol.lower(), state.lower(), (service or "").strip())
        for port, protocol, state, service in _PORT_LINE.findall(text)
    ]


def _nmap_complete(text: str) -> bool:
    lower = text.lower()
    return bool(
        re.search(r"nmap done:", lower)
        and not re.search(r"skipping host|host timeout|scan timed out", lower)
    )


def _all_ports_closed(text: str) -> bool:
    lower = text.lower()
    return bool(
        re.search(r"not shown:.*\bclosed\b.*\bports?", lower)
        or re.search(r"all .*scanned ports.*closed", lower)
    )


def _inconclusive(reason: str, *, observation: str | None = None) -> LiveParse:
    return LiveParse("INCONCLUSIVE", "applicable", reason, (observation,) if observation else ())


def _expected_protocol(testcase_id: str) -> str:
    if testcase_id in {"01", "07", "09", "13", "17", "30"}:
        return "udp"
    if testcase_id == "40":
        return "mixed"
    return "tcp"


def _service_absent(
    states: list[tuple[int, str, str, str]],
    testcase_id: str,
    *,
    complete: bool,
    all_ports_closed: bool = False,
) -> LiveParse | None:
    expected = _expected_protocol(testcase_id)
    relevant = [item for item in states if expected == "mixed" or item[1] == expected]
    if complete and (relevant and all(state == "closed" for _port, _protocol, state, _service in relevant) or all_ports_closed):
        return LiveParse("NA", "No applicable service was observed on the complete tested port set", f"testcase {testcase_id} service ports were explicitly closed", (f"live-{testcase_id}-closed",), "informational", "APPLICABILITY_CONFIRMED")
    if any(state in {"filtered", "open|filtered"} for _port, _protocol, state, _service in relevant) and not any(state == "open" for _port, _protocol, state, _service in relevant):
        if expected == "udp":
            reason = "UDP filtering or silence prevented service applicability from being established"
        elif expected == "tcp":
            reason = "TCP filtering prevented service applicability from being established"
        else:
            reason = "Protocol filtering prevented service applicability from being established"
        return _inconclusive(reason, observation=f"live-{testcase_id}-filtered")
    return None


def _execution_failure(result: CommandResult) -> str:
    executable = result.argv[0].rsplit("/", 1)[-1] if result.argv else "command"
    detail = (result.stderr or result.stdout).decode("utf-8", errors="replace").strip()
    detail = f": {detail[:240]}" if detail else ""
    if result.timed_out:
        return f"{executable} command timed out before the protocol check completed{detail}"
    if executable == "curl" and result.exit_code == 28:
        return f"curl exited 28 (operation timeout); no negative security conclusion is supported{detail}"
    if executable == "dig" and result.exit_code == 9:
        return f"dig exited 9 (no usable DNS response); DNS safety was not established{detail}"
    if executable in {"python", "python3"} and result.exit_code == 2:
        return f"the protocol probe exited 2; inspect its stderr rather than treating it as a negative result{detail}"
    return f"{executable} exited with status {result.exit_code}; the security condition was not completed{detail}"


def _connection_refused(text: str) -> bool:
    """Recognize an explicit TCP refusal, but never treat timeout/silence as absence."""
    return bool(re.search(r"connection refused|conn-refused", text, re.IGNORECASE))


def parse_live_result(testcase_id: str, result: CommandResult) -> LiveParse:
    """Parse a completed live command without trusting generated status tokens."""
    if result.timed_out:
        return _inconclusive(_execution_failure(result))
    text = _text(result)
    lower = text.lower()
    if testcase_id == "18":
        if re.search(r"(?:^|\s)230\s|anonymous ftp login allowed", lower):
            return LiveParse("FOUND", "applicable", None, ("live-18-anonymous-ftp",), "high", "VALIDATED")
        if re.search(r"(?:^|\s)530\s|not logged in|authentication required", lower):
            return LiveParse("NOT_FOUND", "applicable", None, ("live-18-anonymous-denied",), "informational", "VALIDATED")
        if result.exit_code not in {0, None} and _connection_refused(lower):
            return LiveParse("NA", "No applicable FTP service was observed", "FTP control connection was explicitly refused", ("live-18-ftp-refused",), "informational", "APPLICABILITY_CONFIRMED")
        if result.exit_code != 0 or result.status != "COMPLETED":
            return _inconclusive(f"FTP anonymous probe failed with exit status {result.exit_code}")
        return _inconclusive("FTP protocol responses did not establish anonymous access or explicit denial")
    if testcase_id in {"24", "27", "33", "40"} and result.exit_code != 0 and _connection_refused(lower):
        labels = {
            "24": ("Redis", "live-24-redis-refused"),
            "27": ("HTTP", "live-27-http-refused"),
            "33": ("HTTP", "live-33-http-refused"),
            "40": ("DNS", "live-40-dns-refused"),
        }
        service, observation = labels[testcase_id]
        return LiveParse("NA", f"No applicable {service} service was observed", f"{service} connection was explicitly refused", (observation,), "informational", "APPLICABILITY_CONFIRMED")
    if result.exit_code != 0 or result.status != "COMPLETED":
        return _inconclusive(_execution_failure(result))
    states = _states(text)
    complete = _nmap_complete(text)
    if states and not complete and testcase_id not in {"18", "27", "33", "40"}:
        return _inconclusive("Nmap returned port states without a trustworthy completion record")

    if testcase_id in {"01", "07", "09", "13", "17", "30"}:
        absent = _service_absent(states, testcase_id, complete=complete, all_ports_closed=_all_ports_closed(text))
        if absent:
            return absent
        if testcase_id == "13" and ("sysdescr" in lower or "snmpv" in lower) and "script execution failed" not in lower:
            return LiveParse("FOUND", "applicable", None, ("live-13-snmp-response",), "medium", "VALIDATED")
        if testcase_id == "17" and ("snmpv1" in lower or "snmpv2" in lower or "snmpv3" in lower):
            return _inconclusive("SNMP version posture was observed, but the observation alone does not establish a vulnerability", observation="live-17-snmp-version")
        if testcase_id == "07" and ("netbios" in lower or "nbstat" in lower):
            return LiveParse("FOUND", "applicable", None, ("live-07-netbios-response",), "medium", "VALIDATED")
        if testcase_id == "01" and "ntp" in lower:
            return _inconclusive("NTP responded, but safe exposure evidence does not prove amplification risk", observation="live-01-ntp-response")
        if testcase_id == "30" and "ike" in lower:
            return _inconclusive("VPN negotiation was observed, but no safe weakness predicate was established", observation="live-30-ike-response")
        return _inconclusive("UDP response or service state did not establish the supported predicate")

    if testcase_id == "35":
        if "host is up" in lower and "nmap done:" in lower:
            return LiveParse("FOUND", "applicable", None, ("live-35-host-up",), "informational", "VALIDATED")
        return _inconclusive("lack of discovery response cannot prove that a host is down")
    if testcase_id == "29":
        if "host is up" in lower:
            return _inconclusive("an IPv6 discovery response was captured, but it does not establish router-advertisement security", observation="live-29-response")
        return _inconclusive("lack of an IPv6 response cannot prove protection or absence")
    if testcase_id == "38":
        if re.search(r"timestamp\s+reply|icmp.*timestamp|address[ -]?mask", lower):
            return LiveParse("FOUND", "applicable", None, ("live-38-icmp-information",), "medium", "VALIDATED")
        if "host is up" in lower:
            return _inconclusive("an echo reachability response was captured, but it does not establish ICMP information disclosure", observation="live-38-echo-only")
        return _inconclusive("lack of an ICMP information response cannot prove protection or absence")
    if testcase_id == "12":
        if any(state == "filtered" for _port, _protocol, state, _service in states):
            return LiveParse("FOUND", "applicable", None, ("live-12-filtered-port",), "informational", "VALIDATED")
        if complete and states and all(state in {"open", "closed"} for _port, _protocol, state, _service in states):
            return LiveParse("NOT_FOUND", "applicable", None, ("live-12-no-filtered-port",), "informational", "VALIDATED")
        return _inconclusive("TCP state scan did not complete with a definitive filtered/non-filtered result")
    if testcase_id == "19":
        if complete and states:
            return LiveParse("FOUND", "applicable", None, ("live-19-port-inventory",), "informational", "VALIDATED")
        return _inconclusive("no complete port inventory was captured")
    if testcase_id == "20":
        absent = _service_absent(states, testcase_id, complete=complete, all_ports_closed=_all_ports_closed(text))
        if absent:
            return absent
        if complete and states:
            return _inconclusive("Messaging/WebSocket service state was observed, but no safe unauthenticated data or action predicate was established", observation="live-20-service-inventory")
        return _inconclusive("Messaging/WebSocket service inventory was incomplete")
    if testcase_id in {"02", "04", "05", "11", "22"}:
        if not states:
            return _inconclusive("service fingerprint scan returned no parseable port state")
        absent = _service_absent(states, testcase_id, complete=complete, all_ports_closed=_all_ports_closed(text))
        if absent:
            return absent
        identified = [service for _port, _protocol, state, service in states if state == "open" and service and service.lower() not in {"unknown", "tcpwrapped"}]
        if testcase_id == "04":
            database_services = re.compile(
                r"mysql|mariadb|postgres(?:ql)?|mongodb|mongod|redis|ms[- ]?sql|mssql|oracle|cassandra|elasticsearch|memcached",
                re.IGNORECASE,
            )
            identified = [service for service in identified if database_services.search(service)]
            if complete and not identified:
                return LiveParse(
                    "NA",
                    "No database service was identified in the completed service scan",
                    "The completed service inventory did not identify a supported database endpoint",
                    ("live-04-no-database-service",),
                    "informational",
                    "APPLICABILITY_CONFIRMED",
                )
        if testcase_id == "05" and any(re.search(r"telnet|tftp|rlogin|rsh|ftp", service, re.I) for service in identified):
            return LiveParse("FOUND", "applicable", None, ("live-05-legacy-service",), "medium", "VALIDATED")
        if testcase_id == "05" and complete and identified:
            return LiveParse("NOT_FOUND", "applicable", None, ("live-05-no-tested-legacy-service",), "informational", "VALIDATED")
        if testcase_id == "22" and identified:
            return LiveParse("FOUND", "applicable", None, ("live-22-service-banner",), "informational", "VALIDATED")
        if testcase_id == "11" and identified:
            return _inconclusive("product/service evidence was captured but advisory applicability was not independently established", observation="live-11-version-observation")
        if testcase_id == "04" and identified:
            return _inconclusive("database service exposure was observed without a verified unauthenticated read predicate", observation="live-04-database-service")
        if testcase_id == "02" and identified:
            return LiveParse("FOUND", "applicable", None, ("live-02-fingerprint",), "informational", "VALIDATED")
        return _inconclusive("service inventory was completed without a supported condition")
    if testcase_id == "08":
        absent = _service_absent(states, testcase_id, complete=complete, all_ports_closed=_all_ports_closed(text))
        if absent:
            return absent
        if re.search(r"TLSv1\.[01]\b|SSLv3\b", text, re.I):
            return LiveParse("FOUND", "applicable", None, ("live-08-deprecated-tls",), "medium", "VALIDATED")
        if complete and re.search(r"TLSv1\.[23]", text, re.I):
            return LiveParse("NOT_FOUND", "applicable", None, ("live-08-modern-tls-only",), "informational", "VALIDATED")
        return _inconclusive("TLS enumeration did not establish a supported protocol predicate")
    if testcase_id == "06":
        absent = _service_absent(states, testcase_id, complete=complete, all_ports_closed=_all_ports_closed(text))
        if absent:
            return absent
        if re.search(r"namingcontexts|supportedldapversion|rootdomainnamingcontext", lower):
            return LiveParse("FOUND", "applicable", None, ("live-06-rootdse",), "medium", "VALIDATED")
        if re.search(r"result:\s*(49|50)|insufficientaccess|authenticationrequired", lower):
            return LiveParse("NOT_FOUND", "applicable", None, ("live-06-auth-required",), "informational", "VALIDATED")
        return _inconclusive("LDAP was reachable but the safe unauthenticated directory predicate was not established")
    if testcase_id == "10":
        absent = _service_absent(states, testcase_id, complete=complete, all_ports_closed=_all_ports_closed(text))
        if absent:
            return absent
        if "telnet" in lower or re.search(r"login:|username:|welcome", lower):
            return LiveParse("FOUND", "applicable", None, ("live-10-plaintext-telnet",), "medium", "VALIDATED")
        return _inconclusive("Telnet port state was observed without a plaintext service banner")
    if testcase_id == "15":
        absent = _service_absent(states, testcase_id, complete=complete, all_ports_closed=_all_ports_closed(text))
        if absent:
            return absent
        if re.search(r"admin|console|management|dashboard", lower):
            return LiveParse("FOUND", "applicable", None, ("live-15-management-marker",), "medium", "VALIDATED")
        if complete and any(state == "open" and protocol == "tcp" for _port, protocol, state, _service in states):
            return LiveParse(
                "NOT_FOUND",
                "applicable",
                None,
                ("live-15-no-management-marker",),
                "informational",
                "VALIDATED",
            )
        return _inconclusive("HTTP service was observed without a validated management interface marker")
    if testcase_id == "16":
        absent = _service_absent(states, testcase_id, complete=complete, all_ports_closed=_all_ports_closed(text))
        if absent:
            return absent
        if re.search(r"readable|anonymous|share\s+enumeration", lower) and not re.search(r"access.denied|logon.failure|authentication", lower):
            return LiveParse("FOUND", "applicable", None, ("live-16-share-read",), "high", "VALIDATED")
        if re.search(r"access.denied|logon.failure|authentication required", lower):
            return LiveParse("NOT_FOUND", "applicable", None, ("live-16-share-denied",), "informational", "VALIDATED")
        return _inconclusive("SMB share response did not establish unauthenticated read or denial")
    if testcase_id == "18":
        absent = _service_absent(states, testcase_id, complete=complete, all_ports_closed=_all_ports_closed(text))
        if absent:
            return absent
        if "anonymous ftp login allowed" in lower and not re.search(r"false|denied", lower):
            return LiveParse("FOUND", "applicable", None, ("live-18-anonymous-ftp",), "high", "VALIDATED")
        if re.search(r"anonymous ftp login allowed:\s*false|access denied|authentication required", lower):
            return LiveParse("NOT_FOUND", "applicable", None, ("live-18-anonymous-denied",), "informational", "VALIDATED")
        return _inconclusive("FTP response did not establish anonymous access or denial")
    if testcase_id in {"21", "34", "39", "23", "24", "25", "36", "37"}:
        absent = _service_absent(states, testcase_id, complete=complete, all_ports_closed=_all_ports_closed(text))
        if absent:
            return absent
        if testcase_id == "21":
            if "signing disabled" in lower or "not required" in lower:
                return LiveParse("FOUND", "applicable", None, ("live-21-smb-signing",), "high", "VALIDATED")
            if "signing enabled" in lower and ("required" in lower or "mandatory" in lower):
                return LiveParse("NOT_FOUND", "applicable", None, ("live-21-smb-signing-required",), "informational", "VALIDATED")
        elif testcase_id == "23":
            if "nla" in lower and re.search(r"not supported|disabled|false", lower):
                return LiveParse("FOUND", "applicable", None, ("live-23-rdp-no-nla",), "high", "VALIDATED")
            if "nla" in lower and re.search(r"supported|enabled|true", lower):
                return LiveParse("NOT_FOUND", "applicable", None, ("live-23-rdp-nla",), "informational", "VALIDATED")
        elif testcase_id == "24":
            if ("redis_version" in lower or re.search(r"\bversion:\s*\d+\.\d+", lower)) and "noauth" not in lower:
                return LiveParse("FOUND", "applicable", None, ("live-24-redis-unauthenticated",), "high", "VALIDATED")
            if "noauth" in lower or "authentication required" in lower:
                return LiveParse("NOT_FOUND", "applicable", None, ("live-24-redis-auth",), "informational", "VALIDATED")
        elif testcase_id == "25" and ("ms-sql" in lower or "microsoft sql server" in lower):
            return _inconclusive("MS-SQL information was captured without attempting authentication", observation="live-25-mssql-info")
        elif testcase_id == "34" or testcase_id == "39":
            weak = r"diffie-hellman-group1-sha1|ssh-dss|3des-cbc|arcfour|hmac-md5"
            if re.search(weak, lower):
                return LiveParse("FOUND", "applicable", None, (f"live-{testcase_id}-weak-ssh-algorithm",), "medium", "VALIDATED")
            if re.search(r"kex_algorithms|server_host_key_algorithms|encryption_algorithms", lower):
                return LiveParse("NOT_FOUND", "applicable", None, (f"live-{testcase_id}-no-tested-weak-algorithm",), "informational", "VALIDATED")
        elif testcase_id == "36" and re.search(r"program|rpcinfo", lower):
            return LiveParse("FOUND", "applicable", None, ("live-36-rpc-mapping",), "medium", "VALIDATED")
        elif testcase_id == "37":
            if re.search(r"warning:\s*server does not require authentication|security types:\s*\n?\s*none\b|authentication:\s*none", lower):
                return LiveParse("FOUND", "applicable", None, ("live-37-vnc-no-auth",), "high", "VALIDATED")
            if re.search(r"vnc authentication|vncauth|security types:", lower):
                return LiveParse("NOT_FOUND", "applicable", None, ("live-37-vnc-auth",), "informational", "VALIDATED")
        return _inconclusive("service configuration response did not establish the supported predicate")
    if testcase_id == "27":
        if not re.search(r"^HTTP/\S+\s+\d+", text, re.I | re.MULTILINE):
            return _inconclusive("HTTP response was not captured completely")
        if re.search(r"^(?:server|x-powered-by):\s*[^\r\n]*\b[A-Za-z][^\r\n]*\d+\.\d+(?:\.\d+)?", text, re.I | re.MULTILINE):
            return LiveParse("FOUND", "applicable", None, ("live-27-specific-version",), "medium", "VALIDATED")
        return LiveParse("NOT_FOUND", "applicable", None, ("live-27-no-specific-version",), "informational", "VALIDATED")
    if testcase_id == "33":
        if re.search(r"x-content-type-options:\s*(?:nosniff|present)\b", text, re.I):
            return LiveParse("NOT_FOUND", "applicable", None, ("live-33-nosniff-present",), "informational", "VALIDATED")
        if re.search(r"x-content-type-options:\s*(missing|absent|not\s+set)\b", text, re.I):
            return LiveParse("FOUND", "applicable", None, ("live-33-nosniff-missing",), "medium", "VALIDATED")
        if re.search(r"\|\s*http-headers:\s*", text, re.I) and re.search(r"request type:\s*(?:get|head)", text, re.I):
            return LiveParse("FOUND", "applicable", None, ("live-33-nosniff-missing",), "medium", "VALIDATED")
        if "potentially risky methods" in lower or re.search(r"http-methods:.*\b(?:put|delete|trace|connect)\b", lower, re.S):
            return LiveParse("FOUND", "applicable", None, ("live-33-risky-http-method",), "medium", "VALIDATED")
        if not re.search(r"^HTTP/\S+\s+\d+", text, re.I | re.MULTILINE):
            return _inconclusive("HTTP response was not captured completely")
        return _inconclusive("HTTP security checks did not produce a supported condition-specific observation")
    if testcase_id == "40":
        has_status = bool(re.search(r"^;;\s*->>HEADER<<-.*status:\s*\w+", text, re.I | re.MULTILINE))
        if re.search(r"status:\s*(refused|servfail)\b", text, re.I | re.MULTILINE):
            return _inconclusive("DNS server returned an error, but recursion/transfer applicability was not established", observation="live-40-dns-error")
        if re.search(r"status:\s*noerror\b", text, re.I | re.MULTILINE):
            if re.search(r"flags:.*\b(?:ra|rd)\b", text, re.I):
                return _inconclusive("DNS response and recursion flags were captured; an authorized recursion or transfer predicate is still required", observation="live-40-dns-response-flags")
            return _inconclusive("DNS response was captured without recursion flags; an authorized condition-specific predicate is still required", observation="live-40-dns-response")
        if has_status:
            return _inconclusive("DNS status was captured without a supported security predicate")
        return _inconclusive("DNS response was incomplete")
    return _inconclusive("No deterministic live parser is registered")
