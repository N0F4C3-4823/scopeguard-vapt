from __future__ import annotations

from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class TestcaseDefinition:
    id: str
    name: str
    condition: str
    required_tools: tuple[str, ...]
    applicable_services: tuple[str, ...]
    positive_observation: str
    negative_observation: str
    na_reason: str
    required_vantage: tuple[str, ...] = ("external",)
    required_capabilities: tuple[str, ...] = ()
    required_permissions: tuple[str, ...] = ()
    requires_credentials: bool = False

    def as_dict(self) -> dict[str, object]:
        return asdict(self) | {
            "required_tools": list(self.required_tools),
            "applicable_services": list(self.applicable_services),
            "supported_fixture_states": ["FOUND", "NOT_FOUND", "NA", "INCONCLUSIVE"],
        }


_RAW = [
    ("01", "NTP (123) — Open reflection/amplification risk", "NTP_Open_Reflection_Amplification", "ntp-safe-query", "123/udp", "safe query behaviour supports the configured reflection predicate", "safe query does not support the configured reflection predicate", "NTP reflection verification requires an authorized UDP fixture"),
    ("02", "Passive/active OS, device and origin-IP fingerprinting", "Fingerprinting_Observation", "fingerprint-observer", "tcp/udp", "validated fingerprint observations were captured", "no validated fingerprint observation was exposed", "fingerprinting is not applicable without a reachable authorized service"),
    ("03", "Sensitive subnet/VLAN segmentation and isolation", "Segmentation_Isolation", "scope-audit", "network", "authorized fixture demonstrates a segmentation boundary violation", "authorized fixture confirms the requested boundary", "external-only access cannot prove internal VLAN isolation"),
    ("04", "Databases — Anonymous access and known vulnerabilities", "Database_Anonymous_Access", "database-safe-probe", "mysql/postgresql/mongodb", "a database returned protected information without authentication", "the database rejected unauthenticated access", "no supported database service is applicable"),
    ("05", "Legacy, deprecated and unsupported services/protocols", "Legacy_Protocol", "service-inventory", "service", "a deprecated service/protocol was reliably identified", "no deprecated service/protocol was identified", "no service inventory is available"),
    ("06", "LDAP — 389", "LDAP_Unauthenticated_Disclosure", "ldap-safe-query", "389/tcp", "LDAP returned permitted unauthenticated directory data", "LDAP refused unauthenticated directory data", "LDAP is not present or requires internal access"),
    ("07", "NetBIOS — 137/138", "NetBIOS_Information_Disclosure", "netbios-safe-query", "137/udp,138/udp", "NetBIOS exposed the configured observation", "NetBIOS did not expose the configured observation", "NetBIOS is not applicable without an authorized UDP fixture"),
    ("08", "SSL/TLS protocol and cryptographic vulnerabilities", "TLS_Weak_Protocol", "tls-config-check", "443/tcp", "a deprecated TLS configuration was negotiated", "the tested TLS configuration rejected the deprecated protocol", "TLS is not present on the target"),
    ("09", "TFTP — 69", "TFTP_Read_Exposure", "tftp-safe-read", "69/udp", "authorized TFTP read returned the configured file", "authorized TFTP read was refused", "TFTP is not applicable without an authorized UDP fixture"),
    ("10", "Telnet — 23", "Telnet_Plaintext_Exposure", "telnet-banner", "23/tcp", "Telnet plaintext service behavior was confirmed", "Telnet was not exposed or plaintext behavior was not confirmed", "Telnet is not present"),
    ("11", "Vulnerable software versions", "Version_CVE_Applicability", "version-corroborator", "service", "a validated product/version matched an applicable advisory", "no applicable advisory was established", "no reliable product/version evidence exists"),
    ("12", "Filtered ports", "Filtered_Port_Observation", "tcp-state-check", "tcp", "a tested port was conclusively filtered", "a tested port was conclusively not filtered", "no complete port-state observation exists"),
    ("13", "Default SNMP community string public", "SNMP_Public_Community", "snmp-safe-get", "161/udp", "public returned a valid authorized SNMP response", "public did not return a valid SNMP response", "SNMP is not present or UDP access is unavailable"),
    ("14", "ARP/MAC spoofing protections and monitoring", "ARP_Spoofing_Controls", "layer2-capability-check", "layer2", "authorized layer-2 fixture demonstrated missing controls", "authorized layer-2 fixture demonstrated the controls", "external WSL mode cannot assess layer-2 controls"),
    ("15", "Exposed management and console interfaces", "Management_Interface", "management-surface-check", "http/https/ssh", "a management interface was accessible without the required control", "the tested management interface required the configured control", "no management service is applicable"),
    ("16", "Exposed sensitive network shares", "Share_Unauthenticated_Read", "share-safe-enumeration", "smb/nfs", "an authorized unauthenticated share exposed the fixture file", "unauthenticated share read was refused", "no share service is present"),
    ("17", "SNMP — 161/162", "SNMP_Version_Posture", "snmp-version-check", "161/162/udp", "SNMP version posture exposed the configured weakness", "SNMP version posture did not expose the configured weakness", "SNMP is not applicable"),
    ("18", "FTP — 21", "FTP_Anonymous_Exposure", "ftp-safe-login", "21/tcp", "FTP anonymous access returned authorized fixture data", "FTP anonymous access was refused", "FTP is not present"),
    ("19", "Open ports and reachable services", "Open_Port_Inventory", "tcp-service-inventory", "tcp", "a configured service port was reachable", "the configured service port was not reachable", "no complete port inventory exists"),
    ("20", "WebSocket and MQTT endpoints", "Messaging_Endpoint_Auth", "messaging-safe-check", "websocket/mqtt", "an endpoint exposed the configured unauthenticated behavior", "the endpoint required the configured authentication", "no messaging endpoint is present"),
    ("21", "SMB — 139/445", "SMB_Signing_Dialect", "smb-config-check", "139/445/tcp", "SMB posture exposed the configured weakness", "SMB posture did not expose the configured weakness", "SMB is not present"),
    ("22", "Banner grabbing and service identification", "Service_Banner", "banner-collector", "service", "a service banner was captured and validated", "no validated service banner was captured", "no service responded with a banner"),
    ("23", "RDP — 3389", "RDP_NLA_Posture", "rdp-safe-negotiate", "3389/tcp", "RDP posture exposed the configured weakness", "RDP posture did not expose the configured weakness", "RDP is not present"),
    ("24", "Redis — 6379", "Redis_Unauthenticated_Access", "redis-safe-ping", "6379/tcp", "Redis accepted the safe unauthenticated probe", "Redis refused the safe unauthenticated probe", "Redis is not present"),
    ("25", "MS-SQL — 1433", "MSSQL_PreAuth_Posture", "mssql-safe-probe", "1433/tcp", "MS-SQL exposed the configured pre-auth behavior", "MS-SQL did not expose the configured pre-auth behavior", "MS-SQL is not present"),
    ("26", "Authentication brute-force resistance", "Auth_Policy_Observation", "auth-policy-reader", "auth", "an externally observable policy weakness was confirmed", "the externally observable policy did not show the tested weakness", "non-intrusive external mode cannot test brute-force resistance"),
    ("27", "Server software version disclosure", "Specific_Version_Disclosure", "http-header-check", "http/https", "a specific software version was disclosed", "a specific version was not disclosed", "no HTTP response was captured"),
    ("28", "Outbound connection and egress controls", "Egress_Control", "egress-capability-check", "network", "an authorized internal fixture confirmed an egress control failure", "an authorized internal fixture confirmed the egress control", "external-only access cannot prove internal egress controls"),
    ("29", "IPv6 exposure and router advertisements", "IPv6_Exposure", "ipv6-safe-probe", "ipv6/icmpv6", "authorized IPv6 exposure was confirmed", "the authorized IPv6 exposure was not observed", "IPv6 or router advertisement access is unavailable"),
    ("30", "VPN endpoints and configuration", "VPN_Configuration", "vpn-safe-negotiate", "ike/ssl-vpn", "VPN negotiation exposed the configured weakness", "VPN negotiation did not expose the configured weakness", "no VPN endpoint is present"),
    ("31", "Rogue or unauthorized network devices", "Inventory_Rogue_Device", "inventory-compare", "inventory", "an authorized inventory comparison identified an unapproved device", "the authorized inventory comparison found no unapproved device", "requires an authorized internal inventory"),
    ("32", "Wireless security", "Wireless_Posture", "wireless-capability-check", "wifi", "authorized wireless fixture demonstrated the configured weakness", "authorized wireless fixture demonstrated the configured control", "wireless hardware/proximity is unavailable"),
    ("33", "HTTP/HTTPS services — 80/443/8080 and discovered ports", "Web_Configuration", "http-safe-check", "http/https", "a safe HTTP check confirmed the configured weakness", "the safe HTTP check did not confirm the configured weakness", "no HTTP service is present"),
    ("34", "SSH — 22", "SSH_Configuration", "ssh-safe-negotiate", "22/tcp", "SSH configuration exposed the configured weakness", "SSH configuration did not expose the configured weakness", "SSH is not present"),
    ("35", "Host-down and reachability validation", "Reachability_State", "multi-signal-reachability", "icmp/tcp", "the host was confirmed reachable", "the host was confirmed unreachable", "reachability signals were insufficient"),
    ("36", "RPC/DCOM — 135/593", "RPC_Endpoint_Disclosure", "rpc-safe-map", "135/593/tcp", "RPC mapping disclosed the configured endpoint", "RPC mapping did not disclose the configured endpoint", "RPC is not present"),
    ("37", "VNC — 5900+", "VNC_Authentication", "vnc-safe-negotiate", "5900/tcp", "VNC exposed the configured authentication weakness", "VNC required the configured authentication", "VNC is not present"),
    ("38", "ICMP information disclosure", "ICMP_Disclosure", "icmp-safe-query", "icmp/icmpv6", "ICMP returned the configured information", "ICMP did not return the configured information", "ICMP access is unavailable"),
    ("39", "SSH-based vulnerabilities/configuration", "SSH_Vulnerability", "ssh-vulnerability-check", "22/tcp", "a specific SSH weakness was verified", "the specific SSH weakness was not verified", "SSH is not present or evidence is incomplete"),
    ("40", "DNS — 53", "DNS_Recursion_Transfer", "dns-safe-query", "53/tcp,53/udp", "authorized DNS behavior exposed the configured weakness", "authorized DNS behavior did not expose the configured weakness", "DNS is not present or no authorized zone was supplied"),
]


# One condition is represented per testcase in this registry. The requirement map makes each
# condition's vantage point and capability contract explicit without hiding it in UI code.
_REQUIREMENTS: dict[str, dict[str, object]] = {
    "03": {"required_vantage": ("internal",), "required_capabilities": ("internal_vantage",), "required_permissions": ("segmentation_testing",)},
    "14": {"required_vantage": ("internal",), "required_capabilities": ("layer2_access",), "required_permissions": ("layer2_testing",)},
    "26": {"requires_credentials": True, "required_permissions": ("credential_policy_testing",)},
    "28": {"required_vantage": ("internal",), "required_capabilities": ("egress_vantage",), "required_permissions": ("egress_testing",)},
    "31": {"required_vantage": ("internal",), "required_capabilities": ("asset_inventory",), "required_permissions": ("inventory_access",)},
    "32": {"required_vantage": ("wireless",), "required_capabilities": ("wireless_adapter",), "required_permissions": ("wireless_testing",)},
}


def _make_definition(row: tuple[str, str, str, str, str, str, str, str]) -> TestcaseDefinition:
    testcase_id, name, condition, tool, service, positive, negative, na_reason = row
    requirements = _REQUIREMENTS.get(testcase_id, {})
    return TestcaseDefinition(
        id=testcase_id,
        name=name,
        condition=condition,
        required_tools=(tool,),
        applicable_services=(service,),
        positive_observation=positive,
        negative_observation=negative,
        na_reason=na_reason,
        required_vantage=requirements.get("required_vantage", ("external",)),
        required_capabilities=requirements.get("required_capabilities", ()),
        required_permissions=requirements.get("required_permissions", ()),
        requires_credentials=bool(requirements.get("requires_credentials", False)),
    )


TESTCASES: tuple[TestcaseDefinition, ...] = tuple(_make_definition(row) for row in _RAW)
TESTCASE_BY_ID = {test.id: test for test in TESTCASES}


def validate_registry() -> None:
    expected = {f"{number:02d}" for number in range(1, 41)}
    actual = {test.id for test in TESTCASES}
    if len(TESTCASES) != 40 or actual != expected or len(actual) != len(TESTCASES):
        raise RuntimeError("ScopeGuard registry must contain exactly 40 unique IDs 01-40")
    for test in TESTCASES:
        if not test.condition or not test.required_tools or not test.applicable_services:
            raise RuntimeError(f"Incomplete testcase definition: {test.id}")


validate_registry()
