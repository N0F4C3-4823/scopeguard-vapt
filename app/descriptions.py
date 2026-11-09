from __future__ import annotations

import re
from typing import Any

# Client-facing descriptions are deliberately independent of the execution
# implementation.  Keep protocol names (SSH, TLS, DNS, etc.) available, but
# reject tool names and internal workflow language before text reaches a
# report, the GUI, or the clipboard.
CLIENT_FORBIDDEN_TERMS = (
    "nmap",
    "curl",
    "dig",
    "openssl",
    "smbclient",
    "sslscan",
    "nse",
    "ollama",
    "qwen",
    "llm",
    "python",
    "scanner",
    "command",
    "parser",
    "execution id",
    "exit code",
    "testcase",
)


def _sentence(value: str) -> str:
    value = " ".join(value.strip().split())
    if not value:
        return ""
    return value if value.endswith((".", "!", "?")) else f"{value}."


def _target(result: dict[str, Any]) -> str:
    return str(result.get("target_label") or result.get("target") or "the authorized target")


def _na_requirement(condition: str, applicability: str) -> str:
    """Translate internal applicability reasons into client-safe language."""
    text = f"{condition} {applicability}".casefold()
    if "wireless" in text or "proximity" in text:
        return "authorized wireless hardware and physical proximity"
    if "layer-2" in text or "layer 2" in text or "arp" in text or "mac" in text:
        return "authorized Layer-2 network access"
    if "egress" in text:
        return "an approved internal egress vantage point"
    if "inventory" in text or "rogue" in text:
        return "an authorized network asset inventory"
    if "credential" in text or "authenticated" in text or "policy" in text:
        return "approved authenticated policy evidence"
    if "ipv6" in text or "router advertisement" in text:
        return "an authorized IPv6 network position"
    if "internal" in text or "vlan" in text or "segmentation" in text:
        return "an authorized internal network position"
    if "database" in text:
        return "an identified database service"
    if "service" in text or "port" in text:
        return "the required reachable service"
    return "the prerequisites for this security check"


def _client_condition(condition: str) -> str:
    """Make registry condition identifiers readable in client reports."""
    value = " ".join(condition.replace("_", " ").replace("-", " ").split())
    for acronym in ("NTP", "LDAP", "SNMP", "FTP", "SMB", "RDP", "DNS", "SSH", "ICMP", "VNC", "TLS", "IPv6", "HTTP", "HTTPS", "MQTT", "RPC", "DCOM"):
        value = re.sub(rf"\b{re.escape(acronym.casefold())}\b", acronym, value, flags=re.IGNORECASE)
    return value[:1].upper() + value[1:]


def two_line_description(
    *,
    testcase_id: str,
    testcase_name: str,
    condition: str,
    verdict: str | None,
    observation_type: str,
    target: str,
    applicability: str,
    observation_ids: tuple[str, ...] = (),
) -> tuple[str, str]:
    """Return exactly two evidence-bounded sentences for a finalized result."""
    if verdict not in {"FOUND", "NOT_FOUND", "NA"}:
        return "", ""
    client_condition = _client_condition(condition)
    if verdict == "NA":
        line1 = _sentence(f"The {client_condition} check requires {_na_requirement(condition, applicability)}")
        line2 = _sentence("The required access or capability is not available for this assessment, so this condition does not apply")
        return line1, line2
    observation_descriptions = {
        "live-05-no-tested-legacy-service": (
            "The completed legacy-service check found no tested deprecated service",
            "The completed service inventory contained identified services but none matched the deprecated protocols covered by this check",
        ),
        "live-06-auth-required": (
            "The LDAP directory query required authentication before returning the tested directory information",
            "The recorded LDAP response denied unauthenticated disclosure for this query",
        ),
        "live-08-modern-tls-only": (
            "The TLS check accepted the tested modern protocols and did not list the deprecated protocols covered by this check",
            "The completed cipher inventory supports a negative result only for those enumerated protocol versions",
        ),
        "live-12-no-filtered-port": (
            "The completed TCP state check found no filtered state among the ports it tested",
            "Each reported port state was open or closed in the completed scan, so this filtering condition was not observed",
        ),
        "live-15-no-management-marker": (
            "The completed HTTP checks returned a response without the management markers covered by this test",
            "The recorded response supports a negative result for those tested markers and does not assess undiscovered interfaces",
        ),
        "live-16-share-denied": (
            "The SMB share check received an access-denied or authentication-required response",
            "That recorded response supports a negative result for unauthenticated share access in this test",
        ),
        "live-18-anonymous-denied": (
            "The FTP anonymous-login check received an explicit denial response",
            "The recorded FTP response supports a negative result for anonymous login in this test",
        ),
        "live-21-smb-signing-required": (
            "The SMB security check reported signing as enabled and required",
            "That completed protocol response supports a negative result for the tested signing weakness",
        ),
        "live-23-rdp-nla": (
            "The RDP security check reported Network Level Authentication as supported or enabled",
            "That completed RDP response supports a negative result for the tested absence of NLA",
        ),
        "live-24-redis-auth": (
            "The Redis information request received an authentication-required response",
            "The recorded Redis response supports a negative result for unauthenticated information access",
        ),
        "live-27-no-specific-version": (
            "The completed HTTP header check did not disclose a specific software version",
            "The recorded response contained no versioned product header for the disclosure condition tested",
        ),
        "live-33-nosniff-present": (
            "The completed HTTP response included the X-Content-Type-Options nosniff header",
            "That recorded header supports a negative result for the missing-header condition tested",
        ),
        "live-34-no-tested-weak-algorithm": (
            "The SSH algorithm check completed without listing the weak algorithms covered by this check",
            "The captured algorithm list supports a negative result only for those enumerated weak algorithms",
        ),
        "live-37-vnc-auth": (
            "The VNC service reported an authentication security type",
            "That completed VNC response supports a negative result for the unauthenticated-service condition tested",
        ),
    }
    for observation_id in observation_ids:
        if observation_id in observation_descriptions:
            return tuple(_sentence(line) for line in observation_descriptions[observation_id])  # type: ignore[return-value]
    if verdict == "NOT_FOUND":
        line1 = _sentence(f"The completed {client_condition} check did not observe the specific condition tested")
        line2 = _sentence("The observed response supports this negative conclusion only for the completed scope and method")
        return line1, line2

    special = {
        "02": (
            "The completed fingerprinting check captured a validated service observation",
            "This identifies observed service evidence and does not prove an origin IP or compromise",
        ),
        "12": (
            "The completed TCP state check recorded a filtered port",
            "This is an informational filtering observation and is not by itself a vulnerability",
        ),
        "19": (
            "The completed inventory recorded reachable service exposure",
            "Reachability is retained for exposure review and does not by itself prove a vulnerability",
        ),
        "22": (
            "The completed banner check captured a validated service identity",
            "The identity is an informational observation and does not by itself prove exploitability",
        ),
        "35": (
            "The completed discovery check confirmed a response to an allowed reachability signal",
            "Reachability is an informational observation and does not by itself prove compromise",
        ),
        "38": (
            "The completed ICMP check captured the configured response",
            "This records an information-disclosure observation without claiming protection or compromise beyond the response",
        ),
    }
    if testcase_id in special:
        return tuple(_sentence(line) for line in special[testcase_id])  # type: ignore[return-value]
    significance = {
        "vulnerability": "This establishes the tested security condition within the authorized scope",
        "misconfiguration": "This identifies a configuration weakness within the authorized scope",
    }.get(observation_type, "This records the verified condition within the authorized scope")
    return (
        _sentence(f"The completed {client_condition} check positively established the tested condition"),
        _sentence(significance),
    )


def validate_two_line_description(
    line_1: str,
    line_2: str,
    *,
    target_identifiers: tuple[str, ...] = (),
) -> bool:
    """Validate the client-facing two-line contract.

    Descriptions are deliberately checked at the report boundary as well as
    when generated.  This protects older persisted rows and any future
    wording provider from leaking targets, tools, or internal workflow terms.
    """
    if not line_1 or not line_2 or "\n" in line_1 or "\n" in line_2:
        return False
    combined = f"{line_1} {line_2}".casefold()
    if any(re.search(rf"\b{re.escape(term)}\b", combined) for term in CLIENT_FORBIDDEN_TERMS):
        return False
    if any(identifier and identifier.casefold() in combined for identifier in target_identifiers):
        return False
    return all(line.rstrip()[-1:] in {".", "!", "?"} for line in (line_1, line_2))
