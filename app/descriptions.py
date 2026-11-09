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
    observation_ids: tuple[str, ...] = (),
) -> tuple[str, str]:
    """Return exactly two evidence-bounded sentences for a finalized result."""
    if verdict not in {"FOUND", "NOT_FOUND", "NA"}:
        return "", ""
    subject = target or "the authorized target"
    if verdict == "NA":
        line1 = _sentence(f"The {condition} check requires {applicability}")
        line2 = _sentence(f"That access or capability was not part of the authorized assessment for {subject}, so this condition does not apply")
        return line1, line2
    observation_descriptions = {
        "live-05-no-tested-legacy-service": (
            f"The completed legacy-service check found no tested deprecated service on {subject}",
            "The completed service inventory contained identified services but none matched the deprecated protocols covered by this check",
        ),
        "live-06-auth-required": (
            f"The LDAP directory query on {subject} required authentication before returning the tested directory information",
            "The recorded LDAP response denied unauthenticated disclosure for this query",
        ),
        "live-08-modern-tls-only": (
            f"The TLS enumeration on {subject} accepted the tested modern TLS protocols and did not list the deprecated protocols covered by this check",
            "The completed cipher inventory supports a negative result only for those enumerated protocol versions",
        ),
        "live-12-no-filtered-port": (
            f"The completed TCP state scan on {subject} found no filtered state among the ports it tested",
            "Each reported port state was open or closed in the completed scan, so this filtering condition was not observed",
        ),
        "live-15-no-management-marker": (
            f"The completed HTTP checks on {subject} returned a response without the management markers covered by this test",
            "The recorded response supports a negative result for those tested markers and does not assess undiscovered interfaces",
        ),
        "live-16-share-denied": (
            f"The SMB share check on {subject} received an access-denied or authentication-required response",
            "That recorded response supports a negative result for unauthenticated share access in this test",
        ),
        "live-18-anonymous-denied": (
            f"The FTP anonymous-login check on {subject} received an explicit denial response",
            "The recorded FTP response supports a negative result for anonymous login in this test",
        ),
        "live-21-smb-signing-required": (
            f"The SMB security check on {subject} reported signing as enabled and required",
            "That completed protocol response supports a negative result for the tested signing weakness",
        ),
        "live-23-rdp-nla": (
            f"The RDP security check on {subject} reported Network Level Authentication as supported or enabled",
            "That completed RDP response supports a negative result for the tested absence of NLA",
        ),
        "live-24-redis-auth": (
            f"The Redis probe on {subject} received an authentication-required response to the safe information request",
            "The recorded Redis response supports a negative result for unauthenticated information access",
        ),
        "live-27-no-specific-version": (
            f"The completed HTTP header check on {subject} did not disclose a specific software version",
            "The recorded response contained no versioned product header for the disclosure condition tested",
        ),
        "live-33-nosniff-present": (
            f"The completed HTTP response from {subject} included the X-Content-Type-Options nosniff header",
            "That recorded header supports a negative result for the missing-header condition tested",
        ),
        "live-34-no-tested-weak-algorithm": (
            f"The SSH algorithm enumeration on {subject} completed without listing the weak algorithms covered by this check",
            "The captured algorithm list supports a negative result only for those enumerated weak algorithms",
        ),
        "live-37-vnc-auth": (
            f"The VNC service on {subject} reported an authentication security type",
            "That completed VNC response supports a negative result for the unauthenticated-service condition tested",
        ),
    }
    for observation_id in observation_ids:
        if observation_id in observation_descriptions:
            return tuple(_sentence(line) for line in observation_descriptions[observation_id])  # type: ignore[return-value]
    if verdict == "NOT_FOUND":
        line1 = _sentence(f"The completed {condition} check did not observe the specific condition tested on {subject}")
        line2 = _sentence("The recorded command output supports this negative conclusion only for the completed scope and method")
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
