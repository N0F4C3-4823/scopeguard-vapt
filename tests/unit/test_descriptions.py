from app.descriptions import two_line_description, validate_two_line_description


def test_finalized_descriptions_have_exactly_two_plain_english_lines():
    for verdict in ("FOUND", "NOT_FOUND", "NA"):
        first, second = two_line_description(
            testcase_id="08",
            testcase_name="SSL/TLS protocol configuration",
            condition="weak TLS protocol",
            verdict=verdict,
            observation_type="misconfiguration",
            target="controlled-service",
            applicability="an applicable TLS service",
        )
        assert validate_two_line_description(first, second)
        assert "\n" not in first and "\n" not in second


def test_unresolved_descriptions_are_empty_and_not_presented_as_verdicts():
    assert two_line_description(
        testcase_id="08",
        testcase_name="TLS",
        condition="TLS condition",
        verdict=None,
        observation_type="misconfiguration",
        target="controlled-service",
        applicability="an applicable TLS service",
    ) == ("", "")


def test_negative_description_is_specific_when_parser_proves_the_condition():
    first, second = two_line_description(
        testcase_id="33",
        testcase_name="HTTP/HTTPS services",
        condition="missing HTTP security header",
        verdict="NOT_FOUND",
        observation_type="misconfiguration",
        target="local fixture",
        applicability="an HTTP response",
        observation_ids=("live-33-nosniff-present",),
    )
    assert "X-Content-Type-Options nosniff" in first
    assert "missing-header" in second
    assert validate_two_line_description(first, second)


def test_client_descriptions_never_leak_target_or_execution_implementation():
    first, second = two_line_description(
        testcase_id="18",
        testcase_name="FTP",
        condition="anonymous FTP access",
        verdict="NOT_FOUND",
        observation_type="vulnerability",
        target="198.51.100.25",
        applicability="an applicable FTP service",
        observation_ids=("live-18-anonymous-denied",),
    )
    text = f"{first}\n{second}"
    assert "198.51.100.25" not in text
    assert "curl" not in text.casefold()
    assert "scanner" not in text.casefold()
    assert validate_two_line_description(first, second, target_identifiers=("198.51.100.25", "web10"))


def test_na_description_uses_safe_requirement_without_target_identifier():
    first, second = two_line_description(
        testcase_id="03",
        testcase_name="VLAN segmentation",
        condition="VLAN segmentation",
        verdict="NA",
        observation_type="coverage",
        target="internal.example.test",
        applicability="an authorized internal vantage point; target=internal.example.test",
    )
    assert "internal.example.test" not in f"{first}\n{second}"
    assert "authorized internal network position" in first
    assert validate_two_line_description(first, second, target_identifiers=("internal.example.test",))
