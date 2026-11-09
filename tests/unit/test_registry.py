from app.registry import TESTCASE_BY_ID, TESTCASES, validate_registry


def test_registry_has_exactly_40_unique_required_ids():
    validate_registry()
    assert len(TESTCASES) == 40
    assert set(TESTCASE_BY_ID) == {f"{number:02d}" for number in range(1, 41)}
    assert all(test.condition and test.required_tools for test in TESTCASES)


def test_each_condition_declares_applicability_contract():
    assert TESTCASE_BY_ID["03"].required_vantage == ("internal",)
    assert "layer2_access" in TESTCASE_BY_ID["14"].required_capabilities
    assert TESTCASE_BY_ID["26"].requires_credentials is True
    assert "wireless_adapter" in TESTCASE_BY_ID["32"].required_capabilities
