from app.applicability import evaluate_applicability, snapshot_for
from app.registry import TESTCASE_BY_ID


def decision(testcase_id, assessment_type, *, capabilities=(), permissions=(), credentials=False):
    return evaluate_applicability(
        TESTCASE_BY_ID[testcase_id],
        assessment_type,
        snapshot_for(
            requested=list(capabilities),
            permissions=list(permissions),
            credentials_available=credentials,
            controlled_fixture=True,
        ),
    )


def test_external_unauthenticated_marks_internal_only_conditions_na():
    assert decision("03", "external_unauthenticated").state == "NA"
    assert decision("14", "external_unauthenticated").state == "NA"
    assert decision("28", "external_unauthenticated").state == "NA"
    assert decision("31", "external_unauthenticated").state == "NA"
    assert decision("32", "external_unauthenticated").state == "NA"
    assert decision("01", "external_unauthenticated").state == "APPLICABLE"


def test_internal_unauthenticated_requires_each_declared_capability():
    assert decision("03", "internal_unauthenticated", capabilities=("internal_vantage",), permissions=("segmentation_testing",)).state == "APPLICABLE"
    assert decision("14", "internal_unauthenticated", capabilities=("internal_vantage",)).state == "NA"
    assert decision("26", "internal_unauthenticated", capabilities=("internal_vantage",)).state == "NA"


def test_internal_authenticated_can_apply_when_contract_is_complete():
    capabilities = ("internal_vantage", "layer2_access", "egress_vantage", "asset_inventory", "wireless_adapter")
    permissions = ("segmentation_testing", "layer2_testing", "egress_testing", "inventory_access", "wireless_testing", "credential_policy_testing")
    for testcase_id in ("03", "14", "26", "28", "31", "32"):
        assert decision(testcase_id, "internal_authenticated", capabilities=capabilities, permissions=permissions, credentials=True).state == "APPLICABLE"


def test_custom_hybrid_preserves_missing_credentials_as_inconclusive():
    result = decision("26", "custom_hybrid", capabilities=("internal_vantage",), permissions=("credential_policy_testing",))
    assert result.state == "INCONCLUSIVE"
    assert "credentials" in result.missing
