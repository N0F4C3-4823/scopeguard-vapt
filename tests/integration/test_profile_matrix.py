from app.applicability import evaluate_applicability, snapshot_for
from app.models import AssessmentCreate
from app.registry import TESTCASE_BY_ID


def test_all_four_assessment_profiles_have_explicit_applicability_contracts(manager):
    profiles = [
        "external_unauthenticated",
        "internal_unauthenticated",
        "internal_authenticated",
        "custom_hybrid",
    ]
    for profile in profiles:
        assessment = manager.create(
            AssessmentCreate(
                name=f"Profile {profile}",
                targets=["fixture://mixed"],
                authorized=True,
                assessment_type=profile,
                capabilities=(
                    ["internal_vantage", "layer2_access", "egress_vantage", "asset_inventory", "wireless_adapter"]
                    if profile == "internal_authenticated"
                    else ["internal_vantage"] if profile == "internal_unauthenticated"
                    else []
                ),
                permissions=(
                    ["segmentation_testing", "layer2_testing", "egress_testing", "inventory_access", "wireless_testing", "credential_policy_testing"]
                    if profile == "internal_authenticated"
                    else ["segmentation_testing"] if profile == "internal_unauthenticated"
                    else []
                ),
                credentials_available=profile == "internal_authenticated",
            )
        )
        assert assessment["assessment_type"] == profile
        snapshot = snapshot_for(
            requested=assessment["capabilities_json"],
            permissions=assessment["permissions_json"],
            credentials_available=bool(assessment["credentials_available"]),
            controlled_fixture=True,
        )
        decisions = {
            testcase_id: evaluate_applicability(TESTCASE_BY_ID[testcase_id], profile, snapshot).state
            for testcase_id in ("03", "14", "26", "28", "31", "32")
        }
        assert set(decisions.values()) <= {"APPLICABLE", "NA", "INCONCLUSIVE"}
        if profile == "external_unauthenticated":
            assert decisions["03"] == "NA"
        if profile == "internal_authenticated":
            assert all(value == "APPLICABLE" for value in decisions.values())
