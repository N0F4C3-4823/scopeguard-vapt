
from fastapi.testclient import TestClient


def test_api_creates_assessment_with_assessment_type_and_capabilities(application):
    client = TestClient(application)
    response = client.post(
        "/api/assessments",
        json={
            "name": "API capability test",
            "targets": ["fixture://negative"],
            "authorized": True,
            "assessment_type": "internal_authenticated",
            "capabilities": ["internal_vantage"],
            "credentials_available": True,
            "profile": "controlled_fixture",
        },
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["assessment_type"] == "internal_authenticated"
    assert "internal_vantage" in payload["capabilities_json"]


def test_api_requires_authorization(application):
    client = TestClient(application)
    response = client.post("/api/assessments", json={"targets": ["fixture://mixed"]})
    assert response.status_code == 400
    assert "authorization" in response.json()["detail"].lower()


def test_api_derives_live_execution_profile_for_real_authorized_target(application):
    client = TestClient(application)
    response = client.post(
        "/api/assessments",
        json={
            "name": "Authorized live target",
            "targets": ["127.0.0.1"],
            "authorized": True,
            "authorization_note": "Explicit loopback authorization for this test",
        },
    )
    assert response.status_code == 200
    assert response.json()["profile"] == "authorized_external"


def test_api_rejects_mixed_fixture_and_live_scope(application):
    client = TestClient(application)
    response = client.post(
        "/api/assessments",
        json={
            "name": "Mixed scope must be rejected",
            "targets": ["fixture://mixed", "127.0.0.1"],
            "authorized": True,
            "authorization_note": "Explicit test authorization",
        },
    )
    assert response.status_code == 400
    assert "mix" in response.json()["detail"].lower()


def test_api_exposes_complete_machine_readable_live_capability_matrix(application):
    client = TestClient(application)
    response = client.get("/api/capability-matrix")
    assert response.status_code == 200
    payload = response.json()
    assert payload["schema_version"] == "scopeguard-live-capability-v1"
    assert payload["registered_testcases"] == 40
    assert payload["live_execution_adapters"] == 34
    assert payload["capability_only_testcases"] == 6
    assert [entry["testcase"]["id"] for entry in payload["entries"]] == [f"{index:02d}" for index in range(1, 41)]
    for entry in payload["entries"]:
        live = entry["live"]
        assert live["execution_adapter"]
        assert live["evidence_parser"]
        assert live["verification_logic"]
        assert set(live["supported_profiles"]) <= {
            "external_unauthenticated",
            "internal_unauthenticated",
            "internal_authenticated",
            "custom_hybrid",
        }
