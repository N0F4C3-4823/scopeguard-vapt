
import time

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


def test_api_deletes_assessment_and_local_artifacts(application):
    client = TestClient(application)
    response = client.post(
        "/api/assessments",
        json={
            "name": "Assessment to delete",
            "targets": ["fixture://negative"],
            "authorized": True,
            "profile": "controlled_fixture",
        },
    )
    assert response.status_code == 200
    assessment_id = response.json()["id"]
    data_dir = application.state.settings.data_dir
    assessment_root = data_dir / "assessments" / assessment_id
    assessment_root.mkdir(parents=True, exist_ok=True)
    (assessment_root / "marker.txt").write_text("local evidence", encoding="utf-8")
    exports = data_dir / "exports"
    exports.mkdir(parents=True, exist_ok=True)
    (exports / f"{assessment_id}.zip").write_bytes(b"zip placeholder")

    deleted = client.delete(f"/api/assessments/{assessment_id}")
    assert deleted.status_code == 200
    assert deleted.json() == {"status": "deleted", "assessment_id": assessment_id}
    assert client.get(f"/api/assessments/{assessment_id}").status_code == 404
    assert not assessment_root.exists()
    assert not (exports / f"{assessment_id}.zip").exists()


def test_api_does_not_delete_active_assessment(application):
    client = TestClient(application)
    response = client.post(
        "/api/assessments",
        json={
            "name": "Active assessment cannot delete",
            "targets": ["fixture://timeout"],
            "authorized": True,
            "profile": "controlled_fixture",
        },
    )
    assessment_id = response.json()["id"]
    started = client.post(f"/api/assessments/{assessment_id}/start")
    assert started.status_code == 200
    for _ in range(50):
        if client.get(f"/api/assessments/{assessment_id}").json()["status"] == "RUNNING":
            break
        time.sleep(0.01)
    deletion = client.delete(f"/api/assessments/{assessment_id}")
    assert deletion.status_code == 409
    assert "before deleting" in deletion.json()["detail"]
    client.post(f"/api/assessments/{assessment_id}/cancel")


def test_api_edits_metadata_without_changing_authorized_scope(application):
    client = TestClient(application)
    created = client.post(
        "/api/assessments",
        json={
            "name": "Metadata before",
            "client_name": "Old client",
            "targets": ["fixture://negative"],
            "authorized": True,
            "profile": "controlled_fixture",
        },
    ).json()
    updated = client.patch(
        f"/api/assessments/{created['id']}",
        json={"name": "Metadata after", "client_name": "New client", "description": "Updated notes"},
    )
    assert updated.status_code == 200
    body = updated.json()
    assert body["name"] == "Metadata after"
    assert body["client_name"] == "New client"
    assert body["description"] == "Updated notes"
    assert client.post(f"/api/assessments/{created['id']}/start").status_code == 200
    running_update = client.patch(
        f"/api/assessments/{created['id']}",
        json={"description": "Notes updated while running"},
    )
    assert running_update.status_code == 200
    assert running_update.json()["description"] == "Notes updated while running"
    for _ in range(100):
        if client.get(f"/api/assessments/{created['id']}").json()["status"] in {"COMPLETED", "FAILED", "CANCELLED"}:
            break
        time.sleep(0.02)
    assert client.get(f"/api/assessments/{created['id']}").json()["targets"][0]["value"] == "fixture://negative"


def test_api_stop_and_delete_active_assessment(application):
    client = TestClient(application)
    created = client.post(
        "/api/assessments",
        json={
            "name": "Active stop and delete",
            "targets": ["fixture://timeout"],
            "authorized": True,
            "profile": "controlled_fixture",
        },
    ).json()
    assessment_id = created["id"]
    assert client.post(f"/api/assessments/{assessment_id}/start").status_code == 200
    response = client.delete(f"/api/assessments/{assessment_id}?cancel_active=true")
    assert response.status_code == 202
    assert response.json()["status"] == "cancellation_requested"
    for _ in range(100):
        if client.get(f"/api/assessments/{assessment_id}").json()["status"] in {"CANCELLED", "FAILED", "COMPLETED"}:
            break
        time.sleep(0.02)
    assert client.delete(f"/api/assessments/{assessment_id}").status_code == 200
    assert client.get(f"/api/assessments/{assessment_id}").status_code == 404


def test_api_reconciles_persisted_active_assessment_after_restart(application):
    client = TestClient(application)
    response = client.post(
        "/api/assessments",
        json={
            "name": "Interrupted assessment recovery",
            "targets": ["fixture://negative"],
            "authorized": True,
            "profile": "controlled_fixture",
        },
    )
    assessment_id = response.json()["id"]
    application.state.db.update_assessment(assessment_id, status="RUNNING")

    from app.orchestrator import AssessmentManager

    AssessmentManager(application.state.db, application.state.settings)

    recovered = client.get(f"/api/assessments/{assessment_id}")
    assert recovered.status_code == 200
    assert recovered.json()["status"] == "FAILED"
    assert recovered.json()["current_phase"] == "Recovery"


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
