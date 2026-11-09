from __future__ import annotations

import csv
import io
import time
import zipfile

from fastapi.testclient import TestClient

from app.registry import TESTCASES


def _wait(client: TestClient, assessment_id: str) -> dict:
    for _ in range(900):
        detail = client.get(f"/api/assessments/{assessment_id}").json()
        if detail["status"] in {"COMPLETED", "FAILED", "CANCELLED"}:
            return detail
        time.sleep(0.05)
    raise AssertionError("multi-target fixture did not reach a terminal state")


def test_multi_target_results_exports_and_evidence_are_isolated(application):
    client = TestClient(application)
    created = client.post(
        "/api/assessments",
        json={
            "name": "Three target isolation fixture",
            "targets": ["fixture://positive", "fixture://negative", "fixture://mixed"],
            "authorized": True,
            "profile": "controlled_fixture",
            "llm_enabled": False,
        },
    ).json()
    assessment_id = created["id"]
    assert client.post(f"/api/assessments/{assessment_id}/start").status_code == 200
    final = _wait(client, assessment_id)
    assert final["status"] == "COMPLETED"

    all_results = client.get(f"/api/assessments/{assessment_id}/results").json()["results"]
    assert len(all_results) == 3 * len(TESTCASES)
    targets = client.get(f"/api/assessments/{assessment_id}").json()["targets"]
    for target in targets:
        target_id = target["id"]
        scoped = client.get(f"/api/assessments/{assessment_id}/targets/{target_id}/results")
        assert scoped.status_code == 200
        payload = scoped.json()
        assert len(payload["results"]) == len(TESTCASES)
        assert {row["target_id"] for row in payload["results"]} == {target_id}
        assert {row["target"] for row in payload["results"]} == {target["value"]}

        csv_response = client.get(f"/api/assessments/{assessment_id}/targets/{target_id}/export/csv")
        assert csv_response.status_code == 200
        rows = list(csv.DictReader(io.StringIO(csv_response.text)))
        assert len(rows) == len(TESTCASES)
        assert {row["target"] for row in rows} == {target["value"]}

        zip_response = client.get(f"/api/assessments/{assessment_id}/targets/{target_id}/export/zip")
        assert zip_response.status_code == 200
        with zipfile.ZipFile(io.BytesIO(zip_response.content)) as archive:
            names = archive.namelist()
            assert names
            blob = b"\n".join(archive.read(name) for name in names if not name.endswith("/"))
            assert target["value"].encode() in blob
            for other in targets:
                if other["id"] != target_id:
                    assert other["value"].encode() not in blob

    first, second = targets[:2]
    first_results = client.get(f"/api/assessments/{assessment_id}/targets/{first['id']}/results").json()["results"]
    evidence = next(path for row in first_results for path in row["evidence_paths_json"])
    assert client.get(
        f"/api/assessments/{assessment_id}/targets/{second['id']}/evidence/{evidence}"
    ).status_code == 404
