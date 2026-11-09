from __future__ import annotations

import asyncio
import json
import platform
import shutil
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from .applicability import ASSESSMENT_TYPES
from .build_info import APP_VERSION
from .build_info import as_dict as build_info
from .config import Settings, load_settings
from .db import Database, now_iso
from .exporter import ExportError, export_assessment, export_target, target_dir_name
from .live_adapters import capability_matrix
from .models import AssessmentCreate, AssessmentEdit
from .ollama import OllamaClient
from .orchestrator import AssessmentManager
from .registry import TESTCASES
from .scope import ScopeError


def _serialize_assessment(row: dict[str, Any]) -> dict[str, Any]:
    result = dict(row)
    if "capabilities_json" in result:
        result["capabilities"] = result["capabilities_json"]
    if "permissions_json" in result:
        result["permissions"] = result["permissions_json"]
    for field in (
        "authorized",
        "llm_enabled",
        "evidence_screenshots",
        "credentials_available",
    ):
        if field in result:
            result[field] = bool(result[field])
    return result


def create_app(settings: Settings | None = None) -> FastAPI:
    active_settings = settings or load_settings()
    active_settings.ensure_dirs()
    db = Database(active_settings.db_path)
    manager = AssessmentManager(db, active_settings)
    app = FastAPI(title="ScopeGuard VAPT", version=APP_VERSION)
    app.state.settings = active_settings
    app.state.db = db
    app.state.manager = manager
    app.state.ollama = OllamaClient(active_settings.ollama_url, active_settings.ollama_model)

    static_dir = active_settings.root_dir / "static"
    app.mount("/static", StaticFiles(directory=static_dir), name="static")

    @app.get("/", response_class=HTMLResponse)
    async def index() -> FileResponse:
        return FileResponse(static_dir / "index.html")

    @app.get("/favicon.ico")
    async def favicon() -> FileResponse:
        return FileResponse(static_dir / "favicon.svg", media_type="image/svg+xml")

    @app.get("/api/health")
    async def health() -> dict[str, Any]:
        return {"status": "ok", "application": "ScopeGuard VAPT", **build_info()}

    @app.get("/api/diagnostics")
    async def diagnostics() -> dict[str, Any]:
        active = [
            item for item in db.list_assessments()
            if item.get("status") in {"QUEUED", "RUNNING", "PAUSED"}
        ]
        return {
            **build_info(),
            "active_assessments": [item["id"] for item in active],
            "classification_authority": "deterministic backend",
            "final_verdicts": ["FOUND", "NOT_FOUND", "NA"],
        }

    @app.get("/api/testcases")
    async def testcases() -> dict[str, Any]:
        return {"count": len(TESTCASES), "testcases": [test.as_dict() for test in TESTCASES]}

    @app.get("/api/capability-matrix")
    async def live_capability_matrix() -> dict[str, Any]:
        matrix = capability_matrix()
        return {
            "schema_version": "scopeguard-live-capability-v1",
            "registered_testcases": len(matrix),
            "live_execution_adapters": sum(item["live"]["has_live_execution"] for item in matrix),
            "capability_only_testcases": sum(item["live"]["live_status"] == "CAPABILITY_ONLY" for item in matrix),
            "entries": matrix,
        }

    @app.get("/api/assessment-types")
    async def assessment_types() -> dict[str, Any]:
        return {"types": [{"id": key, "label": label} for key, label in ASSESSMENT_TYPES.items()]}

    @app.get("/api/overview")
    async def overview() -> dict[str, Any]:
        assessments = db.list_assessments()
        results = [result for assessment in assessments for result in db.list_results(assessment["id"])]
        finalized = [result for result in results if result.get("final_verdict")]
        return {
            "total_assessments": len(assessments),
            "running_assessments": sum(row["status"] in {"QUEUED", "RUNNING", "PAUSED"} for row in assessments),
            "completed_assessments": sum(row["status"] == "COMPLETED" for row in assessments),
            "error_assessments": sum(row["status"] in {"FAILED", "CANCELLED"} for row in assessments),
            "total_targets": sum(row["target_count"] for row in assessments),
            "confirmed_findings": sum(row.get("final_verdict") == "FOUND" and row.get("reportable_finding") for row in results),
            "confirmed_vulnerabilities": sum(row.get("final_verdict") == "FOUND" and row.get("reportable_finding") for row in results),
            "informational_observations": sum(row.get("final_verdict") == "FOUND" and row.get("observation_type") in {"informational", "exposure_inventory"} for row in results),
            "verified_negatives": sum(row.get("final_verdict") == "NOT_FOUND" for row in results),
            "not_applicable": sum(row.get("final_verdict") == "NA" for row in results),
            "inconclusive": sum(1 for row in results if not row.get("final_verdict")),
            "unresolved": sum(1 for row in results if not row.get("final_verdict")),
            "finalized": len(finalized),
            "applicable": sum(row["applicability"] == "applicable" for row in results),
            "severity": {
                "high": sum(row["severity"] == "high" for row in results),
                "medium": sum(row["severity"] == "medium" for row in results),
                "informational": sum(row["severity"] == "informational" for row in results),
                "unknown": sum(row["severity"] == "unknown" for row in results),
            },
            "recent": [_serialize_assessment(row) for row in assessments[:6]],
        }

    @app.get("/api/dependencies")
    async def dependencies() -> dict[str, Any]:
        disk = shutil.disk_usage(active_settings.data_dir)
        mem_available = None
        try:
            for line in Path("/proc/meminfo").read_text().splitlines():
                if line.startswith("MemAvailable:"):
                    mem_available = int(line.split()[1]) * 1024
                    break
        except OSError:
            pass
        ollama = app.state.ollama.status()
        ollama_binary_available = bool(
            active_settings.ollama_binary
            and (
                active_settings.ollama_binary.is_file()
                if active_settings.ollama_binary.is_absolute()
                else shutil.which(str(active_settings.ollama_binary)) is not None
            )
        )
        tools = {
            name: {"available": shutil.which(name) is not None}
            for name in ("python3", "nmap", "openssl", "curl", "dig")
        }
        tools["ollama"] = {"available": ollama_binary_available}
        return {
            "platform": platform.platform(),
            "wsl": "microsoft" in platform.release().lower() or "microsoft" in platform.version().lower(),
            "python": platform.python_version(),
            "available_memory_bytes": mem_available,
            "available_disk_bytes": disk.free,
            "tools": tools,
            "ollama_binary": str(active_settings.ollama_binary),
            "ollama": ollama.__dict__,
        }

    @app.get("/api/ollama/status")
    async def ollama_status() -> dict[str, Any]:
        return app.state.ollama.status().__dict__

    @app.post("/api/ollama/health-test")
    async def ollama_health_test() -> dict[str, Any]:
        try:
            triage_result = app.state.ollama.triage(
                testcase_id="AI_HEALTH",
                observation_ids=["health-check"],
                evidence="Controlled ScopeGuard AI health check. No security conclusion is requested.",
            )
        except Exception as error:
            raise HTTPException(status_code=503, detail=f"LLM health test failed: {error}") from error
        return {"status": "ok", "model": app.state.ollama.model, "triage": triage_result.model_dump()}

    @app.post("/api/assessments")
    async def create_assessment(payload: AssessmentCreate) -> dict[str, Any]:
        try:
            row = manager.create(payload)
        except (ValueError, ScopeError) as error:
            raise HTTPException(status_code=400, detail=str(error)) from error
        return _serialize_assessment(row)

    @app.get("/api/assessments")
    async def list_assessments() -> dict[str, Any]:
        return {"assessments": [_serialize_assessment(row) for row in db.list_assessments()]}

    @app.get("/api/assessments/{assessment_id}")
    async def get_assessment(assessment_id: str) -> dict[str, Any]:
        row = manager.detail(assessment_id)
        if not row:
            raise HTTPException(status_code=404, detail="Assessment not found")
        return _serialize_assessment(row)

    @app.delete("/api/assessments/{assessment_id}", response_model=None)
    async def delete_assessment(assessment_id: str, cancel_active: bool = Query(default=False)) -> dict[str, Any] | JSONResponse:
        try:
            if cancel_active:
                outcome = manager.request_delete(assessment_id)
                if outcome == "cancellation_requested":
                    return JSONResponse(status_code=202, content={"status": outcome, "assessment_id": assessment_id})
            else:
                manager.delete(assessment_id)
        except ValueError as error:
            detail = str(error)
            status_code = 409 if "before deleting" in detail else 404
            raise HTTPException(status_code=status_code, detail=detail) from error
        return {"status": "deleted", "assessment_id": assessment_id}

    @app.patch("/api/assessments/{assessment_id}")
    async def edit_assessment(assessment_id: str, payload: AssessmentEdit) -> dict[str, Any]:
        try:
            row = manager.edit_metadata(
                assessment_id,
                name=payload.name,
                client_name=payload.client_name,
                description=payload.description,
            )
        except ValueError as error:
            status_code = 404 if str(error) == "Assessment not found" else 400
            raise HTTPException(status_code=status_code, detail=str(error)) from error
        return _serialize_assessment(row)

    @app.post("/api/assessments/{assessment_id}/start")
    async def start_assessment(assessment_id: str) -> dict[str, Any]:
        try:
            manager.start(assessment_id)
        except ValueError as error:
            raise HTTPException(status_code=400, detail=str(error)) from error
        return _serialize_assessment(db.get_assessment(assessment_id) or {})

    @app.post("/api/assessments/{assessment_id}/re-adjudicate")
    async def re_adjudicate(assessment_id: str) -> dict[str, Any]:
        try:
            return manager.re_adjudicate(assessment_id)
        except ExportError as error:
            raise HTTPException(status_code=409, detail=str(error)) from error
        except ValueError as error:
            status_code = 404 if str(error) == "Assessment not found" else 409
            raise HTTPException(status_code=status_code, detail=str(error)) from error

    @app.post("/api/assessments/{assessment_id}/pause")
    async def pause_assessment(assessment_id: str) -> dict[str, Any]:
        try:
            manager.pause(assessment_id)
        except ValueError as error:
            raise HTTPException(status_code=400, detail=str(error)) from error
        return {"status": "pause_requested"}

    @app.post("/api/assessments/{assessment_id}/resume")
    async def resume_assessment(assessment_id: str) -> dict[str, Any]:
        try:
            manager.resume(assessment_id)
        except ValueError as error:
            raise HTTPException(status_code=400, detail=str(error)) from error
        return {"status": "resume_requested"}

    @app.post("/api/assessments/{assessment_id}/cancel")
    async def cancel_assessment(assessment_id: str) -> dict[str, Any]:
        try:
            manager.cancel(assessment_id)
        except ValueError as error:
            raise HTTPException(status_code=400, detail=str(error)) from error
        return {"status": "cancel_requested"}

    @app.get("/api/assessments/{assessment_id}/results")
    async def results(assessment_id: str) -> dict[str, Any]:
        if not db.get_assessment(assessment_id):
            raise HTTPException(status_code=404, detail="Assessment not found")
        return {"results": db.list_results(assessment_id)}

    @app.get("/api/assessments/{assessment_id}/targets/{target_id}/results")
    async def target_results(assessment_id: str, target_id: str) -> dict[str, Any]:
        if not db.get_assessment(assessment_id) or not db.get_target(assessment_id, target_id):
            raise HTTPException(status_code=404, detail="Assessment target not found")
        return {
            "target": db.get_target(assessment_id, target_id),
            "results": db.list_results(assessment_id, target_id),
            "ai_recovery": db.list_ai_recovery(assessment_id, target_id),
        }

    @app.get("/api/assessments/{assessment_id}/targets/{target_id}/export/csv")
    async def target_export_csv(assessment_id: str, target_id: str) -> FileResponse:
        try:
            exports = export_target(db, assessment_id, target_id, active_settings.data_dir)
        except ExportError as error:
            raise HTTPException(status_code=409, detail=str(error)) from error
        return FileResponse(exports["csv"], filename=f"{assessment_id}-{target_id}-testcase-results.csv", media_type="text/csv")

    @app.get("/api/assessments/{assessment_id}/targets/{target_id}/export/zip")
    async def target_export_zip(assessment_id: str, target_id: str) -> FileResponse:
        try:
            exports = export_target(db, assessment_id, target_id, active_settings.data_dir)
        except ExportError as error:
            raise HTTPException(status_code=409, detail=str(error)) from error
        return FileResponse(exports["zip"], filename=f"{assessment_id}-{target_id}.zip", media_type="application/zip")

    @app.get("/api/assessments/{assessment_id}/events")
    async def events(assessment_id: str) -> StreamingResponse:
        if not db.get_assessment(assessment_id):
            raise HTTPException(status_code=404, detail="Assessment not found")

        async def stream():
            last_id = 0
            while True:
                entries = db.list_events(assessment_id, last_id)
                for entry in entries:
                    last_id = entry["id"]
                    yield f"id: {last_id}\ndata: {json.dumps(entry, ensure_ascii=False)}\n\n"
                current = db.get_assessment(assessment_id)
                if current and current["status"] in {"COMPLETED", "FAILED", "CANCELLED"} and not entries:
                    break
                await asyncio.sleep(0.15)

        return StreamingResponse(stream(), media_type="text/event-stream")

    @app.get("/api/assessments/{assessment_id}/export/csv")
    async def export_csv(assessment_id: str) -> FileResponse:
        try:
            exports = export_assessment(db, assessment_id, active_settings.data_dir)
        except ExportError as error:
            raise HTTPException(status_code=409, detail=str(error)) from error
        return FileResponse(exports["csv"], filename=f"{assessment_id}-testcase-results.csv", media_type="text/csv")

    @app.get("/api/assessments/{assessment_id}/export/zip")
    async def export_zip(assessment_id: str) -> FileResponse:
        try:
            exports = export_assessment(db, assessment_id, active_settings.data_dir)
        except ExportError as error:
            raise HTTPException(status_code=409, detail=str(error)) from error
        return FileResponse(exports["zip"], filename=f"{assessment_id}.zip", media_type="application/zip")

    @app.get("/api/assessments/{assessment_id}/exports")
    async def export_info(assessment_id: str) -> dict[str, Any]:
        try:
            exports = export_assessment(db, assessment_id, active_settings.data_dir)
        except ExportError as error:
            raise HTTPException(status_code=409, detail=str(error)) from error
        files = []
        for key, path in (("csv", exports["csv"]), ("zip", exports["zip"]), ("manifest", exports["manifest"])):
            files.append({"key": key, "name": path.name, "bytes": path.stat().st_size, "available": True})
        return {"assessment_id": assessment_id, "files": files}

    @app.get("/api/assessments/{assessment_id}/evidence/{evidence_path:path}")
    async def evidence(assessment_id: str, evidence_path: str) -> FileResponse:
        root = (active_settings.data_dir / "assessments" / assessment_id).resolve()
        requested = (root / evidence_path).resolve()
        relative = Path(evidence_path)
        valid_target_roots = {target_dir_name(target) for target in db.get_targets(assessment_id)}
        if not relative.parts or relative.parts[0] not in valid_target_roots:
            raise HTTPException(status_code=404, detail="Evidence artifact not found")
        if not requested.is_relative_to(root) or requested.is_symlink() or not requested.is_file():
            raise HTTPException(status_code=404, detail="Evidence artifact not found")
        return FileResponse(requested)

    @app.get("/api/assessments/{assessment_id}/targets/{target_id}/evidence/{evidence_path:path}")
    async def target_evidence(assessment_id: str, target_id: str, evidence_path: str) -> FileResponse:
        if not db.get_target(assessment_id, target_id):
            raise HTTPException(status_code=404, detail="Assessment target not found")
        root = (active_settings.data_dir / "assessments" / assessment_id).resolve()
        target_root = root / target_dir_name(db.get_target(assessment_id, target_id) or {})
        requested = (target_root / evidence_path).resolve()
        relative = Path(evidence_path)
        if relative.is_absolute() or ".." in relative.parts or not requested.is_relative_to(target_root.resolve()) or requested.is_symlink() or not requested.is_file():
            raise HTTPException(status_code=404, detail="Evidence artifact not found")
        return FileResponse(requested)

    @app.get("/api/assessments/{assessment_id}/ai-recovery")
    async def ai_recovery(assessment_id: str) -> dict[str, Any]:
        if not db.get_assessment(assessment_id):
            raise HTTPException(status_code=404, detail="Assessment not found")
        return {"entries": db.list_ai_recovery(assessment_id)}

    @app.post("/api/assessments/{assessment_id}/llm/triage/{result_id}")
    async def triage(assessment_id: str, result_id: int) -> dict[str, Any]:
        result = next((item for item in db.list_results(assessment_id) if item["id"] == result_id), None)
        if not result:
            raise HTTPException(status_code=404, detail="Result not found")
        evidence = result["output_preview"] or ""
        try:
            observation_ids = [result["evidence_id"]] if result.get("evidence_id") else []
            triage_result = app.state.ollama.triage(
                testcase_id=result["testcase_id"], observation_ids=observation_ids, evidence=evidence
            )
        except Exception as error:
            raise HTTPException(status_code=503, detail=f"LLM triage unavailable: {error}") from error
        db.add_llm_triage({
            "assessment_id": assessment_id,
            "result_id": result_id,
            "model": app.state.ollama.model,
            "prompt_version": "scopeguard-triage-v1",
            "response_json": json.dumps(triage_result.model_dump(), ensure_ascii=False),
            "validation_state": "VALIDATED",
            "created_at": now_iso(),
        })
        return triage_result.model_dump()

    return app


app = create_app()
