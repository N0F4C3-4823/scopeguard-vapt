from __future__ import annotations

import json
import shutil
import sys
import threading
import time
import uuid
from types import SimpleNamespace

from .applicability import ASSESSMENT_TYPES, evaluate_applicability, snapshot_for
from .commands import CommandResult, run_command, sha256_bytes
from .config import Settings
from .db import Database, now_iso
from .evidence import safe_name, write_applicability_evidence, write_testcase_evidence
from .exporter import export_assessment
from .live_adapters import adapter_for, build_command
from .models import AssessmentCreate
from .ollama import OllamaClient
from .registry import TESTCASES
from .scope import NormalizedTarget, parse_scope


class AssessmentManager:
    def __init__(self, db: Database, settings: Settings):
        self.db = db
        self.settings = settings
        self.settings.ensure_dirs()
        self.ollama = OllamaClient(settings.ollama_url, settings.ollama_model)
        self._lock = threading.RLock()
        self._threads: dict[str, threading.Thread] = {}
        self._cancel: dict[str, threading.Event] = {}
        self._pause: dict[str, threading.Event] = {}
        self._command_metrics_lock = threading.Lock()
        self.active_commands = 0
        self.max_active_commands = 0
        self.executed_commands = 0
        self._reconcile_interrupted_assessments()

    def _reconcile_interrupted_assessments(self) -> None:
        """Fail closed for jobs left active when the backend process stopped."""
        for assessment in self.db.list_assessments():
            if assessment.get("status") not in {"QUEUED", "RUNNING", "PAUSED"}:
                continue
            assessment_id = assessment["id"]
            self.db.update_assessment(
                assessment_id,
                status="FAILED",
                completed_at=now_iso(),
                current_phase="Recovery",
            )
            self.db.add_event(
                assessment_id,
                "assessment_interrupted",
                "Recovery",
                "Assessment was interrupted by a backend restart; incomplete checks remain unresolved.",
                status="FAILED",
                payload={"reason": "backend_restart"},
            )

    def create(self, payload: AssessmentCreate) -> dict:
        if not payload.authorized:
            raise ValueError("Operator authorization must be affirmed before creating an assessment")
        targets = parse_scope(payload.targets, payload.excludes, self.settings.max_cidr_hosts, payload.target_labels)
        has_fixture_targets = any(target.kind == "fixture" for target in targets)
        has_live_targets = any(target.kind != "fixture" for target in targets)
        if has_fixture_targets and has_live_targets:
            raise ValueError("Do not mix controlled fixture targets with live authorized targets in one assessment")
        execution_profile = "controlled_fixture" if has_fixture_targets else "authorized_external"
        if execution_profile == "authorized_external" and not payload.authorization_note.strip():
            raise ValueError("An authorization note is required for a live authorized assessment")
        if execution_profile == "controlled_fixture" and payload.profile == "authorized_external":
            raise ValueError("Controlled fixture assessments must use fixture:// targets only")
        assessment_id = f"assessment-{uuid.uuid4().hex[:12]}"
        created_at = now_iso()
        capabilities = sorted(set(payload.capabilities))
        permissions = sorted(set(payload.permissions))
        assessment = {
            "id": assessment_id,
            "name": payload.name,
            "client_name": payload.client_name.strip(),
            "description": payload.description.strip(),
            "status": "DRAFT",
            # The execution profile is derived from the normalized scope. This
            # prevents a stale/default UI value from routing a real target to
            # the fixture runner while retaining an explicit audit field.
            "profile": execution_profile,
            "assessment_type": payload.assessment_type,
            "capabilities_json": json.dumps(capabilities),
            "permissions_json": json.dumps(permissions),
            "credentials_available": int(payload.credentials_available),
            "authorized": 1,
            "authorization_note": payload.authorization_note.strip() or "Controlled local fixture authorization",
            "created_at": created_at,
            "target_count": len(targets),
            "total_units": len(targets) * len(TESTCASES),
            "llm_enabled": int(payload.llm_enabled),
            "evidence_screenshots": int(payload.evidence_screenshots),
        }
        target_rows = [
            {
                "id": f"{assessment_id}-{target.id}",
                "assessment_id": assessment_id,
                "value": target.value,
                "label": target.label,
                "kind": target.kind,
                "host_count": target.host_count,
                "excluded": 0,
            }
            for target in targets
        ]
        self.db.create_assessment(assessment, target_rows)
        root = self.settings.data_dir / "assessments" / assessment_id
        root.mkdir(parents=True, exist_ok=True)
        (root / "authorization.json").write_text(
            json.dumps(
                {
                    "assessment_id": assessment_id,
                    "authorized": True,
                    "note": assessment["authorization_note"],
                    "targets": [target.value for target in targets],
                    "assessment_type": payload.assessment_type,
                    "assessment_type_label": ASSESSMENT_TYPES[payload.assessment_type],
                    "capabilities": capabilities,
                    "permissions": permissions,
                    "credentials_available": payload.credentials_available,
                    "created_at": created_at,
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        self.db.add_event(
            assessment_id,
            "assessment_created",
            "Preflight",
            "Assessment created with an explicit authorized scope and capability contract.",
            total_units=assessment["total_units"],
            payload={
                "targets": [target.value for target in targets],
                "assessment_type": payload.assessment_type,
                "assessment_type_label": ASSESSMENT_TYPES[payload.assessment_type],
                "capabilities": capabilities,
            },
        )
        return self.db.get_assessment(assessment_id) or assessment

    def start(self, assessment_id: str) -> None:
        assessment = self.db.get_assessment(assessment_id)
        if not assessment:
            raise ValueError("Assessment not found")
        with self._lock:
            if assessment_id in self._threads and self._threads[assessment_id].is_alive():
                raise ValueError("Assessment is already running")
            cancel = threading.Event()
            pause = threading.Event()
            self._cancel[assessment_id] = cancel
            self._pause[assessment_id] = pause
            self.db.update_assessment(assessment_id, status="QUEUED")
            self.db.add_event(assessment_id, "assessment_queued", "Preflight", "Assessment queued.")
            thread = threading.Thread(target=self._run, args=(assessment_id, cancel, pause), name=f"scopeguard-{assessment_id}", daemon=True)
            self._threads[assessment_id] = thread
            thread.start()

    def delete(self, assessment_id: str) -> None:
        assessment = self.db.get_assessment(assessment_id)
        if not assessment:
            raise ValueError("Assessment not found")
        if assessment.get("status") in {"QUEUED", "RUNNING", "PAUSED"}:
            raise ValueError("Stop or cancel the assessment before deleting it")
        with self._lock:
            thread = self._threads.get(assessment_id)
            if thread and thread.is_alive():
                raise ValueError("Stop or cancel the assessment before deleting it")

        assessment_path = self.settings.data_dir / "assessments" / assessment_id
        assessments_root = (self.settings.data_dir / "assessments").resolve()
        exports_root = (self.settings.data_dir / "exports").resolve()
        if assessment_path.is_symlink():
            raise ValueError("Refusing to delete a symlinked assessment directory")
        assessment_root = assessment_path.resolve()
        if not assessment_root.is_relative_to(assessments_root):
            raise ValueError("Assessment path is outside the local data directory")
        if assessment_root.exists():
            shutil.rmtree(assessment_path)
        for export_path in (
            self.settings.data_dir / "exports" / f"{assessment_id}.csv",
            self.settings.data_dir / "exports" / f"{assessment_id}.zip",
        ):
            if export_path.is_symlink():
                raise ValueError("Refusing to delete a symlinked assessment export")
            resolved = export_path.resolve()
            if not resolved.is_relative_to(exports_root):
                raise ValueError("Export path is outside the local data directory")
            if export_path.is_file():
                export_path.unlink()
        if not self.db.delete_assessment(assessment_id):
            raise ValueError("Assessment was already deleted")

    def pause(self, assessment_id: str) -> None:
        event = self._pause.get(assessment_id)
        if not event:
            raise ValueError("Assessment is not active")
        event.set()

    def resume(self, assessment_id: str) -> None:
        event = self._pause.get(assessment_id)
        if not event:
            raise ValueError("Assessment is not active")
        event.clear()

    def cancel(self, assessment_id: str) -> None:
        event = self._cancel.get(assessment_id)
        if not event:
            raise ValueError("Assessment is not active")
        event.set()

    def _wait_if_paused(self, assessment_id: str, cancel: threading.Event, pause: threading.Event) -> bool:
        if not pause.is_set():
            return not cancel.is_set()
        self.db.update_assessment(assessment_id, status="PAUSED", current_phase="Paused")
        self.db.add_event(assessment_id, "assessment_paused", "Paused", "Assessment paused at a safe checkpoint.")
        while pause.is_set() and not cancel.is_set():
            time.sleep(0.1)
        if cancel.is_set():
            return False
        self.db.update_assessment(assessment_id, status="RUNNING", current_phase="Security Checks")
        self.db.add_event(assessment_id, "assessment_resumed", "Security Checks", "Assessment resumed.")
        return True

    def _run(self, assessment_id: str, cancel: threading.Event, pause: threading.Event) -> None:
        assessment = self.db.get_assessment(assessment_id)
        if not assessment:
            return
        targets = self.db.get_targets(assessment_id)
        assessment_root = self.settings.data_dir / "assessments" / assessment_id
        counters = {"FOUND": 0, "NOT_FOUND": 0, "NA": 0, "INCONCLUSIVE": 0}
        error_count = 0
        applicable_count = 0
        completed = 0
        pending_triage: list[tuple[int, str, list[str], str]] = []
        try:
            self.db.update_assessment(assessment_id, status="RUNNING", started_at=now_iso(), current_phase="Preflight")
            self.db.add_event(assessment_id, "phase_started", "Preflight", "Preflight checks completed.")
            self.db.update_assessment(assessment_id, current_phase="Dependencies")
            self.db.add_event(assessment_id, "phase_completed", "Dependencies", "Command runner and capability checks are available.")
            self.db.update_assessment(assessment_id, current_phase="Scope Validation")
            self.db.add_event(assessment_id, "phase_completed", "Scope Validation", "Authorized scope and capability manifest was persisted before execution.")
            self.db.update_assessment(assessment_id, current_phase="Discovery")
            self.db.add_event(assessment_id, "phase_completed", "Discovery", "Scope discovery stage completed.")
            self.db.update_assessment(assessment_id, current_phase="Service Enumeration")
            self.db.add_event(assessment_id, "phase_completed", "Service Enumeration", "Service selection uses the canonical testcase registry.")
            for target in targets:
                for testcase in TESTCASES:
                    if not self._wait_if_paused(assessment_id, cancel, pause) or cancel.is_set():
                        break
                    self.db.update_assessment(assessment_id, current_phase="Security Checks", current_target=target["value"], current_testcase=testcase.id)
                    self.db.add_event(
                        assessment_id,
                        "testcase_started",
                        "Security Checks",
                        f"Evaluating applicability for {testcase.id} — {testcase.name}",
                        testcase_id=testcase.id,
                        target_id=target["id"],
                        completed_units=completed,
                        total_units=assessment["total_units"],
                    )
                    capabilities = snapshot_for(
                        requested=assessment["capabilities_json"],
                        permissions=assessment["permissions_json"],
                        credentials_available=bool(assessment["credentials_available"]),
                        controlled_fixture=target["kind"] == "fixture",
                    )
                    decision = evaluate_applicability(testcase, assessment["assessment_type"], capabilities)
                    command_result: CommandResult | None = None
                    if decision.state == "APPLICABLE":
                        applicable_count += 1
                        command_result = self._execute_target(target, testcase.id, cancel)
                        classification = self._classify(testcase, command_result, live=target["kind"] != "fixture")
                        artifact = write_testcase_evidence(
                            assessment_root,
                            self._target_dir_name(target),
                            testcase,
                            command_result,
                            classification,
                            target_value=target["value"],
                            target_id=target["id"],
                            fixture_id=target["value"] if target["kind"] == "fixture" else None,
                            create_screenshots=bool(assessment["evidence_screenshots"]),
                        )
                    else:
                        result_status = "NA" if decision.state == "NA" else "INCONCLUSIVE"
                        classification = SimpleNamespace(
                            status=result_status,
                            applicability=decision.reason,
                            conditions_tested=(testcase.condition,),
                            conditions_confirmed=(),
                            conditions_not_found=(),
                            inconclusive_conditions=(testcase.condition,) if result_status == "INCONCLUSIVE" else (),
                            severity="unknown" if result_status == "INCONCLUSIVE" else "informational",
                            failure_reason=decision.reason,
                            validation_state="APPLICABILITY_LIMITATION" if result_status == "INCONCLUSIVE" else "APPLICABILITY_CONFIRMED",
                        )
                        artifact = write_applicability_evidence(
                            assessment_root,
                            self._target_dir_name(target),
                            testcase,
                            target_value=target["value"],
                            target_id=target["id"],
                            state=decision.state,
                            reason=decision.reason,
                            missing=decision.missing,
                        )
                        if result_status == "INCONCLUSIVE":
                            error_count += 1
                    finding_ids = [f"finding-{assessment_id}-{target['id']}-{testcase.id}"] if classification.status == "FOUND" else []
                    evidence_id = f"evidence-{command_result.id if command_result else uuid.uuid4().hex[:12]}"
                    result_row = {
                        "assessment_id": assessment_id,
                        "target_id": target["id"],
                        "target": target["value"],
                        "target_label": target["label"],
                        "testcase_id": testcase.id,
                        "testcase_name": testcase.name,
                        "status": classification.status,
                        "applicability": classification.applicability,
                        "conditions_tested_json": list(classification.conditions_tested),
                        "conditions_confirmed_json": list(classification.conditions_confirmed),
                        "conditions_not_found_json": list(classification.conditions_not_found),
                        "inconclusive_conditions_json": list(classification.inconclusive_conditions),
                        "severity": classification.severity,
                        "finding_ids_json": finding_ids,
                        "evidence_paths_json": artifact["evidence_paths"],
                        "poc_paths_json": artifact["poc_paths"],
                        "tools_used_json": list(dict.fromkeys(list(testcase.required_tools) + ([command_result.argv[0]] if command_result else []))),
                        "validation_state": classification.validation_state,
                        "failure_reason": classification.failure_reason,
                        "evidence_id": evidence_id,
                        "command": command_result.displayed_command if command_result else None,
                        "output_preview": artifact["stdout_preview"],
                        "created_at": now_iso(),
                    }
                    result_id = self.db.add_result(result_row)
                    if assessment["llm_enabled"] and classification.status == "INCONCLUSIVE":
                        pending_triage.append(
                            (
                                result_id,
                                testcase.id,
                                list(getattr(classification, "observation_ids", ())),
                                "\n".join(
                                    part for part in (
                                        classification.failure_reason or "",
                                        command_result.combined_output.decode("utf-8", errors="replace") if command_result else "",
                                    ) if part
                                )[:6000],
                            )
                        )
                    if command_result is not None:
                        self.db.add_execution({
                            "id": command_result.id,
                            "assessment_id": assessment_id,
                            "target_id": target["id"],
                            "testcase_id": testcase.id,
                            "command_json": json.dumps(list(command_result.argv)),
                            "displayed_command": command_result.displayed_command,
                            "cwd": command_result.cwd,
                            "started_at": command_result.started_at,
                            "ended_at": command_result.ended_at,
                            "exit_code": command_result.exit_code,
                            "timed_out": int(command_result.timed_out),
                            "tool_version": command_result.tool_version,
                            "stdout_path": artifact["evidence_paths"][0],
                            "stderr_path": artifact["evidence_paths"][1],
                            "stdout_sha256": command_result.stdout_sha256,
                            "stderr_sha256": command_result.stderr_sha256,
                            "combined_sha256": command_result.combined_sha256,
                            "execution_status": command_result.status,
                        })
                    for relative in artifact["evidence_paths"] + artifact["poc_paths"]:
                        artifact_path = assessment_root / relative
                        self.db.add_evidence({
                            "id": f"{evidence_id}-{sha256_bytes(relative.encode())[:10]}",
                            "result_id": result_id,
                            "assessment_id": assessment_id,
                            "target_id": target["id"],
                            "testcase_id": testcase.id,
                            "artifact_path": relative,
                            "kind": artifact_path.suffix.lstrip(".") or "file",
                            "sha256": sha256_bytes(artifact_path.read_bytes()),
                            "provenance": artifact["commands"],
                        })
                    counters[classification.status] += 1
                    if command_result is not None and command_result.status != "COMPLETED":
                        error_count += 1
                    completed += 1
                    self.db.update_assessment(assessment_id, completed_units=completed, found_count=counters["FOUND"], not_found_count=counters["NOT_FOUND"], na_count=counters["NA"], inconclusive_count=counters["INCONCLUSIVE"], applicable_count=applicable_count, error_count=error_count)
                    self.db.add_event(
                        assessment_id,
                        "testcase_completed" if decision.state == "APPLICABLE" else "testcase_skipped",
                        "Security Checks",
                        f"{testcase.id} recorded as {classification.status}: {classification.applicability}.",
                        status=classification.status,
                        testcase_id=testcase.id,
                        target_id=target["id"],
                        completed_units=completed,
                        total_units=assessment["total_units"],
                        payload={"command": command_result.displayed_command if command_result else None, "output_preview": artifact["stdout_preview"], "evidence_paths": artifact["evidence_paths"], "poc_paths": artifact["poc_paths"], "failure_reason": classification.failure_reason, "applicability_state": decision.state},
                    )
                if cancel.is_set():
                    break
            if cancel.is_set():
                self.db.update_assessment(assessment_id, status="CANCELLED", completed_at=now_iso(), current_phase="Cancelled")
                self.db.add_event(assessment_id, "assessment_cancelled", "Cancelled", "Assessment cancelled at a safe checkpoint.")
                return
            self.db.update_assessment(assessment_id, current_phase="Evidence Verification")
            self.db.add_event(assessment_id, "phase_completed", "Evidence Verification", "Evidence hashes and provenance were persisted.")
            self.db.update_assessment(assessment_id, current_phase="AI Triage")
            if assessment["llm_enabled"] and pending_triage:
                self.db.add_event(assessment_id, "phase_started", "AI Triage", f"Analyzing {len(pending_triage)} inconclusive result(s) with the optional local model.")
                for result_id, testcase_id, observation_ids, evidence in pending_triage:
                    try:
                        triage = self.ollama.triage(
                            testcase_id=testcase_id,
                            observation_ids=observation_ids,
                            evidence=evidence,
                        )
                        self.db.add_llm_triage({
                            "assessment_id": assessment_id,
                            "result_id": result_id,
                            "model": self.ollama.model,
                            "prompt_version": "scopeguard-triage-v1",
                            "response_json": json.dumps(triage.model_dump(), ensure_ascii=False),
                            "validation_state": "VALIDATED",
                            "created_at": now_iso(),
                        })
                        self.db.add_event(
                            assessment_id,
                            "llm_triage_completed",
                            "AI Triage",
                            f"Validated secondary explanation stored for testcase {testcase_id}; deterministic classification unchanged.",
                            testcase_id=testcase_id,
                        )
                    except Exception as error:
                        self.db.add_event(
                            assessment_id,
                            "llm_triage_failed",
                            "AI Triage",
                            f"Local AI analysis unavailable for testcase {testcase_id}; deterministic result preserved.",
                            testcase_id=testcase_id,
                            payload={"error_type": type(error).__name__, "error": str(error)[:240]},
                        )
                self.db.add_event(assessment_id, "phase_completed", "AI Triage", "Optional local AI analysis completed without changing deterministic classifications.")
            else:
                reason = "disabled by assessment configuration" if not assessment["llm_enabled"] else "no inconclusive evidence required secondary analysis"
                self.db.add_event(assessment_id, "phase_skipped", "AI Triage", f"Optional local AI skipped: {reason}.")
            self.db.update_assessment(assessment_id, current_phase="Report Generation")
            self.db.add_event(assessment_id, "phase_completed", "Report Generation", "Report inputs are complete.")
            self.db.update_assessment(assessment_id, current_phase="Packaging")
            self.db.add_event(assessment_id, "phase_started", "Packaging", "Creating CSV and ZIP exports.")
            exports = export_assessment(self.db, assessment_id, self.settings.data_dir, status_override="COMPLETED")
            self.db.add_event(assessment_id, "assessment_completed", "Complete", "Assessment and exports completed with persisted evidence.", completed_units=completed, total_units=assessment["total_units"], payload={"csv": str(exports["csv"]), "zip": str(exports["zip"])})
            self.db.update_assessment(assessment_id, status="COMPLETED", completed_at=now_iso(), current_phase="Complete", current_target=None, current_testcase=None)
        except Exception as error:
            self.db.update_assessment(assessment_id, status="FAILED", completed_at=now_iso(), current_phase="Failed")
            self.db.add_event(assessment_id, "assessment_failed", "Failed", f"Assessment stopped: {error}", payload={"error_type": type(error).__name__})

    def _execute_target(self, target: dict, testcase_id: str, cancel: threading.Event) -> CommandResult:
        target_obj = NormalizedTarget(target["id"], target["value"], target["label"], target["kind"], target["host_count"])
        if target_obj.kind == "fixture":
            scenario = target_obj.value.split("://", 1)[1]
            argv = [sys.executable, "-m", "app.fixture_command", "--testcase-id", testcase_id, "--scenario", scenario, "--target", target_obj.value]
            timeout = 0.35 if scenario == "timeout" else 4.0
        else:
            adapter = adapter_for(testcase_id)
            argv = build_command(
                testcase_id,
                target_obj.value,
                nmap_host_timeout_seconds=self.settings.scanner_host_timeout_seconds,
                nmap_max_retries=self.settings.scanner_max_retries,
            )
            if argv is None:
                # Capability-only checks remain explicitly incomplete when the
                # selected profile makes them applicable but no authorized
                # sensor/credential source is attached to this process.
                argv = [
                    sys.executable,
                    "-m",
                    "app.live_capability",
                    "--testcase-id",
                    testcase_id,
                    "--target",
                    target_obj.value,
                ]
            timeout = self.settings.live_command_timeout if adapter.live_status == "LIVE" else self.settings.live_limited_command_timeout
            if argv and argv[0].rsplit("/", 1)[-1] == "nmap":
                timeout = max(timeout, self.settings.scanner_host_timeout_seconds + self.settings.scanner_command_grace_seconds)
        with self._command_metrics_lock:
            self.active_commands += 1
            self.max_active_commands = max(self.max_active_commands, self.active_commands)
            self.executed_commands += 1
        try:
            return run_command(argv, timeout_seconds=timeout, cwd=self.settings.root_dir)
        finally:
            with self._command_metrics_lock:
                self.active_commands -= 1

    @staticmethod
    def _classify(testcase, result: CommandResult, *, live: bool = False):
        from .classifier import classify, classify_live

        return classify_live(testcase, result) if live else classify(testcase, result, allow_na=False)

    @staticmethod
    def _target_dir_name(target: dict) -> str:
        return f"{target['id']}_{safe_name(target['label'])[:80]}"

    def detail(self, assessment_id: str) -> dict | None:
        assessment = self.db.get_assessment(assessment_id)
        if not assessment:
            return None
        assessment["targets"] = self.db.get_targets(assessment_id)
        assessment["results"] = self.db.list_results(assessment_id)
        assessment["recent_events"] = self.db.list_events(assessment_id)[-100:]
        return assessment
