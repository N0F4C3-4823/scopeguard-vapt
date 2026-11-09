from __future__ import annotations

import json
import shutil
import sys
import threading
import time
import uuid
from dataclasses import replace
from types import SimpleNamespace

from .applicability import ASSESSMENT_TYPES, evaluate_applicability, snapshot_for
from .commands import CommandResult, run_command, sha256_bytes
from .config import Settings
from .db import Database, now_iso
from .descriptions import two_line_description
from .discovery import (
    DiscoverySnapshot,
    build_discovery_commands,
    parse_discovery_result,
    service_gate,
)
from .evidence import safe_name, write_applicability_evidence, write_testcase_evidence
from .exporter import export_assessment
from .live_adapters import adapter_for, build_command
from .models import AssessmentCreate
from .ollama import OllamaClient
from .recovery import plan_recovery, recovery_is_useful
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
        self._ai_cache: dict[str, object] = {}
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

    def request_delete(self, assessment_id: str) -> str:
        """Cancel an active run or delete a terminal run.

        Scope and authorization are never edited as part of this operation. An
        active job is only removed after its cancellation checkpoint reaches a
        terminal state and the caller retries the deletion.
        """
        assessment = self.db.get_assessment(assessment_id)
        if not assessment:
            raise ValueError("Assessment not found")
        if assessment.get("status") in {"QUEUED", "RUNNING", "PAUSED"}:
            self.cancel(assessment_id)
            self.db.add_event(
                assessment_id,
                "assessment_delete_requested",
                "Recovery",
                "Deletion requested; the active assessment will be removed after safe cancellation.",
                status="CANCELLING",
            )
            return "cancellation_requested"
        self.delete(assessment_id)
        return "deleted"

    def edit_metadata(self, assessment_id: str, *, name: str | None = None, client_name: str | None = None, description: str | None = None) -> dict:
        assessment = self.db.get_assessment(assessment_id)
        if not assessment:
            raise ValueError("Assessment not found")
        fields = {
            key: value.strip() if isinstance(value, str) else value
            for key, value in {
                "name": name,
                "client_name": client_name,
                "description": description,
            }.items()
            if value is not None
        }
        if not fields:
            return assessment
        if "name" in fields and not fields["name"]:
            raise ValueError("Assessment name cannot be blank")
        self.db.update_assessment(assessment_id, **fields)
        self.db.add_event(
            assessment_id,
            "assessment_metadata_updated",
            "Scope Validation",
            "Assessment metadata was updated; authorized scope and execution settings remain unchanged.",
        )
        return self.db.get_assessment(assessment_id) or assessment

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

    @staticmethod
    def _block_final_verdict(classification, reason: str):
        """Remove certification when mandatory evidence generation failed."""
        if isinstance(classification, SimpleNamespace):
            classification.status = "INCONCLUSIVE"
            classification.final_verdict = None
            classification.coverage_status = "BLOCKED"
            classification.coverage_reason = reason
            classification.failure_reason = reason
            classification.validation_state = "EVIDENCE_INCOMPLETE"
            classification.reportable_finding = False
            classification.inconclusive_conditions = tuple(getattr(classification, "conditions_tested", ()))
            return classification
        return replace(
            classification,
            status="INCONCLUSIVE",
            final_verdict=None,
            coverage_status="BLOCKED",
            coverage_reason=reason,
            failure_reason=reason,
            validation_state="EVIDENCE_INCOMPLETE",
            reportable_finding=False,
            inconclusive_conditions=classification.conditions_tested,
        )

    def _discover_target(
        self,
        assessment_id: str,
        target: dict,
        assessment_root,
        cancel: threading.Event,
    ) -> DiscoverySnapshot:
        """Run bounded TCP and UDP discovery once and persist its provenance."""
        tcp_argv, udp_argv = build_discovery_commands(
            target["value"],
            host_timeout_seconds=self.settings.scanner_host_timeout_seconds,
            max_retries=self.settings.scanner_max_retries,
            script_timeout_seconds=self.settings.nmap_script_timeout_seconds,
        )
        target_root = assessment_root / self._target_dir_name(target) / "discovery"
        target_root.mkdir(parents=True, exist_ok=True)
        results: dict[str, CommandResult] = {}
        parsed: dict[str, tuple[tuple, bool, str | None]] = {}
        for protocol, argv in (("tcp", tcp_argv), ("udp", udp_argv)):
            if cancel.is_set():
                parsed[protocol] = ((), False, "discovery cancelled before the protocol scan completed")
                continue
            self.db.add_event(
                assessment_id,
                "discovery_probe_started",
                "Discovery",
                f"Running bounded {protocol.upper()} service discovery for {target['value']}.",
                target_id=target["id"],
            )
            timeout = max(
                self.settings.live_limited_command_timeout,
                self.settings.scanner_host_timeout_seconds + self.settings.scanner_command_grace_seconds,
            )
            result = self._run_argv(argv, timeout)
            results[protocol] = result
            observations, complete, failure = parse_discovery_result(result, protocol)
            parsed[protocol] = (observations, complete, failure)
            protocol_dir = target_root / protocol
            protocol_dir.mkdir(parents=True, exist_ok=True)
            (protocol_dir / "stdout.bin").write_bytes(result.stdout)
            (protocol_dir / "stderr.bin").write_bytes(result.stderr)
            (protocol_dir / "commands.json").write_text(
                json.dumps(
                    {
                        "command_id": result.id,
                        "argv": list(result.argv),
                        "displayed_command": result.displayed_command,
                        "exit_code": result.exit_code,
                        "timed_out": result.timed_out,
                        "execution_status": result.status,
                        "tool_version": result.tool_version,
                        "stdout_sha256": result.stdout_sha256,
                        "stderr_sha256": result.stderr_sha256,
                        "combined_sha256": result.combined_sha256,
                        "protocol": protocol,
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )
            relative_stdout = str((protocol_dir / "stdout.bin").relative_to(assessment_root))
            relative_stderr = str((protocol_dir / "stderr.bin").relative_to(assessment_root))
            self.db.add_execution(
                {
                    "id": result.id,
                    "assessment_id": assessment_id,
                    "target_id": target["id"],
                    "testcase_id": f"DISCOVERY_{protocol.upper()}",
                    "command_json": json.dumps(list(result.argv)),
                    "displayed_command": result.displayed_command,
                    "cwd": result.cwd,
                    "started_at": result.started_at,
                    "ended_at": result.ended_at,
                    "exit_code": result.exit_code,
                    "timed_out": int(result.timed_out),
                    "tool_version": result.tool_version,
                    "stdout_path": relative_stdout,
                    "stderr_path": relative_stderr,
                    "stdout_sha256": result.stdout_sha256,
                    "stderr_sha256": result.stderr_sha256,
                    "combined_sha256": result.combined_sha256,
                    "execution_status": result.status,
                }
            )
            self.db.add_event(
                assessment_id,
                "discovery_probe_completed",
                "Discovery",
                failure or f"{protocol.upper()} discovery completed with {len(observations)} explicit port observations.",
                status="COMPLETED" if complete else "INCONCLUSIVE",
                target_id=target["id"],
                payload={
                    "protocol": protocol,
                    "observations": [item.as_dict() for item in observations],
                    "failure": failure,
                },
            )
        tcp_observations, tcp_complete, tcp_failure = parsed.get("tcp", ((), False, "TCP discovery was not executed"))
        udp_observations, udp_complete, udp_failure = parsed.get("udp", ((), False, "UDP discovery was not executed"))
        tcp_result = results.get("tcp")
        udp_result = results.get("udp")
        combined_text = "".join(
            (item.stdout + item.stderr).decode("utf-8", errors="replace")
            for item in results.values()
        ).lower()
        if "host is up" in combined_text:
            host_state = "HOST_REACHABLE"
        elif "host seems down" in combined_text and tcp_complete and udp_complete:
            host_state = "HOST_UNREACHABLE"
        else:
            host_state = "HOST_INDETERMINATE"
        snapshot = DiscoverySnapshot(
            target=target["value"],
            tcp=tuple(tcp_observations),
            udp=tuple(udp_observations),
            tcp_complete=tcp_complete,
            udp_complete=udp_complete,
            host_state=host_state,
            tcp_command_id=tcp_result.id if tcp_result else None,
            udp_command_id=udp_result.id if udp_result else None,
            tcp_failure=tcp_failure,
            udp_failure=udp_failure,
        )
        (target_root / "discovery.json").write_text(json.dumps(snapshot.as_dict(), indent=2), encoding="utf-8")
        self.db.add_event(
            assessment_id,
            "discovery_snapshot_saved",
            "Discovery",
            f"Saved protocol-aware discovery for {target['value']} ({host_state}).",
            target_id=target["id"],
            payload=snapshot.as_dict(),
        )
        return snapshot

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
        discovery: dict[str, DiscoverySnapshot] = {}
        try:
            self.db.update_assessment(assessment_id, status="RUNNING", started_at=now_iso(), current_phase="Preflight")
            self.db.add_event(assessment_id, "phase_started", "Preflight", "Preflight checks completed.")
            self.db.update_assessment(assessment_id, current_phase="Dependencies")
            self.db.add_event(assessment_id, "phase_completed", "Dependencies", "Command runner and capability checks are available.")
            self.db.update_assessment(assessment_id, current_phase="Scope Validation")
            self.db.add_event(assessment_id, "phase_completed", "Scope Validation", "Authorized scope and capability manifest was persisted before execution.")
            self.db.update_assessment(assessment_id, current_phase="Discovery")
            for target in targets:
                if target["kind"] == "fixture":
                    self.db.add_event(
                        assessment_id,
                        "discovery_skipped",
                        "Discovery",
                        "Controlled fixture discovery is represented by the fixture contract.",
                        target_id=target["id"],
                    )
                    continue
                if cancel.is_set():
                    break
                discovery[target["id"]] = self._discover_target(assessment_id, target, assessment_root, cancel)
            self.db.add_event(
                assessment_id,
                "phase_completed",
                "Discovery",
                "Protocol-aware TCP and UDP discovery completed; incomplete scans remain explicit limitations.",
            )
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
                    related_evidence_paths: tuple[str, ...] = ()
                    if decision.state == "APPLICABLE" and target["kind"] != "fixture":
                        if testcase.id == "29" and target["kind"] == "ip" and ":" not in target["value"]:
                            decision = replace(
                                decision,
                                state="NA",
                                reason="IPv6 exposure testing requires an authorized IPv6 endpoint; the approved target is an IPv4 literal.",
                                missing=(),
                            )
                        gate = service_gate(testcase.id, discovery.get(target["id"])) if target["id"] in discovery else None
                        if gate and gate[0] in {"NA", "INCONCLUSIVE"}:
                            decision = replace(decision, state=gate[0], reason=gate[1], missing=())
                            discovery_root = assessment_root / self._target_dir_name(target) / "discovery"
                            related_evidence_paths = tuple(
                                str(path.relative_to(assessment_root))
                                for path in sorted(discovery_root.rglob("*"))
                                if path.is_file() and not path.is_symlink()
                            )
                    command_result: CommandResult | None = None
                    if decision.state == "APPLICABLE":
                        applicable_count += 1
                        command_result = self._execute_target(target, testcase.id, cancel)
                        classification = self._classify(testcase, command_result, live=target["kind"] != "fixture")
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
                            final_verdict="NA" if result_status == "NA" else None,
                            coverage_status="COMPLETED" if result_status == "NA" else "BLOCKED",
                            coverage_reason=decision.reason,
                            observation_type="coverage",
                            reportable_finding=False,
                        )
                    recovery_attempts: list[CommandResult] = []
                    recovery_audits: list[dict[str, object]] = []
                    if (
                        decision.state == "APPLICABLE"
                        and classification.status == "INCONCLUSIVE"
                    ):
                        command_result, classification, recovery_attempts, recovery_audits = self._resolve_discrepancy(
                            assessment,
                            target,
                            testcase,
                            command_result,
                            classification,
                            cancel,
                        )
                    description_line_1, description_line_2 = two_line_description(
                        testcase_id=testcase.id,
                        testcase_name=testcase.name,
                        condition=testcase.condition,
                        verdict=classification.final_verdict,
                        observation_type=classification.observation_type,
                        target=target["label"] or target["value"],
                        applicability=classification.applicability,
                        observation_ids=tuple(getattr(classification, "observation_ids", ())),
                    )
                    if isinstance(classification, SimpleNamespace):
                        classification.description_line_1 = description_line_1
                        classification.description_line_2 = description_line_2
                    else:
                        classification = replace(
                            classification,
                            description_line_1=description_line_1,
                            description_line_2=description_line_2,
                        )
                    if decision.state == "APPLICABLE":
                        if classification.final_verdict in {"FOUND", "NOT_FOUND"} and not assessment["evidence_screenshots"]:
                            classification = self._block_final_verdict(classification, "POC evidence generation is disabled for this assessment; the security verdict remains uncertified")
                            description_line_1, description_line_2 = two_line_description(
                                testcase_id=testcase.id,
                                testcase_name=testcase.name,
                                condition=testcase.condition,
                                verdict=classification.final_verdict,
                                observation_type=classification.observation_type,
                                target=target["label"] or target["value"],
                                applicability=classification.applicability,
                                observation_ids=tuple(getattr(classification, "observation_ids", ())),
                            )
                            classification = replace(classification, description_line_1=description_line_1, description_line_2=description_line_2)
                        try:
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
                                recovery_attempts=recovery_attempts,
                            )
                        except Exception as error:
                            if classification.final_verdict not in {"FOUND", "NOT_FOUND"}:
                                raise
                            classification = self._block_final_verdict(classification, f"POC evidence generation failed: {type(error).__name__}")
                            description_line_1, description_line_2 = two_line_description(
                                testcase_id=testcase.id,
                                testcase_name=testcase.name,
                                condition=testcase.condition,
                                verdict=classification.final_verdict,
                                observation_type=classification.observation_type,
                                target=target["label"] or target["value"],
                                applicability=classification.applicability,
                                observation_ids=tuple(getattr(classification, "observation_ids", ())),
                            )
                            classification = replace(classification, description_line_1=description_line_1, description_line_2=description_line_2)
                            artifact = write_testcase_evidence(
                                assessment_root,
                                self._target_dir_name(target),
                                testcase,
                                command_result,
                                classification,
                                target_value=target["value"],
                                target_id=target["id"],
                                fixture_id=target["value"] if target["kind"] == "fixture" else None,
                                create_screenshots=False,
                                recovery_attempts=recovery_attempts,
                            )
                    else:
                        artifact = write_applicability_evidence(
                            assessment_root,
                            self._target_dir_name(target),
                            testcase,
                            target_value=target["value"],
                            target_id=target["id"],
                            state=decision.state,
                            reason=decision.reason,
                            missing=decision.missing,
                            description_line_1=description_line_1,
                            description_line_2=description_line_2,
                            related_evidence_paths=related_evidence_paths,
                        )
                        if result_status == "INCONCLUSIVE":
                            error_count += 1
                    finding_ids = [f"finding-{assessment_id}-{target['id']}-{testcase.id}"] if classification.reportable_finding else []
                    evidence_id = f"evidence-{command_result.id if command_result else uuid.uuid4().hex[:12]}"
                    result_row = {
                        "assessment_id": assessment_id,
                        "target_id": target["id"],
                        "target": target["value"],
                        "target_label": target["label"],
                        "testcase_id": testcase.id,
                        "testcase_name": testcase.name,
                        "status": classification.status,
                        "final_verdict": classification.final_verdict,
                        "coverage_status": classification.coverage_status,
                        "coverage_reason": classification.coverage_reason,
                        "observation_type": classification.observation_type,
                        "reportable_finding": int(classification.reportable_finding),
                        "description_line_1": description_line_1,
                        "description_line_2": description_line_2,
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
                    for audit in recovery_audits:
                        self.db.add_ai_recovery({**audit, "result_id": result_id})
                        if audit.get("validation_state") == "VALIDATED":
                            self.db.add_llm_triage({
                                "assessment_id": assessment_id,
                                "result_id": result_id,
                                "model": self.ollama.model,
                                "prompt_version": "scopeguard-recovery-v1",
                                "response_json": audit.get("response_json", "{}"),
                                "validation_state": "VALIDATED",
                                "created_at": audit.get("created_at", now_iso()),
                            })
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
                    if recovery_attempts:
                        recovery_root = (
                            assessment_root
                            / self._target_dir_name(target)
                            / "testcases"
                            / f"{testcase.id}_{safe_name(testcase.condition)}"
                            / "evidence"
                        )
                        for attempt_index, attempt in enumerate(recovery_attempts, start=1):
                            if command_result is not None and attempt.id == command_result.id:
                                continue
                            attempt_root = recovery_root / f"recovery_attempt_{attempt_index:03d}"
                            self.db.add_execution({
                                "id": attempt.id,
                                "assessment_id": assessment_id,
                                "target_id": target["id"],
                                "testcase_id": testcase.id,
                                "command_json": json.dumps(list(attempt.argv)),
                                "displayed_command": attempt.displayed_command,
                                "cwd": attempt.cwd,
                                "started_at": attempt.started_at,
                                "ended_at": attempt.ended_at,
                                "exit_code": attempt.exit_code,
                                "timed_out": int(attempt.timed_out),
                                "tool_version": attempt.tool_version,
                                "stdout_path": str((attempt_root / "stdout.bin").relative_to(assessment_root)),
                                "stderr_path": str((attempt_root / "stderr.bin").relative_to(assessment_root)),
                                "stdout_sha256": attempt.stdout_sha256,
                                "stderr_sha256": attempt.stderr_sha256,
                                "combined_sha256": attempt.combined_sha256,
                                "execution_status": attempt.status,
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
            recovery_count = len(self.db.list_ai_recovery(assessment_id))
            if assessment["llm_enabled"] and recovery_count:
                self.db.add_event(
                    assessment_id,
                    "phase_completed",
                    "AI Triage",
                    f"Automatic discrepancy analysis completed for {recovery_count} captured discrepancy record(s); deterministic classifications remain authoritative.",
                )
            else:
                reason = "disabled by assessment configuration" if not assessment["llm_enabled"] else "no discrepancies required secondary analysis"
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

    def _run_argv(self, argv: list[str], timeout: float) -> CommandResult:
        with self._command_metrics_lock:
            self.active_commands += 1
            self.max_active_commands = max(self.max_active_commands, self.active_commands)
            self.executed_commands += 1
        try:
            return run_command(argv, timeout_seconds=timeout, cwd=self.settings.root_dir)
        finally:
            with self._command_metrics_lock:
                self.active_commands -= 1

    def _execute_target(self, target: dict, testcase_id: str, cancel: threading.Event, *, recovery: bool = False) -> CommandResult:
        target_obj = NormalizedTarget(target["id"], target["value"], target["label"], target["kind"], target["host_count"])
        if target_obj.kind == "fixture":
            scenario = target_obj.value.split("://", 1)[1]
            argv = [sys.executable, "-m", "app.fixture_command", "--testcase-id", testcase_id, "--scenario", scenario, "--target", target_obj.value]
            timeout = 0.35 if scenario == "timeout" else 4.0
        else:
            adapter = adapter_for(testcase_id)
            multiplier = 2 if recovery else 1
            argv = build_command(
                testcase_id,
                target_obj.value,
                nmap_host_timeout_seconds=min(self.settings.scanner_host_timeout_seconds * multiplier, 120),
                nmap_max_retries=min(self.settings.scanner_max_retries + (1 if recovery else 0), 5),
                tcp_connect_timeout_seconds=min(self.settings.tcp_connect_timeout_seconds * multiplier, 15),
                protocol_timeout_seconds=min(self.settings.protocol_timeout_seconds * multiplier, 30),
                nmap_script_timeout_seconds=min(self.settings.nmap_script_timeout_seconds * multiplier, 60),
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
                timeout = max(timeout, self.settings.scanner_host_timeout_seconds * multiplier + self.settings.scanner_command_grace_seconds)
            timeout *= multiplier
        return self._run_argv(argv, timeout)

    def _resolve_discrepancy(self, assessment, target, testcase, command_result, classification, cancel):
        trigger = classification.failure_reason or "insufficient evidence"
        if not recovery_is_useful(testcase_id=testcase.id, result=command_result, reason=trigger):
            self.db.add_event(
                assessment["id"],
                "ai_recovery_skipped",
                "AI Triage",
                "No bounded alternate action is expected to improve a filtering, silence, or unsupported-predicate limitation.",
                testcase_id=testcase.id,
                target_id=target["id"],
            )
            return command_result, classification, [], []
        evidence = "\n".join(
            part for part in (
                f"target={target['value']}",
                f"testcase={testcase.id} {testcase.name}",
                f"command={command_result.displayed_command if command_result else 'none'}",
                f"exit_code={command_result.exit_code if command_result else None}",
                f"execution_status={command_result.status if command_result else 'not executed'}",
                f"failure_reason={trigger}",
                command_result.combined_output.decode("utf-8", errors="replace") if command_result else "",
            ) if part
        )[:6000]
        audits: list[dict[str, object]] = []
        attempts: list[CommandResult] = []
        fallback_action = "run_approved_alternative_probe" if testcase.id == "40" else "retry_safe_probe"
        fallback_parameters: dict[str, object] = (
            {"transport": "tcp"}
            if fallback_action == "run_approved_alternative_probe"
            else {"timeout_profile": "protocol_retry"}
        )
        suggested_action_id: str | None = None
        suggested_parameters: dict[str, object] = {}
        response_payload: dict[str, object] = {}
        validation_state = "FALLBACK_VALIDATED"
        outcome = "DETERMINISTIC_FALLBACK"
        if assessment["llm_enabled"]:
            self.db.add_event(assessment["id"], "ai_analysis_started", "AI Triage", f"Discrepancy detected for testcase {testcase.id}; analyzing the captured evidence.", testcase_id=testcase.id, target_id=target["id"])
            try:
                cache_key = sha256_bytes(evidence.encode("utf-8", errors="replace"))
                triage = self._ai_cache.get(cache_key)
                if triage is None:
                    triage = self.ollama.triage(
                        testcase_id=testcase.id,
                        observation_ids=list(getattr(classification, "observation_ids", ())),
                        evidence=evidence,
                    )
                    self._ai_cache[cache_key] = triage
                response_payload = triage.model_dump()
                suggested_action_id = triage.suggested_action_id
                suggested_parameters = dict(triage.parameters)
                validation_state = "MODEL_VALIDATED"
                outcome = "ANALYZED"
                self.db.add_event(assessment["id"], "ai_cause_identified", "AI Triage", "Local AI returned a schema-validated discrepancy explanation; deterministic status remains authoritative.", testcase_id=testcase.id, target_id=target["id"])
            except Exception as error:
                response_payload = {"error_type": type(error).__name__, "error": str(error)[:240]}
                self.db.add_event(assessment["id"], "ai_analysis_failed", "AI Triage", "Local AI was unavailable or returned invalid output; a deterministic safe fallback will be considered.", testcase_id=testcase.id, target_id=target["id"], payload=response_payload)
        else:
            self.db.add_event(assessment["id"], "ai_recovery_skipped", "AI Triage", "Optional Local AI is disabled; deterministic bounded recovery remains available.", testcase_id=testcase.id, target_id=target["id"])
        action_id = suggested_action_id or fallback_action
        parameters = suggested_parameters or fallback_parameters
        plan = plan_recovery(
            action_id=action_id,
            testcase_id=testcase.id,
            target=target["value"],
            settings=self.settings,
            attempt=0,
            parameters=parameters,
        )
        if plan.action_id is None and suggested_action_id is not None:
            validation_state = "REJECTED"
            self.db.add_event(
                assessment["id"],
                "ai_action_rejected",
                "AI Triage",
                f"Rejected the model's recovery action: {plan.reason}.",
                testcase_id=testcase.id,
                target_id=target["id"],
            )
            action_id = fallback_action
            parameters = fallback_parameters
            plan = plan_recovery(
                action_id=action_id,
                testcase_id=testcase.id,
                target=target["value"],
                settings=self.settings,
                attempt=0,
                parameters=parameters,
            )
        if plan.action_id is not None and validation_state != "REJECTED":
            validation_state = "VALIDATED"
        if plan.argv or plan.action_id in {"reparse_raw_output", "inspect_existing_evidence"}:
            self.db.add_event(
                assessment["id"],
                "ai_corrective_check_selected",
                "AI Triage",
                plan.reason,
                testcase_id=testcase.id,
                target_id=target["id"],
                payload={"action_id": plan.action_id, "parameters": parameters},
            )
            if cancel.is_set():
                return command_result, classification, attempts, audits
            self.db.add_event(
                assessment["id"],
                "ai_corrective_check_started",
                "AI Triage",
                "Running the approved non-destructive corrective check.",
                testcase_id=testcase.id,
                target_id=target["id"],
            )
            if command_result is not None:
                attempts.append(command_result)
            retry_result: CommandResult | None = None
            if plan.argv:
                retry_result = self._run_argv(
                    plan.argv,
                    plan.timeout_seconds or self.settings.live_command_timeout,
                )
                attempts.append(retry_result)
                retry_classification = self._classify(
                    testcase,
                    retry_result,
                    live=target["kind"] != "fixture",
                )
            elif plan.action_id == "reparse_raw_output" and command_result is not None:
                retry_result = command_result
                retry_classification = self._classify(
                    testcase,
                    command_result,
                    live=target["kind"] != "fixture",
                )
            else:
                retry_classification = classification
            outcome = "RECOVERY_SUCCEEDED" if retry_classification.final_verdict else "RECOVERY_EXHAUSTED"
            if retry_classification.final_verdict:
                classification = retry_classification
                if retry_result is not None:
                    command_result = retry_result
                self.db.add_event(
                    assessment["id"],
                    "ai_recovery_succeeded",
                    "AI Triage",
                    "A bounded corrective check produced evidence sufficient for deterministic verification.",
                    testcase_id=testcase.id,
                    target_id=target["id"],
                )
            else:
                self.db.add_event(
                    assessment["id"],
                    "ai_recovery_exhausted",
                    "AI Triage",
                    "The bounded corrective check did not establish a final verdict; the result remains unresolved.",
                    testcase_id=testcase.id,
                    target_id=target["id"],
                )
        audits.append({
            "assessment_id": assessment["id"],
            "target_id": target["id"],
            "testcase_id": testcase.id,
            "result_id": None,
            "trigger": trigger,
            "action_id": action_id,
            "validation_state": validation_state,
            "response_json": json.dumps(response_payload, ensure_ascii=False),
            "outcome": outcome,
            "created_at": now_iso(),
        })
        return command_result, classification, attempts, audits

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
        assessment.update(self._result_summary(assessment["results"]))
        assessment["recent_events"] = self.db.list_events(assessment_id)[-100:]
        return assessment

    @staticmethod
    def _result_summary(results: list[dict]) -> dict[str, int | str]:
        unresolved = sum(1 for result in results if not result.get("final_verdict"))
        informational = sum(
            1 for result in results
            if result.get("final_verdict") == "FOUND" and result.get("observation_type") in {"informational", "exposure_inventory"}
        )
        vulnerabilities = sum(
            1 for result in results
            if result.get("final_verdict") == "FOUND" and result.get("reportable_finding")
        )
        return {
            "confirmed_vulnerability_count": vulnerabilities,
            "informational_count": informational,
            "verified_negative_count": sum(1 for result in results if result.get("final_verdict") == "NOT_FOUND"),
            "not_applicable_count": sum(1 for result in results if result.get("final_verdict") == "NA"),
            "unresolved_count": unresolved,
            "completion_outcome": "COMPLETED_WITH_LIMITATIONS" if unresolved else "COMPLETED",
        }
