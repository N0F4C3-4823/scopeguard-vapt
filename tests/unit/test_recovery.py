from __future__ import annotations

import threading
from pathlib import Path

from app.classifier import Classification
from app.commands import CommandResult
from app.models import TriageModel
from app.recovery import plan_recovery, recovery_is_useful
from app.registry import TESTCASE_BY_ID


def _result(*, status: str, stdout: bytes = b"", timed_out: bool = False) -> CommandResult:
    return CommandResult(
        id=f"cmd-{status.lower()}",
        argv=("nmap", "-Pn", "127.0.0.1"),
        displayed_command="nmap -Pn 127.0.0.1",
        cwd=str(Path.cwd()),
        started_at="2026-01-01T00:00:00+00:00",
        ended_at="2026-01-01T00:00:01+00:00",
        exit_code=0 if status == "COMPLETED" else None,
        timed_out=timed_out,
        stdout=stdout,
        stderr=b"",
        status=status,
        tool_version="nmap fixture",
    )


def test_discrepancy_invokes_ollama_and_accepts_only_bounded_recovery(manager, monkeypatch):
    testcase = TESTCASE_BY_ID["02"]
    initial = _result(status="TIMEOUT", timed_out=True)
    classification = Classification(
        "INCONCLUSIVE", "applicable", (testcase.condition,), (), (), (testcase.condition,),
        "unknown", "bounded live adapter command timed out", (), "INCOMPLETE",
        final_verdict=None, coverage_status="FAILED", coverage_reason="bounded live adapter command timed out",
    )
    calls: list[str] = []

    def triage(**_kwargs):
        calls.append("triage")
        return TriageModel(
            testcase_id="02",
            observation_ids=[],
            interpretation="The command timed out.",
            suggested_action_id="retry_safe_probe",
            explanation="A bounded retry may collect a complete banner.",
        )

    monkeypatch.setattr(manager.ollama, "triage", triage)
    monkeypatch.setattr(manager.db, "add_event", lambda *args, **kwargs: 1)
    recovered = _result(
        status="COMPLETED",
        stdout=(
            b"Nmap scan report for 127.0.0.1\n"
            b"80/tcp open http nginx\n"
            b"Nmap done: 1 IP address (1 host up) scanned in 0.01 seconds\n"
        ),
    )
    monkeypatch.setattr(manager, "_run_argv", lambda *_args, **_kwargs: recovered)
    assessment = {"id": "assessment-test", "llm_enabled": 1}
    target = {"id": "target-test", "value": "127.0.0.1", "label": "loopback", "kind": "live", "host_count": 1}

    command, final, attempts, audits = manager._resolve_discrepancy(
        assessment, target, testcase, initial, classification, threading.Event()
    )

    assert calls == ["triage"]
    assert command is recovered
    assert final.final_verdict == "FOUND"
    assert len(attempts) == 2
    assert audits[0]["action_id"] == "retry_safe_probe"
    assert audits[0]["outcome"] == "RECOVERY_SUCCEEDED"


def test_recovery_registry_rejects_arbitrary_actions(settings):
    plan = plan_recovery(
        action_id="run_shell_command",
        testcase_id="02",
        target="127.0.0.1",
        settings=settings,
        attempt=0,
    )
    assert plan.argv is None
    assert "approved recovery registry" in plan.reason


def test_invalid_model_recovery_action_is_rejected_before_fallback(manager, monkeypatch):
    testcase = TESTCASE_BY_ID["10"]
    initial = _result(status="TIMEOUT", timed_out=True)
    classification = Classification(
        "INCONCLUSIVE", "applicable", (testcase.condition,), (), (), (testcase.condition,),
        "unknown", "bounded command timeout", (), "INCOMPLETE",
        final_verdict=None, coverage_status="FAILED", coverage_reason="bounded command timeout",
    )
    events: list[str] = []
    monkeypatch.setattr(manager.db, "add_event", lambda _a, event, *_args, **_kwargs: events.append(event) or 1)
    monkeypatch.setattr(
        manager.ollama,
        "triage",
        lambda **_kwargs: TriageModel(
            testcase_id="10",
            observation_ids=[],
            interpretation="The registered banner action is not valid for Telnet.",
            suggested_action_id="collect_safe_banner",
            explanation="Use the testcase-specific retry instead.",
        ),
    )
    recovered = _result(
        status="COMPLETED",
        stdout=b"Nmap scan report for 127.0.0.1\n23/tcp open telnet\nNmap done: 1 IP address (1 host up) scanned in 0.01 seconds\n",
    )
    monkeypatch.setattr(manager, "_run_argv", lambda *_args, **_kwargs: recovered)
    command, final, _attempts, audits = manager._resolve_discrepancy(
        {"id": "assessment-test", "llm_enabled": 1},
        {"id": "target-test", "value": "127.0.0.1", "label": "loopback", "kind": "live", "host_count": 1},
        testcase,
        initial,
        classification,
        threading.Event(),
    )
    assert command is recovered
    assert final.final_verdict == "FOUND"
    assert "ai_action_rejected" in events
    assert audits[0]["validation_state"] == "REJECTED"


def test_recovery_skips_repeated_filtering_but_allows_timeout_retry():
    filtered = _result(status="COMPLETED", stdout=b"23/tcp filtered telnet\n")
    timeout = _result(status="TIMEOUT", timed_out=True)
    assert recovery_is_useful(testcase_id="10", result=filtered, reason="TCP filtering prevented applicability") is False
    assert recovery_is_useful(testcase_id="10", result=timeout, reason="bounded command timeout") is True


def test_timeout_recovery_uses_a_second_bounded_attempt_when_first_retry_fails(manager, monkeypatch):
    testcase = TESTCASE_BY_ID["10"]
    initial = _result(status="TIMEOUT", timed_out=True)
    classification = Classification(
        "INCONCLUSIVE", "applicable", (testcase.condition,), (), (), (testcase.condition,),
        "unknown", "bounded command timeout", (), "INCOMPLETE",
        final_verdict=None, coverage_status="FAILED", coverage_reason="bounded command timeout",
    )
    retries = iter([
        _result(status="TIMEOUT", timed_out=True),
        _result(
            status="COMPLETED",
            stdout=b"Nmap scan report for 127.0.0.1\n23/tcp open telnet\nNmap done: 1 IP address (1 host up) scanned in 0.01 seconds\n",
        ),
    ])
    monkeypatch.setattr(manager.db, "add_event", lambda *_args, **_kwargs: 1)
    monkeypatch.setattr(manager, "_run_argv", lambda *_args, **_kwargs: next(retries))
    command, final, attempts, audits = manager._resolve_discrepancy(
        {"id": "assessment-test", "llm_enabled": 0},
        {"id": "target-test", "value": "127.0.0.1", "label": "loopback", "kind": "live", "host_count": 1},
        testcase,
        initial,
        classification,
        threading.Event(),
    )
    assert command.status == "COMPLETED"
    assert final.final_verdict == "FOUND"
    assert len(attempts) == 3  # original timeout + two distinct bounded retries
    assert len(audits) == 2
