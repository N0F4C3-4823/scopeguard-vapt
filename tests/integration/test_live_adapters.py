from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from app.classifier import classify_live
from app.commands import run_command
from app.live_adapters import adapter_for, build_command, capability_matrix
from app.registry import TESTCASES


class _HeaderFixtureHandler(BaseHTTPRequestHandler):
    mode = "positive"

    def version_string(self) -> str:
        return ""

    def do_GET(self) -> None:  # noqa: N802 - stdlib handler contract
        self.send_response(200)
        if self.mode == "positive":
            self.send_header("Server", "nginx/1.25.0")
        else:
            self.send_header("Server", "nginx")
            self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(b"controlled ScopeGuard response\n")

    def log_message(self, _format: str, *_args: object) -> None:
        return


@pytest.fixture
def live_http_service():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _HeaderFixtureHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        thread.join(timeout=2)
        server.server_close()


def _run(testcase_id: str, port: int):
    argv = build_command(testcase_id, "127.0.0.1", port_overrides={"80": port})
    assert argv is not None
    return run_command(argv, timeout_seconds=12, cwd=Path.cwd())


def test_live_http_positive_and_negative_conditions_use_real_subprocess(live_http_service):
    live_http_service.RequestHandlerClass.mode = "positive"
    version_positive = _run("27", live_http_service.server_address[1])
    headers_positive = _run("33", live_http_service.server_address[1])
    assert version_positive.status == "COMPLETED"
    assert headers_positive.status == "COMPLETED"
    assert classify_live(next(test for test in TESTCASES if test.id == "27"), version_positive).status == "FOUND"
    assert classify_live(next(test for test in TESTCASES if test.id == "33"), headers_positive).status == "FOUND"
    assert b"nginx/1.25.0" in version_positive.stdout
    assert b"http-headers" in headers_positive.stdout

    live_http_service.RequestHandlerClass.mode = "negative"
    version_negative = _run("27", live_http_service.server_address[1])
    headers_negative = _run("33", live_http_service.server_address[1])
    assert classify_live(next(test for test in TESTCASES if test.id == "27"), version_negative).status == "NOT_FOUND"
    assert classify_live(next(test for test in TESTCASES if test.id == "33"), headers_negative).status == "NOT_FOUND"
    assert b"X-Content-Type-Options: nosniff" in headers_negative.stdout


def test_reachability_only_adapter_never_becomes_security_finding(live_http_service):
    result = _run("19", live_http_service.server_address[1])
    classification = classify_live(next(test for test in TESTCASES if test.id == "19"), result)
    assert result.status == "COMPLETED"
    assert classification.status == "FOUND"
    assert classification.final_verdict == "FOUND"
    assert classification.observation_type == "exposure_inventory"
    assert classification.reportable_finding is False


def test_every_registered_live_adapter_executes_an_allowlisted_command(live_http_service):
    live_ids = [item["live"]["testcase_id"] for item in capability_matrix() if item["live"]["has_live_execution"]]
    assert len(live_ids) == 34
    assert set(live_ids) == {test.id for test in TESTCASES} - {"03", "14", "26", "28", "31", "32"}
    for testcase_id in live_ids:
        result = _run(testcase_id, live_http_service.server_address[1]) if testcase_id in {"27", "33"} else run_command(
            build_command(testcase_id, "127.0.0.1") or [], timeout_seconds=12, cwd=Path.cwd()
        )
        assert result.argv[0].split("/")[-1] in {"nmap", "curl", "dig", "python", "python3"}, (testcase_id, result)
        classification = classify_live(next(test for test in TESTCASES if test.id == testcase_id), result)
        assert classification.status in {"FOUND", "NOT_FOUND", "NA", "INCONCLUSIVE"}


def test_capability_only_conditions_have_no_live_command():
    for testcase_id in ("03", "14", "26", "28", "31", "32"):
        adapter = adapter_for(testcase_id)
        assert adapter.live_status == "CAPABILITY_ONLY"
        assert build_command(testcase_id, "127.0.0.1") is None
