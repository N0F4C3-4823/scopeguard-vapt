import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from app.commands import CommandResult, run_command
from app.discovery import (
    DiscoverySnapshot,
    PortObservation,
    build_discovery_commands,
    parse_discovery_result,
    service_gate,
)


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802 - stdlib handler contract
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"controlled discovery service")

    def log_message(self, _format, *_args):
        return


@pytest.fixture
def live_http_service():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        thread.join(timeout=2)
        server.server_close()


def _result(output: bytes, *, status: str = "COMPLETED", exit_code: int | None = 0) -> CommandResult:
    return CommandResult(
        id="discovery-test",
        argv=("nmap", "-Pn", "127.0.0.1"),
        displayed_command="nmap -Pn 127.0.0.1",
        cwd=str(Path.cwd()),
        started_at="2026-01-01T00:00:00+00:00",
        ended_at="2026-01-01T00:00:01+00:00",
        exit_code=exit_code,
        timed_out=status == "TIMEOUT",
        stdout=output,
        stderr=b"",
        status=status,
        tool_version="nmap fixture",
    )


def test_discovery_commands_keep_tcp_and_udp_protocols_explicit():
    tcp, udp = build_discovery_commands(
        "127.0.0.1",
        host_timeout_seconds=12,
        max_retries=2,
        script_timeout_seconds=30,
        tcp_ports=(12345,),
        udp_ports=(123,),
    )
    assert "-sT" in tcp and "T:12345" in tcp
    assert "-sU" in udp and "U:123" in udp


def test_discovery_parser_preserves_protocol_and_requires_nmap_completion():
    result = _result(
        b"Nmap scan report for 127.0.0.1\nHost is up.\n\nPORT      STATE SERVICE\n12345/tcp open  unknown\nNmap done: 1 IP address (1 host up) scanned in 0.01 seconds\n"
    )
    observations, complete, failure = parse_discovery_result(result, "tcp")
    assert complete is True
    assert failure is None
    assert observations[0].protocol == "tcp"
    assert observations[0].state == "open"

    incomplete, complete, failure = parse_discovery_result(_result(b"12345/tcp open unknown\n"), "tcp")
    assert incomplete
    assert complete is False
    assert "completion" in failure


def test_service_gate_preserves_filtered_tcp_as_inconclusive():
    closed = DiscoverySnapshot(
        target="127.0.0.1",
        tcp=(PortObservation(23, "tcp", "closed", "telnet"),),
        udp=(),
        tcp_complete=True,
        udp_complete=False,
        host_state="HOST_REACHABLE",
    )
    assert service_gate("10", closed) == (
        "NA",
        "The complete TCP discovery scan explicitly closed the required service ports: 23",
    )
    filtered = DiscoverySnapshot(
        target="127.0.0.1",
        tcp=(PortObservation(23, "tcp", "filtered", "telnet"),),
        udp=(),
        tcp_complete=True,
        udp_complete=False,
        host_state="HOST_INDETERMINATE",
    )
    assert service_gate("10", filtered) == (
        "INCONCLUSIVE",
        "The complete TCP discovery scan showed filtering on every required service port; the application-layer condition could not be tested from this vantage point",
    )
    assert service_gate("10", closed) is not None


def test_actual_nmap_discovery_against_controlled_local_tcp_service(live_http_service):
    port = live_http_service.server_address[1]
    tcp, _ = build_discovery_commands(
        "127.0.0.1",
        host_timeout_seconds=15,
        max_retries=1,
        script_timeout_seconds=30,
        tcp_ports=(port,),
        udp_ports=(port,),
    )
    result = run_command(tcp, timeout_seconds=20, cwd=Path.cwd())
    assert result.status == "COMPLETED"
    observations, complete, failure = parse_discovery_result(result, "tcp")
    assert complete is True, failure
    assert any(item.port == port and item.state == "open" and item.protocol == "tcp" for item in observations)
