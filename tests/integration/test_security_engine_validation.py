from __future__ import annotations

import contextlib
import shutil
import socket
import socketserver
import subprocess
import tempfile
import threading
import time
from pathlib import Path

import pytest

from app.classifier import classify_live
from app.commands import run_command
from app.live_adapters import adapter_for, build_command, capability_matrix
from app.registry import TESTCASE_BY_ID, TESTCASES


class _ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


class _ThreadedUDPServer(socketserver.ThreadingMixIn, socketserver.UDPServer):
    allow_reuse_address = True
    daemon_threads = True


@contextlib.contextmanager
def tcp_service(handler, *, port: int = 0):
    server = _ThreadedTCPServer(("127.0.0.1", port), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        thread.join(timeout=2)
        server.server_close()


@contextlib.contextmanager
def udp_service(handler, *, port: int = 0):
    server = _ThreadedUDPServer(("127.0.0.1", port), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        thread.join(timeout=2)
        server.server_close()


class HttpHandler(socketserver.BaseRequestHandler):
    mode = "positive"

    def handle(self) -> None:
        request = self.request.recv(8192)
        if not request:
            return
        if self.mode == "positive":
            headers = b"Server: nginx/1.25.0\r\n"
            body = b"<html><title>Admin Console</title><body>controlled admin console</body></html>"
        elif self.mode == "negative":
            headers = b"Server: nginx\r\nX-Content-Type-Options: nosniff\r\n"
            body = b"<html><title>Public Home</title><body>controlled public page</body></html>"
        else:
            headers = b"Server: malformed\r\n"
            body = b"not an HTTP response"
        if self.mode == "malformed":
            self.request.sendall(b"not-an-http-response\r\n\r\n")
        else:
            response = b"HTTP/1.1 200 OK\r\n" + headers + f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode() + body
        try:
            self.request.sendall(response)
        except (ConnectionError, OSError):
            return


class TelnetHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        self.request.sendall(b"\xff\xfb\x01ScopeGuard Telnet\r\nlogin: ")
        self.request.settimeout(0.5)
        try:
            self.request.recv(128)
        except (TimeoutError, ConnectionError):
            pass


class FtpHandler(socketserver.BaseRequestHandler):
    mode = "positive"

    def _send(self, value: bytes) -> None:
        self.request.sendall(value)

    def handle(self) -> None:
        self.request.settimeout(3)
        self._send(b"220 ScopeGuard FTP fixture\r\n")
        data_listener: socket.socket | None = None
        try:
            while True:
                line = self.request.recv(1024)
                if not line:
                    return
                command = line.decode("ascii", errors="ignore").strip().upper()
                if command.startswith("USER "):
                    if self.mode == "positive" and command[5:].strip() == "ANONYMOUS":
                        self._send(b"331 Anonymous password required\r\n")
                    else:
                        self._send(b"530 Anonymous access denied\r\n")
                elif command.startswith("PASS ") and self.mode == "positive":
                    self._send(b"230 Login successful\r\n")
                elif command == "SYST":
                    self._send(b"215 UNIX Type: L8\r\n")
                elif command == "PWD":
                    self._send(b'257 "/" is current directory\r\n')
                elif command.startswith("TYPE"):
                    self._send(b"200 Type set\r\n")
                elif command == "FEAT" or command.startswith("OPTS "):
                    self._send(b"211-Features\r\n211 End\r\n")
                elif command == "PASV" and self.mode == "positive":
                    data_listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    data_listener.bind(("127.0.0.1", 0))
                    data_listener.listen(1)
                    port = data_listener.getsockname()[1]
                    self._send(f"227 Entering Passive Mode (127,0,0,1,{port // 256},{port % 256})\r\n".encode())
                elif (command.startswith("LIST") or command.startswith("NLST")) and self.mode == "positive":
                    self._send(b"150 Opening data connection\r\n")
                    if data_listener is not None:
                        data_listener.settimeout(2)
                        try:
                            client, _ = data_listener.accept()
                            client.sendall(b"-rw-r--r-- 1 root root 21 Jan 1 00:00 evidence.txt\r\n")
                            client.close()
                        except (OSError, TimeoutError):
                            pass
                        data_listener.close()
                        data_listener = None
                    self._send(b"226 Transfer complete\r\n")
                elif command == "QUIT":
                    self._send(b"221 Goodbye\r\n")
                    return
                else:
                    self._send(b"502 Command not implemented\r\n")
        except (ConnectionError, OSError, TimeoutError):
            return
        finally:
            if data_listener is not None:
                data_listener.close()


class RedisHandler(socketserver.BaseRequestHandler):
    mode = "positive"

    def handle(self) -> None:
        self.request.settimeout(3)
        try:
            data = self.request.recv(8192).upper()
        except (ConnectionError, TimeoutError):
            return
        if self.mode == "negative":
            self.request.sendall(b"-NOAUTH Authentication required.\r\n")
        elif b"INFO" in data:
            payload = b"# Server\r\nredis_version:7.2.0\r\nprocess_id:1\r\n"
            self.request.sendall(f"${len(payload)}\r\n".encode() + payload + b"\r\n")
        else:
            self.request.sendall(b"+PONG\r\n")


class VncHandler(socketserver.BaseRequestHandler):
    mode = "positive"

    def handle(self) -> None:
        self.request.settimeout(3)
        try:
            self.request.sendall(b"RFB 003.008\n")
            self.request.recv(32)
            if self.mode == "positive":
                self.request.sendall(b"\x01\x01")  # one security type: None
            else:
                self.request.sendall(b"\x01\x02")  # one security type: VNCAuth
        except (ConnectionError, TimeoutError):
            return


def _ber_length(length: int) -> bytes:
    if length < 128:
        return bytes([length])
    raw = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def _ber(tag: int, payload: bytes) -> bytes:
    return bytes([tag]) + _ber_length(len(payload)) + payload


def _ber_int(value: int) -> bytes:
    if value < 0:
        raw = value.to_bytes(4, "big", signed=True)
    else:
        raw = value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")
    if raw[0] & 0x80:
        raw = b"\x00" + raw
    return _ber(0x02, raw)


def _read_ber(data: bytes, offset: int) -> tuple[int, bytes, int] | None:
    if offset + 2 > len(data):
        return None
    tag = data[offset]
    length = data[offset + 1]
    cursor = offset + 2
    if length & 0x80:
        count = length & 0x7F
        if count == 0 or cursor + count > len(data):
            return None
        length = int.from_bytes(data[cursor : cursor + count], "big")
        cursor += count
    end = cursor + length
    if end > len(data):
        return None
    return tag, data[cursor:end], end


class SnmpHandler(socketserver.BaseRequestHandler):
    mode = "positive"

    def handle(self) -> None:
        data, request_socket = self.request
        outer = _read_ber(data, 0)
        if not outer:
            return
        body = outer[1]
        version = _read_ber(body, 0)
        community = _read_ber(body, version[2] if version else 0)
        pdu = _read_ber(body, community[2] if community else 0)
        request_id = 1
        if pdu:
            pdu_id = _read_ber(pdu[1], 0)
            if pdu_id:
                request_id = int.from_bytes(pdu_id[1], "big", signed=False)
        community_value = community[1] if community else b"public"
        oid = bytes.fromhex("2b06010201010100")
        if self.mode == "negative":
            varbinds = _ber(0x30, b"")
            pdu_body = _ber_int(request_id) + _ber_int(2) + _ber_int(0) + varbinds
        else:
            varbind = _ber(0x30, _ber(0x06, oid) + _ber(0x04, b"ScopeGuard SNMP fixture"))
            pdu_body = _ber_int(request_id) + _ber_int(0) + _ber_int(0) + _ber(0x30, varbind)
        response = _ber(0x30, _ber_int(0) + _ber(0x04, community_value) + _ber(0xA2, pdu_body))
        request_socket.sendto(response, self.client_address)


@contextlib.contextmanager
def ssh_service(weak: bool):
    sshd = shutil.which("sshd")
    host_key = Path("/etc/ssh/ssh_host_ed25519_key")
    if not sshd or not host_key.exists():
        pytest.skip("OpenSSH server host key is unavailable")
    privsep_dir = Path("/run/sshd")
    created_privsep_dir = False
    if not privsep_dir.exists():
        try:
            privsep_dir.mkdir(mode=0o755)
            created_privsep_dir = True
        except OSError as error:
            pytest.skip(f"OpenSSH privilege-separation directory is unavailable: {error}")
    with tempfile.TemporaryDirectory(prefix="scopeguard-sshd-") as directory:
        root = Path(directory)
        config = root / "sshd_config"
        kex = "KexAlgorithms +diffie-hellman-group1-sha1" if weak else ""
        config.write_text(
            "\n".join(
                [
                    "Port 0",
                    "ListenAddress 127.0.0.1",
                    f"HostKey {host_key}",
                    "UsePAM no",
                    "PasswordAuthentication no",
                    "KbdInteractiveAuthentication no",
                    "PermitRootLogin no",
                    "PidFile none",
                    kex,
                ]
            ),
            encoding="utf-8",
        )
        # Ask sshd to choose a free port, then read it from stderr is fragile;
        # use an allocated local socket and close it immediately before launch.
        probe = socket.socket()
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
        probe.close()
        config.write_text(config.read_text(encoding="utf-8").replace("Port 0", f"Port {port}"), encoding="utf-8")
        process = subprocess.Popen([sshd, "-D", "-e", "-f", str(config)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    stderr = process.stderr.read().decode(errors="replace") if process.stderr else ""
                    if weak:
                        pytest.skip(f"OpenSSH build does not support the weak controlled algorithm: {stderr[:200]}")
                    raise AssertionError(f"sshd failed to start: {stderr[:500]}")
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                        break
                except OSError:
                    time.sleep(0.05)
            else:
                raise AssertionError("sshd did not become reachable")
            yield port
        finally:
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=2)
            if created_privsep_dir:
                try:
                    privsep_dir.rmdir()
                except OSError:
                    pass


@contextlib.contextmanager
def tls_service():
    openssl = shutil.which("openssl")
    if not openssl:
        pytest.skip("openssl is unavailable")
    with tempfile.TemporaryDirectory(prefix="scopeguard-tls-") as directory:
        root = Path(directory)
        key = root / "key.pem"
        cert = root / "cert.pem"
        generated = subprocess.run(
            [openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=localhost", "-days", "1", "-keyout", str(key), "-out", str(cert)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            check=False,
            timeout=10,
        )
        if generated.returncode != 0:
            raise AssertionError(generated.stderr.decode(errors="replace"))
        probe = socket.socket()
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
        probe.close()
        process = subprocess.Popen(
            [openssl, "s_server", "-quiet", "-www", "-accept", str(port), "-cert", str(cert), "-key", str(key), "-tls1_2"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    raise AssertionError((process.stderr.read() if process.stderr else b"").decode(errors="replace"))
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                        break
                except OSError:
                    time.sleep(0.05)
            yield port
        finally:
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=2)


def execute(testcase_id: str, **ports: int):
    argv = build_command(testcase_id, "127.0.0.1", port_overrides=ports)
    assert argv is not None
    result = run_command(argv, timeout_seconds=15, cwd=Path.cwd())
    return result, classify_live(TESTCASE_BY_ID[testcase_id], result)


def test_controlled_http_positive_negative_and_malformed_conditions():
    with tcp_service(HttpHandler) as port:
        HttpHandler.mode = "positive"
        result, classification = execute("27", **{"80": port})
        assert result.status == "COMPLETED"
        assert classification.status == "FOUND"
        result, classification = execute("33", **{"80": port})
        assert classification.status == "FOUND"
        result, classification = execute("15", **{"80": port})
        assert classification.status == "FOUND"

        HttpHandler.mode = "negative"
        result, classification = execute("27", **{"80": port})
        assert classification.status == "NOT_FOUND"
        result, classification = execute("33", **{"80": port})
        assert classification.status == "NOT_FOUND"
        result, classification = execute("15", **{"80": port})
        assert classification.status == "INCONCLUSIVE"

        HttpHandler.mode = "malformed"
        result, classification = execute("27", **{"80": port})
        assert classification.status == "INCONCLUSIVE"
        assert (result.stdout or result.stderr) and classification.status not in {"FOUND", "NOT_FOUND"}


def test_controlled_ftp_and_redis_positive_negative_conditions():
    with tcp_service(FtpHandler, port=21) as ftp_port:
        FtpHandler.mode = "positive"
        result, classification = execute("18", **{"21": ftp_port})
        assert result.status == "COMPLETED"
        assert classification.status == "FOUND"
        FtpHandler.mode = "negative"
        result, classification = execute("18", **{"21": ftp_port})
        assert classification.status == "NOT_FOUND"

    with tcp_service(RedisHandler, port=6379) as redis_port:
        RedisHandler.mode = "positive"
        result, classification = execute("24", **{"6379": redis_port})
        assert result.status == "COMPLETED"
        assert classification.status == "FOUND"
        RedisHandler.mode = "negative"
        result, classification = execute("24", **{"6379": redis_port})
        assert classification.status == "NOT_FOUND"


def test_controlled_telnet_legacy_vnc_and_tcp_state_conditions():
    with tcp_service(TelnetHandler) as telnet_port:
        result, classification = execute("10", **{"23": telnet_port})
        assert result.status == "COMPLETED"
        assert classification.status == "FOUND"
        result, classification = execute("05", **{"23": telnet_port})
        assert classification.status == "FOUND"

    with tcp_service(HttpHandler) as modern_port:
        HttpHandler.mode = "negative"
        result, classification = execute("05", **{"80": modern_port})
        assert result.status == "COMPLETED"
        assert classification.status == "NOT_FOUND"

    with tcp_service(VncHandler, port=5900) as vnc_port:
        VncHandler.mode = "positive"
        result, classification = execute("37", **{"5900": vnc_port})
        assert result.status == "COMPLETED"
        assert classification.status == "FOUND"
        VncHandler.mode = "negative"
        result, classification = execute("37", **{"5900": vnc_port})
        assert classification.status == "NOT_FOUND"

    with tcp_service(HttpHandler) as http_port:
        HttpHandler.mode = "negative"
        result, classification = execute("12", **{"80": http_port})
        assert result.status == "COMPLETED"
        assert classification.status == "NOT_FOUND"
        result, classification = execute("19", **{"80": http_port})
        assert classification.status == "FOUND"
        assert classification.final_verdict == "FOUND"
        assert classification.reportable_finding is False


def test_controlled_snmp_ntp_and_tls_commands_preserve_uncertainty():
    with udp_service(SnmpHandler, port=161) as snmp_port:
        SnmpHandler.mode = "positive"
        result, classification = execute("13", **{"161/udp": snmp_port})
        assert result.status == "COMPLETED"
        assert classification.status in {"FOUND", "INCONCLUSIVE"}
        SnmpHandler.mode = "negative"
        result, classification = execute("13", **{"161/udp": snmp_port})
        assert classification.status != "NOT_FOUND"  # UDP refusal is not inferred from silence.

    class NtpHandler(socketserver.BaseRequestHandler):
        def handle(self) -> None:
            _request, request_socket = self.request
            response = bytearray(48)
            response[0] = 0x24
            response[1] = 2
            response[2] = 6
            response[3] = 0xEC
            request_socket.sendto(bytes(response), self.client_address)

    with udp_service(NtpHandler, port=123) as ntp_port:
        result, classification = execute("01", **{"123/udp": ntp_port})
        assert result.status == "COMPLETED"
        assert classification.status == "INCONCLUSIVE"

    with tls_service() as tls_port:
        result, classification = execute("08", **{"443": tls_port})
        assert result.status == "COMPLETED"
        assert classification.status in {"NOT_FOUND", "INCONCLUSIVE"}


def test_controlled_ssh_positive_negative_and_host_reachability():
    with ssh_service(weak=False) as ssh_port:
        result, classification = execute("34", **{"22": ssh_port})
        assert result.status == "COMPLETED"
        assert classification.status in {"NOT_FOUND", "INCONCLUSIVE"}
        result, classification = execute("39", **{"22": ssh_port})
        assert classification.status in {"NOT_FOUND", "INCONCLUSIVE"}
    with contextlib.ExitStack() as stack:
        try:
            weak_port = stack.enter_context(ssh_service(weak=True))
        except pytest.skip.Exception:
            weak_port = None
        if weak_port is not None:
            result, classification = execute("34", **{"22": weak_port})
            assert result.status == "COMPLETED"
            assert classification.status == "FOUND"
            result, classification = execute("39", **{"22": weak_port})
            assert classification.status == "FOUND"
    result, classification = execute("35")
    assert result.status == "COMPLETED"
    assert classification.status == "FOUND"


def test_every_matrix_entry_has_an_explicit_controlled_validation_contract():
    matrix = capability_matrix()
    assert len(matrix) == len(TESTCASES) == 40
    for entry in matrix:
        live = entry["live"]
        assert live["controlled_validation"], entry["testcase"]["id"]
        if live["live_status"] == "CAPABILITY_ONLY":
            assert live["has_live_execution"] is False
        else:
            assert live["has_live_execution"] is True
        assert adapter_for(entry["testcase"]["id"]).testcase_id == entry["testcase"]["id"]
