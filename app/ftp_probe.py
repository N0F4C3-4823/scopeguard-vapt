"""Bounded, read-only FTP anonymous-login probe."""

from __future__ import annotations

import argparse
import socket
import sys


def _read_reply(connection: socket.socket) -> list[bytes]:
    lines: list[bytes] = []
    multiline_code: bytes | None = None
    while True:
        line = b""
        while not line.endswith(b"\n"):
            chunk = connection.recv(1)
            if not chunk:
                break
            line += chunk
        if not line:
            break
        lines.append(line)
        if len(line) >= 4 and line[:3].isdigit():
            if line[3:4] == b"-":
                multiline_code = line[:3]
            elif multiline_code is None or (line[:3] == multiline_code and line[3:4] == b" "):
                break
        elif multiline_code is None:
            break
    return lines


def _send(connection: socket.socket, command: bytes) -> list[bytes]:
    connection.sendall(command + b"\r\n")
    return _read_reply(connection)


def probe(target: str, port: int, timeout: float) -> int:
    with socket.create_connection((target, port), timeout=timeout) as connection:
        connection.settimeout(timeout)
        responses = _read_reply(connection)
        user_response = _send(connection, b"USER anonymous")
        responses.extend(user_response)
        if any(line.startswith(b"331") for line in user_response):
            responses.extend(_send(connection, b"PASS IEUser@"))
        try:
            responses.extend(_send(connection, b"QUIT"))
        except (ConnectionError, OSError, TimeoutError):
            pass
        sys.stdout.buffer.write(b"".join(responses))
        sys.stdout.buffer.flush()
        return 0


def main() -> int:
    parser = argparse.ArgumentParser(prog="scopeguard-ftp-probe")
    parser.add_argument("--target", required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--timeout", type=float, default=5.0)
    args = parser.parse_args()
    return probe(args.target, args.port, max(0.1, min(args.timeout, 60.0)))


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ConnectionError, OSError, TimeoutError) as error:
        print(f"FTP control connection failed: {error}", file=sys.stderr)
        raise SystemExit(2) from None
