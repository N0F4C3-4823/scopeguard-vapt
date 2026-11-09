"""Small allowlisted protocol probes used when an NSE script hides a reply.

This module intentionally exposes one fixed, read-only Redis INFO operation.
It is invoked through the structured command runner, never through a shell,
and writes only bytes received from the target service to stdout.
"""

from __future__ import annotations

import argparse
import socket
import sys


def redis_info(target: str, port: int, timeout: float) -> int:
    request = b"*1\r\n$4\r\nINFO\r\n"
    with socket.create_connection((target, port), timeout=timeout) as connection:
        connection.settimeout(timeout)
        connection.sendall(request)
        chunks: list[bytes] = []
        while True:
            chunk = connection.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
            if len(b"".join(chunks)) >= 65536:
                break
    response = b"".join(chunks)
    if not response:
        return 2
    sys.stdout.buffer.write(response)
    sys.stdout.buffer.flush()
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(prog="scopeguard-protocol-probe")
    subparsers = parser.add_subparsers(dest="operation", required=True)
    redis_parser = subparsers.add_parser("redis-info")
    redis_parser.add_argument("--target", required=True)
    redis_parser.add_argument("--port", required=True, type=int)
    redis_parser.add_argument("--timeout", type=float, default=3.0)
    args = parser.parse_args()
    if args.operation == "redis-info":
        return redis_info(args.target, args.port, max(0.1, min(args.timeout, 60.0)))
    return 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, TimeoutError) as error:
        print(f"protocol probe failed: {error}", file=sys.stderr)
        raise SystemExit(2) from None
