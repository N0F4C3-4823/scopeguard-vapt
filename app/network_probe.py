from __future__ import annotations

import argparse
import ipaddress
import socket

PORTS = (21, 22, 23, 53, 80, 135, 139, 443, 445, 1433, 3389, 5900, 6379, 8080)


def resolve_host(target: str) -> list[str]:
    try:
        ipaddress.ip_address(target)
        return [target]
    except ValueError:
        pass
    if "/" in target:
        return []
    return sorted({item[4][0] for item in socket.getaddrinfo(target, None, type=socket.SOCK_STREAM)})


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True)
    parser.add_argument("--testcase-id", required=True)
    args = parser.parse_args()
    print(f"TARGET={args.target}")
    addresses = resolve_host(args.target)
    if not addresses:
        print("OBSERVATION=scope is a network range or did not resolve")
        print("STATUS=INCONCLUSIVE")
        return 0
    reachable: list[int] = []
    for address in addresses[:8]:
        for port in PORTS:
            family = socket.AF_INET6 if ":" in address else socket.AF_INET
            sock = socket.socket(family, socket.SOCK_STREAM)
            sock.settimeout(0.35)
            try:
                if sock.connect_ex((address, port)) == 0:
                    reachable.append(port)
            finally:
                sock.close()
    print(f"RESOLVED_ADDRESSES={','.join(addresses)}")
    print(f"REACHABLE_PORTS={','.join(str(port) for port in sorted(set(reachable)))}")
    print("OBSERVATION=network probe completed; no testcase-specific vulnerability predicate was asserted")
    print("STATUS=INCONCLUSIVE")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
