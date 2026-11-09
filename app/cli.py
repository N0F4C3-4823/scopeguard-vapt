from __future__ import annotations

import argparse

import uvicorn

from .config import load_settings
from .db import Database
from .registry import validate_registry


def self_test() -> int:
    settings = load_settings()
    settings.ensure_dirs()
    Database(settings.db_path)
    validate_registry()
    print(f"ScopeGuard self-test passed: registry=40 database={settings.db_path}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(prog="scopeguard")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("self-test")
    serve = subparsers.add_parser("serve")
    serve.add_argument("--host", default=None)
    serve.add_argument("--port", type=int, default=None)
    args = parser.parse_args()
    if args.command == "self-test":
        return self_test()
    settings = load_settings()
    uvicorn.run(
        "app.main:app",
        host=args.host or settings.host,
        port=args.port or settings.port,
        reload=False,
        log_level="info",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
