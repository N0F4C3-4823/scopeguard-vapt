"""Read-only applicability evidence command used for scope-based NA results."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .registry import TESTCASE_BY_ID


def main() -> int:
    parser = argparse.ArgumentParser(description="Print recorded ScopeGuard applicability facts")
    parser.add_argument("--authorization-file", required=True)
    parser.add_argument("--testcase-id", required=True)
    args = parser.parse_args()
    testcase = TESTCASE_BY_ID.get(args.testcase_id)
    if testcase is None:
        raise SystemExit(f"Unknown testcase ID: {args.testcase_id}")
    authorization_path = Path(args.authorization_file).resolve()
    if not authorization_path.is_file() or authorization_path.is_symlink():
        raise SystemExit("Authorization record is unavailable")
    record = json.loads(authorization_path.read_text(encoding="utf-8"))
    facts = {
        "assessment_id": record.get("assessment_id"),
        "assessment_type": record.get("assessment_type"),
        "authorized": bool(record.get("authorized")),
        "capabilities": record.get("capabilities", []),
        "permissions": record.get("permissions", []),
        "credentials_available": bool(record.get("credentials_available")),
        "testcase_id": testcase.id,
        "condition": testcase.condition,
        "required_vantage": list(testcase.required_vantage),
        "required_capabilities": list(testcase.required_capabilities),
        "required_permissions": list(testcase.required_permissions),
        "requires_credentials": testcase.requires_credentials,
        "source": str(authorization_path),
    }
    print(json.dumps(facts, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
