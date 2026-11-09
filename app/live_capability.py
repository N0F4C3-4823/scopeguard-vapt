"""Explicit fail-closed command for applicable checks needing another sensor."""

from __future__ import annotations

import argparse


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--testcase-id", required=True)
    parser.add_argument("--target", required=True)
    args = parser.parse_args()
    print(f"TARGET={args.target}")
    print(f"TESTCASE_ID={args.testcase_id}")
    print("OBSERVATION=the selected condition requires an authorized internal, Layer-2, wireless, inventory, credential-policy, or egress sensor not attached to this runner")
    print("EXECUTION=INCOMPLETE")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
