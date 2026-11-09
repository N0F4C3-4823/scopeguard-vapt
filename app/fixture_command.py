from __future__ import annotations

import argparse
import sys
import time


def status_for(testcase_id: str, scenario: str) -> str:
    if scenario == "positive":
        return "FOUND"
    if scenario == "negative":
        return "NOT_FOUND"
    if scenario == "na":
        return "NA"
    if scenario in {"failure", "timeout"}:
        return "INCONCLUSIVE"
    cycle = int(testcase_id) % 4
    return {0: "INCONCLUSIVE", 1: "FOUND", 2: "NOT_FOUND", 3: "NA"}[cycle]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--testcase-id", required=True)
    parser.add_argument("--scenario", required=True)
    parser.add_argument("--target", required=True)
    args = parser.parse_args()
    if args.scenario == "timeout":
        time.sleep(5)
        return 0
    if args.scenario == "failure":
        print(f"fixture execution failed for testcase {args.testcase_id}", file=sys.stderr)
        return 2
    status = status_for(args.testcase_id, args.scenario)
    print(f"TESTCASE_ID={args.testcase_id}")
    print(f"TARGET={args.target}")
    if status == "FOUND":
        print(f"OBSERVATION_ID=obs-{args.testcase_id}-positive")
        print("OBSERVATION=controlled fixture positive predicate established")
    elif status == "NOT_FOUND":
        print(f"OBSERVATION_ID=obs-{args.testcase_id}-negative")
        print("OBSERVATION=controlled fixture negative predicate established")
    elif status == "NA":
        print(f"APPLICABILITY=fixture contract marks testcase {args.testcase_id} not applicable")
    else:
        print("OBSERVATION=controlled fixture deliberately returned insufficient evidence")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
