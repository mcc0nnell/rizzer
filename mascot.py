#!/usr/bin/env python3
"""Rizzer's opt-in, read-only voice for native-fuzzer evidence.

Does not run a campaign, rewrite evidence, or declare vulnerabilities.
"""
# SPDX-License-Identifier: Apache-2.0
import argparse
import json
from pathlib import Path

MAX_REPORT_BYTES = 1024 * 1024
EXPECTED_SCHEMA = "ihb.native-fuzz-evidence.v0"

# One deterministic line per recorded outcome; keep the qualifier in the line.
QUIPS = {
    "no_failure_observed": (
        "No crash this round? Cute. That's a bounded observation, not a clean bill of health."
    ),
    "budget_exhausted": (
        "We're out of runway, darling—not out of possible bugs. Preserve the evidence."
    ),
    "asan_failure": (
        "Well, hello, AddressSanitizer. Interesting candidate; replay and assess before calling it a vulnerability."
    ),
    "ubsan_failure": (
        "Undefined behavior just walked in wearing my second collar. Replay the candidate and verify it."
    ),
    "target_failure": (
        "That target exit got my attention. Reproduce and classify it; don't announce a security finding yet."
    ),
    "input_timeout": (
        "This input ghosted the deadline. A timeout is not proof of a vulnerability."
    ),
    "supervisor_timeout": (
        "The campaign ran out of time. That's an execution limit, not a target verdict."
    ),
    "build_failure": (
        "The compiler said no. Fix the harness or toolchain before making any claims."
    ),
    "engine_failure": (
        "My engine tripped over its own collar. That's infrastructure trouble, not a target finding."
    ),
    "cgroup_oom_kill": (
        "Memory budget exceeded. Resource exhaustion alone isn't a memory-safety finding."
    ),
}


def render_evidence(data):
    """Return a deterministic, truthful human line from an imported v0 report."""
    if not isinstance(data, dict) or data.get("schema") != EXPECTED_SCHEMA:
        raise ValueError("unsupported evidence schema (expected the imported v0 format)")
    status = data.get("status")
    if not isinstance(status, str) or status not in QUIPS:
        raise ValueError("missing or unsupported recorded campaign status")
    return f"RIZZER // {status}\n{QUIPS[status]}"


def read_evidence(path):
    """Read a bounded JSON report without changing it."""
    if path.is_symlink() or not path.is_file():
        raise ValueError("evidence must be an existing regular file (no symlink)")
    if path.stat().st_size > MAX_REPORT_BYTES:
        raise ValueError("evidence file exceeds 1 MiB")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("evidence must be UTF-8 JSON") from exc


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--demo", action="store_true", help="show character voice; no results claimed")
    modes.add_argument("--evidence", type=Path, help="display commentary for an existing evidence.json")
    args = parser.parse_args(argv)
    if args.demo:
        print("RIZZER // MEET THE MASCOT\nTwo collars. Zero trust. And excellent taste in reproducible experiments.")
        return 0
    try:
        print(render_evidence(read_evidence(args.evidence)))
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
