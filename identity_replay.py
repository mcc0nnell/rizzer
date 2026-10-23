#!/usr/bin/env python3
"""Read-only, deterministic correlation of synthetic application-identity events.

Not a live detector, credential client, containment engine, or attribution tool.
"""
import argparse
from collections import defaultdict
from datetime import datetime
import hashlib
import json
from pathlib import Path

SCHEMA = "rizzer.identity-replay.v0"
MAX_BYTES = 1_048_576
MAX_EVENTS = 4096
COMMON = {"ts", "event_id", "tenant", "app", "actor", "source", "kind"}
FIELDS = {
    "app_signin": {"result"},
    "graph_activity": {"operation"},
    "credential_added": {"target"},
    "role_grant": {"target", "role"},
}
OPERATIONS = {"directory_read", "mail_read", "secret_read"}
PRIVILEGED = {"Global Administrator", "Privileged Role Administrator"}


class ReplayError(ValueError):
    pass


def _identifier(value, name):
    if not isinstance(value, str) or not 1 <= len(value) <= 128 or not value.strip():
        raise ReplayError(f"{name} must be a nonempty string of at most 128 characters")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        raise ReplayError(f"{name} contains control characters")
    return value


def _parse_record(line, number):
    try:
        row = json.loads(line)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ReplayError(f"line {number}: invalid JSON") from exc
    if (not isinstance(row, dict) or not isinstance(row.get("kind"), str)
            or row["kind"] not in FIELDS):
        raise ReplayError(f"line {number}: unknown event kind or record")
    kind = row["kind"]
    if set(row) != COMMON | FIELDS[kind]:
        raise ReplayError(f"line {number}: unexpected or missing fields")
    for key in COMMON - {"ts", "kind"}:
        _identifier(row[key], f"line {number} {key}")
    stamp = _identifier(row["ts"], f"line {number} ts")
    try:
        dt = datetime.strptime(stamp, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise ReplayError(f"line {number}: ts must be UTC YYYY-MM-DDTHH:MM:SSZ") from exc
    # strptime accepts some noncanonical date spellings. Require one canonical format.
    if dt.strftime("%Y-%m-%dT%H:%M:%SZ") != stamp:
        raise ReplayError(f"line {number}: noncanonical UTC timestamp")
    if kind == "app_signin":
        if row["result"] not in ("success", "failure"):
            raise ReplayError(f"line {number}: invalid result")
    elif kind == "graph_activity":
        if not isinstance(row["operation"], str) or row["operation"] not in OPERATIONS:
            raise ReplayError(f"line {number}: invalid synthetic Graph operation")
    elif kind == "credential_added":
        _identifier(row["target"], f"line {number} target")
    elif kind == "role_grant":
        _identifier(row["target"], f"line {number} target")
        _identifier(row["role"], f"line {number} role")
    return row, dt


def load_records(path):
    if not path.is_file() or path.stat().st_size > MAX_BYTES:
        raise ReplayError(f"input must be a regular file no larger than {MAX_BYTES} bytes")
    try:
        contents = path.read_text(encoding="utf-8")
    except (UnicodeError, OSError) as exc:
        raise ReplayError("input must be readable UTF-8") from exc
    lines = contents.splitlines()
    if not 1 <= len(lines) <= MAX_EVENTS:
        raise ReplayError(f"input must contain 1..{MAX_EVENTS} event lines")
    parsed = [_parse_record(line, i) for i, line in enumerate(lines, 1)]
    ids = [row["event_id"] for row, _ in parsed]
    if len(set(ids)) != len(ids):
        raise ReplayError("duplicate event_id")
    return sorted(parsed, key=lambda item: (item[1], item[0]["event_id"]))


def correlate(parsed, window_seconds=900):
    if not isinstance(window_seconds, int) or not 1 <= window_seconds <= 3600:
        raise ReplayError("window_seconds must be 1..3600")
    signins = defaultdict(list)
    graph = defaultdict(list)
    changes = []
    for row, dt in parsed:
        key = (row["tenant"], row["app"], row["actor"])
        if row["kind"] == "app_signin" and row["result"] == "success":
            signins[key].append((row, dt))
        elif row["kind"] == "graph_activity":
            graph[key].append((row, dt))
        elif row["kind"] in ("credential_added", "role_grant"):
            changes.append((row, dt))

    findings = []
    for change, at in changes:
        key = (change["tenant"], change["app"], change["actor"])
        eligible = [(login, when) for login, when in signins[key]
                    if 0 <= (at - when).total_seconds() <= window_seconds]
        if not eligible:
            continue
        login, start = max(eligible, key=lambda pair: (pair[1], pair[0]["event_id"]))
        corroboration = sorted(
            row["event_id"] for row, when in graph[key]
            if start <= when <= at
        )
        self_elevation = (
            change["kind"] == "role_grant"
            and change["target"] == change["actor"]
            and change["role"] in PRIVILEGED
        )
        findings.append({
            "tenant": change["tenant"],
            "app": change["app"],
            "actor": change["actor"],
            "at": change["ts"],
            "signal": "self_privileged_role_grant" if self_elevation else change["kind"],
            "priority": "high" if self_elevation else "review",
            "event_ids": [login["event_id"], *corroboration, change["event_id"]],
            "source_pair": [login["source"], change["source"]],
            "assessment": "sequence_requires_human_review",
        })
    return findings


def receipt(parsed, window_seconds=900):
    rows = [row for row, _ in parsed]
    encoded = json.dumps(rows, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    return {
        "schema": SCHEMA,
        "scope": "offline_synthetic_only",
        "events": len(rows),
        "window_seconds": window_seconds,
        "normalized_input_sha256": hashlib.sha256(encoded).hexdigest(),
        "findings": correlate(parsed, window_seconds),
        "limits": {
            "attribution": "not_assessed",
            "compromise": "not_established",
            "coverage": "synthetic_sequences_only",
            "signature": "none",
        },
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path,
                        help="new output directory (never overwrites an existing path)")
    parser.add_argument("--window-seconds", type=int, default=900)
    args = parser.parse_args(argv)
    try:
        parsed = load_records(args.input)
        result = receipt(parsed, args.window_seconds)
        args.out.mkdir()
        output = args.out / "receipt.json"
        output.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n",
                          encoding="utf-8")
    except (ReplayError, OSError) as exc:
        parser.error(str(exc))
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
