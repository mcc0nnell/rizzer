#!/usr/bin/env python3
"""Bounded, opt-in reduction of a *trusted* IHB native fuzz campaign crash."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import tempfile
import time

def digest(data):
    return hashlib.sha256(data).hexdigest()

def fingerprint(log, row):
    """Conservative within-build fingerprint: sanitizer kind and harness location."""
    match = re.search(
        r"SUMMARY: AddressSanitizer: ([\w-]+) .*?harness\.(?:c|cc|cpp|cxx):(\d+)(?::\d+)? in ([^\n]+)",
        log)
    if match:
        return "asan:" + ":".join(match.groups())
    match = re.search(
        r"harness\.(?:c|cc|cpp|cxx):(\d+)(?::\d+)?:\d*:?\s*runtime error: ([^\n]+)", log)
    if match:
        return "ubsan:" + ":".join(match.groups())
    if row.get("timeout"):
        return "timeout"
    if row.get("signal"):
        return "signal:" + str(row["signal"])
    if row.get("exit"):
        return "exit:" + str(row["exit"])
    return None

def read_result(directory):
    try:
        summary = json.loads((directory / "summary.json").read_text())
        rows = (directory / "journal.jsonl").read_text().splitlines()
        if summary["executions"] != 1 or not rows or summary["findings"] != 1:
            return None, ""
        row = json.loads(rows[-1])
        logs = sorted((directory / "findings").glob("*.log"))
        if len(logs) != 1:
            return None, ""
        log = logs[0].read_text(errors="replace")
        return fingerprint(log, row), log
    except (OSError, ValueError, KeyError):
        return None, ""

def probe(binary, corpus, candidate, scratch, timeout_ms, remaining_seconds):
    # No untrusted inputs or untrusted executable: fork isolation is not a sandbox.
    scratch.mkdir()
    inp = scratch / "candidate.bin"
    inp.write_bytes(candidate)
    run = scratch / "run"
    run.mkdir()
    env = {"PATH": os.defpath, "HOME": str(scratch), "LANG": "C",
           "ASAN_OPTIONS": "abort_on_error=1:detect_leaks=0:symbolize=1",
           "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1"}
    argv = [str(binary), str(corpus), str(run), "1", "1",
            str(timeout_ms), "2", str(inp)]
    proc = subprocess.Popen(argv, cwd=scratch, env=env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            start_new_session=True)
    try:
        proc.wait(timeout=min(remaining_seconds, 2 + timeout_ms / 1000 + 3))
    except subprocess.TimeoutExpired:
        os.killpg(proc.pid, signal.SIGKILL)
        proc.wait()
        return None, ""
    if proc.returncode != 1:
        return None, ""
    return read_result(run)

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--campaign", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--max-probes", type=int, default=64)
    parser.add_argument("--seconds", type=int, default=20)
    args = parser.parse_args(argv)
    if not 1 <= args.max_probes <= 512 or not 1 <= args.seconds <= 300:
        parser.error("probes must be 1..512; seconds must be 1..300")
    campaign = args.campaign.resolve(strict=True)
    evidence = json.loads((campaign / "evidence.json").read_text())
    if evidence.get("schema") != "ihb.native-fuzz-evidence.v0" or evidence.get("status") not in (
            "asan_failure", "ubsan_failure", "input_timeout", "target_failure"):
        parser.error("requires a completed failing native-fuzz campaign")
    binaries = sorted((campaign / "findings").glob("*.bin"))
    logs = sorted((campaign / "findings").glob("*.log"))
    if len(binaries) != 1 or len(logs) != 1 or binaries[0].stem != logs[0].stem:
        parser.error("exactly one matching finding input/log required")
    binary = campaign / "ihb-native-fuzz"
    files = evidence.get("files", {})
    for file in (binary, binaries[0], logs[0]):
        if file.is_symlink() or not file.is_file() or file.stat().st_size > 20 * 1024 * 1024:
            parser.error("missing, linked or excessive campaign artifact")
        relative = str(file.relative_to(campaign))
        if files.get(relative) != digest(file.read_bytes()):
            parser.error("artifact hash does not match source evidence: " + relative)
    timeout_ms = int(evidence.get("timeout_ms", 0))
    if not 1 <= timeout_ms <= 60000:
        parser.error("invalid original timeout")
    original = binaries[0].read_bytes()
    if len(original) > 4096:
        parser.error("input too long")
    original_log = logs[0].read_text(errors="replace")
    original_journal = (campaign / "journal.jsonl").read_text().splitlines()
    original_row = json.loads(original_journal[-1])
    expected = fingerprint(original_log, original_row)
    if expected is None:
        parser.error("original failure cannot be classified conservatively")
    output = args.out.resolve()
    if output.exists():
        parser.error("output must be a new directory")
    output.mkdir(parents=True)
    (output / "original.bin").write_bytes(original)
    deadline = time.monotonic() + args.seconds
    count = 0
    records = []
    current = original
    last_log = original_log

    with tempfile.TemporaryDirectory(prefix="ihb-reduce-") as tmp:
        tmpdir = Path(tmp)
        # Replay the original first; never minimize an unconfirmed stale failure.
        def check(candidate, stage):
            nonlocal count, last_log
            if count >= args.max_probes or time.monotonic() >= deadline:
                return False, True
            work = tmpdir / f"try-{count:04d}"
            remaining = deadline - time.monotonic()
            if remaining < 0.1:
                return False, True
            # Each candidate execution is also individually supervised by the engine.
            actual, log = probe(binary, campaign / "seeds", candidate, work, timeout_ms, remaining)
            accepted = actual == expected
            records.append({"probe": count, "stage": stage, "bytes": len(candidate),
                            "sha256": digest(candidate), "fingerprint": actual,
                            "accepted": accepted})
            count += 1
            if accepted:
                last_log = log
            shutil.rmtree(work)
            return accepted, False

        confirmed, stopped = check(current, "confirm-original")
        if not confirmed:
            (output / "reduction.json").write_text(json.dumps({
                "status": "original_not_reproduced", "expected_fingerprint": expected,
                "probes": records}, indent=2) + "\n")
            return 2
        # ddmin: eliminate chunks, keeping the *same* failure signature.
        granularity = 2
        while len(current) and not stopped:
            chunk = max(1, (len(current) + granularity - 1) // granularity)
            shrank = False
            for start in range(0, len(current), chunk):
                candidate = current[:start] + current[start + chunk:]
                ok, stopped = check(candidate, "delete")
                if stopped:
                    break
                if ok:
                    current = candidate
                    shrank = True
                    granularity = max(2, granularity - 1)
                    break
            if stopped:
                break
            if not shrank:
                if granularity >= len(current):
                    break
                granularity = min(len(current), granularity * 2)
        # Greedy byte simplification, strictly descending to guarantee termination.
        for i in range(len(current)):
            if stopped:
                break
            for value in (0, 1, 2, 4, 7, 8, 16, 32, 64, 127, 128):
                if value >= current[i]:
                    continue
                candidate = current[:i] + bytes([value]) + current[i+1:]
                ok, stopped = check(candidate, "simplify")
                if stopped:
                    break
                if ok:
                    current = candidate
                    break

    (output / "minimized.bin").write_bytes(current)
    (output / "minimized.log").write_text(last_log)
    (output / "probes.jsonl").write_text("".join(json.dumps(x, sort_keys=True) + "\n" for x in records))
    report = {
        "schema": "ihb.native-fuzz-reduction.v1", "status": "confirmed",
        "origin_evidence_sha256": digest((campaign / "evidence.json").read_bytes()),
        "origin_binary_sha256": digest(binary.read_bytes()),
        "original_sha256": digest(original), "minimized_sha256": digest(current),
        "original_bytes": len(original), "minimized_bytes": len(current),
        "fingerprint": expected,
        "within_build_group_sha256": digest((digest(binary.read_bytes()) + "\n" + expected).encode()),
        "probes": count, "max_probes": args.max_probes, "seconds_budget": args.seconds,
        "budget_stopped": stopped, "heuristic_only": True,
        "warning": "Synthetic/trusted targets only; fingerprint groups may have collisions; no Blade admission."
    }
    (output / "reduction.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"status": report["status"], "original_bytes": len(original),
                      "minimized_bytes": len(current), "probes": count,
                      "fingerprint": expected}))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
