#!/usr/bin/env python3
"""Build and supervise the independent IHB native fuzzing engine (Linux)."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parent


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def dedicated_cgroup_memory():
    """Return local cgroup v2 memory events only for explicitly isolated workers.

    Direct host processes must never infer that another process's OOM is ours.
    The container wrapper opts in after applying a finite Docker memory limit.
    """
    if os.environ.get("IHB_FUZZ_CGROUP_DEDICATED") != "1":
        return None
    root = Path("/sys/fs/cgroup")
    try:
        limit_text = (root / "memory.max").read_text().strip()
        if not limit_text.isdecimal() or int(limit_text) < 1:
            return None
        pairs = dict(line.split() for line in (root / "memory.events.local").read_text().splitlines())
        return {"memory_max_bytes": int(limit_text),
                "oom_kill": int(pairs["oom_kill"]),
                "oom": int(pairs["oom"])}
    except (OSError, ValueError, KeyError):
        return None


def command(argv, out, name, timeout):
    env = {"PATH": os.defpath, "HOME": str(out), "LANG": "C",
           "ASAN_OPTIONS": "abort_on_error=1:detect_leaks=0:symbolize=1",
           "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1"}
    log = out / name
    with log.open("wb") as stream:
        proc = subprocess.Popen(argv, cwd=out, env=env, start_new_session=True,
                                stdout=stream, stderr=subprocess.STDOUT)
        timed_out = False
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            os.killpg(proc.pid, signal.SIGKILL)
            proc.wait()
    return {"argv": argv, "exit": proc.returncode, "timeout": timed_out,
            "log": name, "log_sha256": sha(log)}


def bounded(low, high):
    def parse(text):
        value = int(text)
        if not low <= value <= high:
            raise argparse.ArgumentTypeError(f"must be between {low} and {high}")
        return value
    return parse


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--source", type=Path, required=True)
    p.add_argument("--corpus", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--runs", type=bounded(1, 1000000), default=1000)
    p.add_argument("--seed", type=bounded(1, 2**64-1), default=1)
    p.add_argument("--seconds", type=bounded(1, 3600), default=30)
    p.add_argument("--timeout-ms", type=bounded(1, 60000), default=1000)
    p.add_argument("--replay", type=Path)
    p.add_argument("--banter", action="store_true",
                   help="opt-in Rizzer commentary on stderr; stdout stays JSON")
    args = p.parse_args(argv)
    if platform.system() != "Linux":
        p.error("prototype requires Linux fork/mmap/process groups")
    source = args.source.resolve(strict=True)
    corpus = args.corpus.resolve(strict=True)
    if source.suffix not in (".c", ".cc", ".cpp", ".cxx"):
        p.error("source must be C or C++")
    seeds = sorted(corpus.iterdir())
    if not 1 <= len(seeds) <= 4096:
        p.error("corpus needs 1..4096 seeds")
    if any(not x.is_file() or x.is_symlink() or x.stat().st_size > 4096 for x in seeds):
        p.error("seeds must be regular files no larger than 4096 bytes")
    replay = args.replay.resolve(strict=True) if args.replay else None
    if replay and (not replay.is_file() or replay.stat().st_size > 4096):
        p.error("invalid replay input")
    clang, cxx = shutil.which("clang"), shutil.which("clang++")
    if not clang or not cxx:
        p.error("Clang C/C++ toolchain required")
    out = args.out.resolve()
    if out.exists():
        p.error("output must be a new directory")
    out.mkdir(parents=True)
    if args.banter:
        from rizzer_voice import opening
        print(f"[rizzer] {opening(args.seed)}", file=sys.stderr)
    shutil.copyfile(ROOT / "engine.cc", out / "engine.cc")
    saved_source = out / ("harness" + source.suffix)
    shutil.copyfile(source, saved_source)
    (out / "seeds").mkdir()
    for i, seed in enumerate(seeds):
        shutil.copyfile(seed, out / "seeds" / f"seed-{i:04d}")
    if replay:
        shutil.copyfile(replay, out / "replay.bin")
    evidence = {"schema": "ihb.native-fuzz-evidence.v0", "engine": "ihb-native-v0",
                "platform": platform.platform(), "admission": "not_performed",
                "isolation": "fork state isolation; NOT a security sandbox",
                "source_sha256": sha(saved_source), "engine_sha256": sha(out / "engine.cc"),
                "runner_sha256": sha(__file__), "seed": args.seed,
                "requested_runs": args.runs, "seconds": args.seconds,
                "timeout_ms": args.timeout_ms,
                "compilers": {str(Path(x).resolve()): sha(x) for x in (clang, cxx)},
                "commands": []}
    flags = ["-g", "-O1", "-fno-omit-frame-pointer", "-fsanitize=address,undefined",
             "-fno-sanitize-recover=all"]
    commands = [
        ([clang, "--version"], "compiler.log"),
        ([clang if source.suffix == ".c" else cxx, *flags,
          "-fsanitize-coverage=trace-pc-guard", "-c", str(saved_source), "-o", "harness.o"], "harness-build.log"),
        ([cxx, "-std=c++17", *flags, "-Wall", "-Wextra", "-Werror", "-c", "engine.cc", "-o", "engine.o"], "engine-build.log"),
        ([cxx, *flags, "engine.o", "harness.o", "-o", "ihb-native-fuzz"], "link.log")]
    cgroup_before = dedicated_cgroup_memory()
    last_journal = None
    status = "build_failure"
    for cmd, name in commands:
        result = command(cmd, out, name, 60)
        evidence["commands"].append(result)
        if result["exit"] != 0 or result["timeout"]:
            break
    else:
        result = command([str(out / "ihb-native-fuzz"), str(out / "seeds"), str(out),
                          str(args.runs), str(args.seed), str(args.timeout_ms),
                          str(args.seconds), str(out / "replay.bin") if replay else "-"],
                         out, "engine.log", args.seconds + args.timeout_ms / 1000 + 5)
        evidence["commands"].append(result)
        if result["timeout"]:
            status = "supervisor_timeout"
        elif not (out / "summary.json").exists():
            status = "engine_failure"
        else:
            summary = json.loads((out / "summary.json").read_text())
            evidence["summary"] = summary
            if summary["findings"]:
                logs = "\n".join(x.read_text(errors="replace") for x in (out / "findings").glob("*.log"))
                journal = [json.loads(x) for x in (out / "journal.jsonl").read_text().splitlines()]
                last_journal = journal[-1]
                if journal[-1]["timeout"]:
                    status = "input_timeout"
                elif "ERROR: AddressSanitizer:" in logs:
                    status = "asan_failure"
                elif "runtime error:" in logs:
                    status = "ubsan_failure"
                else:
                    status = "target_failure"
            elif result["exit"] != 0:
                status = "engine_failure"
            else:
                status = "budget_exhausted" if summary["budget_exhausted"] else "no_failure_observed"
    cgroup_after = dedicated_cgroup_memory()
    if cgroup_before is not None and cgroup_after is not None:
        oom_kills = max(0, cgroup_after["oom_kill"] - cgroup_before["oom_kill"])
        evidence["cgroup_memory"] = {
            "memory_max_bytes": cgroup_after["memory_max_bytes"],
            "oom_kill_delta": oom_kills,
            "oom_event_delta": max(0, cgroup_after["oom"] - cgroup_before["oom"]),
            "scope": "dedicated_container_cgroup_v2_local"
        }
        # SIGKILL is not itself proof of OOM. Require an observed local
        # cgroup oom_kill counter increment as well as a failed child.
        if (oom_kills > 0 and status == "target_failure"
                and last_journal is not None and last_journal["signal"] == signal.SIGKILL):
            status = "cgroup_oom_kill"
    evidence["status"] = status
    evidence["files"] = {str(x.relative_to(out)): sha(x) for x in sorted(out.rglob("*")) if x.is_file()}
    (out / "evidence.json").write_text(json.dumps(evidence, indent=2) + "\n")
    print(json.dumps({"status": status, "evidence": str(out / "evidence.json")}))
    if args.banter:
        from rizzer_voice import verdict
        print(f"[rizzer] {verdict(status, args.seed)}", file=sys.stderr)
    return 0 if status == "no_failure_observed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
