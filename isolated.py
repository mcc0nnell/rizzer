#!/usr/bin/env python3
"""Run a native IHB campaign in a disposable, resource-bounded Docker container."""
import argparse
import os
import re
from pathlib import Path
import subprocess

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--image", required=True, help="Locally preapproved digest-pinned image with Python, Clang and compiler-rt")
    parser.add_argument("--memory-mb", type=int, default=1024)
    parser.add_argument("--runs", type=int, default=1000)
    parser.add_argument("--seconds", type=int, default=30)
    parser.add_argument("--seed", type=int, default=1)
    args = parser.parse_args()
    if not 256 <= args.memory_mb <= 16384:
        parser.error("memory-mb must be 256..16384")
    if not 1 <= args.runs <= 1000000 or not 1 <= args.seconds <= 3600 or not 1 <= args.seed < 2**64:
        parser.error("invalid campaign bounds")
    if not re.fullmatch(r"(?:[A-Za-z0-9._:/-]+@)?sha256:[0-9a-f]{64}", args.image):
        parser.error("image must be an immutable local image ID or digest-pinned repository reference")
    root = Path(__file__).resolve().parent
    source, corpus, out = args.source.resolve(strict=True), args.corpus.resolve(strict=True), args.out.resolve()
    if out == root or out.is_relative_to(root) or out == corpus or out.is_relative_to(corpus):
        parser.error("output must be outside the mounted source and corpus trees")
    if out.exists():
        parser.error("output must not exist")
    if not source.is_file() or not corpus.is_dir():
        parser.error("source must be a file and corpus a directory")
    out.mkdir(mode=0o700, parents=True)
    uid, gid = os.getuid(), os.getgid()
    command = [
        "docker", "run", "--rm", "--pull=never", "--network=none", "--read-only",
        "--cap-drop=ALL", "--security-opt=no-new-privileges",
        "--pids-limit=64", "--memory", f"{args.memory_mb}m",
        "--memory-swap", f"{args.memory_mb}m", "--cpus=2",
        "--user", f"{uid}:{gid}", "--tmpfs", "/tmp:rw,nosuid,nodev,size=64m",
        "--mount", f"type=bind,src={root},dst=/work,readonly",
        "--mount", f"type=bind,src={source},dst=/input/harness{source.suffix},readonly",
        "--mount", f"type=bind,src={corpus},dst=/seeds,readonly",
        "--mount", f"type=bind,src={out},dst=/output",
        "--workdir", "/work", "--env", "HOME=/tmp",
        "--env", "IHB_FUZZ_CGROUP_DEDICATED=1",
        "--entrypoint=python3", args.image, "/work/run.py", "--source", f"/input/harness{source.suffix}",
        "--corpus", "/seeds", "--out", "/output/campaign",
        "--runs", str(args.runs), "--seconds", str(args.seconds), "--seed", str(args.seed),
    ]
    print("Container campaign output:", out / "campaign", flush=True)
    return subprocess.run(command, check=False).returncode

if __name__ == "__main__":
    raise SystemExit(main())
