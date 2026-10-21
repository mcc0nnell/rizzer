#!/usr/bin/env python3
"""Local-only negative controls for an operator-run disposable IHB container.

This is a smoke test of observed restrictions, never a sandbox certification.
"""
import errno
import json
import os
from pathlib import Path
import socket
import sys

def check_restrictions():
    checks = {}
    checks["nonroot_uid"] = os.getuid() != 0
    try:
        for line in Path("/proc/self/status").read_text().splitlines():
            if line.startswith("CapEff:"):
                checks["effective_caps_dropped"] = int(line.split()[1], 16) == 0
                break
    except OSError:
        checks["effective_caps_dropped"] = False

    try:
        Path("/etc/ihb-should-not-write").write_text("no")
    except OSError as exc:
        checks["root_filesystem_readonly"] = exc.errno in (errno.EROFS, errno.EACCES)
    else:
        checks["root_filesystem_readonly"] = False

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.3)
            s.connect(("198.51.100.1", 9))  # RFC 5737 TEST-NET-2 address
    except OSError as exc:
        checks["external_network_denied"] = exc.errno in (
            errno.ENETUNREACH, errno.EHOSTUNREACH, errno.EACCES, errno.EPERM)
    else:
        checks["external_network_denied"] = False

    try:
        checks["memory_limit_mib"] = int(Path("/sys/fs/cgroup/memory.max").read_text()) // (1024*1024)
        checks["pids_limit"] = int(Path("/sys/fs/cgroup/pids.max").read_text())
    except (OSError, ValueError):
        checks["memory_limit_mib"] = -1
        checks["pids_limit"] = -1
    checks["memory_limit_enforced"] = checks["memory_limit_mib"] == 512
    checks["pids_limit_enforced"] = checks["pids_limit"] == 64
    checks["host_home_not_mounted"] = not Path("/home/commander/.ssh").exists()
    ok = all(value for key, value in checks.items() if key not in ("memory_limit_mib", "pids_limit"))
    return {"schema": "ihb.container-restriction-probe.v0", "passed": ok, "checks": checks,
            "assurance": "smoke test only, not security attestation"}

if __name__ == "__main__":
    report = check_restrictions()
    print(json.dumps(report, sort_keys=True, indent=2))
    raise SystemExit(0 if report["passed"] else 1)
