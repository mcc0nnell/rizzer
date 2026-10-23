#!/usr/bin/env python3
"""Read-only, local hash consistency check for Rizzer v0 campaign evidence.

This verifies integrity against an *unsigned* manifest, not authenticity,
compiler behavior, isolation, or the security impact of any observed fault.
"""
# SPDX-License-Identifier: Apache-2.0
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re

SCHEMA = "ihb.native-fuzz-evidence.v0"
MAX_MANIFEST_BYTES = 8 * 1024 * 1024
HEX_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def _unique_pairs(pairs):
    data = {}
    for key, value in pairs:
        if key in data:
            raise ValueError(f"duplicate JSON key: {key!r}")
        data[key] = value
    return data


def _relative_path(name):
    if not isinstance(name, str) or not name or "\\" in name:
        raise ValueError("invalid manifest path")
    path = PurePosixPath(name)
    if path.is_absolute() or path.as_posix() != name or ".." in path.parts:
        raise ValueError(f"unsafe manifest path: {name!r}")
    if name == "evidence.json":
        raise ValueError("evidence.json must not self-hash")
    return path


def _hash_file(root, path):
    candidate = root
    for part in path.parts:
        candidate = candidate / part
        if candidate.is_symlink():
            raise ValueError(f"symlink not allowed: {path.as_posix()}")
    if not candidate.is_file():
        raise ValueError(f"missing or non-regular artifact: {path.as_posix()}")
    digest = hashlib.sha256()
    with candidate.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def verify(campaign):
    """Return a result for a completed, locally trusted campaign directory."""
    root = Path(campaign)
    if root.is_symlink() or not root.is_dir():
        raise ValueError("campaign must be a real directory, not a symlink")
    root = root.resolve(strict=True)
    manifest = root / "evidence.json"
    if manifest.is_symlink() or not manifest.is_file():
        raise ValueError("missing or symlinked evidence.json")
    if manifest.stat().st_size > MAX_MANIFEST_BYTES:
        raise ValueError("evidence manifest exceeds 8 MiB")
    try:
        data = json.loads(manifest.read_text(encoding="utf-8"), object_pairs_hook=_unique_pairs)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("evidence must be UTF-8 JSON") from exc
    if not isinstance(data, dict) or data.get("schema") != SCHEMA:
        raise ValueError("unsupported evidence schema")
    files = data.get("files")
    if not isinstance(files, dict) or not files:
        raise ValueError("evidence has no artifact hash manifest")
    validated = {}
    for name, expected in files.items():
        path = _relative_path(name)
        if not isinstance(expected, str) or not HEX_SHA256.fullmatch(expected):
            raise ValueError(f"invalid SHA-256 for artifact: {name!r}")
        validated[name] = (path, expected)
    if "engine.cc" not in validated or data.get("engine_sha256") != validated["engine.cc"][1]:
        raise ValueError("engine source digest disagrees with file manifest")
    harnesses = [name for name in validated if name in
                 ("harness.c", "harness.cc", "harness.cpp", "harness.cxx")]
    if len(harnesses) != 1 or data.get("source_sha256") != validated[harnesses[0]][1]:
        raise ValueError("harness source digest disagrees with file manifest")
    mismatches = []
    for name, (path, expected) in sorted(validated.items()):
        try:
            actual = _hash_file(root, path)
        except (OSError, ValueError) as exc:
            mismatches.append(f"{name}: {exc}")
        else:
            if actual != expected:
                mismatches.append(f"{name}: SHA-256 mismatch")
    return {"status": "hashes_match" if not mismatches else "mismatch",
            "checked_files": len(validated), "errors": mismatches,
            "scope": "unsigned local manifest consistency only"}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--campaign", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        report = verify(args.campaign)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    print(json.dumps(report, sort_keys=True))
    return 0 if report["status"] == "hashes_match" else 1


if __name__ == "__main__":
    raise SystemExit(main())
