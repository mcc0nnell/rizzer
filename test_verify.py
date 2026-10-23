"""Offline evidence-manifest consistency tests, no compiler or native binaries."""
# SPDX-License-Identifier: Apache-2.0
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from verify import verify


def digest(blob):
    return hashlib.sha256(blob).hexdigest()


class VerifyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.artifacts = {"engine.cc": b"engine", "harness.c": b"harness", "summary.json": b"{}"}
        for name, blob in self.artifacts.items():
            (self.root / name).write_bytes(blob)
        self.data = {"schema": "ihb.native-fuzz-evidence.v0",
                     "engine_sha256": digest(b"engine"),
                     "source_sha256": digest(b"harness"),
                     "files": {name: digest(blob) for name, blob in self.artifacts.items()}}
        self.write_manifest()

    def write_manifest(self):
        (self.root / "evidence.json").write_text(json.dumps(self.data))

    def test_clean_manifest_and_non_mutation(self):
        before = (self.root / "evidence.json").read_bytes()
        result = verify(self.root)
        self.assertEqual(result["status"], "hashes_match")
        self.assertEqual(result["checked_files"], 3)
        self.assertEqual(result["errors"], [])
        self.assertEqual((self.root / "evidence.json").read_bytes(), before)

    def test_modified_or_missing_file_fails(self):
        (self.root / "summary.json").write_bytes(b"{tampered}")
        self.assertEqual(verify(self.root)["status"], "mismatch")
        (self.root / "summary.json").unlink()
        self.assertEqual(verify(self.root)["status"], "mismatch")

    def test_symlink_file_and_directory_fail(self):
        (self.root / "summary.json").unlink()
        (self.root / "summary.json").symlink_to("engine.cc")
        self.assertEqual(verify(self.root)["status"], "mismatch")
        (self.root / "summary.json").unlink()
        (self.root / "inside").mkdir()
        (self.root / "inside" / "blob").write_bytes(b"blob")
        (self.root / "indirect").symlink_to("inside", target_is_directory=True)
        self.data["files"]["indirect/blob"] = digest(b"blob")
        self.write_manifest()
        self.assertEqual(verify(self.root)["status"], "mismatch")

    def test_rejects_traversal_and_unexpected_schema(self):
        for path in ("../escape", "/tmp/escape", "./engine.cc", "x//y", "evidence.json"):
            with self.subTest(path=path):
                self.data["files"][path] = digest(b"x")
                self.write_manifest()
                with self.assertRaises(ValueError):
                    verify(self.root)
                del self.data["files"][path]
        self.data["schema"] = "rizzer.future.v1"
        self.write_manifest()
        with self.assertRaises(ValueError):
            verify(self.root)

    def test_requires_consistent_source_hashes(self):
        self.data["source_sha256"] = digest(b"wrong")
        self.write_manifest()
        with self.assertRaisesRegex(ValueError, "harness"):
            verify(self.root)

    def test_rejects_duplicate_json_keys(self):
        (self.root / "evidence.json").write_text('{"schema":"x","schema":"y"}')
        with self.assertRaisesRegex(ValueError, "duplicate"):
            verify(self.root)


if __name__ == "__main__":
    unittest.main()
