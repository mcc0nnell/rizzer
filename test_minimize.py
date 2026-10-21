"""Acceptance tests for the opt-in native crash reducer."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent

class MinimizerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name)
        (self.home / "corpus").mkdir()

    def command(self, *args):
        return subprocess.run([sys.executable, *map(str, args)],
                              capture_output=True, text=True, timeout=120)

    def test_reduce_replay_and_keep_original_evidence_intact(self):
        (self.home / "corpus/seed").write_bytes(b"\x56\x00\x00")
        campaign = self.home / "campaign"
        found = self.command(ROOT / "run.py", "--source", ROOT / "fixtures/buggy.c",
                             "--corpus", self.home / "corpus", "--out", campaign,
                             "--runs", "1", "--seed", "17", "--seconds", "10")
        self.assertEqual(found.returncode, 1, found.stderr)
        self.assertEqual(json.loads((campaign / "evidence.json").read_text())["status"], "asan_failure")
        digest = hashlib.sha256((campaign / "evidence.json").read_bytes()).hexdigest()
        reduced = self.home / "reduced"
        result = self.command(ROOT / "minimize.py", "--campaign", campaign, "--out",
                              reduced, "--max-probes", "64", "--seconds", "10")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        report = json.loads((reduced / "reduction.json").read_text())
        self.assertEqual(report["status"], "confirmed")
        self.assertEqual(report["original_bytes"], 3)
        self.assertEqual((reduced / "minimized.bin").read_bytes(), b"\x08")
        self.assertEqual(report["fingerprint"].split(":")[0], "asan")
        self.assertTrue((reduced / "probes.jsonl").read_text())
        self.assertEqual(hashlib.sha256((campaign / "evidence.json").read_bytes()).hexdigest(), digest)
        verified = self.command(ROOT / "run.py", "--source", ROOT / "fixtures/buggy.c",
                                "--corpus", self.home / "corpus", "--out", self.home / "verified",
                                "--replay", reduced / "minimized.bin")
        self.assertEqual(verified.returncode, 1, verified.stderr)
        self.assertEqual(json.loads((self.home / "verified/evidence.json").read_text())["status"], "asan_failure")

    def test_ubsan_failure_fingerprint_and_reduction(self):
        (self.home / "corpus/seed").write_bytes(b"\x00\xff")
        campaign = self.home / "undefined"
        found = self.command(ROOT / "run.py", "--source", ROOT / "fixtures/undefined.c",
                             "--corpus", self.home / "corpus", "--out", campaign,
                             "--runs", "1", "--seconds", "10")
        self.assertEqual(found.returncode, 1, found.stderr)
        self.assertEqual(json.loads((campaign / "evidence.json").read_text())["status"], "ubsan_failure")
        output = self.home / "reduced_ub"
        reduced = self.command(ROOT / "minimize.py", "--campaign", campaign,
                               "--out", output, "--seconds", "10")
        self.assertEqual(reduced.returncode, 0, reduced.stdout + reduced.stderr)
        report = json.loads((output / "reduction.json").read_text())
        self.assertTrue(report["fingerprint"].startswith("ubsan:"), report)
        self.assertEqual((output / "minimized.bin").read_bytes(), b"\x00")

    def test_reject_safe_campaign_and_keep_existing_output(self):
        (self.home / "corpus/seed").write_bytes(b"\x00")
        campaign = self.home / "safe"
        built = self.command(ROOT / "run.py", "--source", ROOT / "fixtures/safe.c",
                             "--corpus", self.home / "corpus", "--out", campaign,
                             "--runs", "1", "--seconds", "10")
        self.assertEqual(built.returncode, 0, built.stderr)
        out = self.home / "existing"
        out.mkdir()
        (out / "sentinel").write_text("keep")
        rejected = self.command(ROOT / "minimize.py", "--campaign", campaign, "--out", out)
        self.assertNotEqual(rejected.returncode, 0)
        self.assertEqual((out / "sentinel").read_text(), "keep")

if __name__ == "__main__":
    unittest.main()
