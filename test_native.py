import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent


class NativeEngineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)
        (self.work / "corpus").mkdir()
        (self.work / "corpus/zero").write_bytes(b"\0")

    def run_engine(self, name, source="safe.c", replay=None, extra=()):
        out = self.work / name
        command = [sys.executable, str(ROOT / "run.py"), "--source", str(ROOT / "fixtures" / source),
                   "--corpus", str(self.work / "corpus"), "--out", str(out),
                   "--runs", "96", "--seed", "17", "--seconds", "15", *extra]
        if replay:
            command += ["--replay", str(replay)]
        proc = subprocess.run(command, capture_output=True, text=True, timeout=100)
        self.assertTrue((out / "evidence.json").exists(), proc.stderr)
        evidence = json.loads((out / "evidence.json").read_text())
        if evidence["status"] == "build_failure":
            self.fail("build failed: " + "\n".join(x.read_text() for x in out.glob("*.log")))
        return out, proc, evidence

    def test_discovers_replays_and_fixed_control(self):
        out, proc, evidence = self.run_engine("discovery", "buggy.c")
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(evidence["status"], "asan_failure")
        self.assertGreater(evidence["summary"]["executions"], 1)  # Seed was safe; mutation found it.
        crash = next((out / "findings").glob("*.bin"))
        self.assertNotEqual(crash.read_bytes(), b"\0")
        self.assertIn("heap-buffer-overflow", next((out / "findings").glob("*.log")).read_text())
        _, _, replay = self.run_engine("replay", "buggy.c", crash)
        self.assertEqual(replay["status"], "asan_failure")
        _, fixed_proc, fixed = self.run_engine("fixed", replay=crash)
        self.assertEqual(fixed_proc.returncode, 0)
        self.assertEqual(fixed["status"], "no_failure_observed")

    def test_coverage_growth_and_repeatable_schedule(self):
        first, proc, evidence = self.run_engine("first")
        second, _, repeat = self.run_engine("second")
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(evidence["status"], "no_failure_observed")
        self.assertEqual(evidence["summary"]["executions"], 96)
        self.assertGreater(evidence["summary"]["retained"], 0)
        self.assertGreater(evidence["summary"]["edges"], 1)
        self.assertEqual(evidence["summary"], repeat["summary"])
        self.assertEqual((first / "journal.jsonl").read_bytes(), (second / "journal.jsonl").read_bytes())
        self.assertEqual([x.read_bytes() for x in sorted((first / "retained").glob("*"))],
                         [x.read_bytes() for x in sorted((second / "retained").glob("*"))])
        flags = " ".join(" ".join(x["argv"]) for x in evidence["commands"])
        self.assertIn("-fsanitize-coverage=trace-pc-guard", flags)
        self.assertNotIn("-fsanitize=fuzzer", flags)

    def test_hang_is_timeout_not_memory_failure(self):
        out, _, evidence = self.run_engine("hang", "timeout.c", extra=("--timeout-ms", "30"))
        self.assertEqual(evidence["status"], "input_timeout")
        self.assertEqual(evidence["summary"]["executions"], 1)
        row = json.loads((out / "journal.jsonl").read_text())
        self.assertTrue(row["timeout"])
        self.assertEqual(row["new_edges"], 0)

    def test_existing_evidence_is_preserved(self):
        out = self.work / "existing"
        out.mkdir()
        (out / "sentinel").write_text("keep")
        proc = subprocess.run([sys.executable, str(ROOT / "run.py"), "--source", str(ROOT / "fixtures/safe.c"),
                               "--corpus", str(self.work / "corpus"), "--out", str(out)], capture_output=True)
        self.assertEqual(proc.returncode, 2)
        self.assertEqual((out / "sentinel").read_text(), "keep")

    def test_state_is_reset_and_secret_environment_is_removed(self):
        import os
        from unittest.mock import patch
        with patch.dict(os.environ, {"IHB_FUZZ_TEST_SECRET": "synthetic-canary"}):
            _, proc, evidence = self.run_engine("state", "state.c", extra=("--runs", "12"))
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(evidence["summary"]["executions"], 12)
        self.assertEqual(evidence["status"], "no_failure_observed")

    def test_undefined_behavior_is_preserved(self):
        out, _, evidence = self.run_engine("undefined", "undefined.c")
        self.assertEqual(evidence["status"], "ubsan_failure")
        self.assertIn("division by zero", next((out / "findings").glob("*.log")).read_text())


if __name__ == "__main__":
    unittest.main()
