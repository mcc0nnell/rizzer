"""Regression checks for the experimental Docker isolation CLI (no network/image needed)."""
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import isolated


PINNED = "example.invalid/ihb-native@sha256:" + "a" * 64


class IsolatedRunnerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)
        self.source = self.work / "harness.c"
        self.source.write_text("int IHBTestOneInput(const void *p, unsigned n) { return 0; }")
        self.corpus = self.work / "seeds"
        self.corpus.mkdir()
        (self.corpus / "zero").write_bytes(b"\\0")

    def invoke(self, output=None, image=PINNED, extra=()):
        out = output or (self.work / "results")
        argv = ["isolated.py", "--source", str(self.source),
                "--corpus", str(self.corpus), "--out", str(out),
                "--image", image, *extra]
        with patch.object(sys, "argv", argv), patch.object(
                isolated.subprocess, "run", return_value=SimpleNamespace(returncode=0)) as run:
            result = isolated.main()
        return result, run, out

    def test_pinned_image_overrides_entrypoint_and_restricts_container(self):
        result, run, out = self.invoke()
        self.assertEqual(result, 0)
        command = run.call_args.args[0]
        self.assertEqual(command[:4], ["docker", "run", "--rm", "--pull=never"])
        for flag in ("--network=none", "--read-only", "--cap-drop=ALL",
                     "--security-opt=no-new-privileges", "--pids-limit=64",
                     "--memory-swap", "--cpus=2"):
            self.assertIn(flag, command)
        self.assertIn("--entrypoint=python3", command)
        self.assertIn("IHB_FUZZ_CGROUP_DEDICATED=1", command)
        image_index = command.index(PINNED)
        self.assertEqual(command[image_index + 1], "/work/run.py")
        self.assertEqual(command[command.index("--memory") + 1], "1024m")
        self.assertEqual(command[command.index("--memory-swap") + 1], "1024m")
        self.assertIn(f"type=bind,src={out},dst=/output", command)
        self.assertTrue(out.is_dir())

    def test_local_immutable_image_id_is_accepted(self):
        pinned_id = "sha256:" + "b" * 64
        result, mocked_run, _ = self.invoke(image=pinned_id)
        self.assertEqual(result, 0)
        self.assertIn(pinned_id, mocked_run.call_args.args[0])

    def test_reject_mutable_tag_before_writing_anything(self):
        with self.assertRaises(SystemExit) as caught:
            self.invoke(image="ubuntu:latest")
        self.assertEqual(caught.exception.code, 2)
        self.assertFalse((self.work / "results").exists())

    def test_reject_output_nested_in_corpus(self):
        with self.assertRaises(SystemExit) as caught:
            self.invoke(output=self.corpus / "results")
        self.assertEqual(caught.exception.code, 2)
        self.assertFalse((self.corpus / "results").exists())

    def test_existing_output_is_never_overwritten(self):
        output = self.work / "results"
        output.mkdir()
        (output / "sentinel").write_text("preserved")
        with self.assertRaises(SystemExit) as caught:
            self.invoke(output=output)
        self.assertEqual(caught.exception.code, 2)
        self.assertEqual((output / "sentinel").read_text(), "preserved")

    def test_invalid_resource_bounds_fail_closed(self):
        with self.assertRaises(SystemExit) as caught:
            self.invoke(extra=("--memory-mb", "64"))
        self.assertEqual(caught.exception.code, 2)
        self.assertFalse((self.work / "results").exists())


if __name__ == "__main__":
    unittest.main()
