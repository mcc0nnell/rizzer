"""Regression checks for optional, dedicated cgroup v2 OOM observation."""
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import run


class CgroupMemoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "memory.max").write_text("536870912\n")
        (self.root / "memory.events.local").write_text(
            "low 0\nhigh 0\nmax 8\noom 2\noom_kill 1\noom_group_kill 0\n"
        )

    def read_with_marker(self):
        with patch.dict(os.environ, {"IHB_FUZZ_CGROUP_DEDICATED": "1"}), \
                patch.object(run, "Path", lambda unused: self.root):
            return run.dedicated_cgroup_memory()

    def test_direct_execution_does_not_attribute_host_ooms(self):
        with patch.dict(os.environ, {"IHB_FUZZ_CGROUP_DEDICATED": ""}), \
                patch.object(run, "Path", lambda unused: self.root):
            self.assertIsNone(run.dedicated_cgroup_memory())

    def test_reads_finite_local_cgroup_counters(self):
        self.assertEqual(self.read_with_marker(), {
            "memory_max_bytes": 536870912, "oom_kill": 1, "oom": 2
        })

    def test_unbounded_cgroup_not_classified(self):
        (self.root / "memory.max").write_text("max\n")
        self.assertIsNone(self.read_with_marker())

    def test_unavailable_cgroup_not_classified(self):
        (self.root / "memory.events.local").unlink()
        self.assertIsNone(self.read_with_marker())


if __name__ == "__main__":
    unittest.main()
