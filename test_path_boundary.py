"""Synthetic path-component policy tests; no C2, no actual filesystem writes."""
import ctypes
import json
import ntpath
from pathlib import Path
import random
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent
SOURCE = ROOT / "fixtures/path_boundary.c"
CORPUS = ROOT / "fixtures/path-boundary-corpus"
VROOT = r"C:\synthetic\recovery"


class PathBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        clang = shutil.which("clang")
        if not clang:
            raise unittest.SkipTest("Clang required for native policy tests")
        cls.tmp = tempfile.TemporaryDirectory()
        cls.library = Path(cls.tmp.name) / "path_boundary.so"
        command = [clang, "-std=c11", "-Wall", "-Wextra", "-Werror",
                   "-pedantic", "-fPIC", "-shared", str(SOURCE),
                   "-o", str(cls.library)]
        compiled = subprocess.run(command, capture_output=True, text=True, timeout=30)
        if compiled.returncode:
            raise AssertionError(compiled.stderr)
        cls.lib = ctypes.CDLL(str(cls.library))
        cls.lib.rz_validate_component.argtypes = [ctypes.c_char_p, ctypes.c_size_t]
        cls.lib.rz_validate_component.restype = ctypes.c_int
        cls.lib.rz_build_destination.argtypes = [
            ctypes.c_char_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t
        ]
        cls.lib.rz_build_destination.restype = ctypes.c_int

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, "tmp"):
            cls.tmp.cleanup()

    def check(self, raw, expected):
        self.assertEqual(self.lib.rz_validate_component(raw, len(raw)), int(expected), raw)
        buffer = ctypes.create_string_buffer(b"x" * 200, 256)
        result = self.lib.rz_build_destination(raw, len(raw), buffer, len(buffer))
        self.assertEqual(result, int(expected), raw)
        if expected:
            self.assertEqual(buffer.value,
                             b"/synthetic/recovery/" + raw + b"/record.bin")
        else:
            self.assertEqual(buffer.raw[:8], b"x" * 8)

    def test_known_good_identifiers(self):
        for sample in (b"client-7", b"device_A", b"agent.v1", b"A" * 64,
                       b"x-y_z.12", b"8", b"Comms7"):
            with self.subTest(sample=sample):
                self.check(sample, True)

    def test_traversal_absolute_device_and_ambiguous_names_rejected(self):
        invalid = [
            b"", b".", b"..", b"../outside", b"..\\outside",
            b"a/../b", b"\\root", b"/absolute", b"C:\\root", b"C:relative",
            b"\\\\server\\share", b"CON", b"con.txt", b"PRN", b"AUX",
            b"NUL", b"nul.log", b"COM0", b"COM1.log", b"com9",
            b"LPT1", b"LPT9.txt", b"a..b", b".hidden", b"trailing.",
            b"name ", b"has space", b"a:b", b"evil%2e%2e",
            b"file?query", b"file*wild", b"<xml>", b"|pipe", b"\"quote",
            b"a\nb", b"bad\x00name", b"\xffbyte", b"\xe9", b"Z" * 65,
        ]
        for raw in invalid:
            with self.subTest(raw=raw):
                self.check(raw, False)

    def test_too_small_output_is_not_modified(self):
        raw = b"client-7"
        for capacity in (0, 1, 16, len(b"/synthetic/recovery/client-7/record.bin")):
            dest = ctypes.create_string_buffer(b"z" * 255, 256)
            status = self.lib.rz_build_destination(raw, len(raw), dest, capacity)
            self.assertEqual(status, 0)
            self.assertEqual(dest.raw, b"z" * 255 + b"\x00")
        self.assertEqual(self.lib.rz_validate_component(None, 12), 0)

    def test_deterministic_mutation_invariants(self):
        rng = random.Random(27013)
        alphabet = b"abcXYZ19_.-:/\\% \x00\x7f"
        for _ in range(512):
            size = rng.randint(0, 90)
            raw = bytes(alphabet[rng.randrange(len(alphabet))] for _ in range(size))
            accepted = bool(self.lib.rz_validate_component(raw, len(raw)))
            self.check(raw, accepted)
            if accepted:
                self.assertFalse(any(char in raw for char in (b"/", b"\\", b":")))
                self.assertNotIn(b"..", raw)

    def test_virtual_naive_join_can_escape_root(self):
        # Illustrative lexical reference only: no process, C2, or file access.
        unsafe = ntpath.normpath(ntpath.join(VROOT, "..", "..", "record.bin"))
        self.assertFalse(unsafe.startswith(VROOT + "\\"))
        self.check(b"..", False)
        absolute = ntpath.normpath(ntpath.join(VROOT, r"C:\other", "record.bin"))
        self.assertFalse(absolute.startswith(VROOT + "\\"))
        self.check(b"C:\\other", False)

    def test_native_fuzz_campaign_records_no_property_failure(self):
        if not shutil.which("clang++"):
            self.skipTest("Clang C++ toolchain required")
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "new-evidence"
            proc = subprocess.run([
                sys.executable, str(ROOT / "run.py"),
                "--source", str(SOURCE), "--corpus", str(CORPUS),
                "--out", str(output), "--runs", "192", "--seed", "27013",
                "--seconds", "20", "--timeout-ms", "1000",
            ], capture_output=True, text=True, timeout=60)
            self.assertTrue((output / "evidence.json").exists(), proc.stderr)
            evidence = json.loads((output / "evidence.json").read_text())
            self.assertEqual(evidence["status"], "no_failure_observed",
                             (proc.stdout, evidence.get("status"),
                              (output / "engine.log").read_text(errors="replace")
                              if (output / "engine.log").exists() else ""))
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(evidence["summary"]["executions"], 192)
            self.assertEqual(evidence["summary"]["findings"], 0)
            self.assertEqual(evidence["requested_runs"], 192)


if __name__ == "__main__":
    unittest.main()
