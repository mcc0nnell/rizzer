"""The mascot must never turn candidate evidence into a claimed security finding."""
# SPDX-License-Identifier: Apache-2.0
from contextlib import redirect_stdout, redirect_stderr
from io import StringIO
import json
from pathlib import Path
import tempfile
import unittest

from mascot import EXPECTED_SCHEMA, QUIPS, main, read_evidence, render_evidence


class MascotTests(unittest.TestCase):
    def test_shared_character_demo_is_clearly_a_demo(self):
        stream = StringIO()
        with redirect_stdout(stream):
            self.assertEqual(main(["--demo"]), 0)
        self.assertIn("MEET THE MASCOT", stream.getvalue())
        self.assertIn("Two collars. Zero trust.", stream.getvalue())
        self.assertNotIn("finding confirmed", stream.getvalue().lower())

    def test_known_statuses_have_deterministic_plain_language(self):
        for status in QUIPS:
            data = {"schema": EXPECTED_SCHEMA, "status": status}
            with self.subTest(status=status):
                one = render_evidence(data)
                self.assertEqual(one, render_evidence(data))
                self.assertTrue(one.startswith(f"RIZZER // {status}\n"))
                self.assertNotIn("\x1b", one)
                self.assertNotIn("CVE-", one)

    def test_existing_report_is_not_mutated(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "evidence.json"
            path.write_text(json.dumps({"schema": EXPECTED_SCHEMA,
                                        "status": "asan_failure",
                                        "source_sha256": "abc"}) + "\n")
            before = path.read_bytes()
            out = StringIO()
            with redirect_stdout(out):
                self.assertEqual(main(["--evidence", str(path)]), 0)
            self.assertIn("replay and assess", out.getvalue())
            self.assertEqual(path.read_bytes(), before)
            self.assertEqual(read_evidence(path)["source_sha256"], "abc")

    def test_rejects_unsupported_or_missing_status(self):
        for data in ({}, {"schema": "rizzer.future.v1", "status": "asan_failure"},
                     {"schema": EXPECTED_SCHEMA, "status": "magic_vulnerability"},
                     {"schema": EXPECTED_SCHEMA}):
            with self.subTest(data=data), self.assertRaises(ValueError):
                render_evidence(data)

    def test_bad_json_symlink_and_oversize_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            invalid = root / "invalid.json"
            invalid.write_text("{")
            huge = root / "huge.json"
            huge.write_bytes(b"x" * (1024 * 1024 + 1))
            shortcut = root / "shortcut.json"
            shortcut.symlink_to(invalid)
            for path in (invalid, huge, shortcut):
                with self.subTest(path=path):
                    with redirect_stderr(StringIO()), self.assertRaises(SystemExit) as caught:
                        main(["--evidence", str(path)])
                    self.assertEqual(caught.exception.code, 2)

    def test_no_implicit_execution_mode(self):
        with redirect_stderr(StringIO()), self.assertRaises(SystemExit) as caught:
            main([])
        self.assertEqual(caught.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
