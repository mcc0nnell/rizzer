import unittest

from rizzer_voice import OPENERS, VERDICTS, opening, verdict


class VoiceTests(unittest.TestCase):
    def test_opening_is_deterministic(self):
        for seed in (1, 17, 2**64 - 1):
            self.assertEqual(opening(seed), opening(seed))
            self.assertIn(opening(seed), OPENERS)

    def test_every_runner_status_has_a_line(self):
        expected = {
            "asan_failure", "ubsan_failure", "target_failure", "input_timeout",
            "cgroup_oom_kill", "build_failure", "engine_failure",
            "supervisor_timeout", "budget_exhausted", "no_failure_observed",
        }
        self.assertEqual(set(VERDICTS), expected)
        for status in expected:
            self.assertIn(verdict(status, 17), VERDICTS[status])

    def test_unknown_status_is_safe(self):
        self.assertIn("evidence", verdict("other", 17).lower())

    def test_persona_is_sanitized_for_single_line_stderr(self):
        for line in (*OPENERS, *(line for lines in VERDICTS.values() for line in lines)):
            self.assertEqual(line, line.strip())
            self.assertNotIn("\n", line)
            self.assertNotIn("\r", line)
            self.assertLess(len(line), 140)


if __name__ == "__main__":
    unittest.main()
