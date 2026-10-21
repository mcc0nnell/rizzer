"""Read-only, accessible terminal mascot behavior."""
# SPDX-License-Identifier: Apache-2.0
from io import StringIO
from unittest.mock import patch
import unittest

import terminal


class TerminalTests(unittest.TestCase):
    def test_five_poses_have_unique_static_text_and_plain_mode(self):
        messages = set()
        for pose in terminal.POSES:
            with self.subTest(pose=pose):
                result = terminal.render(pose)
                self.assertIn("HOT PINK", result)
                self.assertIn("LIME", result)
                self.assertIn(pose.upper(), result)
                self.assertNotIn("\x1b", result)
                plain = terminal.render(pose, plain=True, color=True)
                self.assertNotIn("\n", plain)
                self.assertNotIn("\x1b", plain)
                messages.add(plain)
        self.assertEqual(len(messages), 5)

    def test_animation_is_opt_in_tty_only(self):
        self.assertFalse(terminal.should_animate(requested=True, is_tty=False, plain=False,
                                                 reduced_motion=False))
        self.assertFalse(terminal.should_animate(requested=True, is_tty=True, plain=True,
                                                 reduced_motion=False))
        self.assertFalse(terminal.should_animate(requested=True, is_tty=True, plain=False,
                                                 reduced_motion=True))
        self.assertFalse(terminal.should_animate(requested=False, is_tty=True, plain=False,
                                                 reduced_motion=False))
        self.assertTrue(terminal.should_animate(requested=True, is_tty=True, plain=False,
                                                reduced_motion=False))

    def test_plain_and_reduced_motion_stay_static_even_on_terminal(self):
        for args in (["--animate", "--plain"], ["--animate", "--reduced-motion"]):
            output = StringIO()
            with self.subTest(args=args):
                with patch.dict("os.environ", {"NO_COLOR": "1"}):
                    self.assertEqual(terminal.main(args, out=output, is_tty=True,
                                                   sleep=lambda seconds: self.fail("slept")), 0)
                self.assertNotIn("\x1b", output.getvalue())
                self.assertEqual(output.getvalue().count("RIZZER //"), 0 if "--plain" in args else 1)

    def test_animation_is_bounded_and_requires_explicit_flag(self):
        output = StringIO()
        sleeps = []
        self.assertEqual(terminal.main(["--animate", "--pose", "caution", "--no-color"],
                                       out=output, is_tty=True, sleep=sleeps.append), 0)
        self.assertEqual(len(sleeps), 3)
        self.assertTrue(all(n <= .2 for n in sleeps))
        self.assertEqual(output.getvalue().count("RIZZER //"), 4)
        self.assertEqual(output.getvalue().count("\x1b[14F"), 3)
        self.assertIn("RIZZER // CAUTION", output.getvalue())

    def test_animation_on_pipe_renders_one_static_frame(self):
        output = StringIO()
        self.assertEqual(terminal.main(["--animate"], out=output, is_tty=False,
                                       sleep=lambda seconds: self.fail("slept")), 0)
        self.assertEqual(output.getvalue().count("RIZZER //"), 1)
        self.assertNotIn("\x1b", output.getvalue())

    def test_reduced_motion_environment_disables_animation(self):
        output = StringIO()
        with patch.dict("os.environ", {"RIZZER_REDUCED_MOTION": "1"}):
            self.assertEqual(terminal.main(["--animate"], out=output, is_tty=True,
                                           sleep=lambda seconds: self.fail("slept")), 0)
        self.assertEqual(output.getvalue().count("RIZZER //"), 1)

    def test_unknown_pose_never_becomes_an_untrusted_command(self):
        with self.assertRaises(ValueError):
            terminal.render("../../../bin/sh")


if __name__ == "__main__":
    unittest.main()
