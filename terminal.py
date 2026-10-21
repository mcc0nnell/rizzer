#!/usr/bin/env python3
"""Rizzer terminal cameo. Opt-in display only: never dispatches a fuzz campaign."""
# SPDX-License-Identifier: Apache-2.0
import argparse
import os
import sys
import time

POSES = ("smug", "investigating", "surprised", "celebrating", "caution")
FACES = {
    "smug": ("  -    ^ ", "  \\___/  "),
    "investigating": ("  o    o ", "   ____  "),
    "surprised": ("  O    O ", "    ()   "),
    "celebrating": ("  >    < ", "  \\___/  "),
    "caution": ("  !    ! ", "   ~~~~  "),
}
CAPTIONS = {
    "smug": "Two collars. Zero trust.",
    "investigating": "That parser looks interesting. Mind if I check its boundaries?",
    "surprised": "Whoa, sanitizer! Preserve the input before naming a bug.",
    "celebrating": "A reproducible test case? Be still, my popped collars.",
    "caution": "A crash is a candidate. Reproduce it. Verify the impact.",
}
ESC = "\x1b["
PINK = ESC + "95m"
LIME = ESC + "92m"
LIGHT = ESC + "97m"
RESET = ESC + "0m"


def artwork(pose):
    """An accessible, fixed-width text rendering independent of terminal width."""
    if pose not in POSES:
        raise ValueError("unknown pose")
    eyes, mouth = FACES[pose]
    upper = [
        "                /\\  /\\",
        "       ________/  \\/  \\__",
        "      /  HOT PINK     __\\",
        "     /    .__________/",
        "    /    /",
    ]
    lower = [
        "   /    /  .-----------.",
        "  |    |  /   LIME      \\",
        "  |    | | " + eyes + " |",
        "  |    | | " + mouth + " |",
        "   \\    \\ \\           /",
        "    \\    '-.---------'",
        "     '--------------'",
    ]
    return upper, lower


def render(pose="smug", *, plain=False, color=False):
    """Deterministic text; color never conveys status alone."""
    if pose not in POSES:
        raise ValueError("unknown pose")
    if plain:
        return f"Rizzer ({pose}) — {CAPTIONS[pose]}"
    upper, lower = artwork(pose)
    if color:
        graphic = "\n".join(PINK + line + RESET for line in upper)
        graphic += "\n" + "\n".join(LIME + line + RESET for line in lower)
        heading = LIGHT + "RIZZER // " + pose.upper() + RESET
    else:
        graphic = "\n".join([*upper, *lower])
        heading = "RIZZER // " + pose.upper()
    return graphic + "\n" + heading + "\n" + CAPTIONS[pose]


def should_animate(*, requested, is_tty, plain, reduced_motion):
    """Explicit opt-in plus a live terminal. Capture and a11y paths stay static."""
    return bool(requested and is_tty and not plain and not reduced_motion)


def main(argv=None, *, out=None, is_tty=None, sleep=time.sleep):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pose", choices=POSES, default="smug")
    parser.add_argument("--animate", action="store_true",
                        help="animate a four-frame cameo in a real terminal")
    parser.add_argument("--plain", action="store_true",
                        help="single screen-reader-friendly line; no artwork or ANSI")
    parser.add_argument("--reduced-motion", action="store_true",
                        help="force a static frame, even if animation was requested")
    parser.add_argument("--no-color", action="store_true", help="disable ANSI colors")
    args = parser.parse_args(argv)
    stream = out if out is not None else sys.stdout
    tty = stream.isatty() if is_tty is None else is_tty
    reduced = args.reduced_motion or os.environ.get("RIZZER_REDUCED_MOTION") == "1" or (
        os.environ.get("REDUCED_MOTION") == "1"
    )
    color = bool(tty and not args.no_color and not args.plain and "NO_COLOR" not in os.environ)
    animate = should_animate(requested=args.animate, is_tty=tty, plain=args.plain,
                             reduced_motion=reduced)
    if not animate:
        print(render(args.pose, plain=args.plain, color=color), file=stream)
        return 0
    # Four bounded frames, no background task and no interaction with native fuzzing.
    for i, pose in enumerate(("investigating", "surprised", "smug", args.pose)):
        if i:
            stream.write(ESC + "14F")  # cursor to top of previous fixed-height frame
        stream.write(render(pose, color=color) + "\n")
        stream.flush()
        if i < 3:
            sleep(0.16)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
