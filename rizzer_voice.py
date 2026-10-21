"""Deterministic, human-only banter for Rizzer.

This module never reads inputs, changes a mutation schedule, or writes evidence.
"""

from hashlib import sha256

OPENERS = (
    "Name's Rizzer. Two collars, zero mercy. You brought the bytes, right?",
    "Hey, gorgeous. Is that a malformed packet, or did you slide into my input queue?",
    "You had me at hello. You lost me at unchecked length. Let's investigate.",
    "Away message: BRB, checking your boundaries. Very 2004 of me.",
    "I brought two polo shirts and a coverage map. One of us is overdressed.",
)

# Status-specific jokes must never imply that a crash proves a vulnerability.
VERDICTS = {
    "asan_failure": (
        "Ooh, an address red flag. ASan has receipts; let's reproduce it.",
        "That heap chemistry is toxic, babe. Save the ASan log.",
    ),
    "ubsan_failure": (
        "Undefined behavior? Sweetheart, I don't do situationships. Keep the trace.",
        "Mixed signals from UBSan. Evidence first, relationship status later.",
    ),
    "target_failure": (
        "The target ghosted us. That's a candidate failure, not a CVE.",
        "A dramatic exit? Cute. Now reproduce it before making claims.",
    ),
    "input_timeout": (
        "Left on read by an input. Timeout recorded; causality still pending.",
        "We're not exclusive, but this input sure is hanging around. Log it.",
    ),
    "cgroup_oom_kill": (
        "Out of memory? I respect boundaries. Check the cgroup evidence.",
        "Memory said 'it's not you, it's me.' The local OOM counter agrees.",
    ),
    "build_failure": (
        "Couldn't get past the introduction. Check the compiler logs, hot stuff.",
        "Our first date didn't compile. The build logs know why.",
    ),
    "engine_failure": (
        "It's not you, it's the engine. Read the logs before blaming the target.",
        "The engine went offline. Even my AIM away message has more detail.",
    ),
    "supervisor_timeout": (
        "My patience is bounded, babe. Supervisor timeout; see the logs.",
        "Campaign ran out of time. We have a deadline, not a diagnosis.",
    ),
    "budget_exhausted": (
        "We hit our budget, not a proof of safety. Call me after more coverage.",
        "Time's up, gorgeous. No all-clear implied by the budget.",
    ),
    "no_failure_observed": (
        "No crash observed this round. Doesn't mean we're soulmates—or safe.",
        "Nothing broke on this date. That's an observation, not a guarantee.",
    ),
}

FALLBACK = ("Status recorded. My charm is optional; the evidence isn't.",)


def _pick(lines, key):
    digest = sha256(key.encode("ascii")).digest()
    return lines[int.from_bytes(digest[:4], "big") % len(lines)]


def opening(seed):
    """Stable opening line; does not touch the fuzzer's random state."""
    return _pick(OPENERS, f"intro:{seed}")


def verdict(status, seed):
    """Stable, cautious outcome line for an observed campaign status."""
    return _pick(VERDICTS.get(status, FALLBACK), f"outro:{status}:{seed}")


if __name__ == "__main__":
    print("RIZZER — Two Collars. Zero Mercy. (personality demo only)")
    print(opening(17))
    for outcome in ("asan_failure", "ubsan_failure", "input_timeout", "no_failure_observed"):
        print(f"{outcome}: {verdict(outcome, 17)}")
