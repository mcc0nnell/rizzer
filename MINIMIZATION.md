# IHB native-fuzz crash reduction (opt-in)

This companion command reduces a saved crash from a **completed, trusted** native
campaign without changing the original run or rebuilding its target.  This is a
bounded engineering triage aid, not a vulnerability proof or an admitted Blade
capability.  It does not invoke libFuzzer or AFL.

## Usage

Use the complete output directory previously produced by `native_fuzz/run.py`
(the directory containing `evidence.json`, `ihb-native-fuzz`, `seeds/`,
and `findings/`):

```sh
python3 native_fuzz/minimize.py \
  --campaign /tmp/ihb-native-discovery \
  --out /tmp/ihb-native-reduction \
  --max-probes 64 --seconds 20
```

Requires one original failing input, a matching log, and a compiled executable
whose SHA-256 matches the original evidence manifest.  Reducing a safe campaign,
modified artifact or existing output directory fails closed.  First, replay
the exact original input.  Only if the same fingerprint reproduces does the
reducer try deterministic chunk deletion and smaller byte substitutions.
Replayed cases inherit the original per-input timeout.  The wall-clock budget
also caps individual replay supervision; a budget stop yields the best
already-confirmed input, not a claim of a globally minimal crash.

## Evidence

The new output contains `original.bin`, `minimized.bin`,
`minimized.log`, `probes.jsonl` and `reduction.json`.  The JSON reports
original and minimized hashes and sizes, original evidence and binary digests,
the within-build grouping key, probe count, whether a budget stopped
reduction, and a `heuristic_only` warning.  Original run evidence is
never edited or overwritten.

Fingerprinting is deliberately conservative for sanitizer reports: class +
harness source line + function (ASan), or harness line + diagnostic (UBSan).
Raw exit codes, signals and timeouts only receive coarse labels and must not be
treated as definitive crash identities.  An identical key within one exact
binary is a *triage suggestion*, not proof of a shared root cause; ASan reports
from other compilation layouts need independent comparison.

## Important limits

**Only run on locally reviewed, trusted synthetic harnesses.**  The native
engine uses fork for state reset, but remains neither an OS sandbox nor
network/filesystem isolation.  The Docker memory-bounded runner, if used for
untrusted processing in a future phase, requires independent review.  This
reducer runs its saved binary directly and is **not** an alternative to
admitted restricted execution.  It has no coverage guarantees, stack-based
cross-build dedup, leak detection, or exploitation assessment.

Test:

```sh
python3 -m unittest discover -s native_fuzz -p 'test_*.py' -v
```
