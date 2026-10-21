# Rizzer

**A small, independent, coverage-guided native fuzzer for reproducible experiments.**

**Status:** experimental Linux research engine · Apache-2.0 · synthetic fixtures only.

Rizzer starts from the tested native fuzzing work developed in the [IHB draft merge request !203](https://gitlab.com/ihatebanks-group/IHATEBANKS-project/-/merge_requests/203). It now has its **own repository, release lifecycle and test suite**. It does not require 6lowStick, Tronix, TalkPipe, or the rest of IHB to run.

## What it does

- Compiles C or C++ harnesses with **Clang trace-pc-guard**, **ASan**, and **UBSan**.
- Exercises deterministic, bounded mutation campaigns with a retained coverage corpus.
- Runs each input in a forked subprocess, reporting signals, sanitizer failures and timeouts.
- Preserves input, compiler identity, source digests, journal, crash logs and JSON evidence.
- Replays exact failure bytes; supports opt-in, evidence-preserving crash reduction.
- Offers an optional Docker wrapper with a pinned image, no default network and resource limits.

This is **not** an authorization framework, production-grade sandbox, or proof of a vulnerability. A fork isolates process state, **not** untrusted code from the host.

## Requirements

Linux, Python 3.11+, Clang/Clang++ with compiler-rt sanitizer support, and a C++17-capable toolchain. Docker is optional and is only for the separately reviewed `isolated.py` path.

## Run the synthetic acceptance suite

```bash
python3 -m unittest discover -v -p 'test_*.py'
```

On Butcher, the imported baseline passed **19/19 synthetic tests** on October 21, 2026. This is local verification, not hosted CI or independent security assurance.

## Your first fuzzing campaign

```bash
mkdir -p /tmp/rizzer-seeds
printf '\0' > /tmp/rizzer-seeds/zero
python3 run.py \
  --source fixtures/safe.c \
  --corpus /tmp/rizzer-seeds \
  --out /tmp/rizzer-safe-01 \
  --runs 96 --seed 17 --seconds 15
cat /tmp/rizzer-safe-01/evidence.json
```

`--out` must name a **new** directory. Never point it at important existing files.

A failure demonstration is included as a synthetic fixture:

```bash
python3 run.py --source fixtures/buggy.c \
  --corpus /tmp/rizzer-seeds --out /tmp/rizzer-buggy-01 \
  --runs 96 --seed 17 --seconds 15
```

The synthetic buggy fixture is expected to produce a nonzero runner exit and retained ASan evidence.

## Evidence boundaries

- `evidence.json`: source/compiler/runner identity, commands and reported outcome.
- `summary.json`, `journal.jsonl`: campaign summary and per-input records.
- `findings/`: candidate crash bytes and diagnostic logs; **candidates are not security findings**.
- `retained/`: coverage-growth corpus.
- `minimize.py`: bounded reproduction and simplification of a previously recorded synthetic failure; see [MINIMIZATION.md](MINIMIZATION.md).

Current v0 code intentionally retains identifiers such as `ihb.native-fuzz-evidence.v0` and `IHBTestOneInput` so imported fixtures and evidence remain reproducible. These are **compatibility names**, not a runtime dependency on IHB. Any future Rizzer-native schema and harness ABI will be explicitly versioned rather than silently rewriting evidence.

## Integrations: independent by design

| Consumer | Intended boundary | State |
| --- | --- | --- |
| **6lowStick** | Provide reviewed Spinel/6LoWPAN parsing harnesses and semantic invariants; consume evidence | Proposed; no live Rizzer adapter |
| **Tronix** | Schedule allowlisted, bounded campaigns by reviewed manifest/profile; not arbitrary commands | [Design only](https://github.com/mcc0nnell/tronix/blob/main/docs-ihb-fuzzing.md) |
| **IHB** | Supply candidate evidence for a *separate* scope/impact/admission review | Origin prototype; no automatic vulnerability filing |
| **WindAnvil** | Optional independent provenance verification | Proposed |

A future adapter must not grant Rizzer network access, radio-transmit authority, emergency-alert origination, arbitrary shell execution, or a privileged Docker socket. Use only owned or explicitly authorized test targets.

## Provenance & license

[Apache License 2.0](LICENSE). See [NOTICE](NOTICE) for the original IHB work, preserved branch and commit. The first repository import retains the tested upstream engine, runner, fixture and isolation code instead of substituting an untested reimplementation.
