<div align="center">
  <img src="assets/rizzer-transparent.webp" alt="Rizzer: the original hot-pink and lime-green conjoined polo shirts forming a six, with two raised collars and button plackets" width="300" />
  <h1>Rizzer</h1>
  <p><strong>Two collars. Zero trust.</strong></p>
  <p>The official 6lowStick mascot. A fuzzer with a life of his own.</p>
</div>

**Mascot by birth. Fuzzer by trade.**

Rizzer is a lightweight, coverage-guided native fuzzer built for reproducible experiments on Linux. Independent by design, experimental by nature, and deeply suspicious of well-behaved software.

**Two collars. One mission: find what the tests missed.**

**Experimental** · Linux · Apache-2.0 · Synthetic fixtures only.

[Original logo](assets/rizzer.webp) · [Transparent presentation asset](assets/rizzer-transparent.webp) · [Character guide](docs/character.md)

## Meet Rizzer

**Rizzer the Siamese Polo Shirts** is one character with two roles: official [6lowStick](https://github.com/mcc0nnell/6lowstick) mascot and namesake of this independently maintained fuzzing engine. Two conjoined polos, two popped collars, one unmistakable six.

An unofficial wink at Loopt-era layered polos—not an affiliation or endorsement. Think millennial Leisure Suit Larry with a pointer-arithmetic habit. **He flirts with bugs, not people**, and knows a crash is not a confirmed vulnerability.

Meet him without starting a campaign:

```bash
python3 mascot.py --demo
# RIZZER // MEET THE MASCOT
# Two collars. Zero trust. And excellent taste in reproducible experiments.
```

Or let him comment on an **existing** local evidence file:

```bash
python3 mascot.py --evidence /path/to/campaign/evidence.json
```

This is read-only, deterministic, opt-in human commentary. It never modifies evidence, changes fuzzing status, or claims a confirmed finding. [Character bible and art guidance](docs/character.md).

<details>
<summary><strong>Explore Rizzer’s optional vector expressions</strong> (five poses)</summary>

### Five expressions, one Rizzer

| Smug | Investigating | Surprised | Celebrating | Caution |
| :---: | :---: | :---: | :---: | :---: |
| <img src="assets/rizzer-smug.svg" alt="Rizzer looking smug" width="112" /> | <img src="assets/rizzer-investigating.svg" alt="Rizzer inspecting something suspicious" width="112" /> | <img src="assets/rizzer-surprised.svg" alt="Rizzer startled" width="112" /> | <img src="assets/rizzer-celebrating.svg" alt="Rizzer celebrating" width="112" /> | <img src="assets/rizzer-caution.svg" alt="Rizzer expressing caution" width="112" /> |

The original [two-polo logo](assets/rizzer.webp) is Rizzer’s canonical public mark. The five expression SVGs are supporting character art, not replacements for the original. All six SVGs (five variants and the generated SVG master) are generated from [readable source](scripts/build_mascot.py), not raster-upscaled. Rebuild with `python3 scripts/build_mascot.py`. No external fonts, SVG images, scripts, or CDN dependencies.

</details>

The transparent README hero is derived from the original WebP—not a new design. To reproduce it, install Pillow in an optional art-only environment and run `python3 scripts/prepare_original_logo.py`. The original file stays untouched.

### Terminal cameo

```bash
python3 terminal.py --pose smug              # static, no terminal required
python3 terminal.py --pose investigating --plain
python3 terminal.py --pose celebrating --animate
python3 terminal.py --animate --reduced-motion
```

Animation is **opt-in**, four frames maximum, and only runs when stdout is a terminal. Piped output, `--plain`, reduced-motion preference and `NO_COLOR` are handled without changing any fuzzing outcome. The terminal cameo never invokes a campaign. `mascot.py --evidence` remains a separate, read-only narrator for real reports.

## What it does

- Compiles C or C++ harnesses with **Clang trace-pc-guard**, **ASan**, and **UBSan**.
- Exercises deterministic, bounded mutation campaigns with a retained coverage corpus.
- Runs each input in a forked subprocess, reporting signals, sanitizer failures and timeouts.
- Preserves input, compiler identity, source digests, journal, crash logs and JSON evidence.
- Replays exact failure bytes; supports opt-in, evidence-preserving crash reduction.
- Offers an optional Docker wrapper with a pinned image, no default network and resource limits.

This is **not** an authorization framework, production-grade sandbox, or proof of a vulnerability. A fork isolates process state, **not** untrusted code from the host.

## Experimental identity-sequence replay

`identity_replay.py` is a **separate, read-only synthetic lab** for correlating
application-only sign-ins, Graph activity, and subsequent credential or role
changes. It follows the defensive questions raised by Microsoft's October 2026
Storm-0940 / ARTEX reporting; it does not perform offensive operations,
connect to cloud tenants, or extend the native fuzzer's privileges.

```sh
python3 identity_replay.py --input fixtures/identity-sequence.jsonl \
  --out /tmp/rizzer-identity-demo-01
```

Outputs a deterministic JSON receipt for human review, **not** a verified
compromise finding or signed attestation. See
[the synthetic identity-replay contract](docs/identity-replay.md).

## Requirements

Linux, Python 3.11+, Clang/Clang++ with compiler-rt sanitizer support, and a C++17-capable toolchain. Docker is optional and is only for the separately reviewed `isolated.py` path.

## Run the synthetic acceptance suite

```bash
python3 -m unittest discover -v -p 'test_*.py'
```

On Butcher, **37/37 local tests passed** on October 21, 2026, including the native engine and opt-in mascot behavior. This is local synthetic verification, not hosted CI or independent security assurance.

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
| **6lowStick** | Native Spinel HDLC-lite harness, bounded campaigns, then separate differential replay into the actual JavaScript recorder | [Opt-in offline adapter implemented](https://github.com/mcc0nnell/6lowstick/blob/main/docs/rizzer-spinel-fuzzing.md); no radio or JS coverage authority |
| **Tronix** | Schedule allowlisted, bounded campaigns by reviewed manifest/profile; not arbitrary commands | [Design only](https://github.com/mcc0nnell/tronix/blob/main/docs-ihb-fuzzing.md) |
| **IHB** | Supply candidate evidence for a *separate* scope/impact/admission review | Origin prototype; no automatic vulnerability filing |
| **WindAnvil** | Optional independent provenance verification | Proposed |

The 6lowStick adapter is invoked from **6lowStick**; this repository does not bundle or install that integration. Rizzer guides native **C++** coverage only, and 6lowStick replays only fixed seeds and coverage-retained/failure candidates into the **JavaScript** parser, not every mutation. The first clean-commit local campaign tested 256 native inputs and 18 replay inputs with zero reported native fault candidates or differential mismatches; that does not establish security, Spinel conformance or physical RF delivery. The [controlled hardware protocol](https://github.com/mcc0nnell/6lowstick/blob/main/docs/physical-radio-test-protocol.md) is design-only.

Any other future adapter must likewise avoid granting Rizzer network access, radio-transmit authority, emergency-alert origination, arbitrary shell execution, or a privileged Docker socket. Use only owned or explicitly authorized test targets.

## Provenance & license

[Apache License 2.0](LICENSE). See [NOTICE](NOTICE) for the original IHB work, preserved branch and commit. The first repository import retains the tested upstream engine, runner, fixture and isolation code instead of substituting an untested reimplementation.
