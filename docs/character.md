# Rizzer: character and brand guide

> **Two collars. Zero trust.**

## Canon

**Rizzer the Siamese Polo Shirts** is the official mascot of [6lowStick](https://github.com/mcc0nnell/6lowstick) *and* the shared character identity behind the independent Rizzer native fuzzer. There is **one** Rizzer, not two unrelated mascots.

He is an impossible creature: two joined, popped-collar polo shirts—hot pink and radioactive lime—folded into a legible numeral **6**. The visual is an affectionate, unofficial wink at the famous two-polo-shirt look associated with Sam Altman's early Loopt era. Rizzer is **not** a depiction of, endorsement by, or affiliation with Sam Altman, OpenAI, or Loopt.

His vibe: **millennial Leisure Suit Larry meets protocol nerd**, with more confidence than common sense about fashion and a surprising amount of rigor about evidence.

Rizzer thinks he is the smoothest thing on the mesh. He still knows a CRC is not authentication, a signed application receipt is not human comprehension, and a crashing process is not automatically a security vulnerability.

## Character rules

- **Silhouette:** two overlapping *polo shirts*, visibly joined, not a person wearing them. The overall silhouette reads as the number **6**.
- **Essential details:** two distinct collars, a couple of buttons, hot pink and lime green. The fabric may be textured, but a simplified icon must still read clearly at avatar scale.
- **Expression:** cheeky, charming, self-assured, occasionally startled by a sanitizer report. Use body language, collar tilt, or stylized eyes sparingly; the two collars remain recognizable.
- **Supporting palette:** midnight navy or black backgrounds; accessible light-colored type. Use contrast and shapes, never color alone, to distinguish states.
- **The joke:** nostalgia for conspicuously layered polos; networking layers are a secondary pun.
- **The serious core:** resilience, autonomy, secure communications, reproducibility, and accessible alerts.

### His voice

Rizzer talks like a slightly overconfident millennial lounge-lizard programmer. One raised eyebrow, one bad pickup line, and then a technically accurate finding.

**Do**
- “Two collars. Zero trust.”
- “Keep your pointers close and your boundaries closer.”
- “Well, hello, sanitizer. Let's preserve those bytes before we celebrate.”
- “An ACK is not a standing ovation. Check what it actually confirms.”
- “Hot pink, lime green, and a completely reproducible test case.”

**Don't**
- Invent a confirmed vulnerability from a crash, parser rejection, timeout, or fuzzing coverage.
- Flirt with users, contributors, or reviewers; **Rizzer flirts with bugs, not people**.
- Joke about Deaf people, failed emergency warnings, or people harmed by inaccessible systems.
- Claim radio transmission, commissioned devices, emergency readiness, or human receipt from a simulation.
- Present the unofficial Loopt clothing reference as endorsement or association.
- Make the mascot replace accessible text, command results, provenance, or standard log output.

## Where he belongs

| Project | Rizzer's role |
| --- | --- |
| **6lowStick** | Official public-facing mascot, repository hero, accessibility and networking storytelling |
| **Rizzer** | Mascot and name of the standalone Apache-2.0 fuzzing engine |
| **Tronix** | Optional future campaign integration; Rizzer is not Tronix's mascot |
| **IHB** | Historical origin of native-fuzzer prototype; independent downstream integration only |

The character is shared. The repositories remain independently governed, tested, and released.

## What we're building next

1. **A small-format vector icon** that preserves the readable six and the two collars; retain the original raster as reference.
2. **Expression sheet:** smug, investigating, surprised, celebrating, caution; no expressions that could obscure warning severity.
3. **Terminal presence:** opt-in read-only quips; deterministic and never mixed into machine-readable evidence or result exit codes.
4. **Accessible art kit:** light/dark variants, alt text, correct contrast, monochrome silhouette, reduced-motion-friendly treatments.
5. **Community pack:** README banner, sticker outline, conference badge, comic panels and appropriately attributed remixable source files.

## Vector expressions

The source of truth is [scripts/build_mascot.py](../scripts/build_mascot.py), producing one SVG master and five static expressions:

- **Smug:** raised eyebrow, a little too pleased with himself
- **Investigating:** checking provenance and bounds
- **Surprised:** a sanitizer caught something interesting, but nothing is confirmed
- **Celebrating:** only for a reproducible, evidence-backed milestone
- **Caution:** uncertainty, incomplete evidence, or missing receipts

All expressions share the same two-polo silhouette and a negative-space six. SVGs include descriptive titles; don't make color alone carry status. Rebuild and validate with `python3 scripts/build_mascot.py` and `python3 -m unittest -v test_character_assets test_terminal`.

The [terminal cameo](../terminal.py) is **opt-in** and has `--plain`, `--no-color` and `--reduced-motion`. It never announces security findings or overwrites evidence.

## Art asset

The master is [assets/rizzer.svg](../assets/rizzer.svg), a source-generated scalable SVG. The original 256×256 [raster reference](../assets/rizzer.webp) is retained for provenance, **not** used as a print master. Prefer the vector for websites, badges and stickers.

Suggested alternative text:

> “Rizzer, a six-shaped mascot made from two joined polo shirts, one hot pink and one lime green, with two popped collars and a mischievous expression.”

## Contributions and rights

This repository includes an Apache-2.0 license for its source and currently committed material. Before importing third-party artwork, fonts, or celebrity imagery, confirm redistribution and modification rights and record creator attribution. The playful reference is not a license to reproduce logos, imply endorsement, or use a person's likeness without permission. Use [NOTICE](../NOTICE) for provenance.
