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

## Existing and future art

The original two-polo mark, five optional vector expressions, and the accessible, read-only terminal cameo already ship. The expressions **do not replace** the original identity.

Future work: a separately reviewed high-resolution source recreation faithful to the original; contrast-tested light/dark versions; a monochrome outline; and attributed community art. Preserve legibility and reduced-motion behavior. Do not treat simple raster enlargement as a true vector master.

## Vector expressions

The source of truth for the **supporting vector expression set** is [scripts/build_mascot.py](../scripts/build_mascot.py), producing one SVG master and five static expressions:

- **Smug:** raised eyebrow, a little too pleased with himself
- **Investigating:** checking provenance and bounds
- **Surprised:** a sanitizer caught something interesting, but nothing is confirmed
- **Celebrating:** only for a reproducible, evidence-backed milestone
- **Caution:** uncertainty, incomplete evidence, or missing receipts

All expressions share the same two-polo silhouette and a negative-space six. SVGs include descriptive titles; don't make color alone carry status. Rebuild and validate with `python3 scripts/build_mascot.py` and `python3 -m unittest -v test_character_assets test_terminal`.

The [terminal cameo](../terminal.py) is **opt-in** and has `--plain`, `--no-color` and `--reduced-motion`. It never announces security findings or overwrites evidence.

## Art asset

The **canonical Rizzer design** is the original 256×256 [two-polo illustration](../assets/rizzer.webp), shared with 6lowStick as `assets/6lowstick-two-polos.webp`. The README uses a transparent [presentation derivative](../assets/rizzer-transparent.webp), which retains the original silhouette, collars, and colors while suppressing the black raster background and WebP compression artifacts. Generate it with optional Pillow via `python3 scripts/prepare_original_logo.py`; the source image is never rewritten.

Do not replace the original design with the generated cartoon character in README heroes or other primary brand placements.

The generated [SVG master](../assets/rizzer.svg) and five [expression variants](../assets/rizzer-smug.svg) remain supporting art for character reactions, badges, and terminal appearances. The transparent 512px derivative is still enlarged raster artwork, **not** a true high-resolution print master. For print, produce a separately reviewed faithful recreation.

Suggested alternative text:

> “Rizzer, two conjoined polo shirts in hot pink and lime green forming the number six, with two popped collars and button plackets.”

## Contributions and rights

This repository includes an Apache-2.0 license for its source and currently committed material. Before importing third-party artwork, fonts, or celebrity imagery, confirm redistribution and modification rights and record creator attribution. The playful reference is not a license to reproduce logos, imply endorsement, or use a person's likeness without permission. Use [NOTICE](../NOTICE) for provenance.
