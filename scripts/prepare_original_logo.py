#!/usr/bin/env python3
"""Make a transparent presentation asset from the original two-polo WebP.

Requires Pillow only when regenerating artwork; not a fuzzing runtime dependency.
The source image is never modified, and no generative redesign is involved.
"""
# SPDX-License-Identifier: Apache-2.0
from collections import deque
from pathlib import Path

from PIL import Image, ImageFilter

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "assets" / "rizzer.webp"
OUTPUT = ROOT / "assets" / "rizzer-transparent.webp"


def make_transparent_logo(source: Path = SOURCE, output: Path = OUTPUT) -> None:
    image = Image.open(source).convert("RGB")
    if image.size != (256, 256):
        raise ValueError("Expected the 256x256 original Rizzer logo")
    width, height = image.size
    colors = list(image.get_flattened_data()) if hasattr(image, "get_flattened_data") else list(image.getdata())

    # Reject near-black WebP compression noise rather than enlarging the halo.
    foreground = [
        max(rgb) >= 32 and (max(rgb) - min(rgb) >= 17 or min(rgb) >= 55)
        for rgb in colors
    ]
    visited = set()
    components = []
    for start, included in enumerate(foreground):
        if not included or start in visited:
            continue
        queue = deque([start])
        visited.add(start)
        component = []
        while queue:
            index = queue.popleft()
            component.append(index)
            x, y = index % width, index // width
            for nx, ny in ((x - 1, y), (x + 1, y), (x, y - 1), (x, y + 1)):
                if 0 <= nx < width and 0 <= ny < height:
                    neighbor = ny * width + nx
                    if foreground[neighbor] and neighbor not in visited:
                        visited.add(neighbor)
                        queue.append(neighbor)
        components.append(component)
    if not components:
        raise ValueError("Source image has no recognizable foreground")

    main = max(components, key=len)
    if len(main) < 10_000:
        raise ValueError("Detected artwork is unexpectedly small")
    mask = Image.new("L", (width, height))
    for index in main:
        mask.putpixel((index % width, index // width), 255)

    # Retain the original silhouette, smooth the matte by less than one pixel.
    mask = mask.filter(ImageFilter.MaxFilter(3)).filter(ImageFilter.GaussianBlur(0.6))
    rgba = []
    mask_pixels = list(mask.get_flattened_data()) if hasattr(mask, "get_flattened_data") else list(mask.getdata())
    for (r, g, b), alpha in zip(colors, mask_pixels):
        if alpha < 10:
            rgba.append((0, 0, 0, 0))
            continue
        # Recover colors compressed against the original solid black background.
        scale = 255 / alpha
        rgba.append((
            min(255, round(r * scale)),
            min(255, round(g * scale)),
            min(255, round(b * scale)),
            alpha,
        ))
    result = Image.new("RGBA", (width, height))
    result.putdata(rgba)
    result = result.resize((512, 512), Image.Resampling.LANCZOS)
    result.save(output, format="WEBP", quality=95, method=6)


if __name__ == "__main__":
    make_transparent_logo()
    print(f"Prepared {OUTPUT.relative_to(ROOT)} from untouched original")
