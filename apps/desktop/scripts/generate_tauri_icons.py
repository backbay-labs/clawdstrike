#!/usr/bin/env python3

"""Generate clean Tauri icon assets from a single base RGB/PNG.

Key properties:
- Resize RGB first.
- Apply alpha mask per-size.
- Zero RGB where alpha==0 to avoid halo/bleed in some viewers/diff tools.

This avoids the classic artifact where you downsample a masked RGBA and get stray
nonzero RGB in fully-transparent pixels.
"""

from __future__ import annotations

import argparse
import subprocess
import tempfile
from pathlib import Path

import numpy as np
from PIL import Image, ImageDraw


def _squircle_mask(size: int, *, exponent: float = 5.0, oversample: int = 8) -> Image.Image:
    """Return an L-mode alpha mask (0..255) shaped like a squircle/superellipse."""

    n = float(exponent)
    s = int(size)
    k = int(oversample)
    big = s * k

    # Superellipse: |x|^n + |y|^n <= 1
    yc = xc = (big - 1) / 2.0
    a = xc

    y, x = np.ogrid[:big, :big]
    xn = np.abs((x - xc) / a) ** n
    yn = np.abs((y - yc) / a) ** n
    inside = (xn + yn) <= 1.0

    m = np.zeros((big, big), dtype=np.uint8)
    m[inside] = 255

    return Image.fromarray(m, mode="L").resize((s, s), Image.LANCZOS)


def _checkerboard(size: int, *, tile: int = 16) -> Image.Image:
    bg = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(bg)
    for y in range(0, size, tile):
        for x in range(0, size, tile):
            c = (210, 210, 210, 255) if ((x // tile + y // tile) % 2 == 0) else (160, 160, 160, 255)
            d.rectangle([x, y, x + tile - 1, y + tile - 1], fill=c)
    return bg


def _apply_mask(rgb: Image.Image, mask: Image.Image) -> Image.Image:
    rgba = rgb.convert("RGBA")
    rgba.putalpha(mask)

    a = np.array(rgba)
    alpha = a[:, :, 3]
    # Zero RGB when fully transparent to prevent halos in viewers/diffs.
    a[alpha == 0, 0:3] = 0
    return Image.fromarray(a, mode="RGBA")


def _write_png(img: Image.Image, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    img.save(path, format="PNG", optimize=True)


def _build_icns(icon_png_512: Path, out_icns: Path) -> None:
    with tempfile.TemporaryDirectory() as td:
        iconset = Path(td) / "icon.iconset"
        iconset.mkdir(parents=True, exist_ok=True)

        base = Image.open(icon_png_512).convert("RGBA")
        # Standard iconutil set
        sizes = [
            (16, "icon_16x16.png"),
            (32, "icon_16x16@2x.png"),
            (32, "icon_32x32.png"),
            (64, "icon_32x32@2x.png"),
            (128, "icon_128x128.png"),
            (256, "icon_128x128@2x.png"),
            (256, "icon_256x256.png"),
            (512, "icon_256x256@2x.png"),
            (512, "icon_512x512.png"),
        ]

        for s, name in sizes:
            im = base.resize((s, s), Image.LANCZOS)
            _write_png(im, iconset / name)

        subprocess.check_call(["iconutil", "-c", "icns", str(iconset), "-o", str(out_icns)])


def _build_ico(icon_png_512: Path, out_ico: Path) -> None:
    # ImageMagick can generate multi-resolution ICO.
    subprocess.check_call(
        [
            "magick",
            str(icon_png_512),
            "-define",
            "icon:auto-resize=16,32,48,64,128,256",
            str(out_ico),
        ]
    )


def generate(
    *,
    base_rgb_path: Path,
    out_dir: Path,
    exponent: float,
    oversample: int,
    write_preview: bool,
) -> None:
    base_rgb = Image.open(base_rgb_path).convert("RGB")

    # Tauri expects these PNGs.
    targets = {
        "32x32.png": 32,
        "64x64.png": 64,
        "128x128.png": 128,
        "128x128@2x.png": 256,
        "icon.png": 512,
    }

    for name, size in targets.items():
        rgb = base_rgb.resize((size, size), Image.LANCZOS)
        mask = _squircle_mask(size, exponent=exponent, oversample=oversample)
        out = _apply_mask(rgb, mask)
        _write_png(out, out_dir / name)

        if write_preview and name == "icon.png":
            # Useful when iterating locally.
            cb = Image.alpha_composite(_checkerboard(size), out)
            _write_png(cb, out_dir / "_preview_checker.png")

    # icns/ico derived from icon.png
    _build_icns(out_dir / "icon.png", out_dir / "icon.icns")
    _build_ico(out_dir / "icon.png", out_dir / "icon.ico")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", required=True, help="Base RGB image (square) used for all sizes")
    ap.add_argument("--out", required=True, help="Output icon directory")
    ap.add_argument("--exponent", type=float, default=5.0, help="Squircle exponent (higher => squarer)")
    ap.add_argument("--oversample", type=int, default=8, help="Mask oversample factor")
    ap.add_argument("--preview", action="store_true", help="Write checkerboard preview next to icon.png")

    args = ap.parse_args()

    generate(
        base_rgb_path=Path(args.base),
        out_dir=Path(args.out),
        exponent=args.exponent,
        oversample=args.oversample,
        write_preview=args.preview,
    )


if __name__ == "__main__":
    main()
