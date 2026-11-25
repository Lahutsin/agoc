#!/usr/bin/env python3
"""AGOC icon generator: rounded square (gate) + globe (public IP). Original geometric artwork.

Each tray size is drawn separately with its geometry snapped to the pixel grid
(integer stroke widths, straight edges on pixel boundaries), so the app never
resamples the icon at runtime and small sizes stay sharp instead of blurry.

    python3 icon/gen_icon.py        # writes icon/icon.png, icon/tray/tray-<N>.png
                                    # and icon/tray/globe-<N>.png

Per size, two files are written:
  * tray-<N>.png  - the frame: blue rim + dark body, without the globe.
  * globe-<N>.png - 8-bit coverage mask of the globe lines. The tray app paints
    the globe in the status color (green/red/...) through this mask.
icon/icon.png is the full artwork at 1024 px with a green globe (preview only).

Sizes:
  * Linux (StatusNotifierItem): 16, 22, 24, 32, 44, 48, 64 - the tray host picks
    the closest one for its panel height and HiDPI scale.
  * macOS: the menu bar draws the icon 18 pt high -> 18 px (@1x) or 36 px (Retina).
  * Windows (for a future port): 16, 20, 24, 32, 40, 48 for 100-300 % scaling.

Requires Pillow only.
"""
import os
import sys

from PIL import Image, ImageChops, ImageDraw

HERE = os.path.dirname(os.path.abspath(__file__))
TRAY_SIZES = (16, 18, 20, 22, 24, 32, 36, 40, 44, 48, 64)

RIM = (56, 152, 236)      # rim: blue, separates the icon from dark panels
BODY = (18, 27, 43)       # body: dark navy, silhouette on light panels
PREVIEW = (60, 220, 110)  # globe color in icon.png (the "allowed" status color)


def render(size):
    """Returns (frame RGBA, globe mask L), both size x size."""
    ss = max(4, 256 // size)  # supersampling; box downsampling = exact pixel coverage
    hi = size * ss

    def new():
        return Image.new("L", (hi, hi), 0)

    def box(cx, cy, rx, ry):
        return [(cx - rx) * ss, (cy - ry) * ss, (cx + rx) * ss - 1, (cy + ry) * ss - 1]

    # Pixel-snapped geometry (output pixels).
    rim = max(1, round(size * 0.07))
    line = max(1, round(size * 0.06))
    half = (line % 2) / 2                 # odd strokes are centred on pixel centres
    # The globe axes must sit on a pixel centre for odd strokes and on a pixel
    # boundary for even ones; if the canvas centre does not, shrink the square by
    # one pixel (its side becomes odd) instead of blurring the lines.
    shift = 0.5 if ((size / 2) % 1 != half) else 0.0
    side = size - 2 * shift
    cx = cy = side / 2
    corner = max(1.0, size * 0.12)
    radius = max(3, round(size * 0.30)) + half   # outer edge lands on a pixel boundary

    outer = new()
    ImageDraw.Draw(outer).rounded_rectangle(
        [0, 0, side * ss - 1, side * ss - 1], radius=corner * ss, fill=255)
    body = new()
    # The body is the square moved inwards by exactly `rim`, with the corner radius
    # reduced by the same amount, so the rim has a uniform width everywhere.
    ImageDraw.Draw(body).rounded_rectangle(
        [rim * ss, rim * ss, (side - rim) * ss - 1, (side - rim) * ss - 1],
        radius=max(0.0, corner - rim) * ss, fill=255)

    disc = new()
    ImageDraw.Draw(disc).ellipse(box(cx, cy, radius, radius), fill=255)
    globe = new()
    draw = ImageDraw.Draw(globe)
    draw.ellipse(box(cx, cy, radius, radius), fill=255)
    draw.ellipse(box(cx, cy, radius - line, radius - line), fill=0)
    meridian = new()
    draw = ImageDraw.Draw(meridian)
    if size <= 24:
        # Small sizes: a curved meridian turns into grey mush, so use a straight
        # vertical bar on whole pixels (circle + cross still reads as a globe).
        draw.rectangle([(cx - line / 2) * ss, (cy - radius) * ss,
                        (cx + line / 2) * ss - 1, (cy + radius) * ss - 1], fill=255)
    else:
        # vertical ellipse ring, about half the radius wide
        mrx = max(line + 0.5, round(radius * 0.5 * 2) / 2)
        draw.ellipse(box(cx, cy, mrx, radius), fill=255)
        draw.ellipse(box(cx, cy, mrx - line, radius - line), fill=0)
    globe = ImageChops.lighter(globe, meridian)
    # equator: horizontal bar on whole pixels
    equator = new()
    ImageDraw.Draw(equator).rectangle(
        [(cx - radius) * ss, (cy - line / 2) * ss, (cx + radius) * ss - 1, (cy + line / 2) * ss - 1],
        fill=255)
    globe = ImageChops.multiply(ImageChops.multiply(ImageChops.lighter(globe, equator), disc), body)

    frame = Image.new("RGBA", (hi, hi), (0, 0, 0, 0))
    frame.paste(Image.new("RGBA", (hi, hi), RIM + (255,)), mask=outer)
    frame.paste(Image.new("RGBA", (hi, hi), BODY + (255,)), mask=body)
    return frame.resize((size, size), Image.BOX), globe.resize((size, size), Image.BOX)


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else HERE
    os.makedirs(os.path.join(out, "tray"), exist_ok=True)
    for size in TRAY_SIZES:
        frame, globe = render(size)
        frame.save(os.path.join(out, "tray", f"tray-{size}.png"), optimize=True)
        globe.save(os.path.join(out, "tray", f"globe-{size}.png"), optimize=True)
    frame, globe = render(1024)
    frame.paste(Image.new("RGBA", frame.size, PREVIEW + (255,)), mask=globe)
    frame.save(os.path.join(out, "icon.png"), optimize=True)


if __name__ == "__main__":
    main()
