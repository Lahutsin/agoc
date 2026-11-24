#!/usr/bin/env python3
"""AGOC icon generator: shield (gate) + globe (public IP). Original geometric artwork.

Each tray size is drawn separately with its geometry snapped to the pixel grid
(integer stroke widths, straight edges on pixel boundaries), so the app never
resamples the icon at runtime and small sizes stay sharp instead of blurry.

    python3 icon/gen_icon.py        # writes icon/icon.png and icon/tray/tray-<N>.png

Sizes:
  * Linux (StatusNotifierItem): 16, 22, 24, 32, 44, 48, 64 - the tray host picks
    the closest one for its panel height and HiDPI scale.
  * macOS: the menu bar draws the icon 18 pt high -> 18 px (@1x) or 36 px (Retina).
  * Windows (for a future port): 16, 20, 24, 32, 40, 48 for 100-300 % scaling.

Requires Pillow only.
"""
import math
import os
import sys

from PIL import Image, ImageChops, ImageDraw

HERE = os.path.dirname(os.path.abspath(__file__))
TRAY_SIZES = (16, 18, 20, 22, 24, 32, 36, 40, 44, 48, 64)

RIM = (56, 152, 236)      # shield rim: blue, separates the icon from dark panels
BODY = (18, 27, 43)       # shield body: dark navy, silhouette on light panels
GLOBE = (226, 242, 255)   # globe lines: near white, maximum contrast on the body


def shield(left, right, top, bottom, corner, steps=96):
    """Flat top with rounded corners, vertical sides, sides curving into a point."""
    cx = (left + right) / 2
    shoulder = top + (bottom - top) * 0.48
    pts = [(left, shoulder)]
    for i in range(steps // 4 + 1):  # top-left corner, from the side to the top edge
        a = math.pi - (math.pi / 2) * i / (steps // 4)
        pts.append((left + corner + corner * math.cos(a), top + corner - corner * math.sin(a)))
    for i in range(steps // 4 + 1):  # top-right corner, from the top edge to the side
        a = math.pi / 2 - (math.pi / 2) * i / (steps // 4)
        pts.append((right - corner + corner * math.cos(a), top + corner - corner * math.sin(a)))
    pts.append((right, shoulder))
    curve = top + (bottom - top) * 0.84
    for p0, p1, p2 in (((right, shoulder), (right, curve), (cx, bottom)),
                       ((cx, bottom), (left, curve), (left, shoulder))):
        for i in range(1, steps + 1):
            t = i / steps
            pts.append(((1 - t) ** 2 * p0[0] + 2 * (1 - t) * t * p1[0] + t ** 2 * p2[0],
                        (1 - t) ** 2 * p0[1] + 2 * (1 - t) * t * p1[1] + t ** 2 * p2[1]))
    return pts


def inset(points, distance):
    """Exact inward offset of a convex polygon: intersect the half-planes that lie
    `distance` inside each edge (Sutherland-Hodgman clipping). Every point of the
    result is at least `distance` from the outline, and the boundary is at exactly
    that distance, so a rim drawn between the two has a uniform width."""
    pts = [p for i, p in enumerate(points) if p != points[i - 1]]
    cx = sum(x for x, _ in pts) / len(pts)
    cy = sum(y for _, y in pts) / len(pts)
    result = list(pts)
    for (x1, y1), (x2, y2) in zip(pts, pts[1:] + pts[:1]):
        dx, dy = x2 - x1, y2 - y1
        length = math.hypot(dx, dy)
        if length < 1e-9:
            continue
        nx, ny = -dy / length, dx / length
        if nx * (cx - x1) + ny * (cy - y1) < 0:   # make the normal point inwards
            nx, ny = -nx, -ny
        offset = nx * x1 + ny * y1 + distance       # keep points with n.p >= offset

        def side(point):
            return nx * point[0] + ny * point[1] - offset

        clipped = []
        for a, b in zip(result, result[1:] + result[:1]):
            sa, sb = side(a), side(b)
            if sa >= 0:
                clipped.append(a)
            if (sa >= 0) != (sb >= 0):
                t = sa / (sa - sb)
                clipped.append((a[0] + (b[0] - a[0]) * t, a[1] + (b[1] - a[1]) * t))
        result = clipped
    return result


def render(size):
    ss = max(4, 256 // size)  # supersampling; box downsampling = exact pixel coverage
    hi = size * ss

    def new():
        return Image.new("L", (hi, hi), 0)

    def poly(points):
        return [(x * ss, y * ss) for x, y in points]

    def box(cx, cy, rx, ry):
        return [(cx - rx) * ss, (cy - ry) * ss, (cx + rx) * ss - 1, (cy + ry) * ss - 1]

    # Pixel-snapped geometry (output pixels).
    rim = max(1, round(size * 0.07))
    line = max(1, round(size * 0.06))
    margin = max(1, round(size * 0.07))
    half = (line % 2) / 2                 # odd strokes are centred on pixel centres
    # The vertical axis must sit on a pixel centre for odd strokes and on a pixel
    # boundary for even ones; if the canvas centre does not, shift the whole
    # shield half a pixel left (its width becomes odd) instead of blurring lines.
    shift = 0.5 if ((size / 2) % 1 != half) else 0.0
    cx = size / 2 - shift
    left, right = margin, size - margin - 2 * shift
    top, bottom = max(0, round(size * 0.04)), size
    corner = max(1.0, size * 0.10)
    radius = max(3, round(size * 0.24)) + half   # outer edge lands on a pixel boundary
    cy = round(size * 0.44) + half

    outline = shield(left, right, top, bottom, corner)
    outer = new()
    ImageDraw.Draw(outer).polygon(poly(outline), fill=255)
    body = new()
    # The body is the outline moved inwards by exactly `rim` everywhere, so the blue
    # rim has the same thickness on the top, the sides, the curves and the point.
    ImageDraw.Draw(body).polygon(poly(inset(outline, rim)), fill=255)

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
    globe = ImageChops.multiply(ImageChops.lighter(globe, equator), disc)

    img = Image.new("RGBA", (hi, hi), (0, 0, 0, 0))
    img.paste(Image.new("RGBA", (hi, hi), RIM + (255,)), mask=outer)
    img.paste(Image.new("RGBA", (hi, hi), BODY + (255,)), mask=body)
    img.paste(Image.new("RGBA", (hi, hi), GLOBE + (255,)), mask=ImageChops.multiply(globe, body))
    return img.resize((size, size), Image.BOX)


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else HERE
    os.makedirs(os.path.join(out, "tray"), exist_ok=True)
    for size in TRAY_SIZES:
        render(size).save(os.path.join(out, "tray", f"tray-{size}.png"), optimize=True)
    render(1024).save(os.path.join(out, "icon.png"), optimize=True)


if __name__ == "__main__":
    main()
