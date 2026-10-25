#!/usr/bin/env python3
"""Generate icon-512.png — brand §6: eclipse motif on navy (#0d1b2a),
one per-product glyph. Haven's glyph is a shelter arch over a ticket
card — a haven for the support queue — inside the gradient eclipse
ring. PIL only; deterministic."""
from PIL import Image, ImageDraw

S = 512
NAVY = (13, 27, 42, 255)
STOPS = [(15, 246, 247), (0, 212, 255), (123, 44, 191)]


def lerp(a, b, t):
    return tuple(int(a[i] + (b[i] - a[i]) * t) for i in range(3)) + (255,)


def grad(t):
    return lerp(STOPS[0], STOPS[1], t * 2) if t < 0.5 else \
        lerp(STOPS[1], STOPS[2], (t - 0.5) * 2)


def main():
    img = Image.new("RGBA", (S, S), NAVY)
    d = ImageDraw.Draw(img)
    ring = [54, 54, 458, 458]
    for i in range(72):
        t = i / 72
        d.arc(ring, start=i * 5, end=i * 5 + 6, fill=grad(t), width=13)
    d.ellipse([126, 126, 386, 386], fill=NAVY)
    # The shelter arch.
    d.arc([166, 128, 346, 300], start=180, end=360, fill=grad(0.25),
          width=11)
    d.line([(166, 214), (166, 372)], fill=grad(0.25), width=11)
    d.line([(346, 214), (346, 372)], fill=grad(0.65), width=11)
    # The ticket card under the arch.
    card = [196, 252, 316, 372]
    d.rounded_rectangle(card, radius=10, fill=(8, 12, 20, 255),
                        outline=(254, 254, 254, 255), width=5)
    for i, y in enumerate((282, 312, 342)):
        d.line([(216, y), (296, y)], fill=grad(0.35 + 0.2 * i),
               width=7)
    img.save("icon-512.png")
    print("wrote icon-512.png", img.size, img.mode)


if __name__ == "__main__":
    main()
