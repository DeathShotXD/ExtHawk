#!/usr/bin/env python3
"""Render a terminal-style GIF from a real ExtHawk lab session.

The lines below are copied from actual runs against lab/extension-vuln and
lab/extension-patched in Chrome for Testing 157.0.8103.78. No output is
invented. Regenerate with:

    python3 scripts/make_demo.py
"""
from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "assets" / "demo.gif"

W, H = 960, 640
FPS = 12
FRAME = int(1000 / FPS)

BG = (5, 8, 12)
PANEL = (8, 13, 20)
BAR = (10, 17, 25)
BONE = (231, 226, 216)
DIM = (111, 128, 147)
CYAN = (53, 208, 192)
VIOLET = (167, 139, 250)
AMBER = (240, 180, 90)
RED = (255, 92, 122)
GREEN = (53, 208, 192)

MONO = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
MONO_B = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf"
FONT = ImageFont.truetype(MONO, 13)
FONT_B = ImageFont.truetype(MONO_B, 13)
FONT_S = ImageFont.truetype(MONO, 10)
FONT_T = ImageFont.truetype(MONO_B, 12)

LEFT = 52
TOP = 96
LH = 21

Segments = list[tuple[str, tuple[int, int, int]]]


def seg(*parts: tuple[str, tuple[int, int, int]]) -> Segments:
    return list(parts)


def cmd(text: str) -> Segments:
    return seg(("$ ", CYAN), (text, BONE))


SCAN = [
    seg(("  target  ", DIM), ("lab/extension-vuln", BONE)),
    seg(("  name    ", DIM), ("HawkNotes 1.0.0  (MV3)", BONE)),
    seg(("  id      ", DIM), ("nmfikiipecbppmhonpohidnkihhfkhog", BONE)),
    seg(("  grade   ", DIM), ("CRITICAL", RED), ("  (score 100/100)", DIM)),
    seg(("[CRITICAL] ", RED), ("External message handler reaches cookie access", BONE)),
    seg(("[CRITICAL] ", RED), ("External message handler reaches script injection", BONE)),
    seg(("[CRITICAL] ", RED), ("External message handler reaches dynamic code evaluation", BONE)),
    seg(("summary: ", DIM), ("3 critical, 12 high, 5 medium, 3 low", BONE)),
]

EXPLOIT = [
    seg(("  ping                 ", BONE), ("CONFIRMED", CYAN), ("  response with version", DIM)),
    seg(("  cookie-theft         ", BONE), ("CONFIRMED", CYAN), ("  callback with cookies (1 cookie(s): exthawk_session)", DIM)),
    seg(("  ssrf                 ", BONE), ("CONFIRMED", CYAN), ("  callback /cb?ssrf=1", DIM)),
    seg(("  page-injection       ", BONE), ("CONFIRMED", CYAN), ("  live marker EXTHAWK_INJECT", DIM)),
    seg(("  dom-xss              ", BONE), ("CONFIRMED", CYAN), ("  live marker EXTHAWK_DOM", DIM)),
    seg(("[+] 5/5 payloads confirmed", GREEN)),
]

LAB = [
    seg(("=== vulnerable extension ===", BONE)),
    seg(("[+] vulnerable extension: exploit confirmed (expected)", GREEN)),
    seg(("=== patched extension ===", BONE)),
    seg(("[!] 0/5 payloads confirmed", RED)),
    seg(("[+] patched extension: no exploit (expected)", GREEN)),
    seg(("[+] A/B lab complete", VIOLET)),
]


def base() -> tuple[Image.Image, ImageDraw.ImageDraw]:
    im = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(im)
    d.rounded_rectangle([24, 24, W - 24, H - 24], radius=12, fill=PANEL,
                        outline=(30, 44, 58), width=1)
    d.rectangle([25, 25, W - 25, 68], fill=BAR)
    d.line([24, 68, W - 24, 68], fill=(30, 44, 58))
    for i, c in enumerate((RED, AMBER, CYAN)):
        d.ellipse([52 + i * 22, 40, 62 + i * 22, 50], fill=c)
    d.text((126, 38), "exthawk / lab", font=FONT_T, fill=DIM)
    d.text((W - 52, 38), "AUTHORIZED LAB", font=FONT_T, fill=VIOLET, anchor="ra")
    d.line([24, H - 48, W - 24, H - 48], fill=(30, 44, 58))
    d.text((52, H - 34), "real run / chrome for testing 157.0.8103.78", font=FONT_S, fill=DIM)
    d.text((W - 52, H - 34), "github.com/DeathShotXD/ExtHawk", font=FONT_S, fill=DIM, anchor="ra")
    return im, d


def draw_line(d: ImageDraw.ImageDraw, y: int, parts: Segments) -> None:
    x = LEFT
    for text, colour in parts:
        d.text((x, y), text, font=FONT, fill=colour)
        x += d.textlength(text, font=FONT)


def render(lines: list[Segments], typed: str | None = None,
           typed_done: int = 0, cursor: bool = True) -> Image.Image:
    im, d = base()
    y = TOP
    for parts in lines:
        draw_line(d, y, parts)
        y += LH
    if typed is not None:
        draw_line(d, y, seg(("$ ", CYAN), (typed[:typed_done], BONE)))
        if cursor:
            x = LEFT + d.textlength("$ ", font=FONT) + d.textlength(typed[:typed_done], font=FONT)
            d.rectangle([x + 1, y + 1, x + 8, y + 15], fill=CYAN)
    elif cursor:
        d.rectangle([LEFT, y + 1, LEFT + 7, y + 15], fill=CYAN)
    return im


def main() -> None:
    frames: list[Image.Image] = []
    lines: list[Segments] = []

    def hold(n: int = 2) -> None:
        for _ in range(n):
            frames.append(render(lines))

    hold(12)

    commands = [
        ("python3 exthawk.py scan -e lab/extension-vuln", SCAN),
        ("python3 exthawk.py exploit -e lab/extension-vuln --payloads lab/payloads.json", EXPLOIT),
        ("./lab/run.sh", LAB),
    ]
    for text, output in commands:
        # type the command
        for i in range(0, len(text) + 1, 3):
            frames.append(render(lines, typed=text, typed_done=i))
        lines.append(cmd(text))
        hold(3)
        for item in output:
            lines.append(item)
            hold(2)
        hold(10)

    # final hold
    for _ in range(24):
        frames.append(render(lines, cursor=False))

    OUT.parent.mkdir(parents=True, exist_ok=True)
    flat = frames[-1].quantize(colors=32, method=Image.MEDIANCUT)
    pal_frames = [im.quantize(palette=flat, dither=Image.NONE) for im in frames]
    pal_frames[0].save(
        OUT,
        save_all=True,
        append_images=pal_frames[1:],
        duration=FRAME,
        loop=0,
        optimize=True,
        disposal=2,
    )
    print(f"wrote {OUT} ({OUT.stat().st_size / 1024:.0f} KiB, {len(frames)} frames)")


if __name__ == "__main__":
    main()
