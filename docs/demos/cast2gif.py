#!/usr/bin/env python3
"""Render an asciinema v2 .cast to an animated GIF (self-contained, Pillow + Menlo)."""
import json
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont

SKILL = Path.home() / ".claude" / "skills" / "mcp-sentinel"
CAST = SKILL / "docs" / "demos" / "sentinel-demo.cast"
GIF = SKILL / "docs" / "demos" / "sentinel-demo.gif"
FONT = "/System/Library/Fonts/Menlo.ttc"

COLS, ROWS = 92, 26
FS = 15
font = ImageFont.truetype(FONT, FS)
CW = int(round(font.getlength("M")))
CH = FS + 5
BG = (13, 17, 23)
DEF = (200, 200, 205)

SGR = {
    "0": None, "2": (138, 138, 138), "31": (255, 95, 95), "1;31": (255, 100, 100),
    "32": (95, 215, 95), "1;32": (120, 230, 120), "33": (230, 210, 90),
    "35": (215, 95, 215), "1;35": (225, 110, 225), "36": (95, 215, 215),
    "1;36": (110, 230, 230),
}
REPL = {"🛡️": "", "🛡": "", "▶": ">", "✓": "OK", "—": "-", "️": ""}


def clean(s):
    for a, b in REPL.items():
        s = s.replace(a, b)
    return s


# terminal buffer: ROWS lines of COLS cells (char, color)
screen = [[(" ", DEF) for _ in range(COLS)] for _ in range(ROWS)]
row = col = 0
cur = DEF


def scroll():
    screen.pop(0)
    screen.append([(" ", DEF) for _ in range(COLS)])


def feed(data):
    global row, col, cur
    i, n = 0, len(data)
    while i < n:
        c = data[i]
        if c == "\x1b" and i + 1 < n and data[i + 1] == "[":
            j = data.find("m", i)
            if j == -1:
                break
            code = data[i + 2:j]
            cur = SGR.get(code, DEF if code in ("0", "") else cur)
            if code == "0":
                cur = DEF
            i = j + 1
            continue
        if c == "\r":
            col = 0
        elif c == "\n":
            row += 1
            col = 0
            if row >= ROWS:
                scroll()
                row = ROWS - 1
        else:
            if row < ROWS and col < COLS:
                screen[row][col] = (c, cur)
            col += 1
        i += 1


def snapshot():
    return tuple(tuple(cell for cell in line) for line in screen)


def render(snap):
    img = Image.new("RGB", (COLS * CW, ROWS * CH), BG)
    d = ImageDraw.Draw(img)
    for r, line in enumerate(snap):
        for cc, (ch, color) in enumerate(line):
            if ch != " ":
                d.text((cc * CW, r * CH), ch, font=font, fill=color)
    return img.quantize(colors=128, method=Image.MEDIANCUT)


lines = CAST.read_text().splitlines()
events = [json.loads(l) for l in lines[1:]]

frames, durations = [], []
last_t = 0.0
last_sig = None
INTERVAL = 0.10
pending = None  # (image, sig)

for t, kind, data in events:
    if kind != "o":
        continue
    if (t - last_t) >= INTERVAL:
        sig = snapshot()
        if sig != last_sig:
            frames.append(render(sig))
            durations.append(max(30, int((t - last_t) * 1000)))
            last_sig = sig
            last_t = t
        else:
            last_t = t
    feed(clean(data))

# final frame + hold
sig = snapshot()
frames.append(render(sig))
durations.append(2500)

frames[0].save(GIF, save_all=True, append_images=frames[1:], duration=durations,
               loop=0, optimize=True, disposal=2)
print(f"wrote {GIF}  ({len(frames)} frames, {sum(durations)/1000:.1f}s, {GIF.stat().st_size//1024} KB)")
frames[len(frames)//2].convert("RGB").save("/tmp/sentinel-demo/mid.png")
frames[-1].convert("RGB").save("/tmp/sentinel-demo/last.png")
print("probes: /tmp/sentinel-demo/mid.png last.png")
