#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok

"""Draws the diagrams of the user documentation (docs/guide, README.md) as
SVG files in docs/images, all in one style, with a light and a dark theme
(prefers-color-scheme). Edit a diagram here and run it again:

    python3 tools/diagrams/diagrams.py
"""

import html
import math
import os
import sys

OUT = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), '..', '..', 'docs', 'images')

STYLE = """
<style>
  .bg { fill: none; }
  .zone { fill: #f6f8fa; stroke: #d0d7de; stroke-width: 1; }
  .zone-t { fill: #57606a; font: 600 13px system-ui, -apple-system, 'Segoe UI', sans-serif; letter-spacing: .02em; }
  .card { fill: #ffffff; stroke: #d0d7de; stroke-width: 1.2; }
  .card.key { stroke: #8250df; stroke-width: 2; }
  .card.srv { fill: #fff8c5; stroke: #d4a72c; }
  .t { fill: #1f2328; font: 600 14px system-ui, -apple-system, 'Segoe UI', sans-serif; }
  .s { fill: #57606a; font: 12px system-ui, -apple-system, 'Segoe UI', sans-serif; }
  .ic { fill: none; stroke: #1f2328; stroke-width: 1.6; stroke-linecap: round; stroke-linejoin: round; }
  .key .ic, .ic.key { stroke: #8250df; }
  .badge { fill: #8250df; }
  .badge-t { fill: #ffffff; font: 600 10px system-ui, -apple-system, 'Segoe UI', sans-serif; letter-spacing: .04em; }
  .e-tunnel { fill: none; stroke: #0969da; stroke-width: 3; }
  .e-home { fill: none; stroke: #57606a; stroke-width: 1.6; stroke-dasharray: 5 4; }
  .e-pair { fill: none; stroke: #8250df; stroke-width: 1.8; }
  .e-e2e { fill: none; stroke: #1a7f37; stroke-width: 1.8; stroke-dasharray: 2 4; stroke-linecap: round; }
  .a-tunnel { fill: #0969da; } .a-home { fill: #57606a; } .a-pair { fill: #8250df; } .a-e2e { fill: #1a7f37; }
  .lbl-bg { fill: #ffffff; stroke: #d0d7de; stroke-width: 1; }
  .lbl { fill: #1f2328; font: 12px system-ui, -apple-system, 'Segoe UI', sans-serif; }
  .lbl.tunnel { fill: #0969da; } .lbl.pair { fill: #8250df; } .lbl.e2e { fill: #1a7f37; }
  .note { fill: #57606a; font: italic 12px system-ui, -apple-system, 'Segoe UI', sans-serif; }
  @media (prefers-color-scheme: dark) {
    .zone { fill: #161b22; stroke: #30363d; }
    .zone-t, .s, .note { fill: #8b949e; }
    .card { fill: #0d1117; stroke: #3d444d; }
    .card.key { stroke: #a371f7; }
    .card.srv { fill: #272115; stroke: #9e6a03; }
    .t, .lbl { fill: #e6edf3; }
    .ic { stroke: #e6edf3; }
    .key .ic, .ic.key { stroke: #a371f7; }
    .badge { fill: #a371f7; }
    .badge-t { fill: #0d1117; }
    .e-tunnel { stroke: #4493f8; } .a-tunnel { fill: #4493f8; } .lbl.tunnel { fill: #4493f8; }
    .e-home { stroke: #8b949e; } .a-home { fill: #8b949e; }
    .e-pair { stroke: #a371f7; } .a-pair { fill: #a371f7; } .lbl.pair { fill: #a371f7; }
    .e-e2e { stroke: #3fb950; } .a-e2e { fill: #3fb950; } .lbl.e2e { fill: #3fb950; }
    .lbl-bg { fill: #0d1117; stroke: #3d444d; }
  }
</style>
"""

def esc(s): return html.escape(s, quote=True)

# Icons drawn in a 28x28 box at (x, y).
def icon(kind, x, y):
    t = f'transform="translate({x},{y})"'
    if kind == 'phone':
        return f'<g {t} class="ic"><rect x="8" y="2" width="12" height="24" rx="2.5"/><line x1="12.5" y1="22.5" x2="15.5" y2="22.5"/></g>'
    if kind == 'laptop':
        return f'<g {t} class="ic"><rect x="5" y="6" width="18" height="12" rx="1.5"/><path d="M2 22h24l-2 -3H4z"/></g>'
    if kind == 'desktop':
        return f'<g {t} class="ic"><rect x="3" y="4" width="22" height="15" rx="1.5"/><line x1="14" y1="19" x2="14" y2="24"/><line x1="9" y1="24" x2="19" y2="24"/></g>'
    if kind == 'board':
        return f'<g {t} class="ic"><rect x="4" y="7" width="20" height="14" rx="1.5"/><rect x="9" y="11" width="6" height="6"/><line x1="7" y1="4" x2="7" y2="7"/><line x1="11" y1="4" x2="11" y2="7"/><line x1="15" y1="4" x2="15" y2="7"/><line x1="19" y1="4" x2="19" y2="7"/></g>'
    if kind == 'cloud':
        return f'<g {t} class="ic"><path d="M8 21h13a5 5 0 0 0 0 -10a7 7 0 0 0 -13.5 1.5A4.3 4.3 0 0 0 8 21z"/></g>'
    if kind == 'server':
        return f'<g {t} class="ic"><rect x="5" y="4" width="18" height="8" rx="1.5"/><rect x="5" y="16" width="18" height="8" rx="1.5"/><line x1="9" y1="8" x2="11" y2="8"/><line x1="9" y1="20" x2="11" y2="20"/></g>'
    raise ValueError(kind)

class D:
    def __init__(self, w, h, title):
        self.w, self.h, self.title, self.parts = w, h, title, []
        self.labels = []
    def zone(self, x, y, w, h, label):
        self.parts.append(f'<rect class="zone" x="{x}" y="{y}" width="{w}" height="{h}" rx="14"/>')
        self.parts.append(f'<text class="zone-t" x="{x+16}" y="{y+24}">{esc(label)}</text>')
    def card(self, cx, cy, kind, title, sub=None, w=170, cls='', badge=None):
        h = 64 if sub else 52
        x, y = cx - w/2, cy - h/2
        g = [f'<g class="{cls}">', f'<rect class="card {cls}" x="{x}" y="{y}" width="{w}" height="{h}" rx="10"/>']
        g.append(icon(kind, x + 12, cy - 14))
        tx = x + 50
        if sub:
            g.append(f'<text class="t" x="{tx}" y="{cy-4}">{esc(title)}</text>')
            g.append(f'<text class="s" x="{tx}" y="{cy+14}">{esc(sub)}</text>')
        else:
            g.append(f'<text class="t" x="{tx}" y="{cy+5}">{esc(title)}</text>')
        if badge:
            bw = 8 + 6.4 * len(badge)
            g.append(f'<rect class="badge" x="{x+w-bw-8}" y="{y-9}" width="{bw}" height="18" rx="9"/>')
            g.append(f'<text class="badge-t" x="{x+w-8-bw/2}" y="{y+4}" text-anchor="middle">{esc(badge)}</text>')
        g.append('</g>')
        self.parts.append(''.join(g))
        return (x, y, w, h)
    def edge(self, pts, kind, label=None, at=None, start=False, end=True, lw=None):
        d = 'M' + ' L'.join(f'{a},{b}' for a, b in pts)
        self.parts.append(f'<path class="e-{kind}" d="{d}"/>')
        if end: self.parts.append(self._head(pts[-2], pts[-1], kind))
        if start: self.parts.append(self._head(pts[1], pts[0], kind))
        if label:
            if at is None:
                (x1, y1), (x2, y2) = pts[len(pts)//2 - 1], pts[len(pts)//2]
                at = ((x1+x2)/2, (y1+y2)/2)
            self.labels.append((at, label, kind))
    def _head(self, p, q, kind):
        (x1, y1), (x2, y2) = p, q
        a = math.atan2(y2-y1, x2-x1)
        s = 10 if kind == 'tunnel' else 8
        l = (x2 - s*math.cos(a) + s*0.55*math.sin(a), y2 - s*math.sin(a) - s*0.55*math.cos(a))
        r = (x2 - s*math.cos(a) - s*0.55*math.sin(a), y2 - s*math.sin(a) + s*0.55*math.cos(a))
        return f'<path class="a-{kind}" d="M{x2},{y2} L{l[0]:.1f},{l[1]:.1f} L{r[0]:.1f},{r[1]:.1f}z"/>'
    def note(self, x, y, text, anchor='middle'):
        self.parts.append(f'<text class="note" x="{x}" y="{y}" text-anchor="{anchor}">{esc(text)}</text>')
    def save(self, name):
        lab = []
        for (x, y), text, kind in self.labels:
            lines = text.split('\n')
            w = max(len(l) for l in lines) * 6.3 + 16
            h = 16 * len(lines) + 6
            lab.append(f'<rect class="lbl-bg" x="{x-w/2:.1f}" y="{y-h/2:.1f}" width="{w:.1f}" height="{h}" rx="{min(h/2, 11)}"/>')
            for i, l in enumerate(lines):
                ly = y - h/2 + 15 + 16*i
                lab.append(f'<text class="lbl {kind}" x="{x}" y="{ly:.1f}" text-anchor="middle">{esc(l)}</text>')
        svg = ('<!-- SPDX-License-Identifier: AGPL-3.0-only. Drawn by tools/diagrams/diagrams.py; edit it there. -->\n'
               f'<svg xmlns="http://www.w3.org/2000/svg" width="{self.w}" height="{self.h}" viewBox="0 0 {self.w} {self.h}" role="img" aria-label="{esc(self.title)}">\n'
               f'<title>{esc(self.title)}</title>{STYLE}' + '\n'.join(self.parts + lab) + '\n</svg>\n')
        open(os.path.join(OUT, name + '.svg'), 'w').write(svg)

def right(c): x, y, w, h = c; return (x + w, y + h/2)
def left(c): x, y, w, h = c; return (x, y + h/2)
def top(c): x, y, w, h = c; return (x + w/2, y)
def bottom(c): x, y, w, h = c; return (x + w/2, y + h)

# 1. The group: the phone adds each computer.
d = D(720, 300, "The phone adds each computer by its QR code; then the computers share one clipboard")
p = d.card(120, 140, 'phone', 'Phone', 'holds the group\'s key', w=190, cls='key', badge='ROOT')
cs = []
for i, (k, t) in enumerate([('laptop', 'Linux'), ('laptop', 'Mac'), ('desktop', 'Windows')]):
    cs.append(d.card(560, 50 + i*90, k, t, w=150))
for i, c in enumerate(cs):
    x0, y0 = right(p); x1, y1 = left(c)
    d.edge([(x0, y0), (330, y0), (330, y1), (x1, y1)] if y1 != y0 else [(x0, y0), (x1, y1)], 'pair')
d.labels.append(((400, 50), 'adds by QR code', 'pair'))
d.labels.append(((400, 140), 'adds by QR code', 'pair'))
d.labels.append(((400, 230), 'adds by QR code', 'pair'))
for a, b in [(cs[0], cs[1]), (cs[1], cs[2])]:
    d.edge([bottom(a), top(b)], 'home', start=True)
d.edge([(right(cs[0])[0], 50), (680, 50), (680, 230), (right(cs[2])[0], 230)], 'home', start=True, label='clipboard', at=(680, 140))
d.note(360, 288, 'Every device syncs with every other one directly, on your home network.')
d.save('group')

# 2. At home: no hub.
d = D(720, 250, "At home every device talks to every other one directly")
d.zone(10, 10, 700, 200, 'Home network')
bus = 150
xs = [110, 280, 450, 610]
items = [('phone', 'Phone', 'with the app', 'key'), ('laptop', 'Laptop', None, ''), ('desktop', 'Desktop', None, ''), ('board', 'Raspberry Pi', 'lite member', '')]
for x, (k, t, s, cls) in zip(xs, items):
    c = d.card(x, 82, k, t, s, w=150, cls=cls, badge='ROOT' if cls else None)
    d.edge([bottom(c), (x, bus)], 'home', end=False)
d.edge([(xs[0], bus), (xs[-1], bus)], 'home', end=False)
d.labels.append(((360, bus + 22), 'direct, encrypted connections, found by mDNS', 'home'))
d.note(360, 236, 'No server in the middle: any device can be off, and the others go on syncing.')
d.save('at-home')

# 3. Away: the hub.
d = D(800, 300, "Away from home, devices reach the hub through the group's WireGuard tunnel")
d.zone(10, 10, 210, 250, 'Away')
d.zone(400, 10, 390, 250, 'Home network')
lp = d.card(115, 90, 'laptop', 'Laptop', w=170)
ph = d.card(115, 190, 'phone', 'Phone', w=170)
hub = d.card(510, 140, 'desktop', 'Hub', 'an admin computer', w=180, cls='key', badge='HUB')
dk = d.card(695, 90, 'desktop', 'Desktop', w=150)
pi = d.card(695, 190, 'board', 'Raspberry Pi', w=150)
d.edge([right(lp), (300, 90), (300, 130), left(hub)[:1] + (130,)], 'tunnel')
d.edge([right(ph), (300, 190), (300, 150), (left(hub)[0], 150)], 'tunnel')
d.labels.append(((310, 140), "WireGuard tunnel", 'tunnel'))
d.edge([(right(hub)[0], 130), (610, 130), (610, 90), left(dk)], 'home', start=True)
d.edge([(right(hub)[0], 150), (610, 150), (610, 190), left(pi)], 'home', start=True)
d.note(400, 288, 'The router forwards UDP port 8764 to the hub. The hub reads the clipboard: it is your own computer.')
d.save('hub')

# 4. A forwarder.
d = D(900, 300, "When the internet cannot reach the hub, it registers with a forwarder")
d.zone(10, 10, 210, 250, 'Away')
d.zone(560, 10, 330, 250, 'Home, behind the provider\'s NAT')
lp = d.card(115, 90, 'laptop', 'Laptop', w=170)
ph = d.card(115, 190, 'phone', 'Phone', w=170)
fw = d.card(380, 140, 'cloud', 'Forwarder', 'reads nothing', w=170, cls='srv')
hub = d.card(690, 100, 'desktop', 'Hub', 'an admin computer', w=180, cls='key', badge='HUB')
dk = d.card(690, 210, 'desktop', 'Desktop', w=180)
d.edge([right(lp), (250, 90), (250, 130), (left(fw)[0], 130)], 'tunnel')
d.edge([right(ph), (250, 190), (250, 150), (left(fw)[0], 150)], 'tunnel')
d.labels.append(((250, 140), 'tunnel', 'tunnel'))
d.edge([right(fw), (530, 140), (530, 100), left(hub)], 'tunnel', start=True)
d.labels.append(((530, 140), 'hub dials out', 'tunnel'))
d.edge([bottom(hub), top(dk)], 'home', start=True, label='home', at=(690, 155))
d.note(450, 288, 'The forwarder holds no keys: yours on any server, or the project\'s at cbb.tools.')
d.save('forwarder')

# 5. A blind relay.
d = D(760, 230, "A blind relay joins two devices and reads nothing")
lp = d.card(110, 70, 'laptop', 'Laptop', 'away', w=170)
rl = d.card(380, 70, 'cloud', 'Blind relay', 'joins two devices', w=190, cls='srv')
mc = d.card(650, 70, 'laptop', 'Mac', 'at home', w=170)
d.edge([right(lp), left(rl)], 'tunnel', label='tunnel')
d.edge([left(mc), right(rl)], 'tunnel', label='tunnel')
d.edge([(110, 102), (110, 160), (650, 160), (650, 102)], 'e2e', start=True, label='end-to-end encryption: the relay cannot read it', at=(380, 160))
d.note(380, 212, 'It sees which of your devices talk, and when. Today: your own server; in 0.5, also cbb.tools.')
d.save('relay')

# 6. Without the app.
d = D(720, 300, "Without the app, a computer holds the group")
rt = d.card(130, 140, 'desktop', 'Linux computer', 'holds the group\'s key', w=210, cls='key', badge='ROOT')
mc = d.card(570, 50, 'laptop', 'Mac', w=170)
wn = d.card(570, 140, 'desktop', 'Windows', w=170)
ip = d.card(570, 230, 'phone', 'iPhone', 'with the shortcut', w=170)
d.edge([right(rt), left(wn)], 'pair', label='six-digit code', at=(405, 140))
d.edge([(330, 140), (330, 50), left(mc)], 'pair')
d.labels.append(((405, 50), 'six-digit code', 'pair'))
d.edge([(330, 140), (330, 230), left(ip)], 'pair')
d.labels.append(((405, 230), 'profile and shortcut', 'pair'))
d.note(360, 290, 'Then every device syncs with every other one, as in a group made on a phone.')
d.save('without-app')
