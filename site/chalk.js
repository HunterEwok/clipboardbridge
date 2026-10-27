// SPDX-License-Identifier: AGPL-3.0-only
//
// Draws the site's pictures as a hand would with chalk on a board, and
// writes them to templates/chalk.html: every line wobbles a little and is
// gone over twice, as rough.js does. The seeds are fixed, so the drawings
// come out the same each time; run `npm run chalk` after changing them.
"use strict";
const fs = require("fs");
const path = require("path");
const rough = require("roughjs");

const g = rough.generator();
let seed = 7;
const opts = (o = {}) => Object.assign({ roughness: 0.75, bowing: 0.7, strokeWidth: 1, seed: seed++, preserveVertices: true }, o);
const round = (d) => d.replace(/-?\d+\.\d+/g, (n) => String(Math.round(parseFloat(n) * 10) / 10));
const paths = (d) => g.toPaths(d).map((p) => round(p.d)).join(" ");
const shapes = {
  rect: (x, y, w, h, r) => g.path(`M${x + r} ${y}H${x + w - r}Q${x + w} ${y} ${x + w} ${y + r}V${y + h - r}Q${x + w} ${y + h} ${x + w - r} ${y + h}H${x + r}Q${x} ${y + h} ${x} ${y + h - r}V${y + r}Q${x} ${y} ${x + r} ${y}Z`, opts()),
  line: (x1, y1, x2, y2) => g.line(x1, y1, x2, y2, opts({ roughness: 0.7 })),
  path: (d) => g.path(d, opts()),
  circle: (cx, cy, d) => g.circle(cx, cy, d, opts({ roughness: 0.6 })),
};
const draw = (list) => list.map(([kind, ...args]) => paths(shapes[kind](...args))).join(" ");

// A device centred at (x, y), at scale s.
function device(kind, x, y, s = 1) {
  const R = (a, b, w, h, r) => ["rect", x + a * s, y + b * s, w * s, h * s, r * s];
  const L = (a, b, c, d) => ["line", x + a * s, y + b * s, x + c * s, y + d * s];
  const P = (d) => ["path", d.replace(/(-?\d+(?:\.\d+)?)\s*,\s*(-?\d+(?:\.\d+)?)/g, (m, a, b) => `${x + a * s} ${y + b * s}`)];
  switch (kind) {
    case "phone": return [R(-19, -33, 38, 66, 8), L(-9, -20, 9, -20), L(-9, -12, 1, -12), L(-6, 25, 6, 25)];
    case "tablet": return [R(-27, -34, 54, 68, 7), L(-16, -22, 16, -22), L(-16, -14, 2, -14), L(-4, 26, 4, 26)];
    case "laptop": return [R(-30, -27, 60, 40, 4), L(-20, -16, 10, -16), L(-20, -7, 0, -7), P("M-40,19 L40,19 L34,27 L-34,27 Z")];
    case "computer": return [R(-34, -31, 68, 46, 4), L(-24, -20, 8, -20), L(-24, -11, -2, -11), L(0, 15, 0, 27), L(-16, 28, 16, 28)];
    case "mac": return [R(-34, -31, 68, 48, 5), L(-34, 6, 34, 6), L(-24, -20, 6, -20), L(-24, -12, -4, -12), L(-5, 17, -8, 28), L(5, 17, 8, 28), L(-16, 29, 16, 29)];
    case "tv": return [R(-40, -27, 80, 46, 4), L(-28, -15, 6, -15), L(-28, -7, -6, -7), L(-26, 19, -31, 28), L(26, 19, 31, 28)];
  }
}

// The hero, in a box of 640 by 330: a laptop and a phone joined through
// the key by one straight yellow line; the key's traces branch above and
// below it and never cross it.
const hero = {
  white: draw([
    ["rect", 28, 66, 134, 88, 7], ["path", "M12 172 L178 172 L168 185 L22 185 Z"], ["line", 48, 90, 118, 90], ["line", 48, 110, 94, 110], ["line", 48, 130, 106, 130],
    ["rect", 540, 40, 72, 140, 15], ["line", 556, 70, 596, 70], ["line", 556, 88, 580, 88], ["line", 566, 164, 586, 164],
    ["rect", 423, 206, 64, 50, 9], ["path", "M435 206 V193 A20 20 0 0 1 475 193 V206"], ["circle", 455, 227, 12], ["line", 455, 233, 455, 243],
    ["path", "M272 84 H238 L222 68"], ["circle", 216, 62, 16], ["path", "M272 136 H238 L222 152"], ["circle", 216, 158, 16],
    ["path", "M368 84 H402 L418 68"], ["circle", 424, 62, 16], ["path", "M368 136 H402 L418 152"], ["circle", 424, 158, 16],
  ]),
  yellow: draw([
    ["circle", 320, 110, 100], ["path", "M286 136 A40 40 0 0 1 284 86"], ["circle", 320, 88, 24],
    ["path", "M308 158 V262 L320 284 L332 262 V248 L325 241 L332 234 V225 L325 218 L332 211 V202 L325 195 L332 188 V158"],
  ]),
  links: draw([["line", 162, 110, 270, 110], ["line", 370, 110, 540, 110]]),
};

// A group, in a box of 420 by 310: the hub in the middle, four devices
// around it, and the links between them.
function group(hub, scale, others) {
  const at = [[76, 64], [344, 62], [76, 244], [344, 244]];
  return {
    yellow: draw(device(hub, 210, 150, scale)),
    white: draw(others.flatMap((kind, i) => device(kind, at[i][0], at[i][1]))),
    links: draw([["line", 168, 126, 114, 90], ["line", 252, 126, 304, 90], ["line", 168, 182, 114, 220], ["line", 252, 182, 304, 220]]),
  };
}
// The three steps of setting up, each in a box of 200 by 150: the app
// comes to the phone; the computer runs one command; the phone scans the
// computer's QR code.
seed = 61;
const step1 = {
  white: draw(device("phone", 100, 76, 1.5)),
  yellow: draw([["line", 100, 52, 100, 92], ["path", "M88 81 L100 94 L112 81"], ["line", 86, 104, 114, 104]]),
  links: "",
};
const step2 = {
  white: draw([["rect", 40, 22, 120, 82, 6], ["line", 100, 104, 100, 120], ["line", 74, 124, 126, 124]]),
  yellow: draw([["path", "M58 50 L70 60 L58 70"], ["line", 78, 72, 100, 72]]),
  links: "",
};
const step3 = {
  white: draw([
    ["rect", 14, 30, 96, 70, 6], ["line", 62, 100, 62, 114], ["line", 40, 118, 84, 118],
    ["rect", 40, 44, 14, 14, 2], ["rect", 70, 44, 14, 14, 2], ["rect", 40, 74, 14, 14, 2], ["line", 72, 78, 84, 78], ["line", 72, 86, 78, 86],
    ...device("phone", 160, 82, 1.05),
  ]),
  yellow: draw([["path", "M140 70 L118 64"], ["path", "M140 94 L118 100"]]),
  links: "",
};
seed = 38;
const computer = group("computer", 1.3, ["phone", "laptop", "phone", "mac"]);
const phones = group("phone", 1.35, ["phone", "tv", "tablet", "phone"]);

// pathLength lets the stylesheet draw each line in, as a hand would.
const line = (cls, d) => (d ? `<path class="${cls}" pathLength="1" d="${d}"/>` : "");
const lines = (d) => line("y link", d.links) + line("w", d.white) + line("y", d.yellow);
const out = `<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Written by chalk.js: the lines of the chalk drawings, without their
     labels, which the pages add in their own language. -->
{{define "chalk-hero"}}${lines(hero)}{{end}}
{{define "chalk-computer"}}${lines(computer)}{{end}}
{{define "chalk-phones"}}${lines(phones)}{{end}}
{{define "chalk-step1"}}${lines(step1)}{{end}}
{{define "chalk-step2"}}${lines(step2)}{{end}}
{{define "chalk-step3"}}${lines(step3)}{{end}}
`;
fs.writeFileSync(path.join(__dirname, "templates", "chalk.html"), out);
