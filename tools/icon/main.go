// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Command icon draws the iPhone app's icon from the terminal theme of the
// design tokens: two clipboards joined by a bridge, on the theme's grid.
// It writes a 1024 by 1024 opaque PNG, which the asset catalog scales.
//
//	go run ./tools/icon          rewrite the icon
//	go run ./tools/icon -check   fail if it is out of date
package main

import (
	"bytes"
	"flag"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"math"
	"os"
	"strconv"
)

const (
	iconFile = "apps/ios/Clipbridge/Resources/Assets.xcassets/AppIcon.appiconset/AppIcon.png"
	size     = 1024
	samples  = 4 // per axis, for smooth edges
)

// The terminal theme's colours (apps/design/tokens.json).
var (
	background = hex("#0A0F0C")
	grid       = hex("#1A261F")
	board      = hex("#E4F2E8")
	line       = hex("#8EA596")
	accent     = hex("#3DFF8A")
)

type rgb struct{ r, g, b float64 }

func hex(s string) rgb {
	v, err := strconv.ParseUint(s[1:], 16, 32)
	if err != nil {
		panic(err)
	}
	return rgb{float64(v >> 16 & 0xff), float64(v >> 8 & 0xff), float64(v & 0xff)}
}

// roundRect is the signed distance from (x, y) to a rectangle with centre
// (cx, cy), half sizes (hx, hy) and corner radius r.
func roundRect(x, y, cx, cy, hx, hy, r float64) float64 {
	qx := math.Abs(x-cx) - (hx - r)
	qy := math.Abs(y-cy) - (hy - r)
	out := math.Hypot(math.Max(qx, 0), math.Max(qy, 0))
	return out + math.Min(math.Max(qx, qy), 0) - r
}

// shade is the colour at a point; later shapes paint over earlier ones.
func shade(x, y float64) rgb {
	c := background
	if math.Mod(x, 64) < 2 || math.Mod(y, 64) < 2 {
		c = grid
	}
	for _, cx := range []float64{318, 706} {
		// The board's outline, then its clip and its lines of text.
		if math.Abs(roundRect(x, y, cx, 600, 168, 230, 44)) < 14 {
			c = board
		}
		if roundRect(x, y, cx, 372, 76, 34, 20) < 0 {
			c = board
		}
		ink := line
		if cx > size/2 {
			ink = accent
		}
		for i, w := range []float64{96, 72, 96, 48} {
			if roundRect(x, y, cx-96+w, 500+float64(i)*72, w, 12, 12) < 0 {
				c = ink
			}
		}
	}
	// The bridge: half a ring from one clip to the other, with round ends.
	const bx, by, br, bw = 512, 372, 194, 34
	if (y <= by && math.Abs(math.Hypot(x-bx, y-by)-br) < bw/2) ||
		math.Hypot(x-(bx-br), y-by) < bw/2 || math.Hypot(x-(bx+br), y-by) < bw/2 {
		c = accent
	}
	return c
}

func draw() []byte {
	img := image.NewRGBA(image.Rect(0, 0, size, size))
	for py := 0; py < size; py++ {
		for px := 0; px < size; px++ {
			var sum rgb
			for sy := 0; sy < samples; sy++ {
				for sx := 0; sx < samples; sx++ {
					c := shade(float64(px)+(float64(sx)+0.5)/samples, float64(py)+(float64(sy)+0.5)/samples)
					sum.r, sum.g, sum.b = sum.r+c.r, sum.g+c.g, sum.b+c.b
				}
			}
			n := float64(samples * samples)
			img.SetRGBA(px, py, color.RGBA{uint8(sum.r/n + 0.5), uint8(sum.g/n + 0.5), uint8(sum.b/n + 0.5), 0xff})
		}
	}
	var buf bytes.Buffer
	// The image is opaque, so the encoder writes it without an alpha
	// channel, as the App Store requires.
	if err := png.Encode(&buf, img); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

func main() {
	check := flag.Bool("check", false, "fail if the icon is out of date")
	flag.Parse()
	out := draw()
	if *check {
		cur, err := os.ReadFile(iconFile)
		if err != nil || !bytes.Equal(cur, out) {
			fmt.Fprintf(os.Stderr, "icon: %s is out of date; run go run ./tools/icon\n", iconFile)
			os.Exit(1)
		}
		return
	}
	if err := os.WriteFile(iconFile, out, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "icon:", err)
		os.Exit(1)
	}
}
