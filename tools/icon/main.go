// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Command icon makes the iPhone app's icons from the drawings in
// apps/design/icon: each clipboard, light and dark, cut out of its
// transparent margin and set on a fill of its own colour, so that the
// system's mask rounds the fill and not the drawing. It writes opaque
// 1024 by 1024 PNGs, the light one for the system's light mode and the dark
// one for dark mode.
//
//	go run ./tools/icon          rewrite the icons
//	go run ./tools/icon -check   fail if they are out of date
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
)

const (
	size    = 1024
	height  = 0.97 // of the icon, for the clipboard
	appIcon = "apps/ios/ClipboardBridge/Resources/Assets.xcassets/AppIcon.appiconset/"
)

var icons = []struct {
	drawing, out string
	fill         color.RGBA
}{
	{"apps/design/icon/light.png", appIcon + "AppIcon.png", color.RGBA{0xF5, 0xF0, 0xE4, 0xFF}},
	// The terminal theme's background (apps/design/tokens.json).
	{"apps/design/icon/dark.png", appIcon + "AppIcon-Dark.png", color.RGBA{0x0A, 0x0F, 0x0C, 0xFF}},
}

// opaqueBounds is the smallest rectangle holding every pixel of img that is
// not fully transparent.
func opaqueBounds(img image.Image) image.Rectangle {
	b := img.Bounds()
	r := image.Rectangle{Min: b.Max, Max: b.Min}
	for y := b.Min.Y; y < b.Max.Y; y++ {
		for x := b.Min.X; x < b.Max.X; x++ {
			if _, _, _, a := img.At(x, y).RGBA(); a != 0 {
				r = r.Union(image.Rect(x, y, x+1, y+1))
			}
		}
	}
	return r
}

// sample is img's premultiplied colour at (x, y), interpolated between the
// four nearest pixels; outside src it is transparent.
func sample(img image.Image, src image.Rectangle, x, y float64) [4]float64 {
	x0, y0 := math.Floor(x-0.5), math.Floor(y-0.5)
	fx, fy := x-0.5-x0, y-0.5-y0
	var out [4]float64
	for _, p := range [4]struct{ dx, dy int }{{0, 0}, {1, 0}, {0, 1}, {1, 1}} {
		px, py := int(x0)+p.dx, int(y0)+p.dy
		if !image.Pt(px, py).In(src) {
			continue
		}
		wx, wy := 1-fx, 1-fy
		if p.dx == 1 {
			wx = fx
		}
		if p.dy == 1 {
			wy = fy
		}
		w := wx * wy
		r, g, b, a := img.At(px, py).RGBA()
		out[0] += w * float64(r)
		out[1] += w * float64(g)
		out[2] += w * float64(b)
		out[3] += w * float64(a)
	}
	return out
}

func compose(drawing image.Image, fill color.RGBA) []byte {
	src := opaqueBounds(drawing)
	scale := size * height / float64(src.Dy())
	w := float64(src.Dx()) * scale
	left, top := (size-w)/2, (size-size*height)/2
	img := image.NewRGBA(image.Rect(0, 0, size, size))
	for py := 0; py < size; py++ {
		for px := 0; px < size; px++ {
			x := float64(src.Min.X) + (float64(px)+0.5-left)/scale
			y := float64(src.Min.Y) + (float64(py)+0.5-top)/scale
			c := sample(drawing, src, x, y)
			a := c[3] / 0xffff
			mix := func(v float64, f uint8) uint8 {
				return uint8(math.Round(v/0xffff*0xff + (1-a)*float64(f)))
			}
			img.SetRGBA(px, py, color.RGBA{mix(c[0], fill.R), mix(c[1], fill.G), mix(c[2], fill.B), 0xff})
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
	check := flag.Bool("check", false, "fail if the icons are out of date")
	flag.Parse()
	for _, icon := range icons {
		f, err := os.Open(icon.drawing)
		if err != nil {
			fmt.Fprintln(os.Stderr, "icon:", err)
			os.Exit(1)
		}
		drawing, err := png.Decode(f)
		f.Close()
		if err != nil {
			fmt.Fprintf(os.Stderr, "icon: %s: %v\n", icon.drawing, err)
			os.Exit(1)
		}
		out := compose(drawing, icon.fill)
		if *check {
			cur, err := os.ReadFile(icon.out)
			if err != nil || !bytes.Equal(cur, out) {
				fmt.Fprintf(os.Stderr, "icon: %s is out of date; run go run ./tools/icon\n", icon.out)
				os.Exit(1)
			}
			continue
		}
		if err := os.WriteFile(icon.out, out, 0o644); err != nil {
			fmt.Fprintln(os.Stderr, "icon:", err)
			os.Exit(1)
		}
	}
}
