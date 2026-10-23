// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Command icon makes the iPhone app's icons from the drawn art in
// apps/design/icon: the light one, which iOS shows by default, and the dark
// one for dark mode. Each puts the art's clipboard, without its transparent
// margin, in the middle of a square of its own background colour, as large
// as the system's rounded mask allows, and writes a 1024 by 1024 opaque PNG
// (the App Store refuses an icon with transparency).
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
	size = 1024
	// fill is the share of the icon's height the clipboard takes; the
	// rounded corners of the mask stay clear of it.
	fill = 0.86
	set  = "apps/ios/ClipboardBridge/Resources/Assets.xcassets/AppIcon.appiconset/"
)

type variant struct {
	art, icon  string
	background color.NRGBA
}

var variants = []variant{
	{"apps/design/icon/cbb-light.png", set + "AppIcon.png", color.NRGBA{0xF7, 0xF2, 0xE6, 0xff}},
	// The terminal theme's background (apps/design/tokens.json).
	{"apps/design/icon/cbb-dark.png", set + "AppIcon-dark.png", color.NRGBA{0x0A, 0x0F, 0x0C, 0xff}},
}

// bounds is the box of the art's pixels that are at least half opaque: the
// clipboard without its faint shadow.
func bounds(img image.Image) image.Rectangle {
	b := img.Bounds()
	box := image.Rectangle{Min: b.Max, Max: b.Min}
	for y := b.Min.Y; y < b.Max.Y; y++ {
		for x := b.Min.X; x < b.Max.X; x++ {
			if _, _, _, a := img.At(x, y).RGBA(); a >= 0x8000 {
				box = box.Union(image.Rect(x, y, x+1, y+1))
			}
		}
	}
	return box
}

// sample is the art's colour at (x, y), premultiplied, between pixels by
// bilinear interpolation, and transparent outside it.
func sample(img image.Image, x, y float64) (r, g, b, a float64) {
	x0, y0 := math.Floor(x-0.5), math.Floor(y-0.5)
	fx, fy := x-0.5-x0, y-0.5-y0
	for _, p := range [4]struct{ dx, dy, w float64 }{
		{0, 0, (1 - fx) * (1 - fy)}, {1, 0, fx * (1 - fy)}, {0, 1, (1 - fx) * fy}, {1, 1, fx * fy},
	} {
		px, py := int(x0+p.dx), int(y0+p.dy)
		if !image.Pt(px, py).In(img.Bounds()) {
			continue
		}
		cr, cg, cb, ca := img.At(px, py).RGBA()
		r, g, b, a = r+p.w*float64(cr), g+p.w*float64(cg), b+p.w*float64(cb), a+p.w*float64(ca)
	}
	return r / 0xffff, g / 0xffff, b / 0xffff, a / 0xffff
}

func render(v variant) ([]byte, error) {
	f, err := os.Open(v.art)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	art, err := png.Decode(f)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", v.art, err)
	}
	box := bounds(art)
	if box.Empty() {
		return nil, fmt.Errorf("%s: no opaque pixels", v.art)
	}
	scale := fill * size / float64(box.Dy())
	if w := scale * float64(box.Dx()); w > fill*size {
		scale = fill * size / float64(box.Dx())
	}
	cx, cy := float64(box.Min.X+box.Max.X)/2, float64(box.Min.Y+box.Max.Y)/2
	out := image.NewNRGBA(image.Rect(0, 0, size, size))
	bg := v.background
	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			r, g, b, a := sample(art, cx+(float64(x)+0.5-size/2)/scale, cy+(float64(y)+0.5-size/2)/scale)
			mix := func(c float64, under uint8) uint8 {
				return uint8(math.Round(math.Min(255, c*255+float64(under)*(1-a))))
			}
			out.SetNRGBA(x, y, color.NRGBA{mix(r, bg.R), mix(g, bg.G), mix(b, bg.B), 0xff})
		}
	}
	var buf bytes.Buffer
	// Every pixel is opaque, so the encoder writes no alpha channel.
	if err := png.Encode(&buf, out); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func main() {
	check := flag.Bool("check", false, "fail if the icons are out of date")
	flag.Parse()
	for _, v := range variants {
		out, err := render(v)
		if err != nil {
			fmt.Fprintln(os.Stderr, "icon:", err)
			os.Exit(1)
		}
		if *check {
			if cur, err := os.ReadFile(v.icon); err != nil || !bytes.Equal(cur, out) {
				fmt.Fprintf(os.Stderr, "icon: %s is out of date; run go run ./tools/icon\n", v.icon)
				os.Exit(1)
			}
			continue
		}
		if err := os.WriteFile(v.icon, out, 0o644); err != nil {
			fmt.Fprintln(os.Stderr, "icon:", err)
			os.Exit(1)
		}
	}
}
