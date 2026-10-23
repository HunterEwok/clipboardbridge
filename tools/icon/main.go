// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Command icon makes the apps' icons from the drawings in apps/design/icon:
// each clipboard, light and dark, cut out of its transparent margin and set
// on a fill of its own colour, so that the system's mask rounds the fill and
// not the drawing. The clipboard's board sits in the middle, as far from the
// top edge as from the bottom one; the clip above it reaches into the top
// margin. For the iPhone it writes opaque 1024 by 1024 PNGs, the
// light one for the system's light mode and the dark one for dark mode. For
// Android it writes the foreground of the adaptive icon, the light clipboard
// on a transparent 432 by 432 canvas inside the launcher's safe zone; the
// fill is the icon's background colour in res/values/ic_launcher.xml.
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
	appIcon     = "apps/ios/ClipboardBridge/Resources/Assets.xcassets/AppIcon.appiconset/"
	androidIcon = "apps/android/app/src/main/res/mipmap-xxxhdpi/ic_launcher_foreground.png"
)

var icons = []struct {
	drawing, out string
	fill         color.RGBA
	// size is the image's width and height in pixels; height the
	// board's height, of the image, without the clip.
	size   int
	height float64
}{
	{"apps/design/icon/light.png", appIcon + "AppIcon.png", color.RGBA{0xF5, 0xF0, 0xE4, 0xFF}, 1024, 0.78},
	// The terminal theme's background (apps/design/tokens.json).
	{"apps/design/icon/dark.png", appIcon + "AppIcon-Dark.png", color.RGBA{0x0A, 0x0F, 0x0C, 0xFF}, 1024, 0.78},
	// 108 dp with the inner 66 dp always shown, at 4 pixels a dp: a
	// transparent fill, as the launcher draws the background below.
	{"apps/design/icon/light.png", androidIcon, color.RGBA{}, 432, 0.5},
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

// board is the rows of src that hold the board: those at least half as wide
// as the widest, which leaves out the narrower clip above it.
func board(img image.Image, src image.Rectangle) (top, bottom int) {
	widths := make([]int, src.Dy())
	widest := 0
	for y := src.Min.Y; y < src.Max.Y; y++ {
		left, right := src.Max.X, src.Min.X
		for x := src.Min.X; x < src.Max.X; x++ {
			if _, _, _, a := img.At(x, y).RGBA(); a != 0 {
				left, right = min(left, x), max(right, x+1)
			}
		}
		widths[y-src.Min.Y] = max(right-left, 0)
		widest = max(widest, right-left)
	}
	top, bottom = src.Max.Y, src.Min.Y
	for i, w := range widths {
		if 2*w >= widest {
			top, bottom = min(top, src.Min.Y+i), max(bottom, src.Min.Y+i+1)
		}
	}
	return top, bottom
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

// compose draws the clipboard on fill, premultiplied; a transparent fill
// keeps the drawing's own transparency.
func compose(drawing image.Image, fill color.RGBA, size int, height float64) []byte {
	src := opaqueBounds(drawing)
	boardTop, boardBottom := board(drawing, src)
	n := float64(size)
	scale := n * height / float64(boardBottom-boardTop)
	w := float64(src.Dx()) * scale
	// top is where src's top row lands: the clip's top, above the board's.
	left := (n - w) / 2
	top := (n-n*height)/2 - float64(boardTop-src.Min.Y)*scale
	if top < 0 {
		panic(fmt.Sprintf("icon: the clip does not fit above a board of height %v", height))
	}
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
			alpha := uint8(math.Round(a*0xff + (1-a)*float64(fill.A)))
			img.SetRGBA(px, py, color.RGBA{mix(c[0], fill.R), mix(c[1], fill.G), mix(c[2], fill.B), alpha})
		}
	}
	var buf bytes.Buffer
	// An opaque image is written without an alpha channel, as the App
	// Store requires.
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
		out := compose(drawing, icon.fill, icon.size, icon.height)
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
