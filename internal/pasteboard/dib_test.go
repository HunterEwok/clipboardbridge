// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package pasteboard

import (
	"bytes"
	"encoding/binary"
	"image"
	"image/color"
	"image/png"
	"testing"

	"github.com/HunterEwok/clipboardbridge/internal/clip"
)

// testImage is 3 by 2 pixels with a transparent and a half-transparent one.
func testImage() *image.NRGBA {
	img := image.NewNRGBA(image.Rect(0, 0, 3, 2))
	img.SetNRGBA(0, 0, color.NRGBA{R: 255, A: 255})
	img.SetNRGBA(1, 0, color.NRGBA{G: 255, A: 255})
	img.SetNRGBA(2, 0, color.NRGBA{B: 255, A: 128})
	img.SetNRGBA(0, 1, color.NRGBA{R: 10, G: 20, B: 30, A: 0})
	img.SetNRGBA(1, 1, color.NRGBA{R: 255, G: 255, B: 255, A: 255})
	img.SetNRGBA(2, 1, color.NRGBA{R: 1, G: 2, B: 3, A: 255})
	return img
}

func samePixels(t *testing.T, got image.Image, want *image.NRGBA) {
	t.Helper()
	if got.Bounds() != want.Bounds() {
		t.Fatalf("bounds %v, want %v", got.Bounds(), want.Bounds())
	}
	for y := range want.Rect.Dy() {
		for x := range want.Rect.Dx() {
			g := color.NRGBAModel.Convert(got.At(x, y)).(color.NRGBA)
			if w := want.NRGBAAt(x, y); g != w {
				t.Errorf("pixel %d,%d = %v, want %v", x, y, g, w)
			}
		}
	}
}

func TestDIBV5RoundTrip(t *testing.T) {
	want := testImage()
	dib := imageDIBV5(want)
	if len(dib) != v5HeaderSize+4*6 {
		t.Fatalf("a DIB of %d bytes", len(dib))
	}
	p, err := dibToPNG(dib)
	if err != nil {
		t.Fatal(err)
	}
	got, err := png.Decode(bytes.NewReader(p))
	if err != nil {
		t.Fatal(err)
	}
	samePixels(t, got, want)
}

// header makes a BITMAPINFOHEADER.
func header(w, h int32, bpp uint16, comp uint32) []byte {
	b := make([]byte, 40)
	le := binary.LittleEndian
	le.PutUint32(b, 40)
	le.PutUint32(b[4:], uint32(w))
	le.PutUint32(b[8:], uint32(h))
	le.PutUint16(b[12:], 1)
	le.PutUint16(b[14:], bpp)
	le.PutUint32(b[16:], comp)
	return b
}

func TestDecodeDIB(t *testing.T) {
	opaque := testImage()
	for i := 3; i < len(opaque.Pix); i += 4 {
		opaque.Pix[i] = 255
	}
	// 24 bits, bottom-up: each row padded to 4 bytes.
	dib := header(3, 2, 24, biRGB)
	for _, y := range []int{1, 0} {
		for x := range 3 {
			c := opaque.NRGBAAt(x, y)
			dib = append(dib, c.B, c.G, c.R)
		}
		dib = append(dib, 0, 0, 0)
	}
	got, err := decodeDIB(dib)
	if err != nil {
		t.Fatal(err)
	}
	samePixels(t, got, opaque)

	// 32 bits, top-down, the fourth byte all zero: opaque.
	dib = header(3, -2, 32, biRGB)
	for y := range 2 {
		for x := range 3 {
			c := opaque.NRGBAAt(x, y)
			dib = append(dib, c.B, c.G, c.R, 0)
		}
	}
	if got, err = decodeDIB(dib); err != nil {
		t.Fatal(err)
	}
	samePixels(t, got, opaque)

	// 32 bits with masks after a plain header, RGBA in that order.
	dib = header(3, -2, 32, biBitfields)
	dib = binary.LittleEndian.AppendUint32(dib, 0x000000FF)
	dib = binary.LittleEndian.AppendUint32(dib, 0x0000FF00)
	dib = binary.LittleEndian.AppendUint32(dib, 0x00FF0000)
	for y := range 2 {
		for x := range 3 {
			c := opaque.NRGBAAt(x, y)
			dib = append(dib, c.R, c.G, c.B, 0)
		}
	}
	if got, err = decodeDIB(dib); err != nil {
		t.Fatal(err)
	}
	samePixels(t, got, opaque)

	// 8 bits with a palette of two colors.
	dib = header(2, 1, 8, biRGB)
	binary.LittleEndian.PutUint32(dib[32:], 2)
	dib = append(dib, 0, 0, 255, 0, 255, 0, 0, 0) // red, blue
	dib = append(dib, 1, 0, 0, 0)
	if got, err = decodeDIB(dib); err != nil {
		t.Fatal(err)
	}
	if c := color.NRGBAModel.Convert(got.At(0, 0)).(color.NRGBA); c != (color.NRGBA{B: 255, A: 255}) {
		t.Errorf("the first palette pixel is %v", c)
	}

	for name, bad := range map[string][]byte{
		"short":      dib[:20],
		"no rows":    header(3, 2, 24, biRGB),
		"compressed": append(header(1, 1, 8, 1), make([]byte, 1024+4)...),
		"too large":  header(1<<16, 1<<16, 32, biRGB),
		"2 bits":     append(header(1, 1, 2, biRGB), make([]byte, 64)...),
	} {
		if _, err := decodeDIB(bad); err == nil {
			t.Errorf("%s: decoded", name)
		}
	}
}

func TestDecodeImage(t *testing.T) {
	var b bytes.Buffer
	png.Encode(&b, testImage())
	img, err := decodeImage(clip.TypePNG, b.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	samePixels(t, img, testImage())
	if _, err := decodeImage(clip.TypeJPEG, b.Bytes()); err == nil {
		t.Error("a PNG decoded as a JPEG")
	}
	if _, err := decodeImage("image/gif", b.Bytes()); err == nil {
		t.Error("a GIF decoded")
	}
}
