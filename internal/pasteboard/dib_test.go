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

// A header of 41 to 55 bytes cannot hold color masks: it is refused, not
// read past its end.
func TestDecodeDIBShortHeaderWithMasks(t *testing.T) {
	for _, comp := range []uint32{biBitfields, biAlphaBitfields} {
		for hs := 41; hs < 56; hs++ {
			for _, extra := range []int{0, 4, 16} {
				dib := make([]byte, hs+extra)
				le := binary.LittleEndian
				le.PutUint32(dib, uint32(hs))
				le.PutUint32(dib[4:], 1)
				le.PutUint32(dib[8:], 1)
				le.PutUint16(dib[14:], 32)
				le.PutUint32(dib[16:], comp)
				// The masks are three words, four with alpha, and lie inside the header.
				n := 3
				if comp == biAlphaBitfields {
					n = 4
				}
				_, err := decodeDIB(dib)
				if short := hs < 40+4*n; short && err == nil {
					t.Errorf("comp %d, header %d, %d more bytes: decoded", comp, hs, extra)
				}
			}
		}
	}
}

func FuzzDecodeDIB(f *testing.F) {
	f.Add(imageDIBV5(testImage()))
	f.Add(header(1, 1, 32, biBitfields))
	f.Fuzz(func(t *testing.T, dib []byte) {
		if len(dib) > 1<<16 {
			return
		}
		decodeDIB(dib)
	})
}

// An image is refused by its size before it is decoded, whatever its file's
// size: a solid PNG of a few hundred KB can hold billions of pixels.
func TestDecodeImageBudget(t *testing.T) {
	big := func(w, h int) []byte {
		var b bytes.Buffer
		// A palette image of one color: its rows compress to almost nothing.
		img := image.NewPaletted(image.Rect(0, 0, w, h), color.Palette{color.Black})
		if err := (&png.Encoder{CompressionLevel: png.BestCompression}).Encode(&b, img); err != nil {
			t.Fatal(err)
		}
		return b.Bytes()
	}
	for name, d := range map[string][2]int{"16384 square": {16384, 16384}, "wide": {1 << 18, 1 << 10}} {
		data := big(d[0], d[1])
		if len(data) > 1<<20 {
			t.Fatalf("%s: the PNG has %d bytes", name, len(data))
		}
		if _, err := decodeImage(clip.TypePNG, data); err == nil {
			t.Errorf("%s: decoded", name)
		}
	}
	if _, err := decodeImage(clip.TypePNG, big(4096, 2160)); err != nil {
		t.Errorf("a 4K screenshot: %v", err)
	}
	// 16 bits a channel doubles what a pixel costs.
	if int64(maxPixels)*decodedPixel(color.NRGBA64Model) <= maxDecodedBytes {
		t.Error("a 16-bit image of the largest size is within the byte budget")
	}
}

func TestImageDIBV5SubImage(t *testing.T) {
	// The row copy of an NRGBA reads from its own origin.
	img := testImage().SubImage(image.Rect(1, 0, 3, 2)).(*image.NRGBA)
	got, err := decodeDIB(imageDIBV5(img))
	if err != nil {
		t.Fatal(err)
	}
	want := image.NewNRGBA(image.Rect(0, 0, 2, 2))
	for y := range 2 {
		for x := range 2 {
			want.SetNRGBA(x, y, img.NRGBAAt(1+x, y))
		}
	}
	samePixels(t, got, want)
}
