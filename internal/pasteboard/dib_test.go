// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package pasteboard

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"hash/crc32"
	"image"
	"image/color"
	"image/jpeg"
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
	// A photo of 48 megapixels fits.
	var photo bytes.Buffer
	if err := jpeg.Encode(&photo, image.NewYCbCr(image.Rect(0, 0, 8000, 6000), image.YCbCrSubsampleRatio444), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := decodeImage(clip.TypeJPEG, photo.Bytes()); err != nil {
		t.Errorf("a 48-megapixel photo: %v", err)
	}
}

// rawPNG is a PNG of w by h zero pixels of the given bit depth and color
// type, with a tRNS chunk when trns is not nil.
func rawPNG(t *testing.T, w, h int, depth, colorType byte, trns []byte) []byte {
	chunk := func(b *bytes.Buffer, typ string, d []byte) {
		binary.Write(b, binary.BigEndian, uint32(len(d)))
		b.WriteString(typ)
		b.Write(d)
		binary.Write(b, binary.BigEndian, crc32.ChecksumIEEE(append([]byte(typ), d...)))
	}
	var out bytes.Buffer
	out.WriteString("\x89PNG\r\n\x1a\n")
	ihdr := make([]byte, 13)
	binary.BigEndian.PutUint32(ihdr, uint32(w))
	binary.BigEndian.PutUint32(ihdr[4:], uint32(h))
	ihdr[8], ihdr[9] = depth, colorType
	chunk(&out, "IHDR", ihdr)
	if colorType == 3 {
		chunk(&out, "PLTE", []byte{0, 0, 0})
	}
	if trns != nil {
		chunk(&out, "tRNS", trns)
	}
	channels := map[byte]int{0: 1, 2: 3, 3: 1, 4: 2, 6: 4}[colorType]
	var z bytes.Buffer
	zw := zlib.NewWriter(&z)
	row := make([]byte, 1+w*channels*int(depth)/8)
	for range h {
		zw.Write(row)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	chunk(&out, "IDAT", z.Bytes())
	chunk(&out, "IEND", nil)
	return out.Bytes()
}

// pixBytes is what a decoded image's pixels take.
func pixBytes(t *testing.T, img image.Image) int64 {
	switch m := img.(type) {
	case *image.Gray:
		return int64(len(m.Pix))
	case *image.Gray16:
		return int64(len(m.Pix))
	case *image.NRGBA:
		return int64(len(m.Pix))
	case *image.NRGBA64:
		return int64(len(m.Pix))
	case *image.RGBA:
		return int64(len(m.Pix))
	case *image.RGBA64:
		return int64(len(m.Pix))
	case *image.Paletted:
		return int64(len(m.Pix))
	case *image.YCbCr:
		return int64(len(m.Y) + len(m.Cb) + len(m.Cr))
	}
	t.Fatalf("an image of type %T", img)
	return 0
}

// What an image is counted as before it is decoded is at least what it
// takes decoded and as the DIB, for every kind of PNG and JPEG, a PNG's
// transparency included: a gray PNG with it decodes to 4 times its gray.
func TestImageBytesCoverDecoding(t *testing.T) {
	const w, h = 64, 48
	pngs := map[string][]byte{
		"gray":                      rawPNG(t, w, h, 8, 0, nil),
		"gray with transparency":    rawPNG(t, w, h, 8, 0, []byte{0, 1}),
		"gray16":                    rawPNG(t, w, h, 16, 0, nil),
		"gray16 with transparency":  rawPNG(t, w, h, 16, 0, []byte{0, 1}),
		"gray and alpha":            rawPNG(t, w, h, 8, 4, nil),
		"gray16 and alpha":          rawPNG(t, w, h, 16, 4, nil),
		"RGB":                       rawPNG(t, w, h, 8, 2, nil),
		"RGB with transparency":     rawPNG(t, w, h, 8, 2, []byte{0, 1, 0, 1, 0, 1}),
		"RGB16":                     rawPNG(t, w, h, 16, 2, nil),
		"RGB16 with transparency":   rawPNG(t, w, h, 16, 2, []byte{0, 1, 0, 1, 0, 1}),
		"RGBA16":                    rawPNG(t, w, h, 16, 6, nil),
		"palette":                   rawPNG(t, w, h, 8, 3, nil),
		"palette with transparency": rawPNG(t, w, h, 8, 3, []byte{0}),
	}
	for name, data := range pngs {
		checkImageBytes(t, name, clip.TypePNG, data)
	}
	for _, r := range []image.YCbCrSubsampleRatio{image.YCbCrSubsampleRatio444, image.YCbCrSubsampleRatio420} {
		var b bytes.Buffer
		if err := jpeg.Encode(&b, image.NewYCbCr(image.Rect(0, 0, w, h), r), nil); err != nil {
			t.Fatal(err)
		}
		checkImageBytes(t, "JPEG "+r.String(), clip.TypeJPEG, b.Bytes())
	}
	var b bytes.Buffer
	if err := jpeg.Encode(&b, image.NewGray(image.Rect(0, 0, w, h)), nil); err != nil {
		t.Fatal(err)
	}
	checkImageBytes(t, "gray JPEG", clip.TypeJPEG, b.Bytes())
	// A PNG cut short before its image data counts as transparent.
	if !pngTransparent(rawPNG(t, w, h, 8, 0, nil)[:20]) {
		t.Error("a PNG cut short counts as opaque")
	}
}

func checkImageBytes(t *testing.T, name, typ string, data []byte) {
	t.Helper()
	cfg, err := decodeConfig(typ, data)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	img, err := decodeImage(typ, data)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	if got, want := imageBytes(typ, data, cfg), pixBytes(t, img)+int64(len(imageDIBV5(img))-v5HeaderSize); got < want {
		t.Errorf("%s (%T): counted %d bytes, it takes %d", name, img, got, want)
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

// The row copy of an NRGBA64 keeps the high byte of each channel, from the
// image's own origin.
func TestImageDIBV5NRGBA64(t *testing.T) {
	full := image.NewNRGBA64(image.Rect(0, 0, 4, 3))
	for y := range 3 {
		for x := range 4 {
			full.SetNRGBA64(x, y, color.NRGBA64{R: uint16(x*20000 + 5), G: uint16(y*30000 + 7), B: uint16(x*y*5000 + 9), A: uint16(65535 - x*10000)})
		}
	}
	img := full.SubImage(image.Rect(1, 1, 4, 3)).(*image.NRGBA64)
	got, err := decodeDIB(imageDIBV5(img))
	if err != nil {
		t.Fatal(err)
	}
	want := image.NewNRGBA(image.Rect(0, 0, 3, 2))
	for y := range 2 {
		for x := range 3 {
			c := img.NRGBA64At(1+x, 1+y)
			want.SetNRGBA(x, y, color.NRGBA{R: uint8(c.R >> 8), G: uint8(c.G >> 8), B: uint8(c.B >> 8), A: uint8(c.A >> 8)})
		}
	}
	samePixels(t, got, want)
}
