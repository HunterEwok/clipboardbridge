// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package pasteboard

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"math/bits"

	"github.com/HunterEwok/clipboardbridge/internal/clip"
)

// Windows keeps a bitmap on the clipboard as a DIB: a BITMAPINFOHEADER, or
// one of its longer versions, the color masks or palette, and the rows of
// pixels, bottom-up unless the height is negative. These convert between it
// and the PNG the group carries; they are plain Go so they are tested on
// every system.

const (
	biRGB            = 0
	biBitfields      = 3
	biAlphaBitfields = 6
	lcsSRGB          = 0x73524742 // 'sRGB'
	lcsGMImages      = 4
	v5HeaderSize     = 124
	// maxPixels bounds a bitmap on the clipboard: 2^25 pixels, which holds
	// an 8K screen (7680 by 4320 is 33.2 million).
	maxPixels = 1 << 25
	// maxImageBytes bounds the memory a received image takes before it is
	// decoded: its pixels decoded and the DIB made of them together, 384
	// MiB, which holds a 48-megapixel photo. The group carries up to
	// clip.MaxMedia bytes, but a small file can hold far more pixels than
	// bytes, so the decoded bytes are counted, not the file's.
	maxImageBytes = 3 << 27
)

// dibToPNG converts a DIB, as CF_DIB or CF_DIBV5 holds it, to a PNG.
func dibToPNG(dib []byte) ([]byte, error) {
	img, err := decodeDIB(dib)
	if err != nil {
		return nil, err
	}
	var b bytes.Buffer
	if err := png.Encode(&b, img); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func decodeDIB(dib []byte) (image.Image, error) {
	le := binary.LittleEndian
	if len(dib) < 40 {
		return nil, errors.New("pasteboard: a bitmap without its header")
	}
	hs := int(le.Uint32(dib))
	if hs < 40 || hs > len(dib) {
		return nil, fmt.Errorf("pasteboard: a bitmap header of %d bytes", hs)
	}
	w, h := int(int32(le.Uint32(dib[4:]))), int(int32(le.Uint32(dib[8:])))
	bpp, comp := int(le.Uint16(dib[14:])), le.Uint32(dib[16:])
	used := int(le.Uint32(dib[32:]))
	topDown := h < 0
	if topDown {
		h = -h
	}
	if w <= 0 || h <= 0 || int64(w)*int64(h) > maxPixels {
		return nil, fmt.Errorf("pasteboard: a bitmap of %d by %d pixels", w, h)
	}
	off := hs
	masks := [4]uint32{0x00FF0000, 0x0000FF00, 0x000000FF, 0}
	switch comp {
	case biRGB:
		switch bpp {
		case 16:
			masks = [4]uint32{0x7C00, 0x03E0, 0x001F, 0} // 5 bits each
		case 32:
			masks[3] = 0xFF000000 // the fourth byte, if any pixel uses it
		}
	case biBitfields, biAlphaBitfields:
		n := 3
		if comp == biAlphaBitfields {
			n = 4
		}
		src := dib[40:]
		if hs == 40 {
			// After a plain header the masks follow it.
			if len(dib) < 40+4*n {
				return nil, errors.New("pasteboard: a bitmap without its color masks")
			}
			off += 4 * n
		} else if hs >= 56 {
			n = 4 // V4 and V5 headers hold the alpha mask too
		}
		if len(src) < 4*n || (hs != 40 && hs < 40+4*n) {
			// A header of 41 to 55 bytes does not hold the masks.
			return nil, errors.New("pasteboard: a bitmap header too short for its color masks")
		}
		masks[3] = 0
		for i := range n {
			masks[i] = le.Uint32(src[4*i:])
		}
		if bpp != 32 && bpp != 16 {
			return nil, fmt.Errorf("pasteboard: a %d-bit bitmap with color masks", bpp)
		}
	default:
		return nil, fmt.Errorf("pasteboard: a compressed bitmap (%d)", comp)
	}
	var palette []color.NRGBA
	if bpp <= 8 {
		if bpp != 1 && bpp != 4 && bpp != 8 {
			return nil, fmt.Errorf("pasteboard: a %d-bit bitmap", bpp)
		}
		if used <= 0 || used > 1<<bpp {
			used = 1 << bpp
		}
		if len(dib) < off+4*used {
			return nil, errors.New("pasteboard: a bitmap without its palette")
		}
		for i := range used {
			p := dib[off+4*i:]
			palette = append(palette, color.NRGBA{R: p[2], G: p[1], B: p[0], A: 0xFF})
		}
		off += 4 * used
	} else if bpp != 16 && bpp != 24 && bpp != 32 {
		return nil, fmt.Errorf("pasteboard: a %d-bit bitmap", bpp)
	}
	stride := (w*bpp + 31) / 32 * 4
	if len(dib)-off < stride*h {
		return nil, errors.New("pasteboard: a bitmap shorter than its rows")
	}
	img := image.NewNRGBA(image.Rect(0, 0, w, h))
	alpha := false
	for y := range h {
		row := dib[off+stride*y:]
		dy := h - 1 - y
		if topDown {
			dy = y
		}
		for x := range w {
			var c color.NRGBA
			switch bpp {
			case 1, 4, 8:
				i := int(row[x*bpp/8]>>(8-bpp-x*bpp%8)) & (1<<bpp - 1)
				if i >= len(palette) {
					return nil, errors.New("pasteboard: a bitmap pixel outside its palette")
				}
				c = palette[i]
			case 24:
				c = color.NRGBA{R: row[3*x+2], G: row[3*x+1], B: row[3*x], A: 0xFF}
			default:
				var v uint32
				if bpp == 16 {
					v = uint32(le.Uint16(row[2*x:]))
				} else {
					v = le.Uint32(row[4*x:])
				}
				c = color.NRGBA{R: channel(v, masks[0]), G: channel(v, masks[1]), B: channel(v, masks[2]), A: 0xFF}
				if masks[3] != 0 {
					c.A = channel(v, masks[3])
					alpha = alpha || c.A != 0
				}
			}
			img.SetNRGBA(x, dy, c)
		}
	}
	if masks[3] != 0 && !alpha && bpp > 8 {
		// Most programs leave the fourth byte at zero: an opaque image,
		// not an invisible one.
		for i := 3; i < len(img.Pix); i += 4 {
			img.Pix[i] = 0xFF
		}
	}
	return img, nil
}

// channel takes the bits of mask out of v, scaled to 8 bits.
func channel(v, mask uint32) uint8 {
	if mask == 0 {
		return 0
	}
	shift := bits.TrailingZeros32(mask)
	n := bits.OnesCount32(mask)
	x := (v & mask) >> shift
	if n >= 8 {
		return uint8(x >> (n - 8))
	}
	return uint8(x * 0xFF / (1<<n - 1))
}

// imageDIBV5 converts an image to the DIB of CF_DIBV5: 32 bits, bottom-up,
// with an alpha mask, in sRGB.
func imageDIBV5(img image.Image) []byte {
	le := binary.LittleEndian
	r := img.Bounds()
	w, h := r.Dx(), r.Dy()
	b := make([]byte, v5HeaderSize+4*w*h)
	le.PutUint32(b, v5HeaderSize)
	le.PutUint32(b[4:], uint32(w))
	le.PutUint32(b[8:], uint32(h))
	le.PutUint16(b[12:], 1)
	le.PutUint16(b[14:], 32)
	le.PutUint32(b[16:], biBitfields)
	le.PutUint32(b[20:], uint32(4*w*h))
	le.PutUint32(b[24:], 2835) // 72 dots an inch
	le.PutUint32(b[28:], 2835)
	le.PutUint32(b[40:], 0x00FF0000)
	le.PutUint32(b[44:], 0x0000FF00)
	le.PutUint32(b[48:], 0x000000FF)
	le.PutUint32(b[52:], 0xFF000000)
	le.PutUint32(b[56:], lcsSRGB)
	le.PutUint32(b[108:], lcsGMImages)
	px := b[v5HeaderSize:]
	if n, ok := img.(*image.NRGBA); ok {
		// What a PNG decodes to: copy the rows, no conversion a pixel.
		for y := range h {
			row := px[4*w*(h-1-y):][:4*w]
			src := n.Pix[n.PixOffset(r.Min.X, r.Min.Y+y):][:4*w]
			for x := 0; x < 4*w; x += 4 {
				row[x], row[x+1], row[x+2], row[x+3] = src[x+2], src[x+1], src[x], src[x+3]
			}
		}
		return b
	}
	if n, ok := img.(*image.NRGBA64); ok {
		// What a 16-bit PNG with transparency decodes to: the high byte of
		// each channel, with no pixel converted on the heap.
		for y := range h {
			row := px[4*w*(h-1-y):][:4*w]
			src := n.Pix[n.PixOffset(r.Min.X, r.Min.Y+y):][:8*w]
			for x := range w {
				row[4*x], row[4*x+1], row[4*x+2], row[4*x+3] = src[8*x+4], src[8*x+2], src[8*x], src[8*x+6]
			}
		}
		return b
	}
	for y := range h {
		row := px[4*w*(h-1-y):]
		for x := range w {
			c := color.NRGBAModel.Convert(img.At(r.Min.X+x, r.Min.Y+y)).(color.NRGBA)
			row[4*x], row[4*x+1], row[4*x+2], row[4*x+3] = c.B, c.G, c.R, c.A
		}
	}
	return b
}

// decodeImage decodes an image of a type the group carries.
func decodeImage(typ string, data []byte) (image.Image, error) {
	cfg, err := decodeConfig(typ, data)
	if err != nil {
		return nil, err
	}
	if cfg.Width <= 0 || cfg.Height <= 0 || imageBytes(typ, data, cfg) > maxImageBytes {
		return nil, fmt.Errorf("pasteboard: an image of %d by %d pixels", cfg.Width, cfg.Height)
	}
	if typ == clip.TypeJPEG {
		return jpeg.Decode(bytes.NewReader(data))
	}
	return png.Decode(bytes.NewReader(data))
}

// imageBytes is what the image of cfg, from data, takes in memory decoded
// and as the DIB of CF_DIBV5 (4 bytes a pixel), as image/png and image/jpeg
// decode it: a PNG's transparency turns gray into NRGBA or NRGBA64. An
// unknown model counts as the largest.
func imageBytes(typ string, data []byte, cfg image.Config) int64 {
	var n int64 = 8
	switch m := cfg.ColorModel; {
	case m == color.GrayModel:
		n = 1
	case m == color.Gray16Model:
		n = 2
	case m == color.YCbCrModel:
		n = 3 // the most, without subsampling
	case m == color.RGBAModel, m == color.NRGBAModel, m == color.CMYKModel:
		n = 4
	default:
		if _, ok := m.(color.Palette); ok {
			n = 1
		}
	}
	if typ == clip.TypePNG && n <= 2 && pngTransparent(data) {
		if _, ok := cfg.ColorModel.(color.Palette); !ok {
			n *= 4
		}
	}
	return int64(cfg.Width) * int64(cfg.Height) * (n + 4)
}

// pngTransparent reports whether a PNG has a tRNS chunk before its image
// data; one that cannot be read through counts as having one.
func pngTransparent(data []byte) bool {
	const sig = 8
	for i := sig; ; {
		if len(data)-i < 8 {
			return true
		}
		n := int64(binary.BigEndian.Uint32(data[i:]))
		switch string(data[i+4 : i+8]) {
		case "tRNS":
			return true
		case "IDAT", "IEND":
			return false
		}
		if n > int64(len(data)-i-12) {
			return true
		}
		i += 12 + int(n)
	}
}

func decodeConfig(typ string, data []byte) (image.Config, error) {
	switch typ {
	case clip.TypePNG:
		return png.DecodeConfig(bytes.NewReader(data))
	case clip.TypeJPEG:
		return jpeg.DecodeConfig(bytes.NewReader(data))
	}
	return image.Config{}, fmt.Errorf("pasteboard: no image of type %s", typ)
}
