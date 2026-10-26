// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build darwin && cgo

package pasteboard

/*
#cgo CFLAGS: -x objective-c -fobjc-arc -Wall
#cgo LDFLAGS: -framework AppKit
#include <stdlib.h>
#include "pasteboard_darwin.h"
*/
import "C"

import (
	"errors"
	"unsafe"

	"github.com/HunterEwok/clipboardbridge/internal/clip"
)

// Supported reports whether this build reaches the pasteboard.
const Supported = true

// A Board is a pasteboard: the general one, or a private one for tests.
type Board struct {
	name *C.char // nil for the general pasteboard
}

// General returns the general pasteboard, the one Cmd-C and Cmd-V use.
func General() *Board { return &Board{} }

// Private returns a private pasteboard with the given name, for tests.
// Release frees it.
func Private(name string) *Board { return &Board{name: C.CString(name)} }

// Release frees a private pasteboard.
func (b *Board) Release() {
	if b.name != nil {
		C.cb_release(b.name)
		C.free(unsafe.Pointer(b.name))
		b.name = nil
	}
}

// ChangeCount returns the pasteboard's change counter, which grows with
// every change of its contents.
func (b *Board) ChangeCount() int64 { return int64(C.cb_change_count(b.name)) }

// Read returns the pasteboard's item, and false if it holds no text or
// image.
func (b *Board) Read() (Item, bool, error) {
	var text *C.char
	var n C.long
	var flags C.int
	var change C.long
	switch C.cb_read(b.name, &text, &n, &flags, &change) {
	case -1:
		return Item{}, false, errors.New("pasteboard: out of memory")
	case 0:
		return b.readImage(flags)
	}
	it := Item{Secret: flags&C.CB_SECRET != 0, Remote: flags&C.CB_REMOTE != 0, Change: int64(change)}
	if text != nil {
		it.Text = C.GoStringN(text, C.int(n))
		C.free(unsafe.Pointer(text))
	}
	return it, true, nil
}

// readImage returns the pasteboard's image, if it holds no text.
func (b *Board) readImage(flags C.int) (Item, bool, error) {
	var data unsafe.Pointer
	var n C.long
	var typ C.int
	var change C.long
	switch C.cb_read_image(b.name, &data, &n, &typ, &change, C.long(clip.MaxMedia)) {
	case -1:
		return Item{}, false, errors.New("pasteboard: out of memory")
	case -2:
		return Item{Change: int64(change)}, false, errors.New("pasteboard: the image is larger than the group carries")
	case 0:
		return Item{Change: int64(change)}, false, nil
	}
	it := Item{Secret: flags&C.CB_SECRET != 0, Remote: flags&C.CB_REMOTE != 0, Change: int64(change), ImageType: clip.TypePNG}
	if typ == C.CB_JPEG {
		it.ImageType = clip.TypeJPEG
	}
	it.Image = C.GoBytes(data, C.int(n))
	C.free(data)
	return it, true, nil
}

// WriteImage puts an image of a type on the pasteboard, as itself and as a
// TIFF, with its text, if any, and returns the new change counter.
func (b *Board) WriteImage(typ string, data []byte, text string) (int64, error) {
	if len(data) == 0 {
		return 0, errors.New("pasteboard: an empty image")
	}
	t := C.int(C.CB_PNG)
	switch typ {
	case clip.TypePNG:
	case clip.TypeJPEG:
		t = C.CB_JPEG
	default:
		return 0, errors.New("pasteboard: no image of type " + typ)
	}
	ct := C.CString(text)
	defer C.free(unsafe.Pointer(ct))
	cd := C.CBytes(data)
	defer C.free(cd)
	change := C.cb_write_image(b.name, cd, C.long(len(data)), t, ct, C.long(len(text)))
	if change < 0 {
		return 0, errors.New("pasteboard: the image could not be written")
	}
	return int64(change), nil
}

// Write puts a text on the pasteboard and returns the new change counter.
func (b *Board) Write(text string, secret bool) (int64, error) {
	ct := C.CString(text)
	defer C.free(unsafe.Pointer(ct))
	s := C.int(0)
	if secret {
		s = 1
	}
	change := C.cb_write(b.name, ct, C.long(len(text)), s)
	if change < 0 {
		return 0, errors.New("pasteboard: the text could not be written")
	}
	return int64(change), nil
}

// Clear empties the pasteboard, for a secret that expired.
func (b *Board) Clear() int64 { return int64(C.cb_clear(b.name)) }
