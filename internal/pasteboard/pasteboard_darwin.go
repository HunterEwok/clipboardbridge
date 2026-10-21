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
)

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

// Read returns the pasteboard's item, and false if it holds no text.
func (b *Board) Read() (Item, bool, error) {
	var text *C.char
	var n C.long
	var flags C.int
	var change C.long
	switch C.cb_read(b.name, &text, &n, &flags, &change) {
	case -1:
		return Item{}, false, errors.New("pasteboard: out of memory")
	case 0:
		return Item{Change: int64(change)}, false, nil
	}
	it := Item{Secret: flags&C.CB_SECRET != 0, Remote: flags&C.CB_REMOTE != 0, Change: int64(change)}
	if text != nil {
		it.Text = C.GoStringN(text, C.int(n))
		C.free(unsafe.Pointer(text))
	}
	return it, true, nil
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
