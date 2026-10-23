// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package pasteboard

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"time"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

// On Windows the pasteboard is the clipboard of the user's session, read
// and written through the Win32 API. Its change counter is the clipboard
// sequence number. A password manager marks a secret with the formats that
// Windows documents for clipboard monitors and the clipboard history;
// received secrets are written with them. Windows apps end lines with CR LF:
// the text is read with LF and written with CR LF, so the group carries one
// form. A text with a NUL ends there, since the clipboard's text format ends
// at the first NUL.

var (
	user32   = windows.NewLazySystemDLL("user32.dll")
	kernel32 = windows.NewLazySystemDLL("kernel32.dll")

	procOpenClipboard              = user32.NewProc("OpenClipboard")
	procCloseClipboard             = user32.NewProc("CloseClipboard")
	procEmptyClipboard             = user32.NewProc("EmptyClipboard")
	procGetClipboardData           = user32.NewProc("GetClipboardData")
	procSetClipboardData           = user32.NewProc("SetClipboardData")
	procIsClipboardFormatAvailable = user32.NewProc("IsClipboardFormatAvailable")
	procRegisterClipboardFormatW   = user32.NewProc("RegisterClipboardFormatW")
	procGetClipboardSequenceNumber = user32.NewProc("GetClipboardSequenceNumber")
	procCreateWindowExW            = user32.NewProc("CreateWindowExW")
	procGlobalAlloc                = kernel32.NewProc("GlobalAlloc")
	procGlobalFree                 = kernel32.NewProc("GlobalFree")
	procGlobalLock                 = kernel32.NewProc("GlobalLock")
	procGlobalUnlock               = kernel32.NewProc("GlobalUnlock")
	procGlobalSize                 = kernel32.NewProc("GlobalSize")
)

const (
	cfUnicodeText = 13
	gmemMoveable  = 0x0002
	hwndMessage   = ^uintptr(2) // HWND_MESSAGE, (HWND)-3
)

// The formats that mark a secret. A clipboard monitor skips an item with
// ExcludeClipboardContentFromMonitorProcessing, and the clipboard history
// and the cloud clipboard skip one whose CanIncludeInClipboardHistory or
// CanUploadToCloudClipboard is the number 0. "Clipboard Viewer Ignore" is
// the older mark that KeePass and other password managers also set.
var (
	formatsOnce                                   sync.Once
	cfExclude, cfViewerIgnore, cfHistory, cfCloud uintptr
)

func registerFormats() {
	formatsOnce.Do(func() {
		cfExclude = register("ExcludeClipboardContentFromMonitorProcessing")
		cfViewerIgnore = register("Clipboard Viewer Ignore")
		cfHistory = register("CanIncludeInClipboardHistory")
		cfCloud = register("CanUploadToCloudClipboard")
	})
}

func register(name string) uintptr {
	p, _ := windows.UTF16PtrFromString(name)
	r, _, _ := procRegisterClipboardFormatW.Call(uintptr(unsafe.Pointer(p)))
	return r
}

// A Board is the clipboard. Its calls run on one locked thread, which owns
// the hidden window that the clipboard needs as the owner of what this
// program writes.
type Board struct{}

// General returns the clipboard of the user's session.
func General() *Board { return &Board{} }

// Private returns the clipboard too: Windows has no private ones, so the
// tests that use it run only when asked to (CBB_TEST_CLIPBOARD=1).
func Private(string) *Board { return &Board{} }

// Release does nothing on Windows.
func (b *Board) Release() {}

// ChangeCount returns the clipboard sequence number, which grows with every
// change of the clipboard.
func (b *Board) ChangeCount() int64 {
	r, _, _ := procGetClipboardSequenceNumber.Call()
	return int64(uint32(r))
}

// Read returns the clipboard's text, and false if it holds none.
func (b *Board) Read() (Item, bool, error) {
	var it Item
	var ok bool
	err := onThread(func(hwnd uintptr) error {
		if err := open(hwnd); err != nil {
			return err
		}
		defer procCloseClipboard.Call()
		it.Change = b.ChangeCount()
		if !available(cfUnicodeText) {
			return nil
		}
		h, _, err := procGetClipboardData.Call(cfUnicodeText)
		if h == 0 {
			return fmt.Errorf("pasteboard: reading the clipboard: %w", err)
		}
		text, err := globalText(h)
		if err != nil {
			return err
		}
		registerFormats()
		it.Text = strings.ReplaceAll(text, "\r\n", "\n")
		it.Secret = available(cfExclude) || available(cfViewerIgnore) || zero(cfHistory)
		ok = true
		return nil
	})
	return it, ok, err
}

// Write puts a text on the clipboard and returns the new change counter.
// A secret carries the marks, so clipboard histories, the cloud clipboard
// and other monitors skip it.
func (b *Board) Write(text string, secret bool) (int64, error) {
	if i := strings.IndexByte(text, 0); i >= 0 {
		text = text[:i]
	}
	text = strings.ReplaceAll(strings.ReplaceAll(text, "\r\n", "\n"), "\n", "\r\n")
	var change int64
	err := onThread(func(hwnd uintptr) error {
		if err := open(hwnd); err != nil {
			return err
		}
		defer procCloseClipboard.Call()
		if r, _, err := procEmptyClipboard.Call(); r == 0 {
			return fmt.Errorf("pasteboard: emptying the clipboard: %w", err)
		}
		if err := set(cfUnicodeText, utf16Bytes(text)); err != nil {
			return err
		}
		if secret {
			registerFormats()
			var errs []error
			errs = append(errs, set(cfExclude, []byte{0}))
			errs = append(errs, set(cfViewerIgnore, []byte{0}))
			errs = append(errs, set(cfHistory, []byte{0, 0, 0, 0}))
			errs = append(errs, set(cfCloud, []byte{0, 0, 0, 0}))
			if err := errors.Join(errs...); err != nil {
				procEmptyClipboard.Call() // never leave a secret without its marks
				return err
			}
		}
		change = b.ChangeCount()
		return nil
	})
	if err != nil {
		return 0, err
	}
	return change, nil
}

// Clear empties the clipboard, for a secret that expired.
func (b *Board) Clear() int64 {
	var change int64
	onThread(func(hwnd uintptr) error {
		if err := open(hwnd); err != nil {
			return err
		}
		defer procCloseClipboard.Call()
		procEmptyClipboard.Call()
		change = b.ChangeCount()
		return nil
	})
	return change
}

// open opens the clipboard, waiting a little while another program has it
// open.
func open(hwnd uintptr) error {
	var err error
	for range 20 {
		var r uintptr
		r, _, err = procOpenClipboard.Call(hwnd)
		if r != 0 {
			return nil
		}
		time.Sleep(25 * time.Millisecond)
	}
	return fmt.Errorf("pasteboard: another program keeps the clipboard open: %w", err)
}

func available(format uintptr) bool {
	if format == 0 {
		return false
	}
	r, _, _ := procIsClipboardFormatAvailable.Call(format)
	return r != 0
}

// zero tells whether the clipboard holds the format as the number 0.
func zero(format uintptr) bool {
	if !available(format) {
		return false
	}
	h, _, _ := procGetClipboardData.Call(format)
	if h == 0 {
		return false
	}
	p, _, _ := procGlobalLock.Call(h)
	if p == 0 {
		return false
	}
	defer procGlobalUnlock.Call(h)
	n, _, _ := procGlobalSize.Call(h)
	return n >= 4 && *(*uint32)(ptr(p)) == 0
}

// globalText reads the UTF-16 text in a clipboard memory block, up to its
// first NUL or its end.
func globalText(h uintptr) (string, error) {
	p, _, err := procGlobalLock.Call(h)
	if p == 0 {
		return "", fmt.Errorf("pasteboard: reading the clipboard: %w", err)
	}
	defer procGlobalUnlock.Call(h)
	n, _, _ := procGlobalSize.Call(h)
	u := unsafe.Slice((*uint16)(ptr(p)), n/2)
	for i, c := range u {
		if c == 0 {
			u = u[:i]
			break
		}
	}
	return string(utf16.Decode(u)), nil
}

// ptr turns the address of locked global memory, which is outside Go's
// heap, into a pointer.
func ptr(p uintptr) unsafe.Pointer { return *(*unsafe.Pointer)(unsafe.Pointer(&p)) }

func utf16Bytes(s string) []byte {
	u := utf16.Encode([]rune(s))
	u = append(u, 0)
	return unsafe.Slice((*byte)(unsafe.Pointer(&u[0])), 2*len(u))
}

// set puts data in a format on the open clipboard, which then owns the
// memory.
func set(format uintptr, data []byte) error {
	if format == 0 {
		return errors.New("pasteboard: a clipboard format could not be registered")
	}
	h, _, err := procGlobalAlloc.Call(gmemMoveable, uintptr(len(data)))
	if h == 0 {
		return fmt.Errorf("pasteboard: out of memory: %w", err)
	}
	p, _, err := procGlobalLock.Call(h)
	if p == 0 {
		procGlobalFree.Call(h)
		return fmt.Errorf("pasteboard: writing the clipboard: %w", err)
	}
	copy(unsafe.Slice((*byte)(ptr(p)), len(data)), data)
	procGlobalUnlock.Call(h)
	if r, _, err := procSetClipboardData.Call(format, h); r == 0 {
		procGlobalFree.Call(h)
		return fmt.Errorf("pasteboard: writing the clipboard: %w", err)
	}
	return nil
}

// The clipboard thread: a locked OS thread with a hidden message-only
// window, on which every call that opens the clipboard runs.
var (
	threadOnce sync.Once
	calls      chan func(hwnd uintptr)
	threadErr  error
)

func onThread(f func(hwnd uintptr) error) error {
	threadOnce.Do(startThread)
	if threadErr != nil {
		return threadErr
	}
	done := make(chan error, 1)
	calls <- func(hwnd uintptr) { done <- f(hwnd) }
	return <-done
}

func startThread() {
	calls = make(chan func(uintptr))
	ready := make(chan uintptr)
	go func() {
		runtime.LockOSThread()
		class, _ := windows.UTF16PtrFromString("STATIC")
		hwnd, _, err := procCreateWindowExW.Call(0, uintptr(unsafe.Pointer(class)), 0, 0, 0, 0, 0, 0, hwndMessage, 0, 0, 0)
		if hwnd == 0 {
			threadErr = fmt.Errorf("pasteboard: the clipboard window could not be made: %w", err)
		}
		ready <- hwnd
		if hwnd == 0 {
			return
		}
		for f := range calls {
			f(hwnd)
		}
	}()
	<-ready
}
