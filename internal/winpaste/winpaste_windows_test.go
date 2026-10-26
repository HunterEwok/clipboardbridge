// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package winpaste

import (
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// TestInputSize checks INPUT's layout: SendInput refuses any other size.
func TestInputSize(t *testing.T) {
	want := uintptr(40)
	if unsafe.Sizeof(uintptr(0)) == 4 {
		want = 28
	}
	if got := unsafe.Sizeof(input{}); got != want {
		t.Errorf("INPUT is %d bytes, want %d", got, want)
	}
}

// TestIntegrity checks reading a process's integrity level: the test runs
// at medium or above.
func TestIntegrity(t *testing.T) {
	got, err := integrity(windows.CurrentProcess())
	if err != nil {
		t.Fatal(err)
	}
	if got < 0x2000 || got > 0x4000 {
		t.Errorf("the integrity level is %#x", got)
	}
	again, err := processIntegrity(windows.GetCurrentProcessId())
	if err != nil || again != got {
		t.Errorf("by its ID: %#x, %v", again, err)
	}
}

// TestLastSubAuthority reads Mandatory Label\High (S-1-16-12288) and
// rejects a SID that would run past the buffer.
func TestLastSubAuthority(t *testing.T) {
	buf := []byte{0xff, 0xff, 1, 1, 0, 0, 0, 0, 0, 16, 0x00, 0x30, 0, 0}
	if got, err := lastSubAuthority(buf, 2); err != nil || got != 0x3000 {
		t.Errorf("got %#x, %v", got, err)
	}
	if _, err := lastSubAuthority(buf[:13], 2); err == nil {
		t.Error("a cut SID was read")
	}
	if _, err := lastSubAuthority(buf, -1); err == nil {
		t.Error("an offset before the buffer was read")
	}
}
