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
