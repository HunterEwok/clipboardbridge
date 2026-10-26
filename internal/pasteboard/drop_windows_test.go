// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package pasteboard

import (
	"slices"
	"testing"
)

func TestDrop(t *testing.T) {
	paths := []string{`C:\Users\u\report 1.pdf`, "D:\\\u0424\u043e\u0442\u043e"}
	got, err := parseDrop(dropData(paths))
	if err != nil || !slices.Equal(got, paths) {
		t.Errorf("parseDrop(dropData) = %q, %v", got, err)
	}
	// An ANSI list, as old programs write it.
	ansi := append(make([]byte, dropFiles), "C:\\a.txt\x00C:\\b\x00\x00"...)
	ansi[0] = dropFiles
	if got, err := parseDrop(ansi); err != nil || !slices.Equal(got, []string{`C:\a.txt`, `C:\b`}) {
		t.Errorf("parseDrop of an ANSI list = %q, %v", got, err)
	}
	for _, bad := range [][]byte{nil, make([]byte, 10), {200, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0}} {
		if _, err := parseDrop(bad); err == nil {
			t.Errorf("parseDrop(%v) succeeded", bad)
		}
	}
}
