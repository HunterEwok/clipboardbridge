// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build (darwin && cgo) || windows

package pasteboard

import (
	"strings"
	"testing"
)

func TestHTML(t *testing.T) {
	b := private(t)
	html := "<p>Hello, <b>caf\u00e9</b></p>"
	change, err := b.WriteHTML(html, "Hello, caf\u00e9")
	if err != nil {
		t.Fatal(err)
	}
	// Windows keeps it inside a document of its own.
	it, ok, err := b.Read()
	if err != nil || !ok || it.Text != "Hello, caf\u00e9" || !strings.Contains(it.HTML, html) || it.Change != change {
		t.Errorf("Read = %+v, %v, %v", it, ok, err)
	}
	// A plain text has none.
	if _, err := b.Write("plain", false); err != nil {
		t.Fatal(err)
	}
	if it, _, _ := b.Read(); it.HTML != "" {
		t.Errorf("a plain text came with HTML %q", it.HTML)
	}
}
