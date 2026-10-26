// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build (darwin && cgo) || windows

package pasteboard

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// TestFiles writes files as Finder and Explorer copy them and reads them
// back, before the text the Finder adds.
func TestFiles(t *testing.T) {
	b := private(t)
	dir := t.TempDir()
	paths := []string{filepath.Join(dir, "report 1.pdf"), filepath.Join(dir, "\u0424\u043e\u0442\u043e")}
	os.WriteFile(paths[0], []byte("pdf"), 0o644)
	os.Mkdir(paths[1], 0o755)
	change, err := b.WriteFiles(paths)
	if err != nil {
		t.Fatal(err)
	}
	it, ok, err := b.Read()
	if err != nil || !ok || it.Change != change {
		t.Fatalf("Read = %+v, %v, %v", it, ok, err)
	}
	// The Mac may give the paths of folders with their real case and
	// without links in them, as /private/var for /var.
	want := slices.Clone(paths)
	for i, p := range want {
		if r, err := filepath.EvalSymlinks(p); err == nil {
			want[i] = r
		}
	}
	got := slices.Clone(it.Files)
	for i, p := range got {
		if r, err := filepath.EvalSymlinks(p); err == nil {
			got[i] = r
		}
	}
	if !slices.Equal(got, want) {
		t.Errorf("read the files %q, want %q", it.Files, paths)
	}
	if _, err := b.Write("a text", false); err != nil {
		t.Fatal(err)
	}
	if it, ok, err := b.Read(); err != nil || !ok || it.Files != nil || it.Text != "a text" {
		t.Errorf("Read after a text = %+v, %v, %v", it, ok, err)
	}
}
