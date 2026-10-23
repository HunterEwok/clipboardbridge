// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package atomicfile

import (
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestWrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	if err := Write(path, []byte("one"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Write(path, []byte("two"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "two" {
		t.Fatalf("ReadFile = %q, %v; want \"two\"", got, err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v, want 0600 even though the old file was 0644", fi.Mode().Perm())
	}
	// A mode other than the temporary file's own 0600 is set too.
	if err := Write(path, []byte("three"), 0o640); err != nil {
		t.Fatal(err)
	}
	if fi, err = os.Stat(path); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm() != 0o640 {
		t.Errorf("mode = %v, want 0640", fi.Mode().Perm())
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Errorf("the directory holds %d entries, want only the file: %v", len(entries), entries)
	}
}

func TestWriteReplacesTheFile(t *testing.T) {
	// The new content goes into a new file that is renamed over the old
	// one; the old file is never rewritten in place, so a reader that has
	// it open, or a crash in the middle, sees the whole old content.
	path := filepath.Join(t.TempDir(), "state.json")
	if err := Write(path, []byte("old content"), 0o600); err != nil {
		t.Fatal(err)
	}
	old, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer old.Close()
	before, err := old.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "windows" {
		// Windows renames over a file only while nobody has it open.
		old.Close()
	}
	if err := Write(path, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if os.SameFile(before, after) {
		t.Error("Write rewrote the file in place")
	}
	if runtime.GOOS == "windows" {
		return
	}
	if got, err := io.ReadAll(old); err != nil || string(got) != "old content" {
		t.Errorf("the old file now reads %q, %v", got, err)
	}
}

func TestWriteFailureLeavesNoTemporaryFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	if err := Write(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Renaming a file over a directory fails, after the temporary file was
	// written.
	target := filepath.Join(dir, "sub")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "x"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Write(target, []byte("new"), 0o600); err == nil {
		t.Fatal("Write over a non-empty directory succeeded")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Errorf("a failed write left files behind: %v", entries)
	}
	if fi, err := os.Stat(target); err != nil || !fi.IsDir() {
		t.Errorf("the target is no longer the directory: %v", err)
	}
	if got, _ := os.ReadFile(path); string(got) != "old" {
		t.Errorf("another file in the directory changed to %q", got)
	}
}

func TestWriteMissingDirectory(t *testing.T) {
	if err := Write(filepath.Join(t.TempDir(), "no", "such", "file"), nil, 0o600); err == nil {
		t.Error("Write into a missing directory succeeded")
	}
}

func TestWriteRelativePath(t *testing.T) {
	t.Chdir(t.TempDir())
	if err := Write("plain", []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile("plain"); string(got) != "x" {
		t.Errorf("ReadFile = %q", got)
	}
}
