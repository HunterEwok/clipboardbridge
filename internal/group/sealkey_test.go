// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package group

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestSealSecret: the first load makes the secret and keeps it, a later
// load gives the same one, and a file of an unknown version or a secret of
// the wrong size is refused.
func TestSealSecret(t *testing.T) {
	t.Setenv(TPMEnv, "off")
	dir := t.TempDir()
	a, err := LoadSealSecret(dir)
	if err != nil {
		t.Fatal(err)
	}
	b, err := LoadSealSecret(dir)
	if err != nil || !bytes.Equal(a, b) {
		t.Fatalf("loaded again: %v, same %v", err, bytes.Equal(a, b))
	}
	if fi, err := os.Stat(filepath.Join(dir, SealKeyFileName)); err != nil || runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Errorf("the file: %v %v", fi, err)
	}
	for name, body := range map[string]string{
		"version 2": `{"v":2,"secret":"AAAA"}`,
		"short":     `{"v":1,"secret":"AAAA"}`,
		"not json":  `{`,
		"no secret": `{"v":1}`,
	} {
		if err := os.WriteFile(filepath.Join(dir, SealKeyFileName), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadSealSecret(dir); err == nil {
			t.Errorf("%s: taken", name)
		}
	}
}
