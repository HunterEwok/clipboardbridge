// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// pkexec gets each argument as it is, with CBB_DEBUG through env.
func TestPkexecArgs(t *testing.T) {
	got := pkexecArgs("/usr/local/bin/cbb", []string{"rename", "ab12", "Bob's $(x)"}, true)
	want := []string{"/usr/bin/env", "CBB_DEBUG=1", "/usr/local/bin/cbb", "rename", "ab12", "Bob's $(x)"}
	if !slices.Equal(got, want) {
		t.Errorf("pkexecArgs = %q, want %q", got, want)
	}
	if got := pkexecArgs("/usr/local/bin/cbb", []string{"revoke", "x"}, false); got[0] != "/usr/local/bin/cbb" {
		t.Errorf("without details: %q", got)
	}
}

// pkexec runs cbb only from a place that root owns and no one else may change.
func TestRootOnly(t *testing.T) {
	if !rootOnly("/bin/sh") && !rootOnly("/usr/bin/env") {
		t.Error("neither /bin/sh nor /usr/bin/env counts as root's")
	}
	mine := filepath.Join(t.TempDir(), "cbb")
	if err := os.WriteFile(mine, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() != 0 && rootOnly(mine) {
		t.Error("a file of the user's own counts as root's")
	}
	if rootOnly("/tmp") || rootOnly("/nonexistent/cbb") {
		t.Error("a directory or a missing file counts")
	}
}
