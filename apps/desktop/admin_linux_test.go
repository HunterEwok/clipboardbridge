// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
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
