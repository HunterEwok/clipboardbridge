// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"os/exec"
	"strings"
	"testing"
)

// Every argument is a literal: a name with quotes and $ runs nothing.
func TestPSScript(t *testing.T) {
	s := psScript(`C:\Program Files\clipboardbridge\cbb.exe`, []string{"rename", "ab12", "Bob's $(x)"}, false, true, `C:\T\o.txt`)
	want := "$env:CBB_DEBUG = '1'\n& 'C:\\Program Files\\clipboardbridge\\cbb.exe' 'rename' 'ab12' 'Bob''s $(x)' *> 'C:\\T\\o.txt'\nexit $LASTEXITCODE\n"
	if s != want {
		t.Errorf("psScript =\n%s\nwant\n%s", s, want)
	}
	if s := psScript("cbb", []string{"global", "on"}, true, false, "o"); !strings.HasPrefix(s, "'yes' | & 'cbb'") {
		t.Errorf("with yes: %q", s)
	}
}

// PowerShell runs the encoded script as written.
func TestEncodePS(t *testing.T) {
	out, err := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-EncodedCommand", encodePS("$x = 'no'; Write-Output 'Bob''s $x'")).Output()
	if err != nil {
		t.Skip("no powershell:", err)
	}
	if got := strings.TrimSpace(string(out)); got != "Bob's $x" {
		t.Errorf("powershell printed %q", got)
	}
}
