// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package sysinfo

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFormOf(t *testing.T) {
	for _, c := range []struct{ model, product, chassis, want string }{
		{"Raspberry Pi 4 Model B Rev 1.4", "", "", "board"},
		{"", "Jupiter", "10", "console"},
		{"", "ThinkPad", "10", "laptop"},
		{"", "", "3", "desktop"},
		{"", "", "17", "server"},
		{"", "", "", ""},
	} {
		if got := formOf(c.model, c.product, c.chassis); got != c.want {
			t.Errorf("formOf(%q, %q, %q) = %q, want %q", c.model, c.product, c.chassis, got, c.want)
		}
	}
}

func TestOSRelease(t *testing.T) {
	for _, c := range []struct{ file, want string }{
		{"NAME=\"Debian GNU/Linux\"\nVERSION_ID=\"13\"\nPRETTY_NAME=\"Debian GNU/Linux 13 (trixie)\"\n", "Debian GNU/Linux 13 (trixie)"},
		{"NAME=\"SteamOS\"\nVERSION_ID=3.7\nPRETTY_NAME=\"SteamOS Holo with a very long pretty name\"\n", "SteamOS 3.7"},
	} {
		path := filepath.Join(t.TempDir(), "os-release")
		if err := os.WriteFile(path, []byte(c.file), 0o644); err != nil {
			t.Fatal(err)
		}
		f, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := osRelease(f); got != c.want {
			t.Errorf("osRelease = %q, want %q", got, c.want)
		}
		f.Close()
	}
}
