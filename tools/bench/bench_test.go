// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf16"
)

func TestInventory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "inventory.toml")
	os.WriteFile(path, []byte(`
controller = "pi4"

[device.deck]
os = "linux"
ssh = "user@deck.lan"
clipboard = "wayland"
roles = ["member", "hub"]

[device.rpi0w]
os = "linux-lite"
ssh = "user@pi.lan"

[device.win]
os = "windows"
ssh = "user@win.lan"
clipboard = "windows"
vm = { host = "mac", vmx = "win.vmx", snapshot = "clean" }

[router]
ssh = "root@router.lan"
kind = "openwrt"
`), 0o600)
	inv, err := LoadInventory(path)
	if err != nil {
		t.Fatal(err)
	}
	ds, err := inv.Select("")
	if err != nil || len(ds) != 3 || ds[0].Name != "deck" || !ds[0].Has("hub") {
		t.Fatalf("Select = %v, %v", ds, err)
	}
	if ds[1].Clipboard != "none" || ds[2].VM.Snapshot != "clean" {
		t.Fatalf("defaults: %+v %+v", ds[1], ds[2].VM)
	}
	if _, err := inv.Select("deck,nope"); err == nil {
		t.Fatal("Select took an unknown device")
	}

	os.WriteFile(path, []byte("[device.x]\nos = \"plan9\"\nssh = \"a@b\"\n"), 0o600)
	if _, err := LoadInventory(path); err == nil || !strings.Contains(err.Error(), "plan9") {
		t.Fatalf("an unknown os: %v", err)
	}
	os.WriteFile(path, []byte("[device.x]\nos = \"linux\"\nssh = \"a@b\"\ncolour = 1\n"), 0o600)
	if _, err := LoadInventory(path); err == nil || !strings.Contains(err.Error(), "unknown keys") {
		t.Fatalf("an unknown key: %v", err)
	}
}

func TestEncodePS(t *testing.T) {
	s := "Set-Clipboard 'café'"
	b, err := base64.StdEncoding.DecodeString(encodePS(s))
	if err != nil {
		t.Fatal(err)
	}
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = uint16(b[2*i]) | uint16(b[2*i+1])<<8
	}
	if got := string(utf16.Decode(u)); got != s {
		t.Fatalf("decoded %q", got)
	}
}

func TestShellQuote(t *testing.T) {
	if got := shellQuote(`a 'b' $c`); got != `'a '\''b'\'' $c'` {
		t.Fatalf("shellQuote = %s", got)
	}
}

// The patterns read what the full and the lite member print; keep them in step with
// cmd/cbb/commands.go and lite/src/main.rs.
func TestPatterns(t *testing.T) {
	if m := codeRE.FindStringSubmatch("Pairing code: 123 456"); m == nil || m[1]+m[2] != "123456" {
		t.Fatalf("code: %v", m)
	}
	if m := addrRE.FindStringSubmatch("If it cannot find this one: cbb pair -code 192.168.1.10:8764"); m == nil || m[1] != "192.168.1.10:8764" {
		t.Fatalf("address: %v", m)
	}
	for _, s := range []string{
		"Device deck (linux), group 0a1b2c3d4e5f6a7b",
		"device  abc\ngroup   0a1b2c3d4e5f6a7b\nrole    lite",
	} {
		if m := groupRE.FindStringSubmatch(s); m == nil || m[1] != "0a1b2c3d4e5f6a7b" {
			t.Fatalf("group in %q: %v", s, m)
		}
	}
}

func TestNoLocale(t *testing.T) {
	got := noLocale([]string{"HOME=/home/u", "LANG=ru_RU.UTF-8", "LC_ALL=ru_RU.UTF-8", "LC_CTYPE=C", "LANGUAGE=ru", "PATH=/bin"})
	if strings.Join(got, " ") != "HOME=/home/u PATH=/bin" {
		t.Errorf("noLocale = %q", got)
	}
}

func TestDeviceRE(t *testing.T) {
	for _, out := range []string{"Device 3f2a9c01d4 (linux), group 0a1b2c3d4e5f6a7b\n", "device  3f2a9c01d4\ngroup   0a1b2c3d4e5f6a7b\n"} {
		if m := deviceRE.FindStringSubmatch(out); m == nil || m[1] != "3f2a9c01d4" {
			t.Errorf("deviceRE on %q = %v", out, m)
		}
	}
}

// TestTextCases checks the matrix's texts: none is empty or ends with a
// line ending, which the readers trim, and each sender's text differs.
func TestTextCases(t *testing.T) {
	for _, tc := range textCases {
		a, b := tc.text("20261024-120000", "mac"), tc.text("20261024-120000", "win")
		if a == "" || strings.TrimRight(a, "\r\n") != a {
			t.Errorf("%s: %q is empty or ends with a line ending", tc.id, a)
		}
		if a == b {
			t.Errorf("%s: two senders send the same text %q", tc.id, a)
		}
	}
}

func TestSeen(t *testing.T) {
	lin, win := &Device{OS: "linux"}, &Device{OS: "windows"}
	text := "L1\nL2\r\nL3\n"
	for _, c := range []struct {
		from, to *Device
		want     string
	}{
		{lin, lin, text},
		{lin, win, "L1\r\nL2\r\nL3\r\n"},
		{win, lin, "L1\nL2\nL3\n"},
		{win, win, "L1\r\nL2\r\nL3\r\n"},
	} {
		if got := seen(text, c.from, c.to); got != c.want {
			t.Errorf("seen(%q, %s, %s) = %q, want %q", text, c.from.OS, c.to.OS, got, c.want)
		}
	}
}
