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
ssh = "ewok@steamdeck.lan"
clipboard = "wayland"
roles = ["member", "hub"]

[device.rpi0w]
os = "linux-lite"
ssh = "ewok@rpi0w.lan"

[device.win]
os = "windows"
ssh = "ewok@win.lan"
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

// The patterns read what cbb and cbb-lite print; keep them in step with
// cmd/cbb/commands.go and lite/src/main.rs.
func TestPatterns(t *testing.T) {
	if m := codeRE.FindStringSubmatch("Pairing code: 123 456"); m == nil || m[1]+m[2] != "123456" {
		t.Fatalf("code: %v", m)
	}
	if m := addrRE.FindStringSubmatch("If it cannot find this one: cbb join -code 192.168.0.167:8764"); m == nil || m[1] != "192.168.0.167:8764" {
		t.Fatalf("address: %v", m)
	}
	for _, s := range []string{
		"Device deck (linux), group 485666d454cba4e8",
		"device  abc\ngroup   485666d454cba4e8\nrole    lite",
	} {
		if m := groupRE.FindStringSubmatch(s); m == nil || m[1] != "485666d454cba4e8" {
			t.Fatalf("group in %q: %v", s, m)
		}
	}
}
