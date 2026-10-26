// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf16"
)

func TestInventory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "inventory.toml")
	os.WriteFile(path, []byte(`
controller = "controller"

[device.desktop]
os = "linux"
ssh = "user@desktop.lan"
clipboard = "wayland"
roles = ["member", "hub"]

[device.lite]
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
	if err != nil || len(ds) != 3 || ds[0].Name != "desktop" || !ds[0].Has("hub") {
		t.Fatalf("Select = %v, %v", ds, err)
	}
	if ds[1].Clipboard != "none" || ds[2].VM.Snapshot != "clean" {
		t.Fatalf("defaults: %+v %+v", ds[1], ds[2].VM)
	}
	if _, err := inv.Select("desktop,nope"); err == nil {
		t.Fatal("Select took an unknown device")
	}

	os.WriteFile(path, []byte("[device.nas]\nos = \"docker\"\nssh = \"a@b\"\nroles = [\"hub\"]\n"), 0o600)
	if _, err := LoadInventory(path); err == nil || !strings.Contains(err.Error(), "ordinary member") {
		t.Fatalf("a container as the hub: %v", err)
	}
	os.WriteFile(path, []byte("[device.nas]\nos = \"docker\"\nssh = \"a@b\"\n"), 0o600)
	inv, err = LoadInventory(path)
	if err != nil || inv.Device["nas"].Container != "clipboardbridge" || cbbCmd(inv.Device["nas"]) != "docker exec -i clipboardbridge cbb" {
		t.Fatalf("a container: %+v, %v", inv, err)
	}
	os.WriteFile(path, []byte("[device.nas]\nos = \"docker\"\nssh = \"a@b\"\nclipboard = \"x11\"\n"), 0o600)
	if _, err := LoadInventory(path); err == nil {
		t.Fatal("a container with a desktop clipboard")
	}
	os.WriteFile(path, []byte("[device.x]\nos = \"linux\"\nssh = \"a@b\"\ncontainer = \"c\"\n"), 0o600)
	if _, err := LoadInventory(path); err == nil {
		t.Fatal("a container name on a device that is not one")
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
		"Device desktop (linux), group 0a1b2c3d4e5f6a7b",
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

func TestContainer(t *testing.T) {
	// As docker inspect prints the container of compose.home.yaml.
	good := "false|true|[ALL]|65532:65532|[no-new-privileges:true]|host|unless-stopped"
	if err := checkLockedDown(good); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{
		"true|true|[ALL]|65532:65532|[no-new-privileges:true]|host|unless-stopped",
		"false|false|[ALL]|65532:65532|[no-new-privileges:true]|host|unless-stopped",
		"false|true|[]|65532:65532|[no-new-privileges:true]|host|unless-stopped",
		"false|true|[ALL]|0|[no-new-privileges:true]|host|unless-stopped",
		"false|true|[ALL]||[no-new-privileges:true]|host|unless-stopped",
		"false|true|[ALL]|65532:65532|[]|host|unless-stopped",
		"false|true|[ALL]|65532:65532|[no-new-privileges:true]|bridge|unless-stopped",
		"false|true|[ALL]|65532:65532|[no-new-privileges:true]|host|no",
		"false|true",
	} {
		if checkLockedDown(bad) == nil {
			t.Errorf("checkLockedDown took %q", bad)
		}
	}
	if got, want := recreateCmd("cbb|/srv/cbb/compose.home.yaml|clipboardbridge"),
		"docker compose -p 'cbb' -f '/srv/cbb/compose.home.yaml' up -d --force-recreate 'clipboardbridge'"; got != want {
		t.Errorf("recreateCmd = %s, want %s", got, want)
	}
	if got := recreateCmd("||"); got != "" {
		t.Errorf("recreateCmd without compose = %q", got)
	}
}

func TestAdmin(t *testing.T) {
	for os, want := range map[string]string{
		"linux":      "sudo -n cbb",
		"linux-lite": "sudo -n cbb",
		"darwin":     "sudo -n cbb",
		"windows":    `& "$env:ProgramFiles\clipboardbridge\cbb.exe"`,
		"docker":     "docker exec -i c cbb",
	} {
		if got := adminCmd(&Device{OS: os, Container: "c"}); got != want {
			t.Errorf("adminCmd(%s) = %q, want %q", os, got, want)
		}
	}
	refused := &RunError{Device: "mac", Output: "sudo: a password is required\n"}
	if !sudoRefused(refused) || sudoRefused(&RunError{Output: "only the administrator may run it"}) || sudoRefused(nil) {
		t.Fatal("sudoRefused")
	}
	var buf strings.Builder
	r := NewReport("t", &buf, false)
	if err := r.Do("a", func() error { return noSudo(&Device{Name: "mac"}, refused) }); err == nil {
		t.Fatal("a skipped case returned nil")
	}
	r.Do("b", func() error { return noSudo(&Device{Name: "x"}, errors.New("broken")) })
	if r.Failed() != 1 || !strings.Contains(buf.String(), "SKIP a: mac runs no sudo") || !strings.Contains(buf.String(), "FAIL b") {
		t.Fatalf("report:\n%s", buf.String())
	}
}

func TestAway(t *testing.T) {
	path := filepath.Join(t.TempDir(), "inventory.toml")
	os.WriteFile(path, []byte(`
[device.desktop]
os = "linux"
ssh = "a@desktop"
roles = ["member", "hub", "away"]

[device.remote]
os = "linux"
ssh = "a@remote"
roles = ["away"]

[forwarder]
ssh = "a@relay"
address = "relay.example.net:8764"
key = "sha256:AAAA"
service = "cbb-forward"

[relay]
address = "relay.example.net:8765"
key = "sha256:BBBB"
`), 0o600)
	inv, err := LoadInventory(path)
	if err != nil {
		t.Fatal(err)
	}
	if inv.Forwarder.Address != "relay.example.net:8764" || inv.Forwarder.Service != "cbb-forward" || inv.Relay.Key != "sha256:BBBB" {
		t.Fatalf("servers: %+v %+v", inv.Forwarder, inv.Relay)
	}
	ds, _ := inv.Select("")
	if home := atHome(ds); len(home) != 1 || home[0].Name != "desktop" {
		t.Fatalf("atHome = %v", home)
	}
	if away := awayOnly(ds); len(away) != 1 || away[0].Name != "remote" {
		t.Fatalf("awayOnly = %v", away)
	}
	if m := fingerprintRE.FindStringSubmatch("Its key fingerprint:  ab12 cd34 ef56"); m == nil || m[1] != "ab12 cd34 ef56" {
		t.Fatalf("fingerprint: %q", m)
	}
}

func TestReset(t *testing.T) {
	for _, c := range []struct{ os, machine, want string }{
		{"linux", "x86_64", "clipboardbridge-linux-amd64.tar.gz"},
		{"docker", "aarch64", "clipboardbridge-linux-arm64.tar.gz"},
		{"linux-lite", "armv6l", "clipboardbridge-lite-linux-armv6.tar.gz"},
		{"darwin", "arm64", "clipboardbridge-darwin-arm64.tar.gz"},
		{"windows", "ARM64", "clipboardbridge-windows-arm64.zip"},
		{"windows", "AMD64", "clipboardbridge-windows-amd64.zip"},
	} {
		if got, err := archiveFor(&Device{OS: c.os}, c.machine); err != nil || got != c.want {
			t.Errorf("archiveFor(%s, %s) = %q, %v", c.os, c.machine, got, err)
		}
	}
	if _, err := archiveFor(&Device{OS: "linux"}, "mips"); err == nil {
		t.Error("archiveFor took an unknown CPU")
	}

	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "clipboardbridge-linux-amd64.tar.gz"), []byte("archive"), 0o600)
	b, err := LoadBuild(dir)
	if err != nil || len(b.sums) != 1 || len(b.sums["clipboardbridge-linux-amd64.tar.gz"]) != 64 {
		t.Fatalf("LoadBuild = %+v, %v", b, err)
	}
	os.WriteFile(filepath.Join(dir, "clipboardbridge-windows-arm64.zip"), []byte("zip"), 0o600)
	if b, err := LoadBuild(dir); err != nil || len(b.sums) != 2 {
		t.Fatalf("LoadBuild with a zip = %+v, %v", b, err)
	}
	os.WriteFile(filepath.Join(dir, "SHA256SUMS"), []byte(strings.Repeat("0", 64)+"  clipboardbridge-linux-amd64.tar.gz\n"), 0o600)
	if _, err := LoadBuild(dir); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("a wrong checksum: %v", err)
	}
	if _, err := LoadBuild(t.TempDir()); err == nil {
		t.Fatal("LoadBuild took a directory without archives")
	}

	if got := composeCmd("cbb-nas|/home/u/cbb-nas/compose.yaml|clipboardbridge"); got != "docker compose -p 'cbb-nas' -f '/home/u/cbb-nas/compose.yaml'" {
		t.Fatalf("composeCmd = %q", got)
	}
	if composeCmd("||") != "" {
		t.Fatal("composeCmd of a container docker compose did not start")
	}
}
