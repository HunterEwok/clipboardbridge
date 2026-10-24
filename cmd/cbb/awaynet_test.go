// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// fakeUnit points the away drop-in at a temporary unit and records the
// systemctl calls.
func fakeUnit(t *testing.T, root bool) *[]string {
	t.Helper()
	dir := t.TempDir()
	unit := filepath.Join(dir, "clipboardbridge.service")
	if err := os.WriteFile(unit, []byte("[Service]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var calls []string
	fakeLimit(t, &linuxLimit, root)
	oldUnit, oldDropIn, oldCtl := serviceUnit, awayDropIn, systemctl
	t.Cleanup(func() { serviceUnit, awayDropIn, systemctl = oldUnit, oldDropIn, oldCtl })
	serviceUnit, awayDropIn = unit, filepath.Join(dir, "clipboardbridge.service.d", "away.conf")
	systemctl = func(args ...string) error {
		calls = append(calls, strings.Join(args, " "))
		return nil
	}
	return &calls
}

// fakeLimit makes l this computer's limit, with or without privileges.
func fakeLimit(t *testing.T, l *netLimit, root bool) {
	t.Helper()
	oldLimit, oldElevated := limit, elevated
	t.Cleanup(func() { limit, elevated = oldLimit, oldElevated })
	limit, elevated = l, func() bool { return root }
}

func TestAwayNet(t *testing.T) {
	calls := fakeUnit(t, true)
	if err := checkAwayNet(true); err != nil {
		t.Fatal(err)
	}
	changed, restarted, err := setAwayNet(true)
	if err != nil || !changed || !restarted {
		t.Fatalf("on: changed %v, restarted %v, %v", changed, restarted, err)
	}
	data, err := os.ReadFile(awayDropIn)
	if err != nil || !strings.Contains(string(data), "IPAddressAllow=any") {
		t.Fatalf("drop-in %q, %v", data, err)
	}
	if want := []string{"daemon-reload", "restart clipboardbridge.service"}; !slices.Equal(*calls, want) {
		t.Fatalf("systemctl %q, want %q", *calls, want)
	}
	if changed, _, err := setAwayNet(true); err != nil || changed {
		t.Fatalf("on again: changed %v, %v", changed, err)
	}
	if changed, _, err := setAwayNet(false); err != nil || !changed {
		t.Fatalf("off: changed %v, %v", changed, err)
	}
	if _, err := os.Stat(awayDropIn); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the drop-in is still there: %v", err)
	}
	if len(*calls) != 4 {
		t.Fatalf("systemctl %q", *calls)
	}
}

func TestAwayNetNeedsRoot(t *testing.T) {
	calls := fakeUnit(t, false)
	if err := checkAwayNet(true); !errors.Is(err, errNeedRoot) {
		t.Fatalf("on without root: %v", err)
	}
	if err := checkAwayNet(false); err != nil {
		t.Fatalf("off without root, nothing to close: %v", err)
	}
	if _, _, err := setAwayNet(true); !errors.Is(err, errNeedRoot) {
		t.Fatalf("on without root: %v", err)
	}
	if _, err := os.Stat(awayDropIn); !errors.Is(err, os.ErrNotExist) || len(*calls) != 0 {
		t.Fatalf("something changed: %v, systemctl %q", err, *calls)
	}
}

func TestAwayNetNotConfined(t *testing.T) {
	calls := fakeUnit(t, false)
	serviceUnit = filepath.Join(t.TempDir(), "missing.service")
	if err := checkAwayNet(true); err != nil {
		t.Fatal(err)
	}
	if changed, _, err := setAwayNet(true); err != nil || changed || len(*calls) != 0 {
		t.Fatalf("changed %v, %v, systemctl %q", changed, err, *calls)
	}
	limit = nil // a system without a limit
	if confined() || awayNetOpen() || checkAwayNet(true) != nil {
		t.Fatal("no limit, yet confined")
	}
}

// On a Mac the mark tells pf.sh to load the anchor without the rules for
// the home network; nothing restarts.
func TestAwayNetMac(t *testing.T) {
	fakeLimit(t, &macLimit, true)
	dir := t.TempDir()
	oldScript, oldMark, oldSh := pfScript, awayMark, sh
	t.Cleanup(func() { pfScript, awayMark, sh = oldScript, oldMark, oldSh })
	pfScript, awayMark = filepath.Join(dir, "pf.sh"), filepath.Join(dir, "etc", "away")
	var calls []string
	sh = func(args ...string) error {
		calls = append(calls, strings.Join(args, " "))
		return nil
	}
	if confined() {
		t.Fatal("confined without pf.sh")
	}
	if err := os.WriteFile(pfScript, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	changed, restarted, err := setAwayNet(true)
	if err != nil || !changed || restarted || !awayNetOpen() {
		t.Fatalf("on: changed %v, restarted %v, open %v, %v", changed, restarted, awayNetOpen(), err)
	}
	if changed, _, err := setAwayNet(false); err != nil || !changed || awayNetOpen() {
		t.Fatalf("off: changed %v, open %v, %v", changed, awayNetOpen(), err)
	}
	if want := []string{pfScript + " load", pfScript + " load"}; !slices.Equal(calls, want) {
		t.Fatalf("sh %q, want %q", calls, want)
	}
}

// On Windows the firewall rule's state is the limit.
func TestAwayNetWindows(t *testing.T) {
	fakeLimit(t, &windowsLimit, false)
	oldPS := powershell
	t.Cleanup(func() { powershell = oldPS })
	state := "none"
	var sets []string
	powershell = func(script string) (string, error) {
		if strings.HasPrefix(script, "Set-NetFirewallRule") {
			sets = append(sets, script)
			state = map[bool]string{true: "False", false: "True"}[strings.Contains(script, "-Enabled False")]
			return "", nil
		}
		if state == "error" {
			return "", errors.New("access denied")
		}
		return state, nil
	}
	if confined() || checkAwayNet(true) != nil {
		t.Fatal("confined without the rule")
	}
	state = "True"
	if err := checkAwayNet(true); !errors.Is(err, errNeedRoot) {
		t.Fatalf("on without an administrator: %v", err)
	}
	state = "error" // a lookup that fails asks for an administrator
	if err := checkAwayNet(true); !errors.Is(err, errNeedRoot) {
		t.Fatalf("on after a failed lookup: %v", err)
	}
	state = "True"
	elevated = func() bool { return true }
	changed, restarted, err := setAwayNet(true)
	if err != nil || !changed || restarted || !awayNetOpen() {
		t.Fatalf("on: changed %v, restarted %v, open %v, %v", changed, restarted, awayNetOpen(), err)
	}
	if changed, _, err := setAwayNet(false); err != nil || !changed || awayNetOpen() {
		t.Fatalf("off: changed %v, %v", changed, err)
	}
	if len(sets) != 2 || !strings.Contains(sets[0], firewallRule) {
		t.Fatalf("Set-NetFirewallRule %q", sets)
	}
}

func TestResolveAddrPort(t *testing.T) {
	var out strings.Builder
	for in, want := range map[string]string{
		"203.0.113.9:8764":   "203.0.113.9:8764",
		"[2001:db8::1]:8764": "[2001:db8::1]:8764",
	} {
		got, err := resolveAddrPort(in, &out)
		if err != nil || got != want {
			t.Errorf("resolveAddrPort(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	// A name; some systems know localhost only as ::1.
	if got, err := resolveAddrPort("localhost:8764", &out); err != nil || (got != "127.0.0.1:8764" && got != "[::1]:8764") {
		t.Errorf("resolveAddrPort(localhost:8764) = %q, %v", got, err)
	}
	for _, in := range []string{"cbb.tools", ":8764", "203.0.113.9"} {
		if got, err := resolveAddrPort(in, &out); err == nil {
			t.Errorf("resolveAddrPort(%q) = %q, want an error", in, got)
		}
	}
}
