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
	oldLinux, oldUnit, oldDropIn, oldEuid, oldCtl := onLinux, serviceUnit, awayDropIn, euid, systemctl
	t.Cleanup(func() {
		onLinux, serviceUnit, awayDropIn, euid, systemctl = oldLinux, oldUnit, oldDropIn, oldEuid, oldCtl
	})
	onLinux, serviceUnit, awayDropIn = true, unit, filepath.Join(dir, "clipboardbridge.service.d", "away.conf")
	euid = func() int {
		if root {
			return 0
		}
		return 1000
	}
	systemctl = func(args ...string) error {
		calls = append(calls, strings.Join(args, " "))
		return nil
	}
	return &calls
}

func TestAwayNet(t *testing.T) {
	calls := fakeUnit(t, true)
	if err := checkAwayNet(true); err != nil {
		t.Fatal(err)
	}
	changed, err := setAwayNet(true)
	if err != nil || !changed {
		t.Fatalf("on: changed %v, %v", changed, err)
	}
	data, err := os.ReadFile(awayDropIn)
	if err != nil || !strings.Contains(string(data), "IPAddressAllow=any") {
		t.Fatalf("drop-in %q, %v", data, err)
	}
	if want := []string{"daemon-reload", "restart clipboardbridge.service"}; !slices.Equal(*calls, want) {
		t.Fatalf("systemctl %q, want %q", *calls, want)
	}
	if changed, err := setAwayNet(true); err != nil || changed {
		t.Fatalf("on again: changed %v, %v", changed, err)
	}
	if changed, err := setAwayNet(false); err != nil || !changed {
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
	if _, err := setAwayNet(true); !errors.Is(err, errNeedRoot) {
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
	if changed, err := setAwayNet(true); err != nil || changed || len(*calls) != 0 {
		t.Fatalf("changed %v, %v, systemctl %q", changed, err, *calls)
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
