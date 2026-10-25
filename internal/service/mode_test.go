// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/HunterEwok/clipboardbridge/internal/control"
	"github.com/HunterEwok/clipboardbridge/internal/group"
)

func TestSyncModes(t *testing.T) {
	var h hub
	newDevice := func(c *Config) { c.newMode = nil } // as outside the tests: own
	a := startWith(t, &h, "alpha", group.OSLinux, newDevice)
	b := startWith(t, &h, "beta", group.OSLinux, newDevice)
	if _, err := a.do(t, control.Header{Op: control.OpMode, Name: "shared"}, ""); err == nil {
		t.Error("a device in no group took a sync mode")
	}
	pairWith(t, a, b)
	for _, s := range []*testService{a, b} {
		if m := s.status(t).Mode; m != "own" {
			t.Fatalf("%s: a new device's mode is %q, want own", s.name, m)
		}
	}
	waitFor(t, "a connected to b", func() bool { return len(a.status(t).Peers) == 1 })

	// A deliberate copy reaches the group in own mode, and cbb paste on
	// the other device prints the group's text.
	if _, err := a.do(t, control.Header{Op: control.OpCopy}, "from alpha"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "beta has the group's text", func() bool { return b.paste(t) == "from alpha" })

	if _, err := b.do(t, control.Header{Op: control.OpMode, Name: "everything"}, ""); err == nil {
		t.Error("an unknown mode was taken")
	}
	m, err := b.do(t, control.Header{Op: control.OpMode, Name: "receive"}, "")
	if err != nil || m.Status.Mode != "receive" {
		t.Fatalf("mode receive: %v, %+v", err, m)
	}
	// The mode is saved, and the others see it in the hello after a restart.
	b.stop()
	b = restartService(t, &h, b)
	if m := b.status(t).Mode; m != "receive" {
		t.Fatalf("after a restart the mode is %q", m)
	}
	waitFor(t, "alpha sees beta's mode", func() bool {
		for _, d := range a.devices(t) {
			if d.Name == "beta" && d.Mode == "receive" {
				return true
			}
		}
		return false
	})
	for _, d := range b.devices(t) {
		if d.Self && d.Mode != "receive" {
			t.Errorf("beta lists its own mode as %q", d.Mode)
		}
	}

	// A device that joined before sync modes has no mode file and keeps sharing.
	a.stop()
	if err := os.Remove(filepath.Join(a.dir, modeFile)); err != nil {
		t.Fatal(err)
	}
	a = restartService(t, &h, a)
	if m := a.status(t).Mode; m != "shared" {
		t.Fatalf("without a mode file the mode is %q, want shared", m)
	}
}
