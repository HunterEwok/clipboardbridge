// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build linux || freebsd

package lockcheck

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

// TestLockerRuns checks that a running swaylock counts as a locked screen,
// as this user's and as anyone's, and another user's only with anyUser.
func TestLockerRuns(t *testing.T) {
	t.Setenv("XDG_SESSION_ID", "")
	uid := uint32(os.Getuid())
	list := []process{{name: "sh", uid: uid}}
	t.Cleanup(func() { running = processes })
	running = func() []process { return list }
	if why := Reason(true); why != "" {
		t.Skipf("this machine looks locked already: %s", why)
	}
	list = append(list, process{name: "swaylock", uid: uid + 1})
	if got := Locker(false); got != "" {
		t.Errorf("another user's swaylock as this user's: %q", got)
	}
	if got := Locker(true); got != "swaylock" {
		t.Errorf("another user's swaylock with anyUser: %q", got)
	}
	list = append(list, process{name: "swaylock", uid: uid})
	if why := Reason(true); why != "the screen is locked (swaylock runs)" {
		t.Errorf("with swaylock running: %q", why)
	}
}

// TestProcesses checks that the process list holds a process this test
// starts, under its command name and this user, as Locker finds lockers.
// The process has a name no locker has, so that the tests of other
// packages running at the same time see no locked screen.
func TestProcesses(t *testing.T) {
	sleep, err := exec.LookPath("sleep")
	if err != nil {
		t.Skip("no sleep")
	}
	bin, err := os.ReadFile(sleep)
	if err != nil {
		t.Fatal(err)
	}
	name := "cbbtestproc"
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, bin, 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(path, "30")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cmd.Process.Kill(); cmd.Wait() }()
	want := process{name: name, uid: uint32(os.Getuid())}
	for range 50 {
		if slices.Contains(processes(), want) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Errorf("%+v is not among the running processes", want)
}

// TestSessionID checks that a process started outside a session, as a
// user service is, still asks logind about its user's session.
func TestSessionID(t *testing.T) {
	t.Setenv("XDG_SESSION_ID", "")
	if got := sessionID(); got != "auto" {
		t.Errorf("without XDG_SESSION_ID: %q", got)
	}
	t.Setenv("XDG_SESSION_ID", "c2")
	if got := sessionID(); got != "c2" {
		t.Errorf("with XDG_SESSION_ID: %q", got)
	}
}

// TestUnknownLockState checks that a target pastes only where logind says
// the session is not locked, unless its user allowed pastes without the
// check: without loginctl, when it fails, and when it says nothing.
func TestUnknownLockState(t *testing.T) {
	t.Cleanup(func() { running = processes })
	running = func() []process { return nil }
	dir := t.TempDir()
	t.Setenv("PATH", dir)
	t.Setenv("XDG_SESSION_ID", "c2")
	loginctl := func(script string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, "loginctl"), []byte("#!/bin/sh\n"+script+"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, c := range []struct {
		name, script string // "" leaves loginctl out
		want         string
		wantAllowed  string
	}{
		{"without loginctl", "", Unknown, ""},
		{"when loginctl fails", "exit 1", Unknown, ""},
		{"when loginctl says nothing", "exit 0", Unknown, ""},
		{"when the hint is neither yes nor no", "echo LockedHint=", Unknown, ""},
		{"when logind says unlocked", "echo LockedHint=no", "", ""},
		{"when logind says locked", "echo LockedHint=yes", "the session is locked", "the session is locked"},
	} {
		os.Remove(filepath.Join(dir, "loginctl"))
		if c.script != "" {
			loginctl(c.script)
		}
		if got := Reason(false); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
		if got := Reason(true); got != c.wantAllowed {
			t.Errorf("%s, without the check: %q, want %q", c.name, got, c.wantAllowed)
		}
	}
}
