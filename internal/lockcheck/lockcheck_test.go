// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build linux || freebsd

package lockcheck

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// TestLockerRuns checks that a running swaylock counts as a locked screen.
func TestLockerRuns(t *testing.T) {
	sleep, err := exec.LookPath("sleep")
	if err != nil {
		t.Skip("no sleep")
	}
	t.Setenv("XDG_SESSION_ID", "")
	if why := Reason(); why != "" {
		t.Skipf("this machine looks locked already: %s", why)
	}
	bin, err := os.ReadFile(sleep)
	if err != nil {
		t.Fatal(err)
	}
	locker := filepath.Join(t.TempDir(), "swaylock")
	if err := os.WriteFile(locker, bin, 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(locker, "30")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cmd.Process.Kill(); cmd.Wait() }()
	time.Sleep(100 * time.Millisecond)
	if why := Reason(); why != "the screen is locked (swaylock runs)" {
		t.Errorf("with swaylock running: %q", why)
	}
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
