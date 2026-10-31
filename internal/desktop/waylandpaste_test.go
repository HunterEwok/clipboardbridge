// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build linux || freebsd

package desktop

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/HunterEwok/clipboardbridge/internal/connector"
)

// TestWaylandPaste pastes and types into foot, a Wayland terminal that
// writes what it gets to a file, under a compositor with virtual keyboards
// such as a headless sway. It runs only when CBB_TEST_WAYLAND is set and
// foot is installed.
func TestWaylandPaste(t *testing.T) {
	if os.Getenv("CBB_TEST_WAYLAND") == "" {
		t.Skip("set CBB_TEST_WAYLAND in a session with a compositor with virtual keyboards and foot")
	}
	if _, err := exec.LookPath("foot"); err != nil {
		t.Skip("foot is not installed")
	}
	w, err := OpenWayland(t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if w.Target() != "desktop" {
		t.Fatalf("Target = %q: the compositor has no virtual keyboards", w.Target())
	}
	out := filepath.Join(t.TempDir(), "out")
	foot := exec.Command("foot", "sh", "-c", `stty -echo; echo ready >"$1.ready"; exec cat >"$1"`, "sh", out)
	foot.Env = append(os.Environ(), "LC_ALL=C.UTF-8")
	if err := foot.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { foot.Process.Kill(); foot.Wait() }()
	for range 100 {
		if _, err := os.Stat(out + ".ready"); err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	time.Sleep(300 * time.Millisecond) // the window takes the focus

	if err := w.Write("there before", false); err != nil {
		t.Fatal(err)
	}
	// The test's session is none that logind knows: the paste goes in as
	// on a device whose user allowed that.
	ctx := connector.WithoutLockCheck(context.Background(), true)
	if err := w.Inject(ctx, "pasted é αβγ€", "paste", true, false); err != nil {
		t.Fatal(err)
	}
	if it, ok, _ := w.Current(); !ok || it.Text != "there before" {
		t.Errorf("the clipboard after a paste holds %+v, %v", it, ok)
	}
	// More different characters than one keymap holds.
	var long strings.Builder
	for r := rune(0x4e00); r < 0x4e00+keysPerMap+50; r++ {
		long.WriteRune(r)
	}
	if err := w.Inject(ctx, "typed Text: é αβγ€ & ~|\tend "+long.String(), "type", true, false); err != nil {
		t.Fatal(err)
	}
	if err := w.Inject(ctx, "a secret", "paste", true, true); err != nil {
		t.Fatal(err)
	}
	want := "pasted é αβγ€\ntyped Text: é αβγ€ & ~|\tend " + long.String() + "\na secret\n"
	var got []byte
	for range 50 {
		if got, _ = os.ReadFile(out); string(got) == want {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if string(got) != want {
		t.Errorf("foot got %q, want %q", got, want)
	}
}
