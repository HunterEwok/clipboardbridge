// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build linux

package desktop

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TestWayland runs against a real compositor with data-control, such as a
// headless sway, and checks the connector's view against wl-clipboard. It
// runs only when CLIPBRIDGE_TEST_WAYLAND is set, for example in a
// container.
func TestWayland(t *testing.T) {
	if os.Getenv("CLIPBRIDGE_TEST_WAYLAND") == "" {
		t.Skip("set CLIPBRIDGE_TEST_WAYLAND in a session with a data-control compositor and wl-clipboard")
	}
	w, err := OpenWayland(t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// wl-copy forks a child that serves the selection; its output is not
	// captured, or the pipes would stay open.
	wlCopy := func(text string) {
		t.Helper()
		if err := exec.Command("wl-copy", text).Run(); err != nil {
			t.Fatalf("wl-copy: %v", err)
		}
	}
	// Another program copies: the connector sees it.
	wlCopy("copied by wl-copy")
	it, ok, err := w.Next(ctx)
	if err != nil || !ok || it.Text != "copied by wl-copy" || it.Secret {
		t.Fatalf("Next = %+v, %v, %v", it, ok, err)
	}

	// The connector writes: other programs paste it, from the clipboard and
	// from the primary selection, and the write does not come back as a
	// change.
	text := "written by clipbridge привет\nline two"
	if err := w.Write(text, false); err != nil {
		t.Fatal(err)
	}
	paste := func(args ...string) string {
		out, err := exec.Command("wl-paste", append([]string{"--no-newline"}, args...)...).Output()
		if err != nil {
			t.Fatalf("wl-paste %v: %v", args, err)
		}
		return string(out)
	}
	if got := paste(); got != text {
		t.Errorf("wl-paste = %q, want %q", got, text)
	}
	if got := paste("--primary"); got != text {
		t.Errorf("wl-paste --primary = %q", got)
	}
	types := paste("--list-types")
	if !strings.Contains(types, "text/plain;charset=utf-8") || !strings.Contains(types, "UTF8_STRING") {
		t.Errorf("offered types:\n%s", types)
	}
	select {
	case it := <-w.changes:
		t.Errorf("our own write came back as a change: %+v", it)
	case <-time.After(500 * time.Millisecond):
	}

	// A secret carries the hint, so clipboard managers skip it.
	if err := w.Write("hunter2", true); err != nil {
		t.Fatal(err)
	}
	if types := paste("--list-types"); !strings.Contains(types, "x-kde-passwordManagerHint") {
		t.Errorf("a secret offered only:\n%s", types)
	}
	// Giving up an expired secret empties the clipboard.
	if err := w.ClearIfUnchanged(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	if out, err := exec.Command("wl-paste", "--no-newline").Output(); err == nil && string(out) == "hunter2" {
		t.Error("the secret is still in the clipboard")
	}

	// A copy after ours is seen again.
	wlCopy("after the secret")
	it, ok, err = w.Next(ctx)
	if err != nil || !ok || it.Text != "after the secret" {
		t.Fatalf("Next = %+v, %v, %v", it, ok, err)
	}
	if cur, ok, _ := w.Current(); !ok || cur.Text != "after the secret" {
		t.Errorf("Current = %+v, %v", cur, ok)
	}
}
