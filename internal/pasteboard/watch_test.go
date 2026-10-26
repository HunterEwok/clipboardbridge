// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build (darwin && cgo) || windows

package pasteboard

import (
	"context"
	"testing"
	"time"
)

func TestWatch(t *testing.T) {
	b := private(t)
	w := NewWatch(b)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// The agent's own write is not reported as a change.
	if err := w.Write("from the group", false); err != nil {
		t.Fatal(err)
	}
	// Another program copies.
	go func() {
		time.Sleep(700 * time.Millisecond)
		b.Write("copied by the user", false)
	}()
	it, ok, err := w.Next(ctx)
	if err != nil || !ok || it.Text != "copied by the user" {
		t.Fatalf("Next = %+v, %v, %v", it, ok, err)
	}

	// An expired secret is given up only while it is still the agent's.
	if err := w.Write("secret", true); err != nil {
		t.Fatal(err)
	}
	if err := w.ClearIfUnchanged(); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := b.Read(); ok {
		t.Error("the expired secret stayed")
	}
	if err := w.Write("secret", true); err != nil {
		t.Fatal(err)
	}
	b.Write("the user's own copy", false)
	w.ClearIfUnchanged()
	if it, ok, _ := b.Read(); !ok || it.Text != "the user's own copy" {
		t.Errorf("the user's copy was cleared: %+v", it)
	}
}

// TestWatchHolds checks Holds, which a remote paste asks before it gives
// the clipboard its text back: true while the agent's write stands, false
// once another program copied.
func TestWatchHolds(t *testing.T) {
	b := private(t)
	w := NewWatch(b)
	if w.Holds("pasted") {
		t.Error("holds a text before any write")
	}
	if err := w.Write("pasted", false); err != nil {
		t.Fatal(err)
	}
	if !w.Holds("pasted") {
		t.Error("does not hold its own write")
	}
	b.Write("copied by the user", false)
	if w.Holds("pasted") {
		t.Error("holds its write after the user copied")
	}
}
