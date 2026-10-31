// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

// TestTypeLater checks that a paste typed after its answer goes one at a
// time on a target and stops once it may no longer go on.
func TestTypeLater(t *testing.T) {
	defer func(d time.Duration) { typingCheck = d }(typingCheck)
	typingCheck = 10 * time.Millisecond
	s := &Service{logf: t.Logf}
	var allowed atomic.Bool
	allowed.Store(true)
	stopped := make(chan error, 1)
	typ := func(ctx context.Context) error {
		<-ctx.Done()
		stopped <- ctx.Err()
		return ctx.Err()
	}
	if !s.typeLater("kb", allowed.Load, typ) {
		t.Fatal("the first paste was refused")
	}
	if s.typeLater("kb", allowed.Load, typ) {
		t.Error("a second paste was taken while the first types")
	}
	if !s.typeLater("tv", allowed.Load, func(context.Context) error { return nil }) {
		t.Error("another target was refused")
	}
	allowed.Store(false) // remote paste off, or the signer removed
	select {
	case err := <-stopped:
		if err != context.Canceled {
			t.Errorf("typing ended with %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("typing went on after the paste may no longer go on")
	}
	deadline := time.Now().Add(5 * time.Second)
	for !s.typeLater("kb", func() bool { return true }, func(context.Context) error { return nil }) {
		if time.Now().After(deadline) {
			t.Fatal("the keyboard stays busy after typing stopped")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
