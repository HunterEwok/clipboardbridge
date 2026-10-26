// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/HunterEwok/clipboardbridge/internal/actions"
	"github.com/HunterEwok/clipboardbridge/internal/control"
)

// fakeRunner records the presets it ran, and refuses those in refuse.
type fakeRunner struct {
	mu     sync.Mutex
	ran    []string
	refuse map[string]string
}

func (r *fakeRunner) Run(_ context.Context, name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if reason, ok := r.refuse[name]; ok {
		return &actions.Refusal{Reason: reason}
	}
	r.ran = append(r.ran, name)
	return nil
}

func (r *fakeRunner) took() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.ran...)
}

func TestQuickActions(t *testing.T) {
	var h hub
	runner := &fakeRunner{refuse: map[string]string{actions.Sleep: "the session is locked"}}
	pi := startService(t, &h, "pi")
	deck := startWith(t, &h, "deck", "linux", func(c *Config) { c.runner = runner })
	pairWith(t, pi, deck)
	waitFor(t, "connected", func() bool { return len(pi.status(t).Peers) == 1 })
	run := func(name string) error {
		time.Sleep(time.Second) // one action a second from one sender
		_, err := pi.do(t, control.Header{Op: control.OpActionOn, Device: "deck", Name: name}, "")
		return err
	}
	set := func(a control.Action) {
		t.Helper()
		if _, err := deck.do(t, control.Header{Op: control.OpActionSet, Actions: []control.Action{a}}, ""); err != nil {
			t.Fatalf("setting %+v: %v", a, err)
		}
	}
	wantRefused := func(name, reason string) {
		t.Helper()
		if err := run(name); err == nil || !strings.Contains(err.Error(), reason) {
			t.Errorf("%s: %v, want %q", name, err, reason)
		}
	}

	wantRefused(actions.Lock, "the action lock is off on this device")
	wantRefused("format-disk", "this device has no action")
	set(control.Action{Name: actions.Lock, On: true})
	if err := run(actions.Lock); err != nil {
		t.Fatal(err)
	}
	set(control.Action{Name: actions.Lock, On: true, By: []string{actions.ByPhone}})
	wantRefused(actions.Lock, "only for phone")

	// pi's keys are in files: reboot takes it only with any key.
	set(control.Action{Name: actions.Reboot, On: true})
	wantRefused(actions.Reboot, "keys are in hardware")
	set(control.Action{Name: actions.Reboot, On: true, AnyKey: true})
	if err := run(actions.Reboot); err != nil {
		t.Fatal(err)
	}
	set(control.Action{Name: actions.Sleep, On: true})
	wantRefused(actions.Sleep, "the session is locked")
	if got := runner.took(); strings.Join(got, ",") != "lock,reboot" {
		t.Errorf("ran %v", got)
	}

	// A member that is not an admin runs none.
	if _, err := deck.do(t, control.Header{Op: control.OpActionOn, Device: "pi", Name: actions.Lock}, ""); err == nil || !strings.Contains(err.Error(), "only an admin") {
		t.Errorf("deck ran an action on pi: %v", err)
	}

	// The log keeps who asked and how it ended.
	log, err := actions.ReadLog(deck.dir)
	if err != nil || len(log) != 7 {
		t.Fatalf("the log: %+v, %v", log, err)
	}
	if e := log[2]; e.Action != actions.Lock || e.Result != "done" || e.Name != "pi" {
		t.Errorf("the lock's entry: %+v", e)
	}

	// Any admin turns them all off, and only deck's user on again.
	if _, err := pi.do(t, control.Header{Op: control.OpActionOff, Device: "deck"}, ""); err != nil {
		t.Fatal(err)
	}
	for _, a := range deck.status(t).Actions {
		if a.On {
			t.Errorf("%s is on after actions-off", a.Name)
		}
	}
	wantRefused(actions.Reboot, "is off on this device")

	// restart ends Run with ErrRestart, for the service manager.
	set(control.Action{Name: actions.Restart, On: true})
	if err := run(actions.Restart); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-deck.done:
		deck.cancel = nil
		if !errors.Is(err, ErrRestart) {
			t.Errorf("Run returned %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Error("deck did not restart")
	}
}

// TestQuickActionsInSession: on a Mac and on Windows the agent runs the
// presets in the user's session.
func TestQuickActionsInSession(t *testing.T) {
	var h hub
	pi := startService(t, &h, "pi")
	deck := startWith(t, &h, "deck", "linux", func(c *Config) { c.actInSession = true })
	pairWith(t, pi, deck)
	waitFor(t, "connected", func() bool { return len(pi.status(t).Peers) == 1 })
	for _, name := range []string{actions.Lock, actions.Sleep} {
		if _, err := deck.do(t, control.Header{Op: control.OpActionSet, Actions: []control.Action{{Name: name, On: true}}}, ""); err != nil {
			t.Fatal(err)
		}
	}
	run := func(name string) error {
		time.Sleep(time.Second) // one action a second from one sender
		_, err := pi.do(t, control.Header{Op: control.OpActionOn, Device: "deck", Name: name}, "")
		return err
	}
	if err := run(actions.Lock); err == nil || !strings.Contains(err.Error(), "nobody is signed in here") {
		t.Errorf("without an agent: %v", err)
	}
	w := deck.dial(t)
	defer w.Close()
	if _, err := w.Do(&control.Message{Header: control.Header{Op: control.OpWatch, Act: true}}); err != nil {
		t.Fatal(err)
	}
	got := make(chan string, 4)
	go func() {
		for {
			m, err := w.Receive()
			if err != nil {
				return
			}
			if m.Op != control.OpAct {
				continue
			}
			got <- m.Name
			ans := control.Header{Op: control.OpActed, Seq: m.Seq}
			if m.Name == actions.Sleep {
				ans.Error, ans.Refused = "the lid is closed", true
			}
			w.Send(&control.Message{Header: ans})
		}
	}()
	if err := run(actions.Lock); err != nil {
		t.Fatal(err)
	}
	if err := run(actions.Sleep); err == nil || !strings.Contains(err.Error(), "the lid is closed") {
		t.Errorf("sleep: %v", err)
	}
	if a, b := <-got, <-got; a != actions.Lock || b != actions.Sleep {
		t.Errorf("the agent got %s and %s", a, b)
	}
}
