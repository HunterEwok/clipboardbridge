// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/HunterEwok/clipboardbridge/internal/control"
	"github.com/HunterEwok/clipboardbridge/internal/node"
	"github.com/HunterEwok/clipboardbridge/internal/tunnel"
)

func tunnelState(t *testing.T, s *testService) *tunnel.State {
	t.Helper()
	st, err := tunnel.LoadState(s.dir)
	if err != nil {
		t.Fatal(err)
	}
	return st
}

// turnTunnelOn writes a tunnel state, as cbb will when the user turns sync
// away from home on.
func turnTunnelOn(t *testing.T, s *testService) {
	t.Helper()
	st, err := tunnel.NewState()
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Save(s.dir); err != nil {
		t.Fatal(err)
	}
}

// TestTunnelKeys checks that the hub admits the tunnel key of each member
// it meets, that each member keeps the hub's offer with the same preshared
// key, and that the hub drops a member the group removes.
func TestTunnelKeys(t *testing.T) {
	var h hub
	pi := startService(t, &h, "pi")
	deck := startService(t, &h, "deck")
	mac := startRole(t, &h, "mac", node.Mac)
	for _, s := range []*testService{pi, deck, mac} {
		turnTunnelOn(t, s)
	}
	pairWith(t, pi, deck)
	pairWith(t, pi, mac)

	// Make the pi the hub, as cbb will when the user turns it on.
	pi.stop()
	st := tunnelState(t, pi)
	if st.Group == "" {
		t.Fatal("the tunnel state names no group")
	}
	st.IsHub = true
	if err := st.Save(pi.dir); err != nil {
		t.Fatal(err)
	}
	pi = restartService(t, &h, pi)
	piID := pi.status(t).Device
	hubKey := st.Key.Public()

	for _, s := range []*testService{deck, mac} {
		waitFor(t, s.name+" keeps the hub's offer", func() bool {
			got := tunnelState(t, s).ToHub
			return got != nil && got.Device == piID
		})
		mine := tunnelState(t, s)
		if mine.ToHub.PublicKey != hubKey {
			t.Errorf("%s keeps hub key %x, want %x", s.name, mine.ToHub.PublicKey, hubKey)
		}
		dev := s.status(t).Device
		var found bool
		for _, m := range tunnelState(t, pi).Members {
			if m.Device == dev {
				found = true
				if m.PublicKey != mine.Key.Public() || m.PresharedKey != mine.ToHub.PresharedKey {
					t.Errorf("the hub keeps %s with other keys", s.name)
				}
			}
		}
		if !found {
			t.Errorf("the hub does not keep %s", s.name)
		}
	}
	if n := len(tunnelState(t, pi).Members); n != 2 {
		t.Errorf("the hub keeps %d members, want 2", n)
	}
	if tunnelState(t, pi).ToHub != nil {
		t.Error("the hub keeps an offer of its own")
	}

	// Removing the Mac drops it from the hub.
	macID := mac.status(t).Device
	if _, err := deck.do(t, control.Header{Op: control.OpRevoke, Name: "mac"}, ""); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the hub drops the Mac", func() bool {
		for _, m := range tunnelState(t, pi).Members {
			if m.Device == macID {
				return false
			}
		}
		return true
	})
}

// TestTunnelOffByDefault checks that a member where sync away from home is
// off offers no key and makes no tunnel state, even when the group has a
// hub.
func TestTunnelOffByDefault(t *testing.T) {
	var h hub
	pi := startService(t, &h, "pi")
	deck := startService(t, &h, "deck")
	turnTunnelOn(t, pi)
	pairWith(t, pi, deck)

	pi.stop()
	st := tunnelState(t, pi)
	st.IsHub = true
	if err := st.Save(pi.dir); err != nil {
		t.Fatal(err)
	}
	pi = restartService(t, &h, pi)
	waitFor(t, "the hub meets the deck", func() bool { return len(pi.status(t).Peers) > 0 })

	if n := len(tunnelState(t, pi).Members); n != 0 {
		t.Errorf("the hub keeps %d members, want none", n)
	}
	if _, err := os.Stat(filepath.Join(deck.dir, tunnel.StateFile)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the deck made a tunnel state: %v", err)
	}
}
