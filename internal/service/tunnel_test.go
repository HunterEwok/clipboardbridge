// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

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

// TestAwayFromHome turns sync away from home on, makes the pi the hub, and
// checks that the deck, once on another network, syncs with it through the
// tunnel, and that turning it off forgets the keys.
func TestAwayFromHome(t *testing.T) {
	t.Setenv("CBB_DEBUG", "1") // WireGuard's messages in the log, if it fails
	var h hub
	pi := startService(t, &h, "pi")
	deck := startService(t, &h, "deck")
	pairWith(t, pi, deck)

	if _, err := deck.do(t, control.Header{Op: control.OpAway, Name: "on"}, ""); err == nil || !strings.Contains(err.Error(), "consent") {
		t.Errorf("away on without consent: %v", err)
	}
	if _, err := pi.do(t, control.Header{Op: control.OpAway, Name: "hub", Addrs: []string{"127.0.0.1:1"}}, ""); err == nil {
		t.Error("a hub while sync away from home is off")
	}
	for _, s := range []*testService{pi, deck} {
		if _, err := s.do(t, control.Header{Op: control.OpAway, Name: "on", Consent: true}, ""); err != nil {
			t.Fatal(err)
		}
	}
	port := freeUDP(t)
	m, err := pi.do(t, control.Header{Op: control.OpAway, Name: "hub", Port: port, Addrs: []string{fmt.Sprintf("127.0.0.1:%d", port)}}, "")
	if err != nil {
		t.Fatal(err)
	}
	if a := m.Status.Away; a == nil || !a.Hub || a.Port != port || a.Error != "" {
		t.Fatalf("the hub's status: %+v", a)
	}
	piID := pi.status(t).Device
	waitFor(t, "the deck keeps the hub's offer", func() bool {
		a := deck.status(t).Away
		return a != nil && a.HubDevice == piID
	})

	// The deck leaves the home network: it reaches the pi only through
	// the tunnel.
	deckID := deck.status(t).Device
	deck.stop()
	h.hide(deckID)
	deck = restartService(t, &h, deck)
	// A first WireGuard handshake that is lost is sent again after the
	// rekey timeout of 5 s, and the TCP connection inside waits for it with
	// its own backoff; on Windows CI that has taken more than 10 s.
	waitUpTo(t, 30*time.Second, "the deck reaches the hub through the tunnel", func() bool {
		st := deck.status(t)
		return st.Away != nil && st.Away.Through && len(st.Peers) == 1 && st.Peers[0].ID == piID
	})
	if _, err := deck.do(t, control.Header{Op: control.OpCopy}, "from far away"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the pi has it", func() bool { return pi.paste(t) == "from far away" })
	if _, err := pi.do(t, control.Header{Op: control.OpCopy}, "from home"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the deck has it", func() bool { return deck.paste(t) == "from home" })

	// Off: the keys are gone and the deck no longer reaches the pi.
	m, err = deck.do(t, control.Header{Op: control.OpAway, Name: "off"}, "")
	if err != nil {
		t.Fatal(err)
	}
	if m.Status.Away != nil {
		t.Errorf("away is still on: %+v", m.Status.Away)
	}
	if _, err := os.Stat(filepath.Join(deck.dir, tunnel.StateFile)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the tunnel state is still there: %v", err)
	}
	waitFor(t, "the deck is alone", func() bool { return len(deck.status(t).Peers) == 0 })
}

func freeUDP(t *testing.T) int {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).Port
}

// TestJoinByAddress checks that a device that joined at an address, as
// through an SSH forward or a VPN, keeps a member connection to the member
// that admitted it although discovery cannot find it, and so meets the hub
// and learns its offer when sync away from home is turned on.
func TestJoinByAddress(t *testing.T) {
	var h hub
	pi := startService(t, &h, "pi")
	deck := startService(t, &h, "deck")
	c, code := openWindow(t, pi)
	defer c.Close()
	piID := pi.status(t).Device
	h.hide(piID) // the deck is on another network
	addr := ""
	h.mu.Lock()
	for m := range h.members {
		if m.cfg.ID == piID {
			addr = net.JoinHostPort("127.0.0.1", strconv.Itoa(int(m.cfg.Port)))
		}
	}
	h.mu.Unlock()
	if _, err := deck.do(t, control.Header{Op: control.OpJoin, Code: code, Address: addr}, ""); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the deck connects to the pi where it joined", func() bool {
		p := deck.status(t).Peers
		return len(p) == 1 && p[0].ID == piID
	})
	if _, err := deck.do(t, control.Header{Op: control.OpCopy}, "from the deck"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the pi has it", func() bool { return pi.paste(t) == "from the deck" })

	for _, s := range []*testService{pi, deck} {
		if _, err := s.do(t, control.Header{Op: control.OpAway, Name: "on", Consent: true}, ""); err != nil {
			t.Fatal(err)
		}
	}
	port := freeUDP(t)
	if _, err := pi.do(t, control.Header{Op: control.OpAway, Name: "hub", Port: port, Addrs: []string{fmt.Sprintf("127.0.0.1:%d", port)}}, ""); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the deck keeps the hub's offer", func() bool {
		a := deck.status(t).Away
		return a != nil && a.HubDevice == piID
	})
}
