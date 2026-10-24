// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/HunterEwok/clipboardbridge/internal/control"
	"github.com/HunterEwok/clipboardbridge/internal/forward"
	"github.com/HunterEwok/clipboardbridge/internal/group"
	"github.com/HunterEwok/clipboardbridge/internal/relay"
	"github.com/HunterEwok/clipboardbridge/internal/tunnel"
)

func tunnelState(t *testing.T, s *testService) *tunnel.State {
	t.Helper()
	// On Windows a read fails for a moment while the service replaces the
	// file (a sharing violation), so a failed read is tried again.
	var err error
	for range 50 {
		var st *tunnel.State
		if st, err = tunnel.LoadState(s.dir); err == nil {
			return st
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal(err)
	return nil
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
	mac := startRole(t, &h, "mac", group.OSMacOS)
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
		// The members dial the restarted hub again with their backoff,
		// which a loaded machine stretches past 10 s.
		waitUpTo(t, 30*time.Second, s.name+" keeps the hub's offer", func() bool {
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

// TestAwayObfuscated makes the pi an obfuscated hub: the deck gets its
// AmneziaWG settings with the offer at home and syncs with it away, and
// setting the hub again keeps the settings.
func TestAwayObfuscated(t *testing.T) {
	t.Setenv("CBB_DEBUG", "1")
	var h hub
	pi := startService(t, &h, "pi")
	deck := startService(t, &h, "deck")
	pairWith(t, pi, deck)
	for _, s := range []*testService{pi, deck} {
		if _, err := s.do(t, control.Header{Op: control.OpAway, Name: "on", Consent: true}, ""); err != nil {
			t.Fatal(err)
		}
	}
	port := freeUDP(t)
	hubAt := control.Header{Op: control.OpAway, Name: "hub", Port: port, Addrs: []string{fmt.Sprintf("127.0.0.1:%d", port)}, Obfuscate: true}
	m, err := pi.do(t, hubAt, "")
	if err != nil {
		t.Fatal(err)
	}
	if a := m.Status.Away; a == nil || !a.Hub || !a.Obfuscated {
		t.Fatalf("the hub's status: %+v", a)
	}
	obf := tunnelState(t, pi).Obfuscation
	if obf == nil {
		t.Fatal("the hub keeps no obfuscation settings")
	}
	if _, err := pi.do(t, hubAt, ""); err != nil {
		t.Fatal(err)
	}
	if again := tunnelState(t, pi).Obfuscation; !again.Equal(obf) {
		t.Error("setting the hub again made new obfuscation settings")
	}
	piID := pi.status(t).Device
	waitFor(t, "the deck keeps the hub's offer with its settings", func() bool {
		a := deck.status(t).Away
		return a != nil && a.HubDevice == piID && a.Obfuscated
	})
	if got := tunnelState(t, deck).ToHub.Obfuscation; !got.Equal(obf) {
		t.Fatalf("the deck keeps %+v, the hub has %+v", got, obf)
	}

	deckID := deck.status(t).Device
	deck.stop()
	h.hide(deckID)
	deck = restartService(t, &h, deck)
	waitUpTo(t, 30*time.Second, "the deck reaches the hub through the obfuscated tunnel", func() bool {
		st := deck.status(t)
		return st.Away != nil && st.Away.Through && len(st.Peers) == 1 && st.Peers[0].ID == piID
	})
	if _, err := deck.do(t, control.Header{Op: control.OpCopy}, "hidden on the way"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the pi has it", func() bool { return pi.paste(t) == "hidden on the way" })
}

// TestAwayThroughForwarder makes the pi a hub that only a forwarder
// reaches, as behind carrier-grade NAT, and checks that the deck syncs with
// it through the forwarder, with plain WireGuard and obfuscated.
func TestAwayThroughForwarder(t *testing.T) {
	t.Run("plain", func(t *testing.T) { testAwayThroughForwarder(t, false) })
	t.Run("obfuscated", func(t *testing.T) { testAwayThroughForwarder(t, true) })
}

func testAwayThroughForwarder(t *testing.T, obfuscate bool) {
	t.Setenv("CBB_DEBUG", "1")
	cert, err := forward.NewCert()
	if err != nil {
		t.Fatal(err)
	}
	f, err := forward.Listen(forward.Config{Listen: "127.0.0.1:0", Cert: cert, Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan struct{})
	go func() {
		defer close(served)
		f.Serve(ctx)
	}()
	defer func() {
		cancel()
		<-served
	}()

	var h hub
	pi := startService(t, &h, "pi")
	deck := startService(t, &h, "deck")
	pairWith(t, pi, deck)
	for _, s := range []*testService{pi, deck} {
		if _, err := s.do(t, control.Header{Op: control.OpAway, Name: "on", Consent: true}, ""); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := pi.do(t, control.Header{Op: control.OpAway, Name: "hub", Forwarder: f.Addr().String(), ForwarderKey: "sha256:nope"}, ""); err == nil {
		t.Error("a forwarder with a bad key")
	}
	if _, err := pi.do(t, control.Header{Op: control.OpAway, Name: "hub", Port: freeUDP(t), Forwarder: f.Addr().String(), ForwarderKey: forward.Pin(cert.Leaf),
		Obfuscate: obfuscate}, ""); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the hub registers with the forwarder", func() bool {
		a := pi.status(t).Away
		return a != nil && a.Forwarder != nil && a.Forwarder.Registered && a.Forwarder.Seen != ""
	})
	piID := pi.status(t).Device
	waitFor(t, "the deck keeps the hub's offer", func() bool {
		a := deck.status(t).Away
		return a != nil && a.HubDevice == piID && len(a.Endpoints) == 1 && a.Endpoints[0] == f.Addr().String() && a.Obfuscated == obfuscate
	})

	deckID := deck.status(t).Device
	deck.stop()
	h.hide(deckID)
	deck = restartService(t, &h, deck)
	waitUpTo(t, 30*time.Second, "the deck reaches the hub through the forwarder", func() bool {
		st := deck.status(t)
		return st.Away != nil && st.Away.Through && len(st.Peers) == 1 && st.Peers[0].ID == piID
	})
	if _, err := deck.do(t, control.Header{Op: control.OpCopy}, "via the forwarder"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the pi has it", func() bool { return pi.paste(t) == "via the forwarder" })
	if _, err := pi.do(t, control.Header{Op: control.OpCopy}, "back home"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the deck has it", func() bool { return deck.paste(t) == "back home" })
}

// TestAwayThroughRelay checks a group without a hub: both devices meet at a
// blind relay, and once one leaves the home network they sync through it.
func TestAwayThroughRelay(t *testing.T) {
	var h hub
	pi := startService(t, &h, "pi")
	deck := startService(t, &h, "deck")
	pairWith(t, pi, deck)
	keys, err := relay.NewKeys()
	if err != nil {
		t.Fatal(err)
	}
	r, err := relay.Listen(relay.Config{Listen: "127.0.0.1:0", Keys: keys, Groups: []string{pi.status(t).Group}, Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan struct{})
	go func() {
		defer close(served)
		r.Serve(ctx)
	}()
	defer func() {
		cancel()
		<-served
	}()

	if _, err := pi.do(t, control.Header{Op: control.OpAway, Name: "relay", Relay: r.Addr().String(), RelayKey: keys.Pin()}, ""); err == nil {
		t.Error("a relay before sync away from home is on")
	}
	for _, s := range []*testService{pi, deck} {
		if _, err := s.do(t, control.Header{Op: control.OpAway, Name: "on", Consent: true}, ""); err != nil {
			t.Fatal(err)
		}
		if _, err := s.do(t, control.Header{Op: control.OpAway, Name: "relay", Relay: r.Addr().String(), RelayKey: "sha256:nope"}, ""); err == nil {
			t.Error("a relay with a bad key")
		}
		if _, err := s.do(t, control.Header{Op: control.OpAway, Name: "relay", Relay: r.Addr().String(), RelayKey: keys.Pin()}, ""); err != nil {
			t.Fatal(err)
		}
	}
	piID, deckID := pi.status(t).Device, deck.status(t).Device
	waitFor(t, "both meet at the relay", func() bool {
		a, b := pi.status(t).Away, deck.status(t).Away
		return a != nil && a.Relay != nil && a.Relay.Connected && len(a.Relay.Online) == 1 && a.Relay.Online[0] == deckID &&
			b != nil && b.Relay != nil && b.Relay.Connected && len(b.Relay.Online) == 1 && b.Relay.Online[0] == piID
	})

	deck.stop()
	h.hide(deckID)
	deck = restartService(t, &h, deck)
	waitUpTo(t, 30*time.Second, "the deck reaches the pi through the relay", func() bool {
		st := deck.status(t)
		return st.Away != nil && st.Away.Through && len(st.Peers) == 1 && st.Peers[0].ID == piID
	})
	if _, err := deck.do(t, control.Header{Op: control.OpCopy}, "via the relay"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the pi has it", func() bool { return pi.paste(t) == "via the relay" })
	if _, err := pi.do(t, control.Header{Op: control.OpCopy}, "back home"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the deck has it", func() bool { return deck.paste(t) == "back home" })

	// Turning sync away from home off leaves the relay.
	if _, err := pi.do(t, control.Header{Op: control.OpAway, Name: "off"}, ""); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the relay drops the pi", func() bool {
		_, n := r.Stats()
		return n == 1
	})
}

// freeUDP returns a UDP port that is free on all addresses, as the hub
// listens. It picks it below the systems' ephemeral ranges (Linux from
// 32768, macOS and Windows from 49152): a port the kernel handed out and
// took back could go to a socket of another test package before the hub
// binds it.
func freeUDP(t *testing.T) int {
	t.Helper()
	for range 100 {
		port := 20000 + rand.IntN(10000)
		c, err := net.ListenUDP("udp4", &net.UDPAddr{Port: port})
		if err != nil {
			continue
		}
		c.Close()
		return port
	}
	t.Fatal("no free UDP port")
	return 0
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
	addr := h.memberAddr(t, piID)
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
