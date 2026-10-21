// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"context"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/HunterEwok/clipbridge/internal/control"
	"github.com/HunterEwok/clipbridge/internal/mdns"
	"github.com/HunterEwok/clipbridge/internal/node"
)

// hub is a fake network for discovery: every member sees the others on the
// loopback address.
type hub struct {
	mu      sync.Mutex
	members map[*fakeDiscovery]bool
}

type fakeDiscovery struct {
	h      *hub
	cfg    DiscoveryConfig
	mu     sync.Mutex
	txt    []string
	holder bool
}

func (h *hub) discover(c DiscoveryConfig) (Discovery, error) {
	return &fakeDiscovery{h: h, cfg: c, txt: slices.Clone(c.TXT)}, nil
}

func (d *fakeDiscovery) Run(ctx context.Context) error {
	d.h.mu.Lock()
	if d.h.members == nil {
		d.h.members = map[*fakeDiscovery]bool{}
	}
	d.h.members[d] = true
	d.h.mu.Unlock()
	d.h.update()
	<-ctx.Done()
	d.h.mu.Lock()
	delete(d.h.members, d)
	d.h.mu.Unlock()
	d.h.update()
	return nil
}

func (d *fakeDiscovery) SetTXT(txt []string) {
	d.mu.Lock()
	d.txt = slices.Clone(txt)
	d.mu.Unlock()
	d.h.update()
}

func (d *fakeDiscovery) SetHolder(hold bool) {
	d.mu.Lock()
	d.holder = hold
	d.mu.Unlock()
}

// update tells every member about the others.
func (h *hub) update() {
	h.mu.Lock()
	var all []mdns.Peer
	var members []*fakeDiscovery
	for m := range h.members {
		members = append(members, m)
		if m.cfg.BrowseOnly {
			continue
		}
		m.mu.Lock()
		all = append(all, mdns.Peer{ID: m.cfg.ID, Port: m.cfg.Port, TXT: slices.Clone(m.txt),
			Addrs: []netip.Addr{netip.MustParseAddr("127.0.0.1")}})
		m.mu.Unlock()
	}
	h.mu.Unlock()
	for _, m := range members {
		others := slices.DeleteFunc(slices.Clone(all), func(p mdns.Peer) bool { return p.ID == m.cfg.ID })
		go m.cfg.OnPeers(others)
	}
}

type testService struct {
	name   string
	dir    string
	role   node.Role
	socket string
	cancel context.CancelFunc
	done   chan error
}

func startService(t *testing.T, h *hub, name string) *testService {
	t.Helper()
	return startRole(t, h, name, node.Linux)
}

func startRole(t *testing.T, h *hub, name string, role node.Role) *testService {
	t.Helper()
	dir, err := os.MkdirTemp("", "cb")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return startIn(t, h, name, dir, role)
}

// restartService starts a stopped service again with its state.
func restartService(t *testing.T, h *hub, old *testService) *testService {
	t.Helper()
	return startIn(t, h, old.name, old.dir, old.role)
}

func startIn(t *testing.T, h *hub, name, dir string, role node.Role) *testService {
	t.Helper()
	s := &testService{name: name, dir: dir, role: role, socket: filepath.Join(dir, "c.sock"), done: make(chan error, 1)}
	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel
	cfg := Config{
		StateDir: dir, Socket: s.socket, Role: role, Name: name, Discover: h.discover,
		Logf:   func(f string, a ...any) { t.Logf(name+": "+f, a...) },
		listen: func() (net.Listener, error) { return net.Listen("tcp", "127.0.0.1:0") },
	}
	go func() { s.done <- Run(ctx, cfg) }()
	t.Cleanup(s.stop)
	// Wait for the control socket.
	deadline := time.Now().Add(5 * time.Second)
	for {
		if c, err := control.Dial(s.socket); err == nil {
			c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: the control socket never appeared", name)
		}
		time.Sleep(10 * time.Millisecond)
	}
	return s
}

func (s *testService) stop() {
	if s.cancel != nil {
		s.cancel()
		<-s.done
		s.cancel = nil
	}
}

func (s *testService) do(t *testing.T, h control.Header, payload string) (*control.Message, error) {
	t.Helper()
	c, err := control.Dial(s.socket)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return c.Do(&control.Message{Header: h, Payload: []byte(payload)})
}

func (s *testService) status(t *testing.T) *control.Status {
	t.Helper()
	m, err := s.do(t, control.Header{Op: control.OpStatus}, "")
	if err != nil {
		t.Fatal(err)
	}
	return m.Status
}

// pairWith opens a pairing window on admin and joins s through it, found
// by discovery.
func pairWith(t *testing.T, admin, s *testService) {
	t.Helper()
	c, err := control.Dial(admin.socket)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	m, err := c.Do(&control.Message{Header: control.Header{Op: control.OpPair}})
	if err != nil {
		t.Fatalf("pair on %s: %v", admin.name, err)
	}
	if _, err := s.do(t, control.Header{Op: control.OpJoin, Code: m.Code}, ""); err != nil {
		t.Fatalf("join on %s: %v", s.name, err)
	}
	m, err = c.Receive()
	if err != nil || m.Name != s.name {
		t.Fatalf("pair on %s ended with %+v, %v", admin.name, m, err)
	}
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestThreeMembers(t *testing.T) {
	var h hub
	a := startService(t, &h, "alpha")
	b := startService(t, &h, "beta")
	c := startService(t, &h, "gamma")
	if st := a.status(t); st.Group != "" {
		t.Fatalf("a new service is in a group: %+v", st)
	}
	if _, err := a.do(t, control.Header{Op: control.OpPaste}, ""); err == nil || !strings.Contains(err.Error(), "no group") {
		t.Errorf("paste in no group: %v", err)
	}
	pairWith(t, a, b) // creates the group on alpha
	pairWith(t, b, c) // any Linux member can admit
	group := a.status(t).Group
	for _, s := range []*testService{b, c} {
		if g := s.status(t).Group; g != group {
			t.Fatalf("%s is in group %q, want %q", s.name, g, group)
		}
	}
	for _, s := range []*testService{a, b, c} {
		waitFor(t, s.name+" connected to both others", func() bool { return len(s.status(t).Peers) == 2 })
	}
	// One copy reaches every member's own clipboard.
	if _, err := a.do(t, control.Header{Op: control.OpCopy}, "from alpha"); err != nil {
		t.Fatal(err)
	}
	for _, s := range []*testService{a, b, c} {
		waitFor(t, s.name+" has the text", func() bool {
			m, err := s.do(t, control.Header{Op: control.OpPaste}, "")
			return err == nil && string(m.Payload) == "from alpha"
		})
	}
	// Exactly one member holds clipbridge.local: the lowest device ID.
	holders := func() []string {
		var out []string
		for _, s := range []*testService{a, b, c} {
			if s.cancel != nil && s.status(t).Holder {
				out = append(out, s.name)
			}
		}
		return out
	}
	waitFor(t, "one holder", func() bool { return len(holders()) == 1 })
	lowest := a
	for _, s := range []*testService{b, c} {
		if s.status(t).Device < lowest.status(t).Device {
			lowest = s
		}
	}
	if got := holders(); got[0] != lowest.name {
		t.Errorf("holder %v, want %s", got, lowest.name)
	}
	// When it leaves, another takes over.
	lowest.stop()
	waitFor(t, "a new holder", func() bool {
		hs := holders()
		return len(hs) == 1 && hs[0] != lowest.name
	})
}

func TestWatcher(t *testing.T) {
	var h hub
	a := startService(t, &h, "alpha")
	b := startService(t, &h, "beta")
	pairWith(t, a, b)
	waitFor(t, "connected", func() bool { return len(a.status(t).Peers) == 1 })
	// A desktop connector on b watches its clipboard.
	w, err := control.Dial(b.socket)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if _, err := w.Do(&control.Message{Header: control.Header{Op: control.OpWatch}}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.do(t, control.Header{Op: control.OpCopy}, "for the desktop"); err != nil {
		t.Fatal(err)
	}
	m, err := w.Receive()
	if err != nil || m.Op != control.OpWrite || string(m.Payload) != "for the desktop" || m.Seq == 0 {
		t.Fatalf("watcher got %+v, %v", m, err)
	}
	// A copy on b's desktop reaches a.
	if err := w.Send(&control.Message{Header: control.Header{Op: control.OpCopied, Kind: "text"}, Payload: []byte("from the desktop")}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "alpha has the desktop copy", func() bool {
		m, err := a.do(t, control.Header{Op: control.OpPaste}, "")
		return err == nil && string(m.Payload) == "from the desktop"
	})
}

func TestAloneHoldsTheName(t *testing.T) {
	// A single Linux member, with an iPhone and no other computer, answers
	// for clipbridge.local.
	var h hub
	a := startService(t, &h, "alpha")
	b := startService(t, &h, "beta")
	pairWith(t, a, b)
	b.stop()
	waitFor(t, "alpha holds clipbridge.local alone", func() bool { return a.status(t).Holder })
	a.stop()
	a2 := restartService(t, &h, a)
	waitFor(t, "alpha holds it right after a restart", func() bool { return a2.status(t).Holder })
}

func TestMac(t *testing.T) {
	// A Mac joins through a Linux member, cannot admit devices itself, and
	// syncs in both directions; it never holds clipbridge.local.
	var h hub
	pi := startService(t, &h, "pi")
	mac := startRole(t, &h, "mac", node.Mac)
	pairWith(t, pi, mac)
	waitFor(t, "connected", func() bool { return len(mac.status(t).Peers) == 1 })
	if _, err := mac.do(t, control.Header{Op: control.OpPair}, ""); err == nil {
		t.Error("a Mac opened a pairing window")
	}
	if _, err := mac.do(t, control.Header{Op: control.OpCopy}, "from the Mac"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the pi has it", func() bool {
		m, err := pi.do(t, control.Header{Op: control.OpPaste}, "")
		return err == nil && string(m.Payload) == "from the Mac"
	})
	if mac.status(t).Holder || !pi.status(t).Holder {
		t.Error("the Mac holds clipbridge.local, or the pi does not")
	}
}

func TestWrongCode(t *testing.T) {
	var h hub
	a := startService(t, &h, "alpha")
	b := startService(t, &h, "beta")
	c, err := control.Dial(a.socket)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	m, err := c.Do(&control.Message{Header: control.Header{Op: control.OpPair}})
	if err != nil {
		t.Fatal(err)
	}
	wrong := "000000"
	if m.Code == wrong {
		wrong = "111111"
	}
	if _, err := b.do(t, control.Header{Op: control.OpJoin, Code: wrong}, ""); err == nil {
		t.Fatal("joined with a wrong code")
	}
	if st := b.status(t); st.Group != "" {
		t.Errorf("beta is in a group after a wrong code")
	}
}
