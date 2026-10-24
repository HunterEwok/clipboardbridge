// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/HunterEwok/clipboardbridge/internal/control"
	"github.com/HunterEwok/clipboardbridge/internal/group"
	"github.com/HunterEwok/clipboardbridge/internal/mdns"
	"github.com/HunterEwok/clipboardbridge/internal/node"
	"github.com/HunterEwok/clipboardbridge/internal/pair"
	"github.com/HunterEwok/clipboardbridge/internal/phone"
)

// hub is a fake network for discovery: every member sees the others on the
// loopback address. Like the mdns responder, each member gets its lists on
// its own Run goroutine, in order, and none after Run returned.
type hub struct {
	mu      sync.Mutex
	members map[*fakeDiscovery]bool
	// sticky keeps a member that stopped in the lists, with its old port,
	// until one with its device ID starts again, as mDNS does when a member
	// restarts within a record's lifetime.
	sticky bool
	ghosts map[string]mdns.Peer
	// hidden members neither see the others nor are seen, as on another
	// network.
	hidden map[string]bool
}

// hide puts the member with this device ID on another network.
func (h *hub) hide(id string) {
	h.mu.Lock()
	if h.hidden == nil {
		h.hidden = map[string]bool{}
	}
	h.hidden[id] = true
	h.mu.Unlock()
	h.update()
}

type fakeDiscovery struct {
	h      *hub
	cfg    DiscoveryConfig
	mu     sync.Mutex
	txt    []string
	holder bool
	latest []mdns.Peer
	fresh  bool
	kick   chan struct{}
}

func (h *hub) discover(c DiscoveryConfig) (Discovery, error) {
	return &fakeDiscovery{h: h, cfg: c, txt: slices.Clone(c.TXT), kick: make(chan struct{}, 1)}, nil
}

func (d *fakeDiscovery) Run(ctx context.Context) error {
	d.h.mu.Lock()
	if d.h.members == nil {
		d.h.members = map[*fakeDiscovery]bool{}
	}
	d.h.members[d] = true
	delete(d.h.ghosts, d.cfg.ID)
	d.h.mu.Unlock()
	d.h.update()
	for {
		select {
		case <-ctx.Done():
			d.h.mu.Lock()
			delete(d.h.members, d)
			if d.h.sticky && !d.cfg.BrowseOnly {
				if d.h.ghosts == nil {
					d.h.ghosts = map[string]mdns.Peer{}
				}
				d.h.ghosts[d.cfg.ID] = d.peer()
			}
			d.h.mu.Unlock()
			d.h.update()
			return nil
		case <-d.kick:
		}
		d.mu.Lock()
		peers, fresh := d.latest, d.fresh
		d.fresh = false
		d.mu.Unlock()
		if fresh && d.cfg.OnPeers != nil {
			d.cfg.OnPeers(peers)
		}
	}
}

func (d *fakeDiscovery) peer() mdns.Peer {
	d.mu.Lock()
	defer d.mu.Unlock()
	return mdns.Peer{ID: d.cfg.ID, Port: d.cfg.Port, TXT: slices.Clone(d.txt),
		Addrs: []netip.Addr{netip.MustParseAddr("127.0.0.1")}}
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

// txtOf returns the TXT record that the member with this device ID
// publishes.
func (h *hub) txtOf(id string) []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	for m := range h.members {
		if m.cfg.ID == id && !m.cfg.BrowseOnly {
			return m.peer().TXT
		}
	}
	return nil
}

// update tells every member about the others: it replaces the list each
// member has not yet taken.
func (h *hub) update() {
	h.mu.Lock()
	var all []mdns.Peer
	var members []*fakeDiscovery
	for m := range h.members {
		members = append(members, m)
		if !m.cfg.BrowseOnly && !h.hidden[m.cfg.ID] {
			all = append(all, m.peer())
		}
	}
	for _, g := range h.ghosts {
		all = append(all, g)
	}
	slices.SortFunc(all, func(a, b mdns.Peer) int { return strings.Compare(a.ID, b.ID) })
	for _, m := range members {
		others := slices.DeleteFunc(slices.Clone(all), func(p mdns.Peer) bool { return p.ID == m.cfg.ID })
		if h.hidden[m.cfg.ID] {
			others = nil
		}
		m.mu.Lock()
		m.latest, m.fresh = others, true
		m.mu.Unlock()
		select {
		case m.kick <- struct{}{}:
		default:
		}
	}
	h.mu.Unlock()
}

type testService struct {
	name     string
	dir      string
	os       string // group.OSLinux, OSWindows or OSMacOS
	socket   string
	cancel   context.CancelFunc
	done     chan error
	accepted atomic.Int32 // member connections accepted
	cfg      func(*Config)

	mu         sync.Mutex
	memberAddr string // where the member port listens
}

// addrs returns where the shortcut's HTTPS and the profile are: both on the
// member port.
func (s *testService) addrs() (phone, profile string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.memberAddr, s.memberAddr
}

func startService(t *testing.T, h *hub, name string) *testService {
	t.Helper()
	return startRole(t, h, name, group.OSLinux)
}

func startRole(t *testing.T, h *hub, name string, system string) *testService {
	t.Helper()
	return startWith(t, h, name, system, nil)
}

func startWith(t *testing.T, h *hub, name string, system string, cfg func(*Config)) *testService {
	t.Helper()
	dir, err := os.MkdirTemp("", "cb")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return startIn(t, h, &testService{name: name, dir: dir, os: system, cfg: cfg})
}

// restartService starts a stopped service again with its state.
func restartService(t *testing.T, h *hub, old *testService) *testService {
	t.Helper()
	return startIn(t, h, &testService{name: old.name, dir: old.dir, os: old.os, cfg: old.cfg})
}

// countingListener counts the connections it accepts.
type countingListener struct {
	net.Listener
	n *atomic.Int32
}

func (l countingListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err == nil {
		l.n.Add(1)
	}
	return c, err
}

func startIn(t *testing.T, h *hub, s *testService) *testService {
	t.Helper()
	s.socket, s.done = filepath.Join(s.dir, "c.sock"), make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel
	name := s.name
	cfg := Config{
		StateDir: s.dir, Socket: s.socket, Role: node.Full, OS: s.os, Name: name, Discover: h.discover,
		Logf: func(f string, a ...any) { t.Logf(name+": "+f, a...) },
		listen: func() (net.Listener, error) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				return nil, err
			}
			s.mu.Lock()
			s.memberAddr = ln.Addr().String()
			s.mu.Unlock()
			return countingListener{ln, &s.accepted}, nil
		},
		browseFor:  2 * time.Second,
		joinListen: func() (net.Listener, error) { return net.Listen("tcp", "127.0.0.1:0") },
		joinAddrs:  func(port uint16) []string { return []string{fmt.Sprintf("127.0.0.1:%d", port)} },
	}
	if s.cfg != nil {
		s.cfg(&cfg)
	}
	go func() { s.done <- Run(ctx, cfg) }()
	t.Cleanup(s.stop)
	// Wait for the control socket, or for Run to fail.
	deadline := time.Now().Add(5 * time.Second)
	for {
		if c, err := control.Dial(s.socket); err == nil {
			c.Close()
			break
		}
		select {
		case err := <-s.done:
			s.cancel = nil
			t.Fatalf("%s: the service ended at the start: %v", name, err)
		default:
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

// dial connects to the service with a deadline, so that a missing answer
// fails the test instead of hanging it.
func (s *testService) dial(t *testing.T) *control.Client {
	t.Helper()
	c, err := control.Dial(s.socket)
	if err != nil {
		t.Fatal(err)
	}
	c.SetDeadline(time.Now().Add(20 * time.Second))
	return c
}

func (s *testService) do(t *testing.T, h control.Header, payload string) (*control.Message, error) {
	t.Helper()
	c := s.dial(t)
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

func (s *testService) paste(t *testing.T) string {
	t.Helper()
	m, err := s.do(t, control.Header{Op: control.OpPaste}, "")
	if err != nil {
		return ""
	}
	return string(m.Payload)
}

// openWindow opens a pairing window on admin; closing the client closes it.
func openWindow(t *testing.T, admin *testService) (*control.Client, string) {
	t.Helper()
	c := admin.dial(t)
	m, err := c.Do(&control.Message{Header: control.Header{Op: control.OpPair}})
	if err != nil {
		c.Close()
		t.Fatalf("pair on %s: %v", admin.name, err)
	}
	return c, m.Code
}

// pairWith opens a pairing window on admin and joins s through it, found
// by discovery.
func pairWith(t *testing.T, admin, s *testService) {
	t.Helper()
	c, code := openWindow(t, admin)
	defer c.Close()
	if _, err := s.do(t, control.Header{Op: control.OpJoin, Code: code}, ""); err != nil {
		t.Fatalf("join on %s: %v", s.name, err)
	}
	m, err := c.Receive()
	if err != nil || m.Name != s.name {
		t.Fatalf("pair on %s ended with %+v, %v", admin.name, m, err)
	}
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	waitUpTo(t, 10*time.Second, what, ok)
}

func waitUpTo(t *testing.T, d time.Duration, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
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
	if _, err := a.do(t, control.Header{Op: control.OpPaste}, ""); err == nil || !strings.Contains(err.Error(), "pair here to start one") {
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
		waitFor(t, s.name+" has the text", func() bool { return s.paste(t) == "from alpha" })
	}
	// Exactly one member holds clipboardbridge.local: the lowest device ID.
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

func TestOneConnectionBetweenTwo(t *testing.T) {
	// Only the member with the lower device ID dials, so the one with the
	// higher ID accepts the only connection between them.
	var h hub
	a := startService(t, &h, "alpha")
	b := startService(t, &h, "beta")
	pairWith(t, a, b)
	waitFor(t, "connected", func() bool { return len(a.status(t).Peers) == 1 && len(b.status(t).Peers) == 1 })
	since := a.status(t).Peers[0]
	time.Sleep(1500 * time.Millisecond)
	low, high := a, b
	if b.status(t).Device < a.status(t).Device {
		low, high = b, a
	}
	// The join itself was one connection to the admin's port.
	pairing := map[*testService]int32{a: 1, b: 0}
	if n := low.accepted.Load() - pairing[low]; n != 0 {
		t.Errorf("the member with the lower ID accepted %d member connections", n)
	}
	if n := high.accepted.Load() - pairing[high]; n != 1 {
		t.Errorf("the member with the higher ID accepted %d member connections, want 1", n)
	}
	if now := a.status(t).Peers; len(now) != 1 || now[0] != since {
		t.Errorf("the connection changed: %+v, then %+v", since, now)
	}
}

func TestWatcher(t *testing.T) {
	var h hub
	a := startService(t, &h, "alpha")
	b := startService(t, &h, "beta")
	pairWith(t, a, b)
	waitFor(t, "connected", func() bool { return len(a.status(t).Peers) == 1 })
	// A desktop connector on b watches its clipboard.
	w := b.dial(t)
	defer w.Close()
	if _, err := w.Do(&control.Message{Header: control.Header{Op: control.OpWatch}}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.do(t, control.Header{Op: control.OpCopy}, "for the desktop"); err != nil {
		t.Fatal(err)
	}
	m, err := w.Receive()
	if err != nil || m.Op != control.OpWrite || string(m.Payload) != "for the desktop" || m.Seq == 0 || m.Kind != control.KindText {
		t.Fatalf("watcher got %+v, %v", m, err)
	}
	// A secret carries what is left of its lifetime.
	if _, err := a.do(t, control.Header{Op: control.OpCopy, Kind: control.KindSecret}, "one-time code"); err != nil {
		t.Fatal(err)
	}
	m, err = w.Receive()
	if err != nil || string(m.Payload) != "one-time code" || m.Kind != control.KindSecret {
		t.Fatalf("watcher got %+v, %v", m, err)
	}
	if m.TTLMS <= 55000 || m.TTLMS > 60000 {
		t.Errorf("a fresh secret came with ttl_ms %d", m.TTLMS)
	}
	// A copy on b's desktop reaches a.
	if err := w.Send(&control.Message{Header: control.Header{Op: control.OpCopied, Kind: control.KindText}, Payload: []byte("from the desktop")}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "alpha has the desktop copy", func() bool { return a.paste(t) == "from the desktop" })
	// So does one that came through Universal Clipboard, by its name.
	if err := w.Send(&control.Message{Header: control.Header{Op: control.OpCopied, Via: control.ViaUniversal}, Payload: []byte("from the iPhone")}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "alpha has the Universal Clipboard copy", func() bool { return a.paste(t) == "from the iPhone" })
}

func TestWatcherGetsAMissedWrite(t *testing.T) {
	// A write made while no watcher was connected goes to the next one,
	// instead of the stale text its clipboard holds.
	var h hub
	a := startService(t, &h, "alpha")
	b := startService(t, &h, "beta")
	pairWith(t, a, b)
	waitFor(t, "connected", func() bool { return len(a.status(t).Peers) == 1 })
	if _, err := a.do(t, control.Header{Op: control.OpCopy}, "while the desktop was away"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "beta has it", func() bool { return b.paste(t) == "while the desktop was away" })
	w := b.dial(t)
	defer w.Close()
	if _, err := w.Do(&control.Message{Header: control.Header{Op: control.OpWatch}, Payload: []byte("stale desktop text")}); err != nil {
		t.Fatal(err)
	}
	m, err := w.Receive()
	if err != nil || m.Op != control.OpWrite || string(m.Payload) != "while the desktop was away" {
		t.Fatalf("watcher got %+v, %v", m, err)
	}
	if got := b.paste(t); got != "while the desktop was away" {
		t.Errorf("paste %q after the watcher started", got)
	}
	w.Close()
	// Without a missed write, what the watcher reports is the clipboard.
	w2 := b.dial(t)
	defer w2.Close()
	if _, err := w2.Do(&control.Message{Header: control.Header{Op: control.OpWatch}, Payload: []byte("on the desktop")}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "beta knows the desktop text", func() bool { return b.paste(t) == "on the desktop" })
}

func TestWatcherKeepsTheNewestWrite(t *testing.T) {
	w := &watcher{out: make(chan node.Write, 4)}
	for i := uint64(1); i <= 10; i++ {
		w.send(node.Write{Seq: i})
	}
	var got []uint64
	for len(w.out) > 0 {
		got = append(got, (<-w.out).Seq)
	}
	if !slices.Equal(got, []uint64{7, 8, 9, 10}) {
		t.Errorf("a full queue kept %v", got)
	}
}

func TestAloneHoldsTheName(t *testing.T) {
	// A single Linux member, with an iPhone and no other computer, answers
	// for clipboardbridge.local.
	var h hub
	a := startService(t, &h, "alpha")
	b := startService(t, &h, "beta")
	pairWith(t, a, b)
	b.stop()
	waitFor(t, "alpha holds clipboardbridge.local alone", func() bool { return a.status(t).Holder })
	a.stop()
	a2 := restartService(t, &h, a)
	waitFor(t, "alpha holds it right after a restart", func() bool { return a2.status(t).Holder })
}

func TestRestartWithANewPort(t *testing.T) {
	// A member that restarts on a new port while discovery still lists it
	// is dialed at the new port.
	h := hub{sticky: true}
	a := startService(t, &h, "alpha")
	b := startService(t, &h, "beta")
	pairWith(t, a, b)
	waitFor(t, "connected", func() bool { return len(a.status(t).Peers) == 1 })
	high, low := b, a
	if a.status(t).Device > b.status(t).Device {
		high, low = a, b
	}
	high.stop()
	high2 := restartService(t, &h, high)
	waitFor(t, "connected again", func() bool { return len(low.status(t).Peers) == 1 && len(high2.status(t).Peers) == 1 })
}

func TestMac(t *testing.T) {
	// A Mac joins through a Linux member, cannot admit devices itself, and
	// syncs in both directions; it never holds clipboardbridge.local. Its rules
	// must hold whichever device ID is lower, so the test runs until it saw
	// both orders.
	seen := map[bool]bool{}
	for i := 0; i < 16 && len(seen) < 2; i++ {
		var h hub
		pi := startService(t, &h, "pi")
		mac := startRole(t, &h, "mac", group.OSMacOS)
		pairWith(t, pi, mac)
		macLower := mac.status(t).Device < pi.status(t).Device
		if seen[macLower] {
			pi.stop()
			mac.stop()
			continue
		}
		seen[macLower] = true
		t.Logf("the Mac's ID is lower: %v", macLower)
		waitFor(t, "connected", func() bool { return len(mac.status(t).Peers) == 1 })
		if _, err := mac.do(t, control.Header{Op: control.OpPair}, ""); err == nil || !strings.Contains(err.Error(), "a Mac cannot admit devices yet") {
			t.Errorf("pair on a Mac: %v", err)
		}
		if _, err := mac.do(t, control.Header{Op: control.OpCopy}, "from the Mac"); err != nil {
			t.Fatal(err)
		}
		waitFor(t, "the pi has it", func() bool { return pi.paste(t) == "from the Mac" })
		if _, err := pi.do(t, control.Header{Op: control.OpCopy}, "from the pi"); err != nil {
			t.Fatal(err)
		}
		waitFor(t, "the Mac has it", func() bool { return mac.paste(t) == "from the pi" })
		if mac.status(t).Holder || !pi.status(t).Holder {
			t.Error("the Mac holds clipboardbridge.local, or the pi does not")
		}
		pi.stop()
		mac.stop()
	}
	if len(seen) < 2 {
		t.Errorf("saw only one order of device IDs: %v", seen)
	}
}

func TestRenewal(t *testing.T) {
	// Eighteen months after pairing, the pi renews its own certificates
	// when it starts and the Mac's when the Mac connects; both keep them.
	var h hub
	pi := startService(t, &h, "pi")
	mac := startRole(t, &h, "mac", group.OSMacOS)
	pairWith(t, pi, mac)
	before := map[string]*group.Identity{}
	for _, s := range []*testService{pi, mac} {
		s.stop()
		id, err := group.Load(s.dir)
		if err != nil {
			t.Fatal(err)
		}
		before[s.name] = id
	}
	later := func(c *Config) { c.now = func() time.Time { return time.Now().AddDate(1, 6, 0) } }
	pi.cfg, mac.cfg = later, later
	pi, mac = restartService(t, &h, pi), restartService(t, &h, mac)
	for _, s := range []*testService{pi, mac} {
		waitFor(t, s.name+" keeps a renewed certificate", func() bool {
			id, err := group.Load(s.dir)
			return err == nil && id.Cert.NotAfter.After(before[s.name].Cert.NotAfter.AddDate(1, 0, 0))
		})
	}
	id, _ := group.Load(pi.dir)
	if !id.Phone.NotAfter.After(before["pi"].Phone.NotAfter) {
		t.Error("the pi did not renew its clipboardbridge.local certificate")
	}
	// The renewed certificates work: the members connect again.
	mac.stop()
	mac = restartService(t, &h, mac)
	waitFor(t, "connected with the renewed certificates", func() bool { return len(mac.status(t).Peers) == 1 })
}

func TestMacInNoGroup(t *testing.T) {
	// A Mac in no group cannot start one: it would hold no CA keys.
	var h hub
	mac := startRole(t, &h, "mac", group.OSMacOS)
	if _, err := mac.do(t, control.Header{Op: control.OpPair}, ""); err == nil || !strings.Contains(err.Error(), "a Mac cannot admit devices yet") {
		t.Errorf("pair on a Mac in no group: %v", err)
	}
	if st := mac.status(t); st.Group != "" {
		t.Errorf("the Mac is in a group: %+v", st)
	}
	if _, err := mac.do(t, control.Header{Op: control.OpPaste}, ""); err == nil || !strings.Contains(err.Error(), "pair on a Linux or Windows member") {
		t.Errorf("paste on a Mac in no group: %v", err)
	}
}

func TestWrongCode(t *testing.T) {
	var h hub
	a := startService(t, &h, "alpha")
	b := startService(t, &h, "beta")
	c, code := openWindow(t, a)
	defer c.Close()
	wrong := "000000"
	if code == wrong {
		wrong = "111111"
	}
	if _, err := b.do(t, control.Header{Op: control.OpJoin, Code: wrong}, ""); err == nil || !strings.Contains(err.Error(), "wrong code") {
		t.Fatalf("join with a wrong code: %v", err)
	}
	if st := b.status(t); st.Group != "" {
		t.Errorf("beta is in a group after a wrong code")
	}
	if _, err := b.do(t, control.Header{Op: control.OpJoin, Code: "12345"}, ""); err == nil || !strings.Contains(err.Error(), "six digits") {
		t.Errorf("join with five digits: %v", err)
	}
}

func TestPairingWindow(t *testing.T) {
	var h hub
	a := startService(t, &h, "alpha")
	c, _ := openWindow(t, a)
	id := a.status(t).Device
	waitFor(t, "p=1 published", func() bool { return slices.Contains(h.txtOf(id), "p=1") })
	if _, err := a.do(t, control.Header{Op: control.OpPair}, ""); err == nil || !strings.Contains(err.Error(), "already open") {
		t.Errorf("a second window: %v", err)
	}
	// The client hanging up closes the window.
	c.Close()
	waitFor(t, "p=1 gone", func() bool { txt := h.txtOf(id); return txt != nil && !slices.Contains(txt, "p=1") })
	c2, _ := openWindow(t, a)
	c2.Close()
}

func TestConcurrentPairs(t *testing.T) {
	// Two pairs on a device in no group make one group and one window.
	var h hub
	a := startService(t, &h, "alpha")
	var wg sync.WaitGroup
	errs := make([]error, 2)
	clients := make([]*control.Client, 2)
	for i := range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := control.Dial(a.socket)
			if err != nil {
				errs[i] = err
				return
			}
			clients[i] = c
			_, errs[i] = c.Do(&control.Message{Header: control.Header{Op: control.OpPair}})
		}()
	}
	wg.Wait()
	for _, c := range clients {
		if c != nil {
			defer c.Close()
		}
	}
	if (errs[0] == nil) == (errs[1] == nil) {
		t.Fatalf("two pairs at once: %v, %v; want one to fail", errs[0], errs[1])
	}
	published := func() int {
		h.mu.Lock()
		defer h.mu.Unlock()
		n := 0
		for m := range h.members {
			if !m.cfg.BrowseOnly {
				n++
			}
		}
		return n
	}
	waitFor(t, "one discovery", func() bool { return published() == 1 })
	time.Sleep(100 * time.Millisecond)
	if n := published(); n != 1 {
		t.Errorf("%d discoveries publish", n)
	}
}

func TestJoinFindsTheWindow(t *testing.T) {
	// A member without a window is found first; join goes to the one that
	// announces a window.
	var h hub
	a := startService(t, &h, "alpha")
	c := startService(t, &h, "gamma")
	pairWith(t, a, c)
	b := startService(t, &h, "beta")
	if _, err := b.do(t, control.Header{Op: control.OpJoin, Code: "123456"}, ""); err == nil || !strings.Contains(err.Error(), "no member with an open pairing window") {
		t.Errorf("join with no window anywhere: %v", err)
	}
	pairWith(t, a, b)
	if b.status(t).Group != a.status(t).Group {
		t.Error("beta is not in alpha's group")
	}
	// Joining again from a device in a group fails and changes nothing.
	before := b.status(t)
	if _, err := b.do(t, control.Header{Op: control.OpJoin, Code: "123456"}, ""); err == nil || !strings.Contains(err.Error(), "already in a group") {
		t.Errorf("join in a group: %v", err)
	}
	if after := b.status(t); after.Device != before.Device || after.Group != before.Group {
		t.Errorf("status changed from %+v to %+v", before, after)
	}
}

func TestJoinRefusesTwoWindows(t *testing.T) {
	var h hub
	a := startService(t, &h, "alpha")
	d := startService(t, &h, "delta")
	b := startService(t, &h, "beta")
	ca, _ := openWindow(t, a)
	defer ca.Close()
	cd, _ := openWindow(t, d)
	defer cd.Close()
	waitFor(t, "both windows published", func() bool {
		return slices.Contains(h.txtOf(a.status(t).Device), "p=1") && slices.Contains(h.txtOf(d.status(t).Device), "p=1")
	})
	if _, err := b.do(t, control.Header{Op: control.OpJoin, Code: "123456"}, ""); err == nil || !strings.Contains(err.Error(), "2 devices announce a pairing window") {
		t.Errorf("join with two windows: %v", err)
	}
}

// memberAddr returns the loopback address of the member port of the
// service with this device ID, once its discovery runs.
func (h *hub) memberAddr(t *testing.T, id string) string {
	t.Helper()
	addr := ""
	waitFor(t, "the member's discovery runs", func() bool {
		h.mu.Lock()
		defer h.mu.Unlock()
		for m := range h.members {
			if m.cfg.ID == id {
				addr = net.JoinHostPort("127.0.0.1", strconv.Itoa(int(m.cfg.Port)))
			}
		}
		return addr != ""
	})
	return addr
}

func TestJoinAClosedWindow(t *testing.T) {
	// At a member's address with no window, the joiner hears that the
	// window is closed, not a TLS error.
	var h hub
	a := startService(t, &h, "alpha")
	b := startService(t, &h, "beta")
	c := startService(t, &h, "gamma")
	pairWith(t, a, b)
	addr := h.memberAddr(t, a.status(t).Device)
	if _, err := c.do(t, control.Header{Op: control.OpJoin, Code: "123456", Address: addr}, ""); err == nil || !strings.Contains(err.Error(), pair.ErrClosed.Error()) {
		t.Errorf("join at %s without a window: %v", addr, err)
	}
}

func TestDiscoveryFails(t *testing.T) {
	// When the group's network part cannot start, the device stays in no
	// group, and a second try fails the same way instead of crashing.
	var h hub
	a := startWith(t, &h, "alpha", group.OSLinux, func(c *Config) {
		c.Discover = func(DiscoveryConfig) (Discovery, error) { return nil, errors.New("no network") }
	})
	for range 2 {
		if _, err := a.do(t, control.Header{Op: control.OpPair}, ""); err == nil || !strings.Contains(err.Error(), "no network") {
			t.Errorf("pair: %v", err)
		}
		if st := a.status(t); st.Group != "" {
			t.Errorf("in a group after a failed start: %+v", st)
		}
	}
}

func TestSleepDetector(t *testing.T) {
	start := time.Now()
	d := newSleepDetector(time.Hour, start)
	up, mono := time.Hour, start
	for range 10 {
		up, mono = up+sleepCheckEvery, mono.Add(sleepCheckEvery)
		if _, ok := d.check(up, mono); ok {
			t.Fatal("steady ticks counted as sleep")
		}
	}
	up, mono = up+10*time.Minute+sleepCheckEvery, mono.Add(sleepCheckEvery)
	if slept, ok := d.check(up, mono); !ok || slept != 10*time.Minute {
		t.Errorf("check after a sleep = %v, %v", slept, ok)
	}
	up, mono = up+sleepCheckEvery, mono.Add(sleepCheckEvery)
	if _, ok := d.check(up, mono); ok {
		t.Error("one sleep counted twice")
	}
}

// flakyListener fails its first Accept calls with a temporary error.
type flakyListener struct {
	net.Listener
	fails atomic.Int32
}

func (l *flakyListener) Accept() (net.Conn, error) {
	if l.fails.Add(-1) >= 0 {
		return nil, errors.New("accept: too many open files")
	}
	return l.Listener.Accept()
}

func TestAcceptSurvivesErrors(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	fl := &flakyListener{Listener: ln}
	fl.fails.Store(3)
	got := make(chan net.Conn, 1)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		acceptLoop(ctx, fl, t.Logf, "test", func(c net.Conn) { got <- c })
	}()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	select {
	case sc := <-got:
		sc.Close()
	case <-time.After(5 * time.Second):
		t.Fatal("the loop stopped after an error")
	}
	cancel()
	<-done
}

func TestControlSocketMode(t *testing.T) {
	// Not t.TempDir: on macOS its path is too long for a socket.
	dir, err := os.MkdirTemp("", "cb")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "c.sock")
	ln, err := listenControl(path)
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	checkSocketAccess(t, path, fi)
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Errorf("left behind: %v", entries)
	}
	ln.Close()
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Errorf("the socket is still there after Close: %v", err)
	}
}

func TestIPhone(t *testing.T) {
	var h hub
	pi := startService(t, &h, "pi")
	other := startService(t, &h, "other")
	pairWith(t, pi, other) // creates the group
	waitFor(t, "one holder", func() bool { return pi.status(t).Holder != other.status(t).Holder })
	holder, notHolder := pi, other
	if other.status(t).Holder {
		holder, notHolder = other, pi
	}
	// Only the holder of clipboardbridge.local pairs an iPhone.
	if _, err := notHolder.do(t, control.Header{Op: control.OpPairPhone}, ""); err == nil || !strings.Contains(err.Error(), "does not answer for clipboardbridge.local") {
		t.Errorf("pair -phone on a member that does not hold clipboardbridge.local: %v", err)
	}
	c := holder.dial(t)
	defer c.Close()
	m, err := c.Do(&control.Message{Header: control.Header{Op: control.OpPairPhone}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := holder.do(t, control.Header{Op: control.OpPairPhone}, ""); err == nil || !strings.Contains(err.Error(), "already open") {
		t.Errorf("a second iPhone window: %v", err)
	}
	phoneAddr, profileAddr := holder.addrs()

	// 1. The iPhone downloads the profile over plain HTTP and trusts the
	// CA in it, nothing else.
	resp, err := http.Get("http://" + profileAddr + "/clipboardbridge.mobileconfig")
	if err != nil {
		t.Fatal(err)
	}
	profile, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	der := regexp.MustCompile(`<data>([A-Za-z0-9+/=]+)</data>`).FindSubmatch(profile)
	if der == nil {
		t.Fatalf("profile:\n%s", profile)
	}
	raw, _ := base64.StdEncoding.DecodeString(string(der[1]))
	ca, err := x509.ParseCertificate(raw)
	if err != nil {
		t.Fatal(err)
	}
	if group.Fingerprint(ca) != m.Fingerprint {
		t.Fatal("the printed fingerprint is not the profile's")
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	iphone := &http.Client{Timeout: 10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "clipboardbridge.local"}}}

	// 2. The pairing page, reached as clipboardbridge.local, takes the code.
	resp, err = iphone.PostForm("https://"+phoneAddr+"/pair", url.Values{"code": {m.Code}})
	if err != nil {
		t.Fatalf("the iPhone could not reach the pairing page: %v", err)
	}
	page, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	tok := regexp.MustCompile(`<code>(cb1\.[A-Za-z0-9_-]+)</code>`).FindSubmatch(page)
	if tok == nil {
		t.Fatalf("pairing page:\n%s", page)
	}
	if m, err := c.Receive(); err != nil || !m.Done {
		t.Fatalf("pair -phone ended with %+v, %v", m, err)
	}
	// The window and the profile port closed before the answer.
	if _, err := http.Get("http://" + profileAddr + "/clipboardbridge.mobileconfig"); err == nil {
		t.Error("the profile port is still open")
	}

	// 3. The button: the iPhone's text goes to every member.
	sync := func(text string) map[string]any {
		t.Helper()
		body, _ := json.Marshal(map[string]any{"v": 1, "text": text})
		req, _ := http.NewRequest(http.MethodPost, "https://"+phoneAddr+"/sync", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+string(tok[1]))
		resp, err := iphone.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var rep map[string]any
		json.NewDecoder(resp.Body).Decode(&rep)
		return rep
	}
	if rep := sync("from the iPhone"); rep["direction"] != "from_iphone" {
		t.Fatalf("reply %v", rep)
	}
	for _, s := range []*testService{pi, other} {
		waitFor(t, s.name+" has the iPhone's text", func() bool { return s.paste(t) == "from the iPhone" })
	}
	// A computer copies; the next press brings it to the iPhone.
	if _, err := other.do(t, control.Header{Op: control.OpCopy}, "from the computer"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the holder has the copy", func() bool { return holder.paste(t) == "from the computer" })
	if rep := sync("from the iPhone"); rep["direction"] != "to_iphone" || rep["copy"] != "from the computer" {
		t.Errorf("reply %v", rep)
	}
	// A token from another group is refused, and the shortcut told to
	// pair again.
	req, _ := http.NewRequest(http.MethodPost, "https://"+phoneAddr+"/sync", strings.NewReader(`{"v":1,"text":"x"}`))
	req.Header.Set("Authorization", "Bearer cb1.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	if resp, err := iphone.Do(req); err == nil {
		var rep map[string]any
		json.NewDecoder(resp.Body).Decode(&rep)
		resp.Body.Close()
		if rep["direction"] != "unpaired" {
			t.Errorf("a forged token got %v", rep)
		}
	}

	// A second iPhone pairs the way the shortcut does: the code as JSON.
	c2 := holder.dial(t)
	defer c2.Close()
	m, err = c2.Do(&control.Message{Header: control.Header{Op: control.OpPairPhone}})
	if err != nil {
		t.Fatal(err)
	}
	resp, err = iphone.Post("https://"+phoneAddr+"/pair", "application/json", strings.NewReader(`{"v":1,"code":"`+m.Code+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	var paired struct {
		OK    bool   `json:"ok"`
		Token string `json:"token"`
	}
	json.NewDecoder(resp.Body).Decode(&paired)
	resp.Body.Close()
	if !paired.OK || !strings.HasPrefix(paired.Token, "cb1.") {
		t.Fatalf("JSON pairing: %+v", paired)
	}
	if m, err := c2.Receive(); err != nil || !m.Done {
		t.Fatalf("pair -phone ended with %+v, %v", m, err)
	}
	tok[1] = []byte(paired.Token)
	if rep := sync("from the second iPhone"); rep["direction"] == "unpaired" || rep["direction"] == "error" {
		t.Errorf("the second iPhone's token: %v", rep)
	}
}

// shortcutPhone pairs the iPhone shortcut with pi, which creates the group,
// and returns how the shortcut admits a device by its QR code.
func shortcutPhone(t *testing.T, pi *testService) (admit func(token, code string) map[string]any, token string) {
	t.Helper()
	c := pi.dial(t)
	defer c.Close()
	m, err := c.Do(&control.Message{Header: control.Header{Op: control.OpPairPhone}})
	if err != nil {
		t.Fatalf("pair -phone in no group: %v", err)
	}
	if pi.status(t).Group == "" {
		t.Fatal("pair -phone did not create the group")
	}
	// The iPhone port starts with the group, just after it.
	waitFor(t, "the iPhone port", func() bool { a, _ := pi.addrs(); return a != "" })
	phoneAddr, profileAddr := pi.addrs()
	resp, err := http.Get("http://" + profileAddr + "/clipboardbridge.mobileconfig")
	if err != nil {
		t.Fatal(err)
	}
	profile, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	der := regexp.MustCompile(`<data>([A-Za-z0-9+/=]+)</data>`).FindSubmatch(profile)
	raw, _ := base64.StdEncoding.DecodeString(string(der[1]))
	ca, err := x509.ParseCertificate(raw)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	iphone := &http.Client{Timeout: 10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "clipboardbridge.local"}}}
	resp, err = iphone.Post("https://"+phoneAddr+"/pair", "application/json", strings.NewReader(`{"v":1,"code":"`+m.Code+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	var paired struct{ Token string }
	json.NewDecoder(resp.Body).Decode(&paired)
	resp.Body.Close()
	if _, err := c.Receive(); err != nil {
		t.Fatal(err)
	}
	admit = func(token, code string) map[string]any {
		t.Helper()
		req, _ := http.NewRequest(http.MethodPost, "https://"+phoneAddr+"/admit", strings.NewReader(`{"v":1,"code":"`+code+`"}`))
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := iphone.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var rep map[string]any
		json.NewDecoder(resp.Body).Decode(&rep)
		return rep
	}
	return admit, paired.Token
}

func TestPhoneAddsAComputer(t *testing.T) {
	// The phone is the main device: it pairs with the first computer, which
	// creates the group, and adds the next computer by scanning its code.
	var h hub
	pi := startService(t, &h, "pi")
	admit, token := shortcutPhone(t, pi)

	// A new computer runs cbb join: it listens, shows its QR code
	// and waits.
	laptop := startService(t, &h, "laptop")
	lc := laptop.dial(t)
	defer lc.Close()
	where, err := lc.Do(&control.Message{Header: control.Header{Op: control.OpJoin, Code: "246802", Expires: 60, Listen: true}})
	if err != nil || len(where.Addrs) == 0 || where.Fingerprint == "" {
		t.Fatalf("a listening join: %+v, %v", where, err)
	}
	qr := phone.JoinQR(phone.JoinCode{Code: "246802", Addrs: where.Addrs, Fingerprint: where.Fingerprint})
	joined := make(chan error, 1)
	go func() {
		_, err := lc.Receive()
		joined <- err
	}()
	if rep := admit("cb1.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", qr); rep["direction"] != "unpaired" {
		t.Errorf("a forged token: %v", rep)
	}
	if rep := admit(token, "clipboardbridge://join?code=246802"); rep["direction"] != "error" {
		t.Errorf("a QR code without an address: %v", rep)
	}
	if rep := admit(token, qr); rep["direction"] != "none" {
		t.Fatalf("admit: %v", rep)
	}
	select {
	case err := <-joined:
		if err != nil {
			t.Fatalf("join: %v", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("the laptop never joined")
	}
	if laptop.status(t).Group != pi.status(t).Group {
		t.Error("the laptop is not in the phone's group")
	}
	waitFor(t, "the laptop connected", func() bool { return len(laptop.status(t).Peers) == 1 })
	// The window closed: a second admit with the same code opens a new one,
	// which nobody uses; a code that is not six digits is refused.
	if rep := admit(token, "clipboardbridge://join?code=12345"); rep["direction"] != "error" {
		t.Errorf("five digits: %v", rep)
	}
}

func TestListenPreferring(t *testing.T) {
	taken, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer taken.Close()
	port := taken.Addr().(*net.TCPAddr).Port
	ln, err := listenPreferring(port)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if got := ln.Addr().(*net.TCPAddr).Port; got == port || got == 0 {
		t.Errorf("listenPreferring(%d) listened on %d", port, got)
	}
	taken.Close()
	free, err := listenPreferring(port)
	if err != nil {
		t.Fatal(err)
	}
	defer free.Close()
	if got := free.Addr().(*net.TCPAddr).Port; got != port {
		t.Errorf("listenPreferring(%d) on a free port listened on %d", port, got)
	}
}

func TestLinuxMemberWithoutCAKeys(t *testing.T) {
	// A Linux member without the CA keys, as in a group whose root is the
	// phone, connects and syncs, but never holds clipboardbridge.local, even
	// with the lowest device ID, and admits nobody. (A group is either one
	// or the other, so the pi gives the name up to the lower ID here; in a
	// group whose root is the phone nobody holds it.)
	var h hub
	pi := startService(t, &h, "pi")
	c, _ := openWindow(t, pi) // creates the group
	c.Close()
	admin, err := group.Load(pi.dir)
	if err != nil {
		t.Fatal(err)
	}
	key, err := group.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	devID := group.DeviceID("00000000000000000000000000000001")
	cert, err := admin.GroupCA.IssueMember(devID, &key.PublicKey, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp("", "cb")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	id := &group.Identity{ID: devID, Key: key, Cert: cert, GroupCA: group.CA{Cert: admin.GroupCA.Cert}}
	if err := id.Save(dir); err != nil {
		t.Fatal(err)
	}
	box := startIn(t, &h, &testService{name: "box", dir: dir, os: group.OSLinux})
	waitFor(t, "connected", func() bool { return len(box.status(t).Peers) == 1 })
	if _, err := box.do(t, control.Header{Op: control.OpCopy}, "from the box"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the pi has it", func() bool { return pi.paste(t) == "from the box" })
	if box.status(t).Holder {
		t.Error("the member without CA keys holds clipboardbridge.local")
	}
	if _, err := box.do(t, control.Header{Op: control.OpPair}, ""); err == nil {
		t.Error("a member without CA keys opened a pairing window")
	}
	if _, err := box.do(t, control.Header{Op: control.OpPairPhone}, ""); err == nil {
		t.Error("a member without CA keys paired an iPhone")
	}
}

func (s *testService) devices(t *testing.T) []control.Device {
	t.Helper()
	m, err := s.do(t, control.Header{Op: control.OpDevices}, "")
	if err != nil {
		t.Fatalf("devices on %s: %v", s.name, err)
	}
	return m.Devices
}

// listed returns the names of the listed devices, sorted.
func listed(devs []control.Device) string {
	var names []string
	for _, d := range devs {
		if d.Listed {
			names = append(names, d.Name)
		}
	}
	sort.Strings(names)
	return strings.Join(names, " ")
}

func TestDevicesAndRevoke(t *testing.T) {
	var h hub
	pi := startService(t, &h, "pi")
	deck := startService(t, &h, "deck")
	mac := startRole(t, &h, "mac", group.OSMacOS)
	pairWith(t, pi, deck)
	pairWith(t, pi, mac)
	for _, s := range []*testService{pi, deck, mac} {
		waitFor(t, s.name+" lists every device", func() bool { return listed(s.devices(t)) == "deck mac pi" })
	}
	waitFor(t, "the Mac connects to both", func() bool { return len(mac.status(t).Peers) == 2 })
	for _, d := range mac.devices(t) {
		if want := d.OS == "linux"; d.Admin != want || !d.Online || d.Role != "full" {
			t.Errorf("on the Mac: %+v", d)
		}
		if d.Self != (d.Name == "mac") {
			t.Errorf("self is wrong: %+v", d)
		}
	}

	if _, err := mac.do(t, control.Header{Op: control.OpRevoke, Name: "deck"}, ""); err == nil || !strings.Contains(err.Error(), "only an admin") {
		t.Errorf("revoke on the Mac: %v", err)
	}
	if _, err := pi.do(t, control.Header{Op: control.OpRevoke, Name: "deck"}, ""); err == nil || !strings.Contains(err.Error(), "needs a new group") {
		t.Errorf("revoking a Linux member: %v", err)
	}
	if _, err := pi.do(t, control.Header{Op: control.OpRevoke, Name: "pi"}, ""); err == nil || !strings.Contains(err.Error(), "cannot remove itself") {
		t.Errorf("revoking itself: %v", err)
	}
	if _, err := pi.do(t, control.Header{Op: control.OpRevoke, Name: "toaster"}, ""); err == nil {
		t.Error("revoked a device that is not there")
	}
	// Any Linux member holds the keys; deck removes the Mac.
	m, err := deck.do(t, control.Header{Op: control.OpRevoke, Name: "MAC"}, "")
	if err != nil || m.Name != "mac" {
		t.Fatalf("revoke the Mac: %+v, %v", m, err)
	}
	for _, s := range []*testService{pi, deck} {
		waitFor(t, s.name+" drops the Mac", func() bool {
			return listed(s.devices(t)) == "deck pi" && len(s.status(t).Peers) == 1
		})
	}
	waitFor(t, "the Mac is alone", func() bool { return len(mac.status(t).Peers) == 0 })
	// The records survive a restart.
	pi.stop()
	pi = restartService(t, &h, pi)
	if got := listed(pi.devices(t)); got != "deck pi" {
		t.Errorf("after a restart the pi lists %q", got)
	}
}

// TestMacsListen checks that a Mac publishes itself with r=mac and takes
// connections, so two Macs keep syncing when no Linux member is on.
func TestMacsListen(t *testing.T) {
	var h hub
	pi := startService(t, &h, "pi")
	a := startRole(t, &h, "mac-a", group.OSMacOS)
	b := startRole(t, &h, "mac-b", group.OSMacOS)
	pairWith(t, pi, a)
	pairWith(t, pi, b)
	for _, s := range []*testService{a, b} {
		if txt := h.txtOf(s.status(t).Device); !slices.Contains(txt, "r=mac") {
			t.Errorf("%s publishes %q, want r=mac", s.name, txt)
		}
		waitFor(t, s.name+" meets the pi and the other Mac", func() bool { return len(s.status(t).Peers) == 2 })
	}
	if txt := h.txtOf(pi.status(t).Device); slices.Contains(txt, "r=mac") {
		t.Errorf("the pi publishes %q", txt)
	}

	pi.stop()
	waitFor(t, "the Macs are alone together", func() bool {
		return len(a.status(t).Peers) == 1 && len(b.status(t).Peers) == 1
	})
	if _, err := a.do(t, control.Header{Op: control.OpCopy}, "from one Mac"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the other Mac has it", func() bool { return b.paste(t) == "from one Mac" })
}

// TestRecordsTheSystem checks that an admin records a computer's system
// from its hello when its record names another, as for a Windows PC that
// joined as a Linux member.
func TestRecordsTheSystem(t *testing.T) {
	var h hub
	pi := startService(t, &h, "pi")
	pc := startService(t, &h, "pc")
	pairWith(t, pi, pc)
	waitFor(t, "pc is listed", func() bool { return listed(pi.devices(t)) == "pc pi" })
	pc.stop()
	pc.os = group.OSWindows
	pc = restartService(t, &h, pc)
	waitFor(t, "pc connects again", func() bool { return len(pi.status(t).Peers) == 1 })
	pc.stop()
	waitFor(t, "pi records Windows", func() bool {
		for _, d := range pi.devices(t) {
			if d.Name == "pc" {
				return d.OS == group.OSWindows && !d.Online && d.Admin && d.Role == group.RoleFull
			}
		}
		return false
	})
}
