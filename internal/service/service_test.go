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
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/HunterEwok/clipbridge/internal/control"
	"github.com/HunterEwok/clipbridge/internal/group"
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

func (d *fakeDiscovery) isHolder() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.holder
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

	mu          sync.Mutex
	phoneAddr   string // where the iPhone port listens
	profileAddr string // where the profile port listens, while open
}

func (s *testService) addrs() (phone, profile string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.phoneAddr, s.profileAddr
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
		phoneListen: func() (net.Listener, error) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err == nil {
				s.mu.Lock()
				s.phoneAddr = ln.Addr().String()
				s.mu.Unlock()
			}
			return ln, err
		},
		profileListen: func() (net.Listener, error) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err == nil {
				s.mu.Lock()
				s.profileAddr = ln.Addr().String()
				s.mu.Unlock()
			}
			return ln, err
		},
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

func TestIPhone(t *testing.T) {
	var h hub
	pi := startService(t, &h, "pi")
	other := startService(t, &h, "other")
	pairWith(t, pi, other) // creates the group
	waitFor(t, "one holder", func() bool { return pi.status(t).Holder != other.status(t).Holder })
	holder := pi
	if other.status(t).Holder {
		holder = other
	}
	// Only the holder of clipbridge.local pairs an iPhone.
	notHolder := other
	if holder == other {
		notHolder = pi
	}
	if _, err := notHolder.do(t, control.Header{Op: control.OpPairPhone}, ""); err == nil {
		t.Error("a member that does not hold clipbridge.local opened an iPhone window")
	}
	c, err := control.Dial(holder.socket)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	m, err := c.Do(&control.Message{Header: control.Header{Op: control.OpPairPhone}})
	if err != nil {
		t.Fatal(err)
	}
	phoneAddr, profileAddr := holder.addrs()

	// 1. The iPhone downloads the profile over plain HTTP and trusts the
	// CA in it, nothing else.
	resp, err := http.Get("http://" + profileAddr + "/clipbridge.mobileconfig")
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
	iphone := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "clipbridge.local"}}}

	// 2. The pairing page, reached as clipbridge.local, takes the code.
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
		waitFor(t, s.name+" has the iPhone's text", func() bool {
			m, err := s.do(t, control.Header{Op: control.OpPaste}, "")
			return err == nil && string(m.Payload) == "from the iPhone"
		})
	}
	// A computer copies; the next press brings it to the iPhone.
	if _, err := other.do(t, control.Header{Op: control.OpCopy}, "from the computer"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the holder has the copy", func() bool {
		m, err := holder.do(t, control.Header{Op: control.OpPaste}, "")
		return err == nil && string(m.Payload) == "from the computer"
	})
	if rep := sync("from the iPhone"); rep["direction"] != "to_iphone" || rep["copy"] != "from the computer" {
		t.Errorf("reply %v", rep)
	}
	// The profile port closed with the window.
	if _, err := http.Get("http://" + profileAddr + "/clipbridge.mobileconfig"); err == nil {
		t.Error("the profile port is still open")
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
