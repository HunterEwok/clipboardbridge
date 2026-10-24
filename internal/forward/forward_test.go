// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package forward

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20"

	"github.com/HunterEwok/clipboardbridge/internal/group"
	"github.com/HunterEwok/clipboardbridge/internal/tunnel"
	"github.com/HunterEwok/clipboardbridge/internal/vless"
	"github.com/HunterEwok/clipboardbridge/internal/vless/vlesstest"
)

// member returns a member certificate of a new group with its chain, as a
// hub presents it, and the group's tag.
func member(t *testing.T) (tls.Certificate, string) {
	t.Helper()
	now := time.Now()
	ca, err := group.NewGroupCA(now)
	if err != nil {
		t.Fatal(err)
	}
	key, err := group.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := ca.IssueMember(group.NewDeviceID(), &key.PublicKey, now)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{leaf.Raw, ca.Cert.Raw}, PrivateKey: key, Leaf: leaf}, group.Tag(ca.Cert)
}

func startForwarder(t *testing.T, limits Limits) (*Forwarder, string) {
	return startForwarderWith(t, Config{Limits: limits})
}

func startForwarderWith(t *testing.T, cfg Config) (*Forwarder, string) {
	t.Helper()
	cert, err := NewCert()
	if err != nil {
		t.Fatal(err)
	}
	cfg.Listen, cfg.Cert, cfg.Logf = "127.0.0.1:0", cert, t.Logf
	f, err := Listen(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := f.Serve(ctx); err != nil {
			t.Errorf("Serve: %v", err)
		}
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	return f, Pin(cert.Leaf)
}

type hubSide struct {
	hub     *tunnel.Hub
	key     tunnel.Key
	addr    netip.Addr
	obf     *tunnel.Obfuscation
	vless   *tunnel.VLESS // how the hub's clients reach the forwarder over VLESS
	reports chan Report
}

// startHub brings up a hub for the clients and registers it with the
// forwarder; it returns once the forwarder saw the hub's port.
func startHub(t *testing.T, f *Forwarder, pin string, clients []tunnel.Peer, obf *tunnel.Obfuscation) *hubSide {
	return startHubWith(t, f, pin, clients, HubConfig{Obfuscation: obf})
}

// startHubWith is startHub with more of the hub's configuration.
func startHubWith(t *testing.T, f *Forwarder, pin string, clients []tunnel.Peer, hc HubConfig) *hubSide {
	obf := hc.Obfuscation
	t.Helper()
	cert, _ := member(t)
	key, err := tunnel.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	addr, err := tunnel.Addr(string(group.NewDeviceID()))
	if err != nil {
		t.Fatal(err)
	}
	h, err := tunnel.StartHub(tunnel.HubConfig{PrivateKey: key, Addr: addr, Peers: clients, Obfuscation: obf, Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { h.Close() })
	hs := &hubSide{hub: h, key: key, addr: addr, obf: obf, reports: make(chan Report, 16)}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		Register(ctx, HubConfig{Link: Link{Endpoint: f.Addr(), Pin: pin}, Key: key, Obfuscation: obf, VLESSID: hc.VLESSID,
			Cert: func() tls.Certificate { return cert }, Send: h.Send, Report: func(r Report) {
				select {
				case hs.reports <- r:
				default:
				}
			}})
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	deadline := time.After(10 * time.Second)
	for {
		select {
		case r := <-hs.reports:
			if r.Err != nil {
				t.Fatalf("registering: %v", r.Err)
			}
			if r.VLESS != nil {
				hs.vless = r.VLESS
			}
			if r.Seen.IsValid() {
				if r.Seen.Port() != uint16(h.UDPPort()) {
					t.Fatalf("the forwarder sees the hub at %v, not on its port %d", r.Seen, h.UDPPort())
				}
				return hs
			}
		case <-deadline:
			t.Fatal("the forwarder never saw the hub's port")
		}
	}
}

func newClient(t *testing.T) (tunnel.Key, tunnel.Peer) {
	t.Helper()
	key, err := tunnel.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	psk, err := tunnel.NewPresharedKey()
	if err != nil {
		t.Fatal(err)
	}
	addr, err := tunnel.Addr(string(group.NewDeviceID()))
	if err != nil {
		t.Fatal(err)
	}
	return key, tunnel.Peer{PublicKey: key.Public(), PresharedKey: psk, Addr: addr}
}

// roundTrip connects a client through the forwarder to the hub and back.
func roundTrip(t *testing.T, f *Forwarder, hs *hubSide, key tunnel.Key, peer tunnel.Peer) error {
	t.Helper()
	return roundTripTo(t, f.Addr(), hs, key, peer)
}

// roundTripTo is roundTrip with the client sending to ep.
func roundTripTo(t *testing.T, ep netip.AddrPort, hs *hubSide, key tunnel.Key, peer tunnel.Peer) error {
	t.Helper()
	c, err := tunnel.StartClient(tunnel.ClientConfig{PrivateKey: key, PresharedKey: peer.PresharedKey, Addr: peer.Addr,
		HubPublicKey: hs.key.Public(), HubAddr: hs.addr, Endpoint: ep, Obfuscation: hs.obf, Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := hs.hub.Listener().Accept()
		if err == nil {
			accepted <- conn
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := c.Dial(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	var server net.Conn
	select {
	case server = <-accepted:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer server.Close()
	if from := server.RemoteAddr().(*net.TCPAddr).AddrPort().Addr(); from != peer.Addr {
		t.Fatalf("the hub got a connection from %v, not %v", from, peer.Addr)
	}
	go io.Copy(server, server)
	if _, err := conn.Write([]byte("clipboard")); err != nil {
		return err
	}
	buf := make([]byte, 9)
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.ReadFull(conn, buf); err != nil {
		return err
	}
	if string(buf) != "clipboard" {
		t.Fatalf("got %q back", buf)
	}
	return nil
}

func newObfuscation(t *testing.T) *tunnel.Obfuscation {
	t.Helper()
	o, err := tunnel.NewObfuscation()
	if err != nil {
		t.Fatal(err)
	}
	return o
}

func TestThroughForwarder(t *testing.T) {
	f, pin := startForwarder(t, Limits{})
	key, peer := newClient(t)
	hs := startHub(t, f, pin, []tunnel.Peer{peer}, nil)
	if err := roundTrip(t, f, hs, key, peer); err != nil {
		t.Fatal(err)
	}
}

func TestObfuscatedThroughForwarder(t *testing.T) {
	f, pin := startForwarder(t, Limits{})
	key, peer := newClient(t)
	hs := startHub(t, f, pin, []tunnel.Peer{peer}, newObfuscation(t))
	if err := roundTrip(t, f, hs, key, peer); err != nil {
		t.Fatal(err)
	}
}

// TestGroupsApart runs two plain groups and two obfuscated ones through one
// forwarder.
func TestGroupsApart(t *testing.T) {
	f, pin := startForwarder(t, Limits{})
	for i, obf := range []*tunnel.Obfuscation{nil, newObfuscation(t), nil, newObfuscation(t)} {
		key, peer := newClient(t)
		hs := startHub(t, f, pin, []tunnel.Peer{peer}, obf)
		if err := roundTrip(t, f, hs, key, peer); err != nil {
			t.Fatalf("group %d: %v", i, err)
		}
	}
}

// initiation returns a handshake initiation addressed to pub, with the
// sender index idx: the rest is random, which the forwarder cannot tell.
func initiation(pub [32]byte, idx uint32) []byte {
	p := make([]byte, initiationSize)
	rand.Read(p)
	p[0], p[1], p[2], p[3] = msgInitiation, 0, 0, 0
	binary.LittleEndian.PutUint32(p[4:8], idx)
	k := mac1Key(pub)
	h, _ := blake2s.New128(k[:])
	h.Write(p[:initiationSize-32])
	h.Sum(p[:initiationSize-32])
	return p
}

func response(hubIdx, clientIdx uint32) []byte {
	p := make([]byte, responseSize)
	p[0] = msgResponse
	binary.LittleEndian.PutUint32(p[4:8], hubIdx)
	binary.LittleEndian.PutUint32(p[8:12], clientIdx)
	return p
}

func data(idx uint32) []byte {
	p := make([]byte, 64)
	p[0] = msgData
	binary.LittleEndian.PutUint32(p[4:8], idx)
	return p
}

// fakeReg registers a hub without a connection, for route's tests.
func fakeReg(f *Forwarder, tag string, hubEP netip.AddrPort) (*reg, [32]byte) {
	var pub [32]byte
	rand.Read(pub[:])
	now := time.Now()
	r := &reg{tag: tag, key: pub, mac1: mac1Key(pub), hubEP: hubEP, seen: make(chan netip.AddrPort, 1),
		clients: map[netip.AddrPort]int{}, conn: nopConn{}, raw: nopConn{}}
	rand.Read(r.helloKey[:])
	r.id = uint64(len(f.regs) + 1)
	r.packets, r.bytes = *newBucket(f.limits.PacketRate, now), *newBucket(f.limits.ByteRate, now)
	f.mu.Lock()
	f.regs[tag], f.byID[r.id], f.byHubEP[hubEP] = r, r, r
	f.mu.Unlock()
	return r, pub
}

type nopConn struct{ net.Conn }

func (nopConn) Close() error { return nil }

func TestRoute(t *testing.T) {
	cert, _ := NewCert()
	f, err := Listen(Config{Listen: "127.0.0.1:0", Cert: cert})
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	hubA, hubB := netip.MustParseAddrPort("198.51.100.1:8764"), netip.MustParseAddrPort("198.51.100.2:8764")
	client := netip.MustParseAddrPort("203.0.113.5:40000")
	other := netip.MustParseAddrPort("203.0.113.6:40000")
	_, pubA := fakeReg(f, "a", hubA)
	_, pubB := fakeReg(f, "b", hubB)
	now := time.Now()
	expect := func(what string, from netip.AddrPort, p []byte, want netip.AddrPort) {
		t.Helper()
		got, ok := f.route(from, p, now)
		if !want.IsValid() {
			if ok {
				t.Errorf("%s: went to %v, want dropped", what, got)
			}
			return
		}
		if !ok || got != want {
			t.Errorf("%s: went to %v (%v), want %v", what, got, ok, want)
		}
	}

	expect("a handshake to A", client, initiation(pubA, 7), hubA)
	expect("a handshake to B", client, initiation(pubB, 8), hubB)
	var nobody [32]byte
	rand.Read(nobody[:])
	expect("a handshake to no group", client, initiation(nobody, 9), netip.AddrPort{})
	expect("junk", client, []byte("GET / HTTP/1.1\r\n"), netip.AddrPort{})

	// A's answer goes to the client, and the session's data both ways.
	expect("A's answer", hubA, response(100, 7), client)
	expect("the client's data to A", client, data(100), hubA)
	expect("A's data to the client", hubA, data(7), client)
	// B knows no client index 7 of its own: its packets go nowhere.
	expect("B's data with A's client index", hubB, data(7), netip.AddrPort{})
	expect("B's answer for A's handshake", hubB, response(200, 7), netip.AddrPort{})
	// Data with an index no hub chose goes nowhere.
	expect("data of no session", other, data(12345), netip.AddrPort{})
	// A hub's own handshake has no route.
	expect("a handshake from A", hubA, initiation(pubB, 1), netip.AddrPort{})
	// A client sends no answers.
	expect("an answer from a client", client, response(1, 2), netip.AddrPort{})
}

func TestRouteLimits(t *testing.T) {
	cert, _ := NewCert()
	limits := DefaultLimits
	limits.Clients = 2
	limits.SourceRate = 1000
	f, err := Listen(Config{Listen: "127.0.0.1:0", Cert: cert, Limits: limits})
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	hub := netip.MustParseAddrPort("198.51.100.1:8764")
	_, pub := fakeReg(f, "a", hub)
	now := time.Now()
	for i := range 3 {
		from := netip.AddrPortFrom(netip.MustParseAddr("203.0.113.5"), uint16(40000+i))
		_, ok := f.route(from, initiation(pub, uint32(i)), now)
		if want := i < 2; ok != want {
			t.Errorf("client %d: passed %v, want %v", i, ok, want)
		}
	}
	// One source may not flood the hubs with handshakes.
	limits.SourceRate = 1
	g, err := Listen(Config{Listen: "127.0.0.1:0", Cert: cert, Limits: limits})
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	_, pub = fakeReg(g, "a", hub)
	from := netip.MustParseAddrPort("203.0.113.5:40000")
	passed := 0
	for range 10 {
		if _, ok := g.route(from, initiation(pub, 1), now); ok {
			passed++
		}
	}
	if passed != 2 {
		t.Errorf("%d handshakes passed in a burst; want 2", passed)
	}
	// The sweep forgets a handshake the hub never answered.
	g.sweepAt(now.Add(time.Minute))
	if len(g.pending) != 0 {
		t.Errorf("%d handshakes still wait after a minute", len(g.pending))
	}
}

func TestHello(t *testing.T) {
	cert, _ := NewCert()
	f, err := Listen(Config{Listen: "127.0.0.1:0", Cert: cert})
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	hub := netip.MustParseAddrPort("198.51.100.1:8764")
	r, _ := fakeReg(f, "a", hub)
	moved := netip.MustParseAddrPort("198.51.100.1:9000")
	h := hello(&f.mask, &r.helloKey, r.id, 10)
	if h2 := hello(&f.mask, &r.helloKey, r.id, 10); bytes.Equal(h[:helloMin], h2[:helloMin]) {
		t.Error("two hellos look the same on the wire")
	}
	if messageType(h) != 0 || h[0] == msgHello && h[1] == 0 && h[2] == 0 && h[3] == 0 {
		t.Error("a hello shows its type")
	}
	now := time.Now()
	f.route(moved, h, now)
	if r.hubEP != moved {
		t.Fatalf("the hub is at %v after its hello from %v", r.hubEP, moved)
	}
	// The same hello again, from elsewhere: a replay moves nothing.
	f.route(netip.MustParseAddrPort("203.0.113.66:1"), h, now)
	if r.hubEP != moved {
		t.Fatalf("a replayed hello moved the hub to %v", r.hubEP)
	}
	// A hello under another key moves nothing.
	var wrong [32]byte
	f.route(netip.MustParseAddrPort("203.0.113.66:1"), hello(&f.mask, &wrong, r.id, 11), now)
	if r.hubEP != moved {
		t.Fatalf("a forged hello moved the hub to %v", r.hubEP)
	}
	// A hello under another forwarder's mask moves nothing either.
	f.route(netip.MustParseAddrPort("203.0.113.66:1"), hello(&wrong, &r.helloKey, r.id, 12), now)
	if r.hubEP != moved {
		t.Fatalf("a forged hello moved the hub to %v", r.hubEP)
	}
}

// rawRegister registers by hand, claiming key with the proof made by
// holder: a hub that holds key passes holder == key.
func rawRegister(t *testing.T, f *Forwarder, pin string, cert tls.Certificate, claimKey []byte, holder *ecdh.PrivateKey) answer {
	t.Helper()
	tc, err := tls.Dial("tcp", f.Addr().String(), &tls.Config{
		MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}, NextProtos: []string{Protocol},
		InsecureSkipVerify: true,
	})
	if err != nil {
		return answer{Error: err.Error()}
	}
	defer tc.Close()
	if Pin(tc.ConnectionState().PeerCertificates[0]) != pin {
		t.Fatal("the forwarder's pin changed")
	}
	dec := json.NewDecoder(tc)
	var ch challenge
	if err := dec.Decode(&ch); err != nil {
		return answer{Error: err.Error()}
	}
	e, _ := ecdh.X25519().NewPublicKey(ch.E)
	shared, _ := holder.ECDH(e)
	p, _ := proof(shared, tc.ConnectionState())
	json.NewEncoder(tc).Encode(claim{Key: claimKey, Proof: p})
	var a answer
	if err := dec.Decode(&a); err != nil {
		return answer{Error: err.Error()}
	}
	return a
}

func TestRegistration(t *testing.T) {
	f, pin := startForwarder(t, Limits{})
	cert, tag := member(t)
	mine, _ := ecdh.X25519().GenerateKey(rand.Reader)
	theirs, _ := ecdh.X25519().GenerateKey(rand.Reader)

	if a := rawRegister(t, f, pin, cert, theirs.PublicKey().Bytes(), mine); !strings.Contains(a.Error, "does not hold") {
		t.Errorf("a hub that claims another's WireGuard key: %+v", a)
	}
	a := rawRegister(t, f, pin, cert, mine.PublicKey().Bytes(), mine)
	if a.Error != "" || a.ID == 0 {
		t.Fatalf("a hub with its own key: %+v", a)
	}
	for i := 0; ; i++ {
		f.mu.Lock()
		_, there := f.regs[tag]
		f.mu.Unlock()
		if !there {
			break
		}
		if i == 100 {
			t.Fatal("the registration outlived its connection")
		}
		time.Sleep(50 * time.Millisecond)
	}

	// Another group cannot register that key.
	other, _ := member(t)
	done := make(chan answer, 1)
	tc, err := tls.Dial("tcp", f.Addr().String(), &tls.Config{
		MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}, NextProtos: []string{Protocol}, InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer tc.Close()
	go func() {
		dec := json.NewDecoder(tc)
		var ch challenge
		dec.Decode(&ch)
		e, _ := ecdh.X25519().NewPublicKey(ch.E)
		shared, _ := mine.ECDH(e)
		p, _ := proof(shared, tc.ConnectionState())
		json.NewEncoder(tc).Encode(claim{Key: mine.PublicKey().Bytes(), Proof: p})
		var a answer
		dec.Decode(&a)
		done <- a
	}()
	if a := <-done; a.Error != "" {
		t.Fatalf("registering: %+v", a)
	}
	if a := rawRegister(t, f, pin, other, mine.PublicKey().Bytes(), mine); !strings.Contains(a.Error, "another group") {
		t.Errorf("another group with the same WireGuard key: %+v", a)
	}

	// A certificate without a group's chain gets no registration.
	self, _ := NewCert()
	if a := rawRegister(t, f, pin, self, mine.PublicKey().Bytes(), mine); a.ID != 0 {
		t.Errorf("a certificate of no group registered: %+v", a)
	}
	leafOnly := cert
	leafOnly.Certificate = cert.Certificate[:1]
	if a := rawRegister(t, f, pin, leafOnly, mine.PublicKey().Bytes(), mine); a.ID != 0 {
		t.Errorf("a member certificate without its root registered: %+v", a)
	}
}

func TestWrongPin(t *testing.T) {
	f, _ := startForwarder(t, Limits{})
	cert, _ := member(t)
	key, _ := tunnel.NewPrivateKey()
	other, _ := NewCert()
	reports := make(chan Report, 4)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go Register(ctx, HubConfig{Link: Link{Endpoint: f.Addr(), Pin: Pin(other.Leaf)}, Key: key, Cert: func() tls.Certificate { return cert },
		Send: func(netip.AddrPort, []byte) error { return nil }, Report: func(r Report) { reports <- r }})
	select {
	case r := <-reports:
		if r.Registered || r.Err == nil || !strings.Contains(r.Err.Error(), "not the one given") {
			t.Fatalf("with another forwarder's pin: %+v", r)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("no report")
	}
}

func TestPin(t *testing.T) {
	cert, _ := NewCert()
	if err := CheckPin(Pin(cert.Leaf)); err != nil {
		t.Error(err)
	}
	for _, bad := range []string{"", "sha256:", "sha256:abc", "md5:" + strings.Repeat("A", 43)} {
		if CheckPin(bad) == nil {
			t.Errorf("CheckPin(%q) passed", bad)
		}
	}
	path := t.TempDir() + "/key.pem"
	a, err := LoadCert(path)
	if err != nil {
		t.Fatal(err)
	}
	b, err := LoadCert(path)
	if err != nil {
		t.Fatal(err)
	}
	if Pin(a.Leaf) != Pin(b.Leaf) {
		t.Error("the forwarder's key changed when it was read again")
	}
}

// obfuscate pads the plain message m and protects its header, as
// amneziawg-go sends it in a group with the settings o; m's type field is
// set to a value of the type's range.
func obfuscate(o *tunnel.Obfuscation, m []byte) []byte {
	var padding int
	var types tunnel.Range
	switch m[0] {
	case msgInitiation:
		padding, types = o.S1, o.H1
	case msgResponse:
		padding, types = o.S2, o.H2
	case msgCookie:
		padding, types = o.S3, o.H3
	default:
		padding, types = o.S4, o.H4
	}
	p := make([]byte, padding+len(m))
	rand.Read(p[:padding])
	copy(p[padding:], m)
	binary.LittleEndian.PutUint32(p[padding:], types.Min+uint32(m[1]))
	n := len(m)
	if m[0] == msgData {
		n = dataHeaderSize
	}
	c, _ := chacha20.NewUnauthenticatedCipher(o.HeaderKey[:], p[:headerNonceSize])
	c.XORKeyStream(p[padding:padding+n], p[padding:padding+n])
	return p
}

// obfuscatedInitiation is initiation's message to pub as an obfuscated
// group sends it: mac1 covers the type field the group chose.
func obfuscatedInitiation(o *tunnel.Obfuscation, pub [32]byte, idx uint32) []byte {
	m := make([]byte, initiationSize)
	rand.Read(m)
	binary.LittleEndian.PutUint32(m[0:4], o.H1.Min+5)
	binary.LittleEndian.PutUint32(m[4:8], idx)
	k := mac1Key(pub)
	h, _ := blake2s.New128(k[:])
	h.Write(m[:initiationSize-32])
	h.Sum(m[:initiationSize-32])
	p := make([]byte, o.S1+initiationSize)
	rand.Read(p[:o.S1])
	copy(p[o.S1:], m)
	c, _ := chacha20.NewUnauthenticatedCipher(o.HeaderKey[:], p[:headerNonceSize])
	c.XORKeyStream(p[o.S1:], p[o.S1:])
	return p
}

func TestRouteObfuscated(t *testing.T) {
	cert, _ := NewCert()
	f, err := Listen(Config{Listen: "127.0.0.1:0", Cert: cert})
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	hubA, hubB, hubP := netip.MustParseAddrPort("198.51.100.1:8764"), netip.MustParseAddrPort("198.51.100.2:8764"), netip.MustParseAddrPort("198.51.100.3:8764")
	client := netip.MustParseAddrPort("203.0.113.5:40000")
	other := netip.MustParseAddrPort("203.0.113.6:40000")
	// B's handshake initiation has the size of A's, so that only the
	// header key tells them apart.
	oA, oB := newObfuscation(t), newObfuscation(t)
	for oB.S1 = oA.S1; oB.Check() != nil; oB.S1 = oA.S1 {
		oB = newObfuscation(t)
	}
	rA, pubA := fakeReg(f, "a", hubA)
	rB, pubB := fakeReg(f, "b", hubB)
	_, pubP := fakeReg(f, "p", hubP)
	f.mu.Lock()
	rA.obf, rB.obf = oA, oB
	f.byInit[initSize(oA)] = append(f.byInit[initSize(oA)], rA)
	f.byInit[initSize(oB)] = append(f.byInit[initSize(oB)], rB)
	f.mu.Unlock()
	now := time.Now()
	expect := func(what string, from netip.AddrPort, p []byte, want netip.AddrPort) {
		t.Helper()
		got, ok := f.route(from, p, now)
		if !want.IsValid() {
			if ok {
				t.Errorf("%s: went to %v, want dropped", what, got)
			}
			return
		}
		if !ok || got != want {
			t.Errorf("%s: went to %v (%v), want %v", what, got, ok, want)
		}
	}

	expect("a handshake to A", client, obfuscatedInitiation(oA, pubA, 7), hubA)
	expect("a handshake to B", other, obfuscatedInitiation(oB, pubB, 8), hubB)
	expect("a plain handshake to A", client, initiation(pubA, 9), netip.AddrPort{})
	expect("a handshake to A with B's settings", client, obfuscatedInitiation(oB, pubA, 10), netip.AddrPort{})
	expect("a plain handshake to the plain group", client, initiation(pubP, 11), hubP)

	expect("A's answer", hubA, obfuscate(oA, response(100, 7)), client)
	expect("a plain answer from A", hubA, response(101, 7), netip.AddrPort{})
	expect("the client's data to A", client, obfuscate(oA, data(100)), hubA)
	expect("the client's plain data to A", client, data(100), netip.AddrPort{})
	expect("A's data to the client", hubA, obfuscate(oA, data(7)), client)
	expect("data to A with B's settings", client, obfuscate(oB, data(100)), netip.AddrPort{})
	expect("A's data from another address", other, obfuscate(oA, data(100)), netip.AddrPort{})
	expect("junk", client, make([]byte, 200), netip.AddrPort{})

	expect("B's answer", hubB, obfuscate(oB, response(200, 8)), other)
	expect("the other client's data to B", other, obfuscate(oB, data(200)), hubB)
}

func TestThroughVLESS(t *testing.T) {
	for _, obfuscated := range []bool{false, true} {
		t.Run(fmt.Sprintf("obfuscated=%v", obfuscated), func(t *testing.T) {
			// A forwarder of its own, so that the first case's hub and
			// Xray are gone before the second.
			var rk [32]byte
			rand.Read(rk[:])
			f, pin := startForwarderWith(t, Config{VLESS: &VLESSConfig{Listen: "127.0.0.1:0", Site: vlesstest.Site, Dest: vlesstest.Decoy(t), Key: rk}})
			var obf *tunnel.Obfuscation
			if obfuscated {
				obf = newObfuscation(t)
			}
			id, err := tunnel.NewVLESSID()
			if err != nil {
				t.Fatal(err)
			}
			key, peer := newClient(t)
			hs := startHubWith(t, f, pin, []tunnel.Peer{peer}, HubConfig{Obfuscation: obf, VLESSID: id})
			if hs.vless == nil || hs.vless.ID != id || hs.vless.Endpoint.Port() != f.vless.Port() {
				t.Fatalf("the hub learned %+v", hs.vless)
			}
			vc, err := vless.Dial(*hs.vless)
			if err != nil {
				t.Fatal(err)
			}
			defer vc.Close()
			if err := roundTripTo(t, vc.Addr(), hs, key, peer); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestVLESSRefused(t *testing.T) {
	f, pin := startForwarder(t, Limits{})
	cert, _ := member(t)
	key, _ := tunnel.NewPrivateKey()
	id, _ := tunnel.NewVLESSID()
	reports := make(chan Report, 4)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go Register(ctx, HubConfig{Link: Link{Endpoint: f.Addr(), Pin: pin}, Key: key, VLESSID: id,
		Cert: func() tls.Certificate { return cert }, Send: func(netip.AddrPort, []byte) error { return nil },
		Report: func(r Report) { reports <- r }})
	select {
	case r := <-reports:
		if r.Err == nil || !strings.Contains(r.Err.Error(), "no VLESS") {
			t.Fatalf("a hub asking a forwarder without VLESS: %+v", r)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("no answer")
	}
}
