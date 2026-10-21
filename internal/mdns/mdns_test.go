// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package mdns

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// fakeNet is a link that delivers multicast packets to every host on it,
// the sender included, as multicast loopback does.
type fakeNet struct {
	mu    sync.Mutex
	hosts []*fakeHost
}

type fakeHost struct {
	net     *fakeNet
	addrs   []netip.Addr
	packets chan packet
	sent    chan packet // a copy of everything the host sends, for tests
	once    sync.Once
	closed  chan struct{}
}

func (n *fakeNet) host(addrs ...string) *fakeHost {
	h := &fakeHost{net: n, packets: make(chan packet, 256), sent: make(chan packet, 256), closed: make(chan struct{})}
	for _, a := range addrs {
		h.addrs = append(h.addrs, netip.MustParseAddr(a))
	}
	slices.SortFunc(h.addrs, func(a, b netip.Addr) int { return a.Compare(b) })
	n.mu.Lock()
	n.hosts = append(n.hosts, h)
	n.mu.Unlock()
	return h
}

func (h *fakeHost) read() (packet, error) {
	select {
	case p := <-h.packets:
		return p, nil
	case <-h.closed:
		return packet{}, net.ErrClosed
	}
}

func (h *fakeHost) src(dst netip.AddrPort, port uint16) netip.AddrPort {
	for _, a := range h.addrs {
		if a.Is4() == dst.Addr().Is4() {
			return netip.AddrPortFrom(a, port)
		}
	}
	return netip.AddrPortFrom(h.addrs[0], port)
}

func (h *fakeHost) send(data []byte, ifIndex int, dst netip.AddrPort) error {
	return h.sendFrom(Port, data, dst)
}

func (h *fakeHost) sendFrom(port uint16, data []byte, dst netip.AddrPort) error {
	select {
	case <-h.closed:
		return net.ErrClosed
	default:
	}
	p := packet{data: slices.Clone(data), src: h.src(dst, port), ifIndex: 1}
	select {
	case h.sent <- packet{data: p.data, src: dst, ifIndex: 1}:
	default:
	}
	h.net.mu.Lock()
	hosts := slices.Clone(h.net.hosts)
	h.net.mu.Unlock()
	for _, o := range hosts {
		if dst.Addr().IsMulticast() || slices.Contains(o.addrs, dst.Addr()) {
			select {
			case o.packets <- p:
			case <-o.closed:
			default:
			}
		}
	}
	return nil
}

func (h *fakeHost) interfaces() ([]iface, error) {
	f := iface{index: 1, name: "eth0"}
	for _, a := range h.addrs {
		bits := 24
		if a.Is6() {
			bits = 64
		}
		f.prefixes = append(f.prefixes, netip.PrefixFrom(a, bits).Masked())
		if Published(a) {
			f.addrs = append(f.addrs, a)
			f.has4 = f.has4 || a.Is4()
			f.has6 = f.has6 || a.Is6()
		}
	}
	return []iface{f}, nil
}

func (h *fakeHost) close() error {
	h.once.Do(func() { close(h.closed) })
	return nil
}

const (
	idA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	idB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

// run starts a responder on host and returns a channel of its peer sets.
func run(t *testing.T, h *fakeHost, id string, port uint16, now func() time.Time) (*Responder, <-chan []Peer, context.CancelFunc) {
	t.Helper()
	peers := make(chan []Peer, 64)
	r, err := New(Config{ID: id, Port: port, TXT: []string{"v=1", "g=0123456789abcdef"}, Now: now, net: h,
		OnPeers: func(p []Peer) { peers <- p }, Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); r.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-done })
	return r, peers, func() { cancel(); <-done }
}

func waitPeers(t *testing.T, ch <-chan []Peer, ok func([]Peer) bool) []Peer {
	t.Helper()
	timeout := time.After(10 * time.Second)
	for {
		select {
		case p := <-ch:
			if ok(p) {
				return p
			}
		case <-timeout:
			t.Fatal("timed out waiting for peers")
		}
	}
}

func TestTwoMembersFindEachOther(t *testing.T) {
	var n fakeNet
	a := n.host("192.168.1.10", "fe80::a")
	b := n.host("192.168.1.11", "fd00::b")
	_, peersA, _ := run(t, a, idA, 4001, nil)
	_, peersB, _ := run(t, b, idB, 4002, nil)
	got := waitPeers(t, peersA, func(p []Peer) bool { return len(p) == 1 && len(p[0].Addrs) == 2 })
	want := Peer{ID: idB, Port: 4002, TXT: []string{"v=1", "g=0123456789abcdef"},
		Addrs: []netip.Addr{netip.MustParseAddr("192.168.1.11"), netip.MustParseAddr("fd00::b")}}
	if !peerEqual(got[0], want) {
		t.Errorf("A found %+v, want %+v", got[0], want)
	}
	if v, ok := got[0].TXTValue("G"); !ok || v != "0123456789abcdef" {
		t.Errorf("TXTValue(G) = %q, %v", v, ok)
	}
	got = waitPeers(t, peersB, func(p []Peer) bool { return len(p) == 1 && len(p[0].Addrs) == 2 })
	if got[0].ID != idA || got[0].Addrs[1] != netip.MustParseAddr("fe80::a").WithZone("eth0") {
		t.Errorf("B found %+v; want A with a link-local address on eth0", got[0])
	}
}

func peerEqual(a, b Peer) bool {
	return a.ID == b.ID && a.Port == b.Port && slices.Equal(a.TXT, b.TXT) && slices.Equal(a.Addrs, b.Addrs)
}

// ask sends a query from a host that runs no responder and returns the
// first response that answers it: one whose answers all name the first
// question's name, and, for a legacy query from a port other than 5353,
// with the query's ID. It returns nil if none arrives within a second.
func ask(t *testing.T, client *fakeHost, port uint16, qs ...dnsmessage.Question) *dnsmessage.Message {
	t.Helper()
	msg := dnsmessage.Message{Header: dnsmessage.Header{ID: 77}, Questions: qs}
	data, err := msg.Pack()
	if err != nil {
		t.Fatal(err)
	}
	if err := client.sendFrom(port, data, group4); err != nil {
		t.Fatal(err)
	}
	timeout := time.After(time.Second)
	for {
		select {
		case p := <-client.packets:
			var m dnsmessage.Message
			if m.Unpack(p.data) != nil || !m.Response || (port != Port && m.ID != 77) {
				continue
			}
			// An announcement carries other names too; an answer only the
			// name asked for.
			if len(m.Answers) > 0 && !slices.ContainsFunc(m.Answers, func(r dnsmessage.Resource) bool {
				return !sameName(r.Header.Name, qs[0].Name.String())
			}) {
				return &m
			}
		case <-timeout:
			return nil
		}
	}
}

func q(n string, t dnsmessage.Type) dnsmessage.Question {
	return dnsmessage.Question{Name: dnsmessage.MustNewName(n), Type: t, Class: classIN}
}

func TestHolder(t *testing.T) {
	var n fakeNet
	a := n.host("192.168.1.10")
	client := n.host("192.168.1.20")
	r, _, _ := run(t, a, idA, 4001, nil)
	if m := ask(t, client, Port, q(PhoneName, dnsmessage.TypeA)); m != nil {
		t.Fatalf("answered for clipbridge.local without holding it: %v", m)
	}
	r.SetHolder(true)
	m := ask(t, client, Port, q(PhoneName, dnsmessage.TypeA))
	if m == nil {
		t.Fatal("no answer for clipbridge.local")
	}
	ans := m.Answers[0]
	if a, ok := ans.Body.(*dnsmessage.AResource); !ok || netip.AddrFrom4(a.A) != netip.MustParseAddr("192.168.1.10") ||
		ans.Header.TTL != 10 || ans.Header.Class != classIN|cacheFlush {
		t.Errorf("answer %v, want A 192.168.1.10 with TTL 10 and the cache-flush bit", ans.GoString())
	}
	// A question for AAAA gets the NSEC record, which says there is none.
	m = ask(t, client, Port, q(PhoneName, dnsmessage.TypeAAAA))
	if m == nil || typeOf(m.Answers[0]) != typeNSEC {
		t.Errorf("AAAA question: %v, want NSEC", m)
	}
	// Giving it up sends a goodbye.
	drain(client)
	r.SetHolder(false)
	if !waitFor(client, func(m *dnsmessage.Message) bool {
		return len(m.Answers) > 0 && sameName(m.Answers[0].Header.Name, PhoneName) && m.Answers[0].Header.TTL == 0
	}) {
		t.Error("no goodbye for clipbridge.local")
	}
}

func drain(h *fakeHost) {
	for {
		select {
		case <-h.packets:
		default:
			return
		}
	}
}

func waitFor(h *fakeHost, ok func(*dnsmessage.Message) bool) bool {
	timeout := time.After(5 * time.Second)
	for {
		select {
		case p := <-h.packets:
			var m dnsmessage.Message
			if m.Unpack(p.data) == nil && m.Response && ok(&m) {
				return true
			}
		case <-timeout:
			return false
		}
	}
}

func TestLegacyUnicast(t *testing.T) {
	var n fakeNet
	a := n.host("192.168.1.10")
	client := n.host("192.168.1.20")
	run(t, a, idA, 4001, nil)
	m := ask(t, client, 40000, q("cb-"+idA+".local.", dnsmessage.TypeA))
	if m == nil {
		t.Fatal("no answer to a legacy query")
	}
	if m.ID != 77 || len(m.Questions) != 1 || m.Answers[0].Header.TTL > 10 || m.Answers[0].Header.Class != classIN {
		t.Errorf("legacy answer %v", m.GoString())
	}
}

func TestOffLinkQueriesAreIgnored(t *testing.T) {
	var n fakeNet
	a := n.host("192.168.1.10")
	stranger := n.host("192.168.7.20") // another network
	run(t, a, idA, 4001, nil)
	// The services enumeration is answered only when asked.
	if m := ask(t, stranger, Port, q(servicesName, dnsmessage.TypePTR)); m != nil {
		t.Errorf("answered a query from another network: %v", m)
	}
	neighbour := n.host("192.168.1.30")
	if m := ask(t, neighbour, Port, q(servicesName, dnsmessage.TypePTR)); m == nil {
		t.Error("no answer to a query from the same network")
	}
}

func TestGoodbyeOnStop(t *testing.T) {
	var n fakeNet
	clock := &fakeClock{t: time.Unix(1_000_000, 0)}
	a := n.host("192.168.1.10")
	b := n.host("192.168.1.11")
	_, peersA, _ := run(t, a, idA, 4001, clock.now)
	_, _, stopB := run(t, b, idB, 4002, clock.now)
	waitPeers(t, peersA, func(p []Peer) bool { return len(p) == 1 })
	stopB()
	// The goodbye leaves the records a second to live: move the clock on
	// until A has dropped B, and well before B's records would expire on
	// their own.
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		for {
			select {
			case <-stop:
				return
			case <-time.After(50 * time.Millisecond):
				clock.advance(500 * time.Millisecond)
			}
		}
	}()
	waitPeers(t, peersA, func(p []Peer) bool { return len(p) == 0 })
	if waited := clock.now().Sub(time.Unix(1_000_000, 0)); waited > 60*time.Second {
		t.Errorf("A dropped B only after %v", waited)
	}
}

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func TestRecordsAreRefreshed(t *testing.T) {
	// A member that stays keeps being found after its records' lifetime
	// of two minutes, because the browser asks again before they expire.
	var n fakeNet
	clock := &fakeClock{t: time.Unix(1_000_000, 0)}
	a := n.host("192.168.1.10")
	b := n.host("192.168.1.11")
	_, peersA, _ := run(t, a, idA, 4001, clock.now)
	run(t, b, idB, 4002, clock.now)
	waitPeers(t, peersA, func(p []Peer) bool { return len(p) == 1 && len(p[0].Addrs) == 1 })
	for range 20 {
		clock.advance(15 * time.Second)
		time.Sleep(300 * time.Millisecond)
		for len(peersA) > 0 {
			if p := <-peersA; len(p) != 1 || len(p[0].Addrs) != 1 {
				t.Fatalf("at %v A sees %+v", clock.now().Sub(time.Unix(1_000_000, 0)), p)
			}
		}
	}
}

func TestNewChecksItsInput(t *testing.T) {
	for _, cfg := range []Config{
		{ID: ""}, {ID: "a.b"}, {ID: strings.Repeat("a", 60)},
		{ID: idA, TXT: []string{strings.Repeat("x", 256)}},
	} {
		if _, err := New(cfg); err == nil {
			t.Errorf("New(%+v) succeeded", cfg)
		}
	}
	r, err := New(Config{ID: idA, TXT: []string{"v=1"}})
	if err != nil {
		t.Fatal(err)
	}
	r.SetTXT([]string{strings.Repeat("x", 256)})
	if got := r.zone().txt; !slices.Equal(got, []string{"v=1"}) {
		t.Errorf("an oversized TXT record replaced the old one: %v", got)
	}
}

func TestPublished(t *testing.T) {
	for addr, want := range map[string]bool{
		"192.168.1.1": true, "10.0.0.1": true, "172.16.5.4": true, "fd12::1": true, "fe80::1": true,
		"8.8.8.8": false, "169.254.1.1": false, "127.0.0.1": false, "::1": false, "2001:db8::1": false,
		"100.64.0.1": false, "::ffff:192.168.1.1": true,
	} {
		if got := Published(netip.MustParseAddr(addr)); got != want {
			t.Errorf("Published(%s) = %v, want %v", addr, got, want)
		}
	}
}

func TestAnswer(t *testing.T) {
	z := newZone(idA, 4001, []string{"v=1"})
	ips := []netip.Addr{netip.MustParseAddr("192.168.1.10"), netip.MustParseAddr("fe80::a")}
	query := func(known []dnsmessage.Resource, qs ...dnsmessage.Question) ([]rr, []rr) {
		return z.answer(&dnsmessage.Message{Questions: qs, Answers: known}, ips)
	}
	ans, add := query(nil, q(ServiceName, dnsmessage.TypePTR))
	if len(ans) != 1 || typeOf(ans[0].res) != dnsmessage.TypePTR || ans[0].unique {
		t.Errorf("PTR answers %v", ans)
	}
	// SRV, TXT, A, AAAA and NSEC.
	if len(add) != 5 {
		t.Errorf("PTR additionals %d, want 5", len(add))
	}
	// A known answer with enough lifetime left is not repeated.
	ans, _ = query([]dnsmessage.Resource{z.ptr().res}, q(ServiceName, dnsmessage.TypePTR))
	if len(ans) != 0 {
		t.Errorf("known answer repeated: %v", ans)
	}
	old := z.ptr().res
	old.Header.TTL = otherTTL/2 - 1
	if ans, _ = query([]dnsmessage.Resource{old}, q(ServiceName, dnsmessage.TypePTR)); len(ans) != 1 {
		t.Error("a known answer about to expire was suppressed")
	}
	// Names are case-insensitive.
	if ans, _ = query(nil, q("CB-"+idA+".Local.", dnsmessage.TypeALL)); len(ans) != 2 {
		t.Errorf("ANY for the host: %d answers, want A and AAAA", len(ans))
	}
	if ans, _ = query(nil, q(servicesName, dnsmessage.TypePTR)); len(ans) != 1 {
		t.Error("no answer to service enumeration")
	}
	if ans, _ = query(nil, q("other.local.", dnsmessage.TypeA), q(PhoneName, dnsmessage.TypeA)); len(ans) != 0 {
		t.Errorf("answered for names it does not own: %v", ans)
	}
	if ans, _ = z.answer(&dnsmessage.Message{Questions: []dnsmessage.Question{q(ServiceName, dnsmessage.TypePTR)}}, nil); len(ans) != 0 {
		t.Error("answered on an interface without addresses")
	}
}

func TestNSEC(t *testing.T) {
	r := nsec("cb-x.local.", 120, true, true)
	want := append(appendWireName(nil, "cb-x.local."), 0, 4, 0x40, 0, 0, 0x08)
	if got := r.res.Body.(*dnsmessage.UnknownResource).Data; string(got) != string(want) {
		t.Errorf("NSEC data %x, want %x", got, want)
	}
	r = nsec("cb-x.local.", 120, true, false)
	want = append(appendWireName(nil, "cb-x.local."), 0, 1, 0x40)
	if got := r.res.Body.(*dnsmessage.UnknownResource).Data; string(got) != string(want) {
		t.Errorf("NSEC data %x, want %x", got, want)
	}
}

func TestCacheBounds(t *testing.T) {
	var c cache
	now := time.Unix(1000, 0)
	for i := range 2 * maxEntries {
		ip := netip.AddrFrom4([4]byte{10, 0, byte(i >> 8), byte(i)})
		c.add(&dnsmessage.Message{Answers: []dnsmessage.Resource{{
			Header: dnsmessage.ResourceHeader{Name: name("cb-" + idB + ".local."), Class: classIN, TTL: 120},
			Body:   &dnsmessage.AResource{A: ip.As4()},
		}}}, "eth0", now)
	}
	if len(c.entries) > maxEntries {
		t.Errorf("cache holds %d entries", len(c.entries))
	}
	c.expire(now.Add(121 * time.Second))
	if len(c.entries) != 0 {
		t.Errorf("%d entries after expiry", len(c.entries))
	}
}
