// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Package forward is the forwarder for sync away from home: a server that
// holds no keys and passes encrypted WireGuard packets between a group's
// clients and that group's hub, for homes that clients cannot reach
// directly, such as those behind carrier-grade NAT (docs/design.md, "The
// forwarder"; docs/protocol.md, section 13).
//
// It listens on one port, UDP for the packets and TCP for the hubs'
// registrations. A hub keeps one TLS connection to it, proves there that it
// is a member of a group and holds its WireGuard key, and then sends hellos
// from its WireGuard port so that the forwarder learns where that port is
// reached. A client's handshake goes to the hub whose public key its mac1
// field is keyed with; the hub's answer and the data that follow go by the
// indices the two chose. Nothing is added to the packets, so the network
// cannot tell groups apart, and a packet goes only to its own group's hub
// or to a client of that hub. The forwarder keeps everything in memory and
// writes nothing about the groups or their devices, not even to its log.
package forward

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"
)

// Limits bound what one group, one source and all of them may take, so
// that no group can slow down another.
type Limits struct {
	Groups      int     // registered hubs
	Clients     int     // client addresses of one group
	Pending     int     // handshakes of one group waiting for the hub's answer
	PacketRate  float64 // packets per second of one group, both ways
	ByteRate    float64 // bytes per second of one group, both ways
	SourceRate  float64 // handshakes per second from one address
	Connections int     // registrations being set up at a time
}

// DefaultLimits are generous for clipboard texts and small enough that a
// small server keeps many groups.
var DefaultLimits = Limits{
	Groups:      100_000,
	Clients:     16,
	Pending:     64,
	PacketRate:  1000,
	ByteRate:    2 << 20,
	SourceRate:  10,
	Connections: 256,
}

// How long the forwarder remembers a handshake and a session. WireGuard
// drops a session after 180 seconds; its initiator makes a new one every
// 120 seconds while it is in use.
const (
	pendingFor = 10 * time.Second
	sessionFor = 200 * time.Second
	sweepEvery = 10 * time.Second
)

// Forwarder is a running forwarder.
type Forwarder struct {
	udp    *net.UDPConn
	tcp    net.Listener
	tlsCfg *tls.Config
	limits Limits
	logf   func(string, ...any)

	mu       sync.Mutex
	regs     map[string]*reg // by group tag
	byID     map[uint64]*reg // by registration ID, for hellos
	byHubEP  map[netip.AddrPort]*reg
	pending  map[clientKey]pending
	byHubIdx map[uint32]*session
	byClient map[clientKey]*session
	sources  map[netip.Addr]*bucket
	setting  int // registrations being set up

	closeOnce sync.Once
	done      chan struct{}
	wg        sync.WaitGroup
}

// reg is a hub's registration.
type reg struct {
	tag      string
	key      [32]byte // the hub's WireGuard public key
	mac1     [32]byte // mac1Key(key)
	id       uint64
	helloKey [32]byte
	counter  uint64         // the last hello's
	hubEP    netip.AddrPort // where the hub's WireGuard port is reached; zero before its first hello
	seen     chan netip.AddrPort
	clients  map[netip.AddrPort]int // client addresses and their handshakes and sessions
	waiting  int                    // handshakes that wait for the hub's answer
	packets  bucket
	bytes    bucket
	closed   bool
	conn     net.Conn // the registration's TLS
	raw      net.Conn // its TCP connection, which closes without waiting, unlike TLS
}

// clientKey names a client's session by the index it chose; indices are
// unique only per hub.
type clientKey struct {
	reg *reg
	idx uint32
}

type pending struct {
	from netip.AddrPort
	at   time.Time
}

// session is a WireGuard session between a client and a hub.
type session struct {
	reg       *reg
	client    netip.AddrPort
	clientIdx uint32
	hubIdx    uint32
	at        time.Time
}

// Config configures a forwarder.
type Config struct {
	Listen string          // the address to listen on, UDP and TCP, such as ":8764"
	Cert   tls.Certificate // the forwarder's own, whose key the hubs pin
	Limits Limits          // DefaultLimits if zero
	Logf   func(format string, args ...any)
}

// Listen opens the forwarder's ports. Serve then runs it.
func Listen(cfg Config) (*Forwarder, error) {
	logf := cfg.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}
	limits := cfg.Limits
	if limits == (Limits{}) {
		limits = DefaultLimits
	}
	ua, err := net.ResolveUDPAddr("udp", cfg.Listen)
	if err != nil {
		return nil, fmt.Errorf("forward: %w", err)
	}
	udp, err := net.ListenUDP("udp", ua)
	if err != nil {
		return nil, fmt.Errorf("forward: %w", err)
	}
	// TCP on the same port as UDP, which may have been picked just now.
	port := udp.LocalAddr().(*net.UDPAddr).Port
	host, _, err := net.SplitHostPort(cfg.Listen)
	if err != nil {
		udp.Close()
		return nil, fmt.Errorf("forward: %w", err)
	}
	tcp, err := net.Listen("tcp", net.JoinHostPort(host, fmt.Sprint(port)))
	if err != nil {
		udp.Close()
		return nil, fmt.Errorf("forward: %w", err)
	}
	f := &Forwarder{
		udp: udp, tcp: tcp, limits: limits, logf: logf,
		regs: map[string]*reg{}, byID: map[uint64]*reg{}, byHubEP: map[netip.AddrPort]*reg{},
		pending: map[clientKey]pending{}, byHubIdx: map[uint32]*session{}, byClient: map[clientKey]*session{},
		sources: map[netip.Addr]*bucket{},
		done:    make(chan struct{}),
	}
	f.tlsCfg = f.serverTLS(cfg.Cert)
	return f, nil
}

// Addr returns the forwarder's UDP address.
func (f *Forwarder) Addr() netip.AddrPort {
	return f.udp.LocalAddr().(*net.UDPAddr).AddrPort()
}

// Serve forwards packets and takes registrations until ctx is done or the
// forwarder is closed.
func (f *Forwarder) Serve(ctx context.Context) error {
	f.wg.Add(3)
	go func() {
		defer f.wg.Done()
		f.acceptRegistrations()
	}()
	go func() {
		defer f.wg.Done()
		f.sweep()
	}()
	go func() {
		defer f.wg.Done()
		select {
		case <-ctx.Done():
			f.Close()
		case <-f.done:
		}
	}()
	err := f.forward()
	f.Close()
	f.wg.Wait()
	if ctx.Err() != nil {
		return nil
	}
	return err
}

// Close stops the forwarder; every hub's registration ends with it.
func (f *Forwarder) Close() error {
	f.closeOnce.Do(func() {
		close(f.done)
		f.udp.Close()
		f.tcp.Close()
		f.mu.Lock()
		for _, r := range f.regs {
			r.raw.Close()
		}
		f.mu.Unlock()
	})
	return nil
}

// forward reads the UDP port and passes each packet on, or drops it.
func (f *Forwarder) forward() error {
	buf := make([]byte, 65536)
	for {
		n, from, err := f.udp.ReadFromUDPAddrPort(buf)
		if err != nil {
			select {
			case <-f.done:
				return nil
			default:
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return fmt.Errorf("forward: %w", err)
		}
		from = netip.AddrPortFrom(from.Addr().Unmap(), from.Port())
		if to, ok := f.route(from, buf[:n], time.Now()); ok {
			// A packet that cannot go out is lost, as on any network.
			_, _ = f.udp.WriteToUDPAddrPort(buf[:n], to)
		}
	}
}

// route decides where the packet p from goes: to its group's hub, to a
// client of the hub it came from, or nowhere.
func (f *Forwarder) route(from netip.AddrPort, p []byte, now time.Time) (netip.AddrPort, bool) {
	t := messageType(p)
	if t == 0 {
		return netip.AddrPort{}, false
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if t == msgHello {
		f.helloLocked(from, p)
		return netip.AddrPort{}, false
	}
	if r := f.byHubEP[from]; r != nil {
		return f.fromHubLocked(r, t, p, now)
	}
	return f.fromClientLocked(from, t, p, now)
}

// fromHubLocked passes a hub's answer or data to the client whose index it
// names. A hub's own handshake to a client has nowhere to go: its mac1 is
// keyed with the client's key, which the forwarder does not know; clients
// make the handshakes and keep their sessions fresh.
func (f *Forwarder) fromHubLocked(r *reg, t byte, p []byte, now time.Time) (netip.AddrPort, bool) {
	if !r.take(len(p), now) {
		return netip.AddrPort{}, false
	}
	ck := clientKey{r, receiverIndex(p)}
	switch t {
	case msgResponse:
		pd, ok := f.pending[ck]
		if !ok {
			return netip.AddrPort{}, false
		}
		f.unpendLocked(ck, pd)
		hubIdx := senderIndex(p)
		if old := f.byHubIdx[hubIdx]; old != nil {
			// Another session took the same index; the newer wins, and the
			// older's client makes a new handshake when it hears nothing.
			f.dropSessionLocked(old)
		}
		if old := f.byClient[ck]; old != nil {
			f.dropSessionLocked(old)
		}
		s := &session{reg: r, client: pd.from, clientIdx: ck.idx, hubIdx: hubIdx, at: now}
		f.byHubIdx[hubIdx], f.byClient[ck] = s, s
		r.clients[pd.from]++
		return pd.from, true
	case msgCookie:
		if pd, ok := f.pending[ck]; ok {
			return pd.from, true
		}
		if s := f.byClient[ck]; s != nil {
			return s.client, true
		}
	case msgData:
		if s := f.byClient[ck]; s != nil {
			return s.client, true
		}
	}
	return netip.AddrPort{}, false
}

// fromClientLocked passes a client's handshake to the hub it is addressed
// to, and its data to the hub of its session.
func (f *Forwarder) fromClientLocked(from netip.AddrPort, t byte, p []byte, now time.Time) (netip.AddrPort, bool) {
	switch t {
	case msgInitiation:
		src := f.sources[from.Addr()]
		if src == nil {
			if len(f.sources) >= 4*f.limits.Groups {
				return netip.AddrPort{}, false
			}
			src = newBucket(f.limits.SourceRate, now)
			f.sources[from.Addr()] = src
		}
		if !src.take(1, now) {
			return netip.AddrPort{}, false
		}
		r := f.addressedLocked(p)
		if r == nil || !r.hubEP.IsValid() || !r.take(len(p), now) {
			return netip.AddrPort{}, false
		}
		if _, known := r.clients[from]; !known && len(r.clients) >= f.limits.Clients {
			return netip.AddrPort{}, false
		}
		ck := clientKey{r, senderIndex(p)}
		if old, again := f.pending[ck]; again {
			f.unpendLocked(ck, old)
		} else if r.waiting >= f.limits.Pending {
			return netip.AddrPort{}, false
		}
		f.pending[ck] = pending{from: from, at: now}
		r.clients[from]++
		r.waiting++
		return r.hubEP, true
	case msgData:
		s := f.byHubIdx[receiverIndex(p)]
		if s == nil || !s.reg.hubEP.IsValid() || !s.reg.take(len(p), now) {
			return netip.AddrPort{}, false
		}
		return s.reg.hubEP, true
	}
	// A client answers no handshake: the forwarder passes none from a hub.
	return netip.AddrPort{}, false
}

// addressedLocked returns the registration whose hub the handshake
// initiation p is addressed to, or nil. It costs one keyed BLAKE2s per
// group.
func (f *Forwarder) addressedLocked(p []byte) *reg {
	for _, r := range f.regs {
		if hasMac1(&r.mac1, p) {
			return r
		}
	}
	return nil
}

// helloLocked takes a hub's hello: the hub's WireGuard port is where it
// came from.
func (f *Forwarder) helloLocked(from netip.AddrPort, p []byte) {
	id, counter := readHello(p)
	r := f.byID[id]
	if r == nil || counter <= r.counter || !checkHello(&r.helloKey, p) {
		return
	}
	r.counter = counter
	if r.hubEP == from {
		return
	}
	if other := f.byHubEP[from]; other != nil && other != r {
		// Two hubs cannot share a port; the newer hello wins.
		other.hubEP = netip.AddrPort{}
	}
	delete(f.byHubEP, r.hubEP)
	r.hubEP = from
	f.byHubEP[from] = r
	select {
	case r.seen <- from:
	default:
	}
}

// dropSessionLocked forgets a session.
func (f *Forwarder) dropSessionLocked(s *session) {
	if f.byHubIdx[s.hubIdx] == s {
		delete(f.byHubIdx, s.hubIdx)
	}
	ck := clientKey{s.reg, s.clientIdx}
	if f.byClient[ck] == s {
		delete(f.byClient, ck)
	}
	s.reg.clients[s.client]--
	if s.reg.clients[s.client] <= 0 {
		delete(s.reg.clients, s.client)
	}
}

// dropRegLocked forgets a registration and everything of its group.
func (f *Forwarder) dropRegLocked(r *reg) {
	if r.closed {
		return
	}
	r.closed = true
	if f.regs[r.tag] == r {
		delete(f.regs, r.tag)
	}
	delete(f.byID, r.id)
	if f.byHubEP[r.hubEP] == r {
		delete(f.byHubEP, r.hubEP)
	}
	for ck := range f.pending {
		if ck.reg == r {
			delete(f.pending, ck)
		}
	}
	for _, s := range f.byHubIdx {
		if s.reg == r {
			f.dropSessionLocked(s)
		}
	}
	r.raw.Close()
}

// sweep forgets old handshakes, sessions and sources.
func (f *Forwarder) sweep() {
	t := time.NewTicker(sweepEvery)
	defer t.Stop()
	for {
		select {
		case <-f.done:
			return
		case now := <-t.C:
			f.sweepAt(now)
		}
	}
}

func (f *Forwarder) sweepAt(now time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for ck, pd := range f.pending {
		if now.Sub(pd.at) > pendingFor {
			f.unpendLocked(ck, pd)
		}
	}
	for _, s := range f.byHubIdx {
		if now.Sub(s.at) > sessionFor {
			f.dropSessionLocked(s)
		}
	}
	for a, b := range f.sources {
		if b.full(now) {
			delete(f.sources, a)
		}
	}
}

// unpendLocked forgets a handshake that waited for the hub.
func (f *Forwarder) unpendLocked(ck clientKey, pd pending) {
	delete(f.pending, ck)
	r := ck.reg
	r.waiting--
	r.clients[pd.from]--
	if r.clients[pd.from] <= 0 {
		delete(r.clients, pd.from)
	}
}

// take charges a packet of n bytes to the group; false drops it.
func (r *reg) take(n int, now time.Time) bool {
	return r.packets.take(1, now) && r.bytes.take(float64(n), now)
}

// bucket is a token bucket: rate tokens a second, up to two seconds' worth.
type bucket struct {
	rate, tokens float64
	at           time.Time
}

func newBucket(rate float64, now time.Time) *bucket {
	return &bucket{rate: rate, tokens: 2 * rate, at: now}
}

func (b *bucket) fill(now time.Time) {
	b.tokens = min(2*b.rate, b.tokens+now.Sub(b.at).Seconds()*b.rate)
	b.at = now
}

func (b *bucket) take(n float64, now time.Time) bool {
	b.fill(now)
	if b.tokens < n {
		return false
	}
	b.tokens -= n
	return true
}

func (b *bucket) full(now time.Time) bool {
	b.fill(now)
	return b.tokens >= 2*b.rate
}

// Stats counts what the forwarder holds now, for a debug log: no group,
// device or address is in it.
type Stats struct {
	Groups, Sessions, Waiting int
}

// Stats returns what the forwarder holds now.
func (f *Forwarder) Stats() Stats {
	f.mu.Lock()
	defer f.mu.Unlock()
	return Stats{Groups: len(f.regs), Sessions: len(f.byHubIdx), Waiting: len(f.pending)}
}
