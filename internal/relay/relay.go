// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package relay

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/HunterEwok/clipboardbridge/internal/group"
	"github.com/HunterEwok/clipboardbridge/internal/tunnel"
)

// Limits of one group on the relay, which the user runs for their own
// groups; they keep one misbehaving device from taking the relay's memory.
const (
	maxMembers = 64  // devices of one group on the relay at once
	maxCalls   = 16  // calls waiting for one device's answer
	maxPairs   = 256 // joined connections of one group
	maxSetups  = 256 // registrations and connections being set up at once
)

// Timeouts: setupTimeout bounds a registration and a request line,
// callTimeout the wait for the called device to answer, and noteTimeout a
// note to a device that stopped reading.
const (
	setupTimeout = 15 * time.Second
	callTimeout  = 10 * time.Second
	noteTimeout  = 10 * time.Second
)

// Config configures a relay.
type Config struct {
	Listen string // the address of its port, the same for UDP (WireGuard) and TCP (registrations)
	Keys   Keys

	// Groups are the tags of the groups the relay serves; it refuses every
	// other group. The user runs it for their own groups.
	Groups []string
	// Open serves any group that registers, in place of Groups, within
	// Limits: the project's relay, or one a user runs for others.
	Open   bool
	Limits Limits

	Logf    func(format string, args ...any)
	Verbose bool // also log WireGuard's own messages
}

// Relay is a running relay.
type Relay struct {
	cfg     Config
	allowed map[string]bool
	tcp     net.Listener
	hub     *tunnel.Hub
	tlsCfg  *tls.Config
	logf    func(format string, args ...any)
	done    chan struct{}
	once    sync.Once
	wg      sync.WaitGroup

	limits Limits // an open relay's; zero otherwise

	mu      sync.Mutex
	groups  map[string]map[string]*member // tag, then device ID
	fromIP  map[netip.Addr]int            // an open relay's registrations by address
	fromNet map[netip.Prefix]int          // and by network
	byAddr  map[netip.Addr]*member
	calls   map[string]*call // by ticket
	setting int
	// records are each group's authority records, from all its members'
	// registrations, in memory while the relay runs.
	records map[string][]group.Record
	// periods are what it holds of the groups that registered with
	// credentials, by their period's tag.
	periods map[string]*period
}

// member is a registered device.
type member struct {
	tag, device string
	leaf        group.KeyHash // the key of its member certificate
	key, psk    tunnel.Key
	addr        netip.Addr
	conn        *tls.Conn // the registration, open while it is registered
	raw         net.Conn  // its TCP connection

	streams map[net.Conn]bool // its connections in the tunnel
	watch   net.Conn          // the one that takes the notes
	notes   chan note
	calls   int // calls waiting for its answer
	pairs   *int
	bytes   *rate      // the group's copying, on an open relay
	from    netip.Addr // the address it registered from
	dropped bool
}

// call is a device's dial, waiting for the other device to answer.
type call struct {
	from, to *member
	answered chan net.Conn
}

// Listen opens the relay's port: TCP for the registrations, UDP for the
// tunnels, both with the same number.
func Listen(cfg Config) (*Relay, error) {
	switch {
	case cfg.Open && len(cfg.Groups) > 0:
		return nil, errors.New("relay: an open relay serves every group; give no group's tag")
	case !cfg.Open && len(cfg.Groups) == 0:
		return nil, errors.New("relay: no group to serve; give the tags of your groups (cbb status shows them)")
	}
	allowed := map[string]bool{}
	for _, g := range cfg.Groups {
		if b, err := hex.DecodeString(g); err != nil || len(b) != 8 {
			return nil, fmt.Errorf("relay: %q is not a group's tag, 16 hex characters as cbb status shows it", g)
		}
		allowed[g] = true
	}
	if cfg.Keys.WireGuard.IsZero() || cfg.Keys.Cert.Leaf == nil {
		return nil, errors.New("relay: no keys")
	}
	logf := cfg.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}
	// The relay keeps no logs about the devices: what it logs, wireguard-go's
	// errors included, goes without the addresses in it.
	logf = tunnel.Redacted(logf)
	// The tunnel listens on the UDP port of the same number. Where any free
	// port will do, one whose UDP twin is taken or reserved (Windows keeps
	// ranges for Hyper-V) is given up for another.
	_, wanted, _ := net.SplitHostPort(cfg.Listen)
	var (
		tcp net.Listener
		hub *tunnel.Hub
	)
	for try := 0; ; try++ {
		var err error
		if tcp, err = net.Listen("tcp", cfg.Listen); err != nil {
			return nil, fmt.Errorf("relay: %w", err)
		}
		port := tcp.Addr().(*net.TCPAddr).Port
		hub, err = tunnel.StartHub(tunnel.HubConfig{PrivateKey: cfg.Keys.WireGuard, Addr: Addr, ListenPort: port, Logf: logf, Verbose: cfg.Verbose})
		if err == nil {
			break
		}
		tcp.Close()
		if wanted != "0" || try == 4 {
			return nil, fmt.Errorf("relay: %w", err)
		}
	}
	r := &Relay{cfg: cfg, allowed: allowed, tcp: tcp, hub: hub, logf: logf, done: make(chan struct{}),
		groups: map[string]map[string]*member{}, byAddr: map[netip.Addr]*member{}, calls: map[string]*call{},
		records: map[string][]group.Record{}, periods: map[string]*period{}, fromIP: map[netip.Addr]int{}, fromNet: map[netip.Prefix]int{}}
	if cfg.Open {
		r.limits = cfg.Limits.withDefaults()
	}
	r.tlsCfg = r.serverTLS()
	return r, nil
}

// Addr returns the address of the relay's port.
func (r *Relay) Addr() net.Addr { return r.tcp.Addr() }

// Serve runs the relay until ctx is done, then closes it.
func (r *Relay) Serve(ctx context.Context) error {
	r.wg.Add(2)
	go func() {
		defer r.wg.Done()
		r.acceptRegistrations()
	}()
	go func() {
		defer r.wg.Done()
		r.acceptStreams()
	}()
	select {
	case <-ctx.Done():
	case <-r.done:
	}
	r.Close()
	return nil
}

// Close stops the relay and drops every member.
func (r *Relay) Close() error {
	r.once.Do(func() {
		close(r.done)
		r.tcp.Close()
		r.mu.Lock()
		for _, g := range r.groups {
			for _, m := range g {
				r.dropLocked(m)
			}
		}
		r.mu.Unlock()
		r.hub.Close()
	})
	r.wg.Wait()
	return nil
}

// Stats counts what the relay holds now: the groups and the devices.
func (r *Relay) Stats() (groups, members int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.groups), len(r.byAddr)
}

// takeSlot counts a connection being set up; false when there are too many.
func (r *Relay) takeSlot() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.setting >= maxSetups {
		return false
	}
	r.setting++
	return true
}

func (r *Relay) freeSlot() {
	r.mu.Lock()
	r.setting--
	r.mu.Unlock()
}

// addLocked registers m, in place of the same device's earlier
// registration, and gives the tunnel its key.
func (r *Relay) addLocked(m *member) error {
	for _, o := range r.byAddr {
		if o.key == m.key && (o.tag != m.tag || o.device != m.device) {
			return errors.New("another device registered that WireGuard key")
		}
	}
	g := r.groups[m.tag]
	if old := g[m.device]; old != nil {
		r.dropLocked(old)
		g = r.groups[m.tag]
	}
	if len(g) >= maxMembers {
		return errors.New("the relay holds as many devices of this group as it can")
	}
	if r.cfg.Open {
		switch {
		case g == nil && len(r.groups) >= r.limits.Groups:
			return errors.New("the relay serves as many groups as it can; try again later, or run your own relay")
		case r.fromIP[m.from] >= r.limits.PerAddress, r.fromNet[networkOf(m.from)] >= r.limits.PerNetwork:
			return errors.New("too many devices registered from this network; try again later")
		}
	}
	for {
		a, err := tunnel.Addr(string(group.NewDeviceID()))
		if err != nil {
			return err
		}
		if _, used := r.byAddr[a]; !used && a != Addr {
			m.addr = a
			break
		}
	}
	if g == nil {
		g = map[string]*member{}
		r.groups[m.tag] = g
		m.pairs = new(int)
		if r.cfg.Open {
			m.bytes = newRate(r.limits.ByteRate)
		}
	} else {
		for _, o := range g {
			m.pairs, m.bytes = o.pairs, o.bytes
			break
		}
	}
	g[m.device], r.byAddr[m.addr] = m, m
	if err := r.hub.SetPeers(r.peersLocked()); err != nil {
		delete(g, m.device)
		delete(r.byAddr, m.addr)
		if len(g) == 0 {
			delete(r.groups, m.tag)
		}
		return err
	}
	if r.cfg.Open {
		r.fromIP[m.from]++
		r.fromNet[networkOf(m.from)]++
	}
	return nil
}

// dropLocked forgets m: its tunnel and its connections go at once.
func (r *Relay) dropLocked(m *member) {
	if m.dropped {
		return
	}
	r.logf("DBG %s relay: drops %s", time.Now().Format("15:04:05.000"), m.device)
	m.dropped = true
	m.raw.Close()
	for c := range m.streams {
		c.Close()
	}
	if m.notes != nil {
		close(m.notes)
		m.notes = nil
	}
	for t, c := range r.calls {
		if c.from == m || c.to == m {
			delete(r.calls, t)
			close(c.answered)
		}
	}
	if g := r.groups[m.tag]; g[m.device] == m {
		delete(g, m.device)
		if len(g) == 0 {
			delete(r.groups, m.tag)
			// An open relay forgets a group once its last device goes, so
			// groups that come and go do not fill its memory.
			if r.cfg.Open {
				delete(r.records, m.tag)
			}
			delete(r.periods, m.tag)
		}
	}
	if r.byAddr[m.addr] == m {
		delete(r.byAddr, m.addr)
		if r.cfg.Open {
			countDown(r.fromIP, m.from)
			countDown(r.fromNet, networkOf(m.from))
		}
	}
	if err := r.hub.SetPeers(r.peersLocked()); err != nil {
		r.logf("cbb relay: setting the tunnels: %v", err)
	}
	r.announceLocked(m.tag)
}

func (r *Relay) peersLocked() []tunnel.Peer {
	peers := make([]tunnel.Peer, 0, len(r.byAddr))
	for _, m := range r.byAddr {
		peers = append(peers, tunnel.Peer{PublicKey: m.key, PresharedKey: m.psk, Addr: m.addr})
	}
	return peers
}

// announceLocked tells each watching device of the group which others are
// on the relay now.
func (r *Relay) announceLocked(tag string) {
	g := r.groups[tag]
	for _, m := range g {
		if m.notes == nil {
			continue
		}
		others := make([]string, 0, len(g)-1)
		for d := range g {
			if d != m.device {
				others = append(others, d)
			}
		}
		slices.Sort(others)
		r.noteLocked(m, note{Online: &others})
	}
}

// noteLocked queues a note for m; a device that does not take its notes
// loses its watch, and comes back with a new one.
func (r *Relay) noteLocked(m *member, n note) bool {
	if m.notes == nil {
		return false
	}
	select {
	case m.notes <- n:
		return true
	default:
		m.watch.Close()
		return false
	}
}

// acceptStreams takes the connections that come through the tunnels to the
// relay's member port.
func (r *Relay) acceptStreams() {
	ln := r.hub.Listener()
	for {
		c, err := ln.Accept()
		if err != nil {
			select {
			case <-r.done:
				return
			default:
			}
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		if !r.takeSlot() {
			c.Close()
			continue
		}
		r.wg.Add(1)
		go func() {
			defer r.wg.Done()
			r.serveStream(c)
		}()
	}
}

// serveStream reads a connection's request and does what it asks.
func (r *Relay) serveStream(c net.Conn) {
	from, _ := netip.ParseAddrPort(c.RemoteAddr().String())
	r.mu.Lock()
	m := r.byAddr[from.Addr()]
	if m != nil {
		m.streams[c] = true
	}
	r.mu.Unlock()
	if m == nil {
		r.freeSlot()
		c.Close()
		return
	}
	var req request
	if err := readLine(c, &req, setupTimeout); err != nil {
		r.freeSlot()
		r.closeStream(m, c)
		return
	}
	switch {
	case req.Watch:
		r.freeSlot()
		r.serveWatch(m, c)
	case req.Dial != "":
		r.serveDial(m, c, req.Dial)
	case req.Answer != "":
		r.freeSlot()
		r.serveAnswer(m, c, req.Answer)
	default:
		r.freeSlot()
		writeLine(c, note{Error: "an unknown request"}, noteTimeout)
		r.closeStream(m, c)
	}
}

func (r *Relay) closeStream(m *member, c net.Conn) {
	c.Close()
	r.mu.Lock()
	delete(m.streams, c)
	r.mu.Unlock()
}

// serveWatch sends m its notes on c until c or the registration ends.
func (r *Relay) serveWatch(m *member, c net.Conn) {
	r.mu.Lock()
	if m.dropped {
		r.mu.Unlock()
		r.closeStream(m, c)
		return
	}
	if m.watch != nil {
		m.watch.Close()
		close(m.notes)
	}
	notes := make(chan note, 32)
	m.watch, m.notes = c, notes
	r.announceLocked(m.tag)
	r.mu.Unlock()
	gone := make(chan struct{})
	go func() {
		// The device sends nothing more here; reading tells when it goes.
		io.Copy(io.Discard, c)
		c.Close()
		close(gone)
	}()
	for {
		select {
		case n, ok := <-notes:
			if !ok || writeLine(c, n, noteTimeout) != nil {
				c.Close()
				<-gone
				r.endWatch(m, c, notes)
				return
			}
		case <-gone:
			r.endWatch(m, c, notes)
			return
		}
	}
}

func (r *Relay) endWatch(m *member, c net.Conn, notes chan note) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(m.streams, c)
	if m.watch == c {
		m.watch = nil
		if m.notes == notes {
			close(m.notes)
			m.notes = nil
		}
	}
}

// serveDial calls the device to and, once it answers, joins c to its
// connection.
func (r *Relay) serveDial(m *member, c net.Conn, to string) {
	refuse := func(msg string) {
		writeLine(c, note{Error: msg}, noteTimeout)
		r.closeStream(m, c)
	}
	var tb [16]byte
	rand.Read(tb[:])
	ticket := hex.EncodeToString(tb[:])
	cl := &call{from: m, answered: make(chan net.Conn, 1)}
	r.mu.Lock()
	t := r.groups[m.tag][to]
	msg := ""
	switch {
	case m.dropped:
		msg = "this device is not registered"
	case t == nil || t == m:
		msg = "that device is not on the relay"
	case t.notes == nil:
		msg = "that device is not listening yet"
	case t.calls >= maxCalls:
		msg = "that device has too many calls waiting"
	case *m.pairs >= maxPairs:
		msg = "this group has as many connections as the relay joins"
	}
	if msg == "" {
		cl.to = t
		r.calls[ticket] = cl
		t.calls++
		if !r.noteLocked(t, note{Call: m.device, Ticket: ticket}) {
			msg = "that device is not listening"
			delete(r.calls, ticket)
			t.calls--
		}
	}
	r.mu.Unlock()
	r.freeSlot()
	r.logf("DBG %s relay: %s calls %s: %q", time.Now().Format("15:04:05.000"), m.device, to, msg)
	if msg != "" {
		refuse(msg)
		return
	}
	timer := time.NewTimer(callTimeout)
	defer timer.Stop()
	var other net.Conn
	select {
	case other = <-cl.answered:
	case <-timer.C:
	case <-r.done:
	}
	r.mu.Lock()
	if r.calls[ticket] == cl {
		delete(r.calls, ticket)
	} else if other == nil {
		// The answer came just as the wait ended.
		select {
		case other = <-cl.answered:
		default:
		}
	}
	t.calls--
	r.logf("DBG %s relay: %s calls %s: answered %v, dropped %v %v", time.Now().Format("15:04:05.000"), m.device, to, other != nil, m.dropped, t.dropped)
	ok := other != nil && !m.dropped && !t.dropped && *m.pairs < maxPairs
	if ok {
		*m.pairs++
	}
	r.mu.Unlock()
	if !ok {
		if other != nil {
			r.closeStream(t, other)
		}
		refuse("that device did not answer")
		return
	}
	defer func() {
		r.mu.Lock()
		*m.pairs--
		r.mu.Unlock()
		r.closeStream(m, c)
		r.closeStream(t, other)
	}()
	if writeLine(other, note{OK: true}, noteTimeout) != nil || writeLine(c, note{OK: true}, noteTimeout) != nil {
		return
	}
	splice(c, other, m.bytes, r.done)
}

// serveAnswer hands c to the call it answers; the dialing side joins them.
func (r *Relay) serveAnswer(m *member, c net.Conn, ticket string) {
	r.mu.Lock()
	cl := r.calls[ticket]
	r.logf("DBG %s relay: %s answers, call found %v", time.Now().Format("15:04:05.000"), m.device, cl != nil)
	if cl != nil && cl.to == m {
		delete(r.calls, ticket)
		cl.answered <- c
		r.mu.Unlock()
		return
	}
	r.mu.Unlock()
	writeLine(c, note{Error: "no such call"}, noteTimeout)
	r.closeStream(m, c)
}

// countDown lowers the count of k, and forgets it at zero.
func countDown[K comparable](m map[K]int, k K) {
	if m[k] <= 1 {
		delete(m, k)
	} else {
		m[k]--
	}
}

// splice copies between two connections until either ends, at the
// group's rate when it has one.
func splice(a, b net.Conn, limit *rate, stop <-chan struct{}) {
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		limitedCopy(dst, src, limit, stop)
		done <- struct{}{}
	}
	go cp(a, b)
	go cp(b, a)
	<-done
	a.Close()
	b.Close()
	<-done
}
