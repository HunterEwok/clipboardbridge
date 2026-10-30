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
// writes nothing about the groups or their devices, not even to its log;
// with a state file it keeps there only, under a hash of each group's tag,
// the version of the group's newest credential and a hash of its root
// (versions).
package forward

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/HunterEwok/clipboardbridge/internal/tunnel"
	"github.com/HunterEwok/clipboardbridge/internal/vless"
)

// Limits bound what one group, one source and all of them may take, so
// that no group can slow down another.
type Limits struct {
	Groups     int     // registered hubs
	Clients    int     // client addresses of one group
	Pending    int     // handshakes of one group waiting for the hub's answer
	PacketRate float64 // packets per second of one group, both ways
	ByteRate   float64 // bytes per second of one group, both ways
	SourceRate float64 // handshakes per second from one address
	// ScanRate bounds the groups that handshakes to a new group are
	// checked against, per second, all sources together: each such
	// handshake costs one check per group, under the forwarder's lock, and
	// source addresses can be forged.
	ScanRate    float64
	Connections int // registrations being set up at a time
	// NetworkScanRate is ScanRate for the handshakes from one network (an
	// IPv4 /24 or an IPv6 /64), so that one network cannot use up the
	// budget of all; ScanRate/16 if zero.
	NetworkScanRate float64
	// PerAddress and PerNetwork bound the registrations, held or being
	// set up, from one address and from one network (an IPv4 /24 or an
	// IPv6 /64), so that nobody fills the forwarder from a few hosts; 16
	// and 64 if zero.
	PerAddress, PerNetwork int
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
	ScanRate:    500_000,
	Connections: 256,
	PerAddress:  16,
	PerNetwork:  64,
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
	memory   *memory         // the authority records of the groups that register with them
	versions *versions       // the newest credential of each group that registers with one
	byID     map[uint64]*reg // by registration ID, for hellos
	byHubEP  map[netip.AddrPort]*reg
	pending  map[clientKey]pending
	byHubIdx map[uint32]*session
	byClient map[clientKey]*session
	byAddr   map[netip.AddrPort]map[*reg]int // client addresses and the groups they have handshakes and sessions with
	byInit   map[int][]*reg                  // obfuscated groups by the size of their handshake initiation
	sources  map[netip.Addr]*bucket
	scans    *bucket                  // ScanRate
	netScans map[netip.Prefix]*bucket // NetworkScanRate
	fromAddr map[netip.Addr]int       // registrations held or being set up, by address
	fromNet  map[netip.Prefix]int     // and by network
	setting  int                      // registrations being set up
	mask     [32]byte                 // the key of the hellos' mask, given to every hub
	vless    *vless.Server
	vlessCfg *VLESSConfig
	byVLESS  map[string]*reg // by the group's VLESS user ID

	closeOnce sync.Once
	done      chan struct{}
	wg        sync.WaitGroup
}

// reg is a hub's registration.
type reg struct {
	tag      string
	key      [32]byte            // the hub's WireGuard public key
	mac1     [32]byte            // mac1Key(key)
	obf      *tunnel.Obfuscation // the group's AmneziaWG settings; nil for plain WireGuard
	vlessID  string              // the group's VLESS user ID; empty without VLESS
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
	VLESS  *VLESSConfig    // nil without VLESS
	// StateFile, if set, is where the forwarder keeps the version of each
	// group's newest credential, under a hash of its tag, so that a hub
	// the group removed cannot register with an older one after a
	// restart; "" keeps them in memory only.
	StateFile string
	Logf      func(format string, args ...any)
}

// VLESSConfig configures the forwarder's VLESS with REALITY, for the
// clients of hubs that ask for it (docs/design.md, "Blocked networks").
type VLESSConfig struct {
	Listen string // the TCP address to listen on, such as ":443"
	// Site is the well-known site whose TLS the forwarder borrows, such as
	// www.example.com; its port 443 answers whoever is not a client. Dest,
	// if set, is where that site is reached instead, for tests.
	Site string
	Dest string
	Key  [32]byte // the REALITY key, X25519
}

// listenPair opens UDP and TCP on the same port of host. Windows reserves
// ranges of ports, for TCP and for UDP apart, that it never hands out but
// that a pick of the other protocol can land in, and its picks run in
// order, so a whole run of them may fall in one range. A port of 0 is
// therefore picked by TCP and by UDP in turn; a pick whose other side is
// refused is given back and another one is tried.
func listenPair(host string, port int) (*net.UDPConn, net.Listener, error) {
	tries := 1
	if port == 0 {
		tries = 40
	}
	var err error
	for i := range tries {
		var udp *net.UDPConn
		var tcp net.Listener
		if i%2 == 0 {
			tcp, udp, err = tcpFirst(host, port)
		} else {
			udp, tcp, err = udpFirst(host)
		}
		if err == nil {
			return udp, tcp, nil
		}
	}
	return nil, nil, err
}

// tcpFirst listens on TCP at port, then on UDP at the same port.
func tcpFirst(host string, port int) (net.Listener, *net.UDPConn, error) {
	tcp, err := net.Listen("tcp", net.JoinHostPort(host, fmt.Sprint(port)))
	if err != nil {
		return nil, nil, err
	}
	udp, err := listenUDP(host, tcp.Addr().(*net.TCPAddr).Port)
	if err != nil {
		tcp.Close()
		return nil, nil, err
	}
	return tcp, udp, nil
}

// udpFirst listens on UDP at a port the system picks, then on TCP at the
// same port.
func udpFirst(host string) (*net.UDPConn, net.Listener, error) {
	udp, err := listenUDP(host, 0)
	if err != nil {
		return nil, nil, err
	}
	tcp, err := net.Listen("tcp", net.JoinHostPort(host, fmt.Sprint(udp.LocalAddr().(*net.UDPAddr).Port)))
	if err != nil {
		udp.Close()
		return nil, nil, err
	}
	return udp, tcp, nil
}

func listenUDP(host string, port int) (*net.UDPConn, error) {
	ua, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, fmt.Sprint(port)))
	if err != nil {
		return nil, err
	}
	return net.ListenUDP("udp", ua)
}

// Listen opens the forwarder's ports. Serve then runs it.
func Listen(cfg Config) (*Forwarder, error) {
	logf := cfg.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}
	// The forwarder keeps no logs about the hubs and their clients: what it
	// logs goes without the addresses in it.
	logf = tunnel.Redacted(logf)
	limits := cfg.Limits
	if limits == (Limits{}) {
		limits = DefaultLimits
	}
	ua, err := net.ResolveUDPAddr("udp", cfg.Listen)
	if err != nil {
		return nil, fmt.Errorf("forward: %w", err)
	}
	host, _, err := net.SplitHostPort(cfg.Listen)
	if err != nil {
		return nil, fmt.Errorf("forward: %w", err)
	}
	udp, tcp, err := listenPair(host, ua.Port)
	if err != nil {
		return nil, fmt.Errorf("forward: %w", err)
	}
	f := &Forwarder{
		udp: udp, tcp: tcp, limits: limits, logf: logf,
		regs: map[string]*reg{}, byID: map[uint64]*reg{}, byHubEP: map[netip.AddrPort]*reg{},
		pending: map[clientKey]pending{}, byHubIdx: map[uint32]*session{}, byClient: map[clientKey]*session{},
		byAddr: map[netip.AddrPort]map[*reg]int{}, byInit: map[int][]*reg{},
		sources: map[netip.Addr]*bucket{}, netScans: map[netip.Prefix]*bucket{},
		fromAddr: map[netip.Addr]int{}, fromNet: map[netip.Prefix]int{},
		done: make(chan struct{}), memory: newMemory(),
	}
	if f.versions, err = newVersions(cfg.StateFile, cfg.Cert.PrivateKey); err != nil {
		udp.Close()
		tcp.Close()
		return nil, fmt.Errorf("forward: the state file: %w", err)
	}
	if f.limits.ScanRate <= 0 {
		f.limits.ScanRate = DefaultLimits.ScanRate
	}
	if f.limits.NetworkScanRate <= 0 {
		f.limits.NetworkScanRate = f.limits.ScanRate / 16
	}
	if f.limits.PerAddress <= 0 {
		f.limits.PerAddress = DefaultLimits.PerAddress
	}
	if f.limits.PerNetwork <= 0 {
		f.limits.PerNetwork = DefaultLimits.PerNetwork
	}
	f.scans = newBucket(f.limits.ScanRate, time.Now())
	if _, err := rand.Read(f.mask[:]); err != nil {
		udp.Close()
		tcp.Close()
		return nil, fmt.Errorf("forward: %w", err)
	}
	if v := cfg.VLESS; v != nil {
		dest := v.Dest
		if dest == "" {
			dest = net.JoinHostPort(v.Site, "443")
		}
		// VLESS passes the packets to the UDP port, from the loopback.
		to := f.Addr()
		if to.Addr().IsUnspecified() {
			to = netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), to.Port())
		}
		if f.vless, err = vless.Listen(vless.ServerConfig{Listen: v.Listen, Dest: dest, ServerName: v.Site, Key: v.Key, To: to}); err != nil {
			udp.Close()
			tcp.Close()
			return nil, fmt.Errorf("forward: %w", err)
		}
		f.vlessCfg, f.byVLESS = v, map[string]*reg{}
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
		if f.vless != nil {
			f.vless.Close()
		}
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
	f.mu.Lock()
	defer f.mu.Unlock()
	if h, ok := openHello(&f.mask, p); ok && f.helloLocked(from, h) {
		return netip.AddrPort{}, false
	}
	var buf [initiationSize]byte
	if r := f.byHubEP[from]; r != nil {
		t, m := open(r.obf, p, &buf)
		if t == 0 {
			return netip.AddrPort{}, false
		}
		return f.fromHubLocked(r, t, m, len(p), now)
	}
	return f.fromClientLocked(from, p, &buf, now)
}

// fromHubLocked passes a hub's answer or data, the message m of type t in
// a packet of n bytes, to the client whose index it names. A hub's own
// handshake to a client has nowhere to go: its mac1 is keyed with the
// client's key, which the forwarder does not know; clients make the
// handshakes and keep their sessions fresh.
func (f *Forwarder) fromHubLocked(r *reg, t byte, m []byte, n int, now time.Time) (netip.AddrPort, bool) {
	if !r.take(n, now) {
		return netip.AddrPort{}, false
	}
	ck := clientKey{r, receiverIndex(t, m)}
	switch t {
	case msgResponse:
		pd, ok := f.pending[ck]
		if !ok {
			return netip.AddrPort{}, false
		}
		f.unpendLocked(ck, pd)
		hubIdx := senderIndex(m)
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
		f.addClientLocked(r, pd.from)
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
// to, and its data to the hub of its session. A plain packet is read as
// it is; an obfuscated one with the settings of each obfuscated group the
// address already has a handshake or session with, and a handshake to a new
// group with the settings of each obfuscated group whose handshake
// initiation has the packet's size.
func (f *Forwarder) fromClientLocked(from netip.AddrPort, p []byte, buf *[initiationSize]byte, now time.Time) (netip.AddrPort, bool) {
	switch messageType(p) {
	case msgInitiation:
		if !f.sourceLocked(from, now) || !f.scanLocked(from, len(f.regs), now) {
			return netip.AddrPort{}, false
		}
		if r := f.addressedLocked(p); r != nil {
			return f.initiationLocked(from, r, p, len(p), now)
		}
		return netip.AddrPort{}, false
	case msgData:
		if s := f.byHubIdx[receiverIndex(msgData, p)]; s != nil && s.reg.obf == nil {
			return f.dataLocked(s, len(p), now)
		}
	}
	for r := range f.byAddr[from] {
		if r.obf == nil {
			continue
		}
		switch t, m := open(r.obf, p, buf); t {
		case msgData:
			if s := f.byHubIdx[receiverIndex(t, m)]; s != nil && s.reg == r {
				return f.dataLocked(s, len(p), now)
			}
		case msgInitiation:
			if hasMac1(&r.mac1, m) {
				if !f.sourceLocked(from, now) {
					return netip.AddrPort{}, false
				}
				return f.initiationLocked(from, r, m, len(p), now)
			}
		}
	}
	regs := f.byInit[len(p)]
	if len(regs) == 0 || !f.sourceLocked(from, now) || !f.scanLocked(from, len(regs), now) {
		return netip.AddrPort{}, false
	}
	for _, r := range regs {
		if t, m := open(r.obf, p, buf); t == msgInitiation && hasMac1(&r.mac1, m) {
			return f.initiationLocked(from, r, m, len(p), now)
		}
	}
	// A client answers no handshake: the forwarder passes none from a hub.
	return netip.AddrPort{}, false
}

// sourceLocked charges a handshake to the address it came from; false
// drops it. It bounds what one address may make the forwarder look for.
// What comes over VLESS comes from the loopback, from a client its group's
// VLESS user ID let in, and is charged to that group alone.
func (f *Forwarder) sourceLocked(from netip.AddrPort, now time.Time) bool {
	if f.vless != nil && from.Addr().IsLoopback() {
		return true
	}
	src := f.sources[from.Addr()]
	if src == nil {
		if len(f.sources) >= 4*f.limits.Groups {
			return false
		}
		src = newBucket(f.limits.SourceRate, now)
		f.sources[from.Addr()] = src
	}
	return src.take(1, now)
}

// network is the network of an address that the forwarder's per-network
// limits count: an IPv4 /24 or an IPv6 /64, where one host usually gets
// a whole /64.
func network(a netip.Addr) netip.Prefix {
	a = a.Unmap()
	bits := 64
	if a.Is4() {
		bits = 24
	}
	p, _ := a.Prefix(bits)
	return p
}

// scanLocked charges a handshake that n groups are checked against to the
// budget of all sources and to that of its network; false drops it. One
// handshake costs a network at most its whole budget, so it still passes
// now and then on a forwarder with more groups than the budget. What comes
// over VLESS, from the loopback, counts as one network, so its clients
// cannot spend the budget of the others.
func (f *Forwarder) scanLocked(from netip.AddrPort, n int, now time.Time) bool {
	p := network(from.Addr())
	b := f.netScans[p]
	if b == nil {
		if len(f.netScans) >= 4*f.limits.Groups {
			return false
		}
		b = newBucket(f.limits.NetworkScanRate, now)
		f.netScans[p] = b
	}
	cost := min(float64(n), 2*f.limits.NetworkScanRate)
	if !b.take(cost, now) {
		return false
	}
	if !f.scans.take(float64(n), now) {
		b.tokens += cost
		return false
	}
	return true
}

// initiationLocked passes the handshake initiation m, in a packet of n
// bytes from a client, to the hub of r, and waits for the hub's answer.
func (f *Forwarder) initiationLocked(from netip.AddrPort, r *reg, m []byte, n int, now time.Time) (netip.AddrPort, bool) {
	if !r.hubEP.IsValid() || !r.take(n, now) {
		return netip.AddrPort{}, false
	}
	if _, known := r.clients[from]; !known && len(r.clients) >= f.limits.Clients {
		return netip.AddrPort{}, false
	}
	ck := clientKey{r, senderIndex(m)}
	if old, again := f.pending[ck]; again {
		f.unpendLocked(ck, old)
	} else if r.waiting >= f.limits.Pending {
		return netip.AddrPort{}, false
	}
	f.pending[ck] = pending{from: from, at: now}
	f.addClientLocked(r, from)
	r.waiting++
	return r.hubEP, true
}

// dataLocked passes a client's data of n bytes to the hub of its session.
func (f *Forwarder) dataLocked(s *session, n int, now time.Time) (netip.AddrPort, bool) {
	if !s.reg.hubEP.IsValid() || !s.reg.take(n, now) {
		return netip.AddrPort{}, false
	}
	return s.reg.hubEP, true
}

// addClientLocked counts a handshake or session of the client at a with
// the group of r.
func (f *Forwarder) addClientLocked(r *reg, a netip.AddrPort) {
	r.clients[a]++
	regs := f.byAddr[a]
	if regs == nil {
		regs = map[*reg]int{}
		f.byAddr[a] = regs
	}
	regs[r]++
}

// removeClientLocked forgets one handshake or session of the client at a
// with the group of r.
func (f *Forwarder) removeClientLocked(r *reg, a netip.AddrPort) {
	r.clients[a]--
	if r.clients[a] <= 0 {
		delete(r.clients, a)
	}
	regs := f.byAddr[a]
	regs[r]--
	if regs[r] <= 0 {
		delete(regs, r)
	}
	if len(regs) == 0 {
		delete(f.byAddr, a)
	}
}

// addressedLocked returns the registration of a plain group whose hub the
// handshake initiation p is addressed to, or nil. It costs one keyed
// BLAKE2s per plain group.
func (f *Forwarder) addressedLocked(p []byte) *reg {
	for _, r := range f.regs {
		if r.obf == nil && hasMac1(&r.mac1, p) {
			return r
		}
	}
	return nil
}

// helloLocked takes a hub's hello h, without its mask: the hub's WireGuard
// port is where it came from. It tells whether h was a hello of a hub.
func (f *Forwarder) helloLocked(from netip.AddrPort, h []byte) bool {
	id, counter := readHello(h)
	r := f.byID[id]
	if r == nil || !checkHello(&r.helloKey, h) {
		return false
	}
	if counter <= r.counter {
		return true
	}
	r.counter = counter
	if r.hubEP == from {
		return true
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
	return true
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
	f.removeClientLocked(s.reg, s.client)
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
	if r.vlessID != "" && f.byVLESS[r.vlessID] == r {
		delete(f.byVLESS, r.vlessID)
		_ = f.vless.RemoveUser(r.vlessID)
	}
	if r.obf != nil {
		f.byInit[initSize(r.obf)] = slices.DeleteFunc(f.byInit[initSize(r.obf)], func(o *reg) bool { return o == r })
		if len(f.byInit[initSize(r.obf)]) == 0 {
			delete(f.byInit, initSize(r.obf))
		}
	}
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
	for p, b := range f.netScans {
		if b.full(now) {
			delete(f.netScans, p)
		}
	}
}

// unpendLocked forgets a handshake that waited for the hub.
func (f *Forwarder) unpendLocked(ck clientKey, pd pending) {
	delete(f.pending, ck)
	r := ck.reg
	r.waiting--
	f.removeClientLocked(r, pd.from)
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
