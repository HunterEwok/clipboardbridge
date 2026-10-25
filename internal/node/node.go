// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Package node runs a member's connections to the other members and joins
// them to the sync engine: it sends the hello when a connection starts,
// forwards each event the first time the engine sees it to every other
// connection, and passes the writes the engine decides on to the local
// clipboard.
//
// Each side sends a ping when it has sent nothing for PingEvery, and a
// connection is closed when the peer sends nothing for Timeout. A large
// frame gets more time, as if the link carried at least 16 KiB a second. An
// event that waits in a connection's queue is sent with that time added to
// its age.
package node

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/HunterEwok/clipboardbridge/internal/clip"
	"github.com/HunterEwok/clipboardbridge/internal/group"
	"github.com/HunterEwok/clipboardbridge/internal/netguard"
	"github.com/HunterEwok/clipboardbridge/internal/uptime"
)

const (
	defaultPingEvery = 5 * time.Second
	defaultTimeout   = 15 * time.Second
	handshakeTimeout = 10 * time.Second
	rejoinWait       = 2 * time.Second // how long Rejoin waits for the old connections at most
	byeWait          = time.Second     // how long a closing connection may take to say goodbye
	queueLen         = 256
)

// Config configures a Node.
type Config struct {
	Identity *group.Identity
	Role     Role
	Name     string // this device's name, sent in the hello
	OS       string // this device's operating system (group.OSLinux...), sent in the hello
	// Device is this device's form, versions and MAC address, sent in the
	// hello for the others to show.
	Device group.DeviceInfo
	Engine *clip.Engine

	// OnWrite puts a text into this member's own clipboard. Writes carry
	// growing sequence numbers; a write with a smaller one than the last
	// applied must be dropped. It is called from connection goroutines and
	// must not block for long.
	OnWrite func(Write)

	// OnPeers, if set, is called whenever the set of connected members, as
	// Peers reports it, may have changed. Calls may come from several
	// goroutines at once.
	OnPeers func()

	// OnCert, if set, is called with a renewed member certificate that a
	// peer sent for this member, and the admin CA that issued it when the
	// peer sent one; it checks it, keeps it and passes the new identity to
	// SetIdentity. An error is logged.
	OnCert func(der, issuer []byte) error

	// OnAdmin, if set, is called with the admin CA that a peer, the
	// group's root, sent for this member's admin key; it checks it, keeps
	// it and passes the new identity to SetIdentity. An error is logged.
	OnAdmin func(der []byte) error

	// PhoneCAFor, if set, returns the iPhone CA, with its key, to send a
	// peer whose hello said it holds the iPhone CA with the key hash
	// theirs (nil for none), or nil to send nothing: an admin of a group a
	// computer created shares it with the other admins (docs/protocol.md,
	// section 10).
	PhoneCAFor func(peer group.DeviceID, chain []*x509.Certificate, theirs []byte) *group.CA

	// OnPhoneCA, if set, is called with an iPhone CA and its key that a
	// peer sent; it checks them, keeps them and passes the new identity to
	// SetIdentity. An error is logged.
	OnPhoneCA func(from group.DeviceID, chain []*x509.Certificate, cert, key []byte) error

	// Allow, if set, rejects peers, for example revoked devices. Recheck
	// asks it again for the running connections.
	Allow func(group.DeviceID, []*x509.Certificate) error

	// Records, if set, keeps the group's signed records.
	Records RecordStore

	// TunnelKey, if set, is this member's WireGuard public key, which its
	// hello offers the group's hub.
	TunnelKey []byte

	// OnTunnelKey, if set, is called with the tunnel key a peer's hello
	// offered and the certificate chain the peer presented. On the group's
	// hub it admits the key and returns the offer to send the peer; on
	// other members it returns nil.
	OnTunnelKey func(peer group.DeviceID, chain []*x509.Certificate, key []byte) *TunnelOffer

	// OnTunnel, if set, is called with the offer a peer, the group's hub,
	// sent for this member's tunnel key, and the peer's verified chain; it
	// checks it and keeps it. An error is logged.
	OnTunnel func(from group.DeviceID, chain []*x509.Certificate, o TunnelOffer) error

	PingEvery time.Duration        // defaultPingEvery if zero
	Timeout   time.Duration        // defaultTimeout if zero
	Uptime    func() time.Duration // uptime.Now if nil
	Now       func() time.Time     // for certificate checks; time.Now if nil
	Logf      func(format string, args ...any)
}

// A RecordStore keeps the group's signed records (docs/protocol.md, section
// 10). Its methods are called from connection goroutines.
type RecordStore interface {
	// Digest returns the digest of the records, which the hello carries;
	// "" when there are none.
	Digest() string
	// All returns every record, for a peer whose digest differs.
	All() []group.Record
	// Add takes the records a peer sent and returns those that were new
	// and valid, which go on to the other peers.
	Add(from group.DeviceID, rs []group.Record) []group.Record
	// Settle is called with the records Add returned once they are queued
	// for the other peers, so that a device they revoke still gets them
	// before a Recheck closes its connection.
	Settle(fresh []group.Record)
}

// Write is a text to put into the member's own clipboard.
type Write struct {
	Text string
	Kind clip.Kind
	Via  clip.Via
	Seq  uint64
}

// Peer is a connected member.
type Peer struct {
	ID   group.DeviceID
	Role Role
	Name string // from its hello; "" when it sent none or an invalid one
	OS   string // from its hello; "" when it sent none or an unknown one
	// Device is what its hello says about its device, its invalid fields
	// dropped.
	Device group.DeviceInfo
	Key    group.KeyHash
	// AdminKey is the admin key its hello offers, a SubjectPublicKeyInfo
	// in DER; nil when it offers none.
	AdminKey []byte
	// OldKeys tells that its hello says it holds the group CA key of a
	// legacy group.
	OldKeys bool
	// Mode is the sync mode its hello reports; "" when it reports none.
	Mode  string
	Since time.Duration // uptime when the connection started
	// Local is this end's address of the connection; invalid when it is
	// not an IP connection.
	Local netip.Addr
}

// A Node is a member's set of connections.
type Node struct {
	cfg       Config
	id        atomic.Pointer[group.Identity] // the current identity; renewal replaces it
	tunnelKey atomic.Pointer[[]byte]         // what the hello offers the hub; nil for none

	rejoinMu sync.Mutex // one Rejoin at a time

	mu        sync.Mutex
	conns     map[group.DeviceID]*conn
	closed    bool
	rejoining chan struct{} // closed when a Rejoin in progress is done; nil if none
	wg        sync.WaitGroup
}

// New returns a node.
func New(cfg Config) *Node {
	if cfg.PingEvery == 0 {
		cfg.PingEvery = defaultPingEvery
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = defaultTimeout
	}
	if cfg.Uptime == nil {
		cfg.Uptime = uptime.Now
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	if cfg.OnWrite == nil {
		cfg.OnWrite = func(Write) {}
	}
	n := &Node{cfg: cfg, conns: make(map[group.DeviceID]*conn)}
	n.id.Store(cfg.Identity)
	n.SetTunnelKey(cfg.TunnelKey)
	return n
}

// SetTunnelKey replaces the tunnel key that hellos offer the group's hub;
// nil offers none. Connections made from now on carry it (see Reconnect).
func (n *Node) SetTunnelKey(key []byte) {
	if len(key) == 0 {
		n.tunnelKey.Store(nil)
		return
	}
	k := bytes.Clone(key)
	n.tunnelKey.Store(&k)
}

// Reconnect closes every connection, so that the members connect again
// and their hellos carry what changed, such as a new tunnel key.
func (n *Node) Reconnect() { n.closeAll() }

// identity returns the member's current identity.
func (n *Node) identity() *group.Identity { return n.id.Load() }

// SetIdentity replaces the member's identity with a renewed one, of the
// same device and group. New connections present its certificates; the
// running ones keep theirs.
func (n *Node) SetIdentity(id *group.Identity) { n.id.Store(id) }

func (n *Node) tlsOptions() group.TLSOptions {
	return group.TLSOptions{Allow: n.cfg.Allow, Now: n.cfg.Now}
}

// ServerTLS returns the TLS configuration for accepting member connections.
func (n *Node) ServerTLS() *tls.Config { return n.identity().ServerTLS(n.tlsOptions()) }

// Dial connects to the member peer at addr and runs the connection until it
// ends. Of two full members the one with the lower device ID dials, and the
// other only when that has not connected for a while (see Serve).
func (n *Node) Dial(ctx context.Context, peer group.DeviceID, addr string) error {
	d := net.Dialer{Timeout: handshakeTimeout, KeepAlive: -1, Control: netguard.Control}
	raw, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	return n.run(ctx, tls.Client(raw, n.identity().ClientTLS(peer, n.tlsOptions())), true)
}

// DialConn runs a member connection to peer over raw, a connection that is
// already open, such as one through the tunnel to the group's hub, until it
// ends.
func (n *Node) DialConn(ctx context.Context, peer group.DeviceID, raw net.Conn) error {
	return n.run(ctx, tls.Client(raw, n.identity().ClientTLS(peer, n.tlsOptions())), true)
}

// Serve runs a member connection that was accepted with ServerTLS, or with
// a configuration from it, until it ends. It closes the connection.
func (n *Node) Serve(ctx context.Context, tc *tls.Conn) error { return n.run(ctx, tc, false) }

// errOtherConn ends a connection when the one the lower device ID dialed is
// up between the same two members.
var errOtherConn = errors.New("node: the connection the lower device ID dialed is up")

// run runs a member connection until it ends; dialed says this member
// dialed it. A new connection to a peer replaces the old one, as a
// reconnect does, unless the old one was dialed by the member with the lower
// device ID and the new one was not: when both members dial at once, the
// two keep the same connection.
func (n *Node) run(ctx context.Context, tc *tls.Conn, dialed bool) error {
	// Close the socket itself at the end: the goodbye was said, and TLS's
	// own close message could wait for seconds on a peer that stopped
	// reading.
	defer tc.NetConn().Close()
	hctx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	err := tc.HandshakeContext(hctx)
	cancel()
	if err != nil {
		return err
	}
	cs := tc.ConnectionState()
	id, err := group.PeerID(cs)
	if err != nil {
		return err
	}
	if id == n.identity().ID {
		return errors.New("node: connected to itself")
	}
	chain := group.MemberChain(cs)
	if len(chain) == 0 {
		return errors.New("node: the peer's certificate was not verified")
	}
	c := &conn{n: n, id: id, tc: tc, lowerDialed: dialed == (n.identity().ID < id), peerCert: chain[0], peerChain: chain, out: make(chan outgoing, queueLen),
		done: make(chan struct{}), finished: make(chan struct{}), since: n.cfg.Uptime()}
	defer close(c.finished)

	// A connection that arrives while a Rejoin closes the old ones waits
	// until the engine knows the member was away, so its hello counts.
	n.mu.Lock()
	for n.rejoining != nil {
		ch := n.rejoining
		n.mu.Unlock()
		select {
		case <-ch:
		case <-ctx.Done():
			return ctx.Err()
		}
		n.mu.Lock()
	}
	if n.closed {
		n.mu.Unlock()
		return errors.New("node: closed")
	}
	old := n.conns[id]
	if old != nil && old.lowerDialed && !c.lowerDialed && !old.ending() {
		n.mu.Unlock()
		return errOtherConn
	}
	n.conns[id] = c
	// The connection is in the forwarding set before the engine makes the
	// hello, so no event falls between the two.
	hello := n.cfg.Engine.Connected(string(id))
	c.enqueue(outgoing{hello: &hello})
	n.wg.Add(1)
	n.mu.Unlock()
	defer n.wg.Done()
	if old != nil {
		old.close(false) // a reconnect replaces the old connection
	}

	stop := context.AfterFunc(ctx, func() { c.close(false) })
	defer stop()
	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		c.writer()
	}()
	err = c.reader()
	c.close(false)
	<-writerDone

	n.mu.Lock()
	if n.conns[id] == c {
		delete(n.conns, id)
	}
	n.mu.Unlock()
	n.cfg.Engine.Disconnected(string(id))
	n.peersChanged()
	return err
}

// Copied passes a change that a clipboard watcher reported to the engine
// and sends the event, if any, to the connected members.
func (n *Node) Copied(text string, kind clip.Kind, via clip.Via) (bool, error) {
	ev, ok, err := n.cfg.Engine.Copied(text, kind, via)
	if err != nil || !ok {
		return false, err
	}
	n.forward(ev, nil)
	return true, nil
}

// Send makes an event from a deliberate action, sends it to the connected
// members and writes it to the member's own clipboard if needed.
func (n *Node) Send(text string, kind clip.Kind, via clip.Via) error {
	ev, res, err := n.cfg.Engine.Send(text, kind, via)
	if err != nil {
		return err
	}
	n.forward(ev, nil)
	if res.Write {
		n.cfg.OnWrite(Write{Text: ev.Text, Kind: ev.Kind, Via: ev.Via, Seq: res.Seq})
	}
	return nil
}

// Rejoin tells the engine that the member was away: the service started, or
// the machine woke up. First it closes every connection and waits, for at
// most two seconds, until they are gone; new connections wait meanwhile, so
// every hello after the absence counts.
func (n *Node) Rejoin() {
	n.rejoinMu.Lock()
	defer n.rejoinMu.Unlock()
	n.mu.Lock()
	done := make(chan struct{})
	n.rejoining = done
	n.mu.Unlock()

	t := time.NewTimer(rejoinWait)
	defer t.Stop()
wait:
	for _, c := range n.closeAll() {
		select {
		case <-c.finished:
		case <-t.C:
			break wait
		}
	}
	n.cfg.Engine.Rejoin()

	n.mu.Lock()
	n.rejoining = nil
	n.mu.Unlock()
	close(done)
}

// Close closes every connection, saying goodbye, refuses new ones, and
// returns when they are gone.
func (n *Node) Close() {
	n.mu.Lock()
	n.closed = true
	n.mu.Unlock()
	n.closeAll()
	n.wg.Wait()
}

// closeAll closes every connection with a goodbye and returns them.
func (n *Node) closeAll() []*conn {
	n.mu.Lock()
	conns := make([]*conn, 0, len(n.conns))
	for _, c := range n.conns {
		conns = append(conns, c)
	}
	n.mu.Unlock()
	for _, c := range conns {
		c.close(true)
	}
	return conns
}

// Peers returns the connected members that sent their hello, sorted by
// device ID.
func (n *Node) Peers() []Peer {
	n.mu.Lock()
	defer n.mu.Unlock()
	out := make([]Peer, 0, len(n.conns))
	for _, c := range n.conns {
		if role := c.role(); role != "" {
			c.mu.Lock()
			adminKey, oldKeys, device, mode := c.peerAdminKey, c.peerOldKeys, c.peerDevice, c.peerMode
			c.mu.Unlock()
			local, _ := netip.ParseAddrPort(c.tc.LocalAddr().String())
			out = append(out, Peer{ID: c.id, Role: role, Name: c.name(), OS: c.os(), Device: device, Key: group.KeyHashOf(c.peerCert), AdminKey: adminKey,
				OldKeys: oldKeys, Mode: mode, Since: c.since, Local: local.Addr().Unmap()})
		}
	}
	slices.SortFunc(out, func(a, b Peer) int { return strings.Compare(string(a.ID), string(b.ID)) })
	return out
}

// RenewPeers sends a renewed certificate to every connected member whose
// certificate is due for renewal, if this member is an admin.
// Peers are also checked when their hello arrives; this covers connections
// that last for months.
func (n *Node) RenewPeers() {
	n.mu.Lock()
	conns := make([]*conn, 0, len(n.conns))
	for _, c := range n.conns {
		conns = append(conns, c)
	}
	n.mu.Unlock()
	for _, c := range conns {
		if c.role() != "" {
			n.renewPeer(c)
		}
	}
}

// renewPeer sends the peer of c a renewed certificate if it is due, once
// per connection: the connection keeps the certificate of its handshake.
// An admin computer of a phone group renews only computers; the phones
// renew their own.
func (n *Node) renewPeer(c *conn) {
	id := n.identity()
	if role := c.role(); id.AdminCA != nil && role != Full {
		return
	}
	cert, issuer, err := id.RenewMember(c.peerCert, n.cfg.Now())
	if err != nil {
		n.cfg.Logf("node: renewing the certificate of %s: %v", c.id, err)
		return
	}
	if cert == nil {
		return
	}
	c.mu.Lock()
	sent := c.certSent
	c.certSent = true
	c.mu.Unlock()
	if !sent {
		n.cfg.Logf("node: sending %s a renewed certificate, valid until %s", c.id, cert.NotAfter.UTC().Format(time.DateOnly))
		c.enqueue(outgoing{cert: cert, issuer: issuer})
	}
}

// offerRecords sends every record to the peer of c when its digest differs
// from this member's and this member has any.
func (n *Node) offerRecords(c *conn, digest string) {
	st := n.cfg.Records
	if st == nil {
		return
	}
	if mine := st.Digest(); mine == "" || mine == digest {
		return
	}
	for _, chunk := range chunkRecords(st.All()) {
		c.enqueue(outgoing{records: chunk})
	}
}

// offerTunnel passes the tunnel key the peer of c offered to OnTunnelKey
// and sends the peer the hub's offer, if any.
func (n *Node) offerTunnel(c *conn, key []byte) {
	if n.cfg.OnTunnelKey == nil || len(key) == 0 {
		return
	}
	if o := n.cfg.OnTunnelKey(c.id, c.peerChain, key); o != nil {
		c.enqueue(outgoing{tunnel: o})
	}
}

// sharePhoneCA sends the peer of c the iPhone CA that PhoneCAFor returns
// for it, if any.
func (n *Node) sharePhoneCA(c *conn) {
	if n.cfg.PhoneCAFor == nil {
		return
	}
	c.mu.Lock()
	theirs := c.peerPhoneCA
	c.mu.Unlock()
	if ca := n.cfg.PhoneCAFor(c.id, c.peerChain, theirs); ca != nil {
		c.enqueue(outgoing{phoneCA: ca})
	}
}

// SharePhoneCA sends the iPhone CA to every connected member that
// PhoneCAFor names, as after this member replaced it.
func (n *Node) SharePhoneCA() {
	for _, c := range n.helloed() {
		n.sharePhoneCA(c)
	}
}

// SendAdmin sends the connected member dev its admin CA, which makes it an
// admin, and then the iPhone CA that PhoneCAFor returns for it. It reports
// whether dev is connected.
func (n *Node) SendAdmin(dev group.DeviceID, adminCA *x509.Certificate) bool {
	for _, c := range n.helloed() {
		if c.id == dev {
			c.enqueue(outgoing{admin: adminCA})
			n.sharePhoneCA(c)
			return true
		}
	}
	return false
}

// helloed returns the connections whose peer sent its hello.
func (n *Node) helloed() []*conn {
	n.mu.Lock()
	defer n.mu.Unlock()
	out := make([]*conn, 0, len(n.conns))
	for _, c := range n.conns {
		if c.role() != "" {
			out = append(out, c)
		}
	}
	return out
}

// SendRecords sends records to every connected member, for example a
// revocation made on this member.
func (n *Node) SendRecords(rs []group.Record) { n.sendRecords(rs, nil) }

// sendRecords sends records to every connection that sent its hello,
// except the one they came from.
func (n *Node) sendRecords(rs []group.Record, from *conn) {
	chunks := chunkRecords(rs)
	n.mu.Lock()
	defer n.mu.Unlock()
	for _, c := range n.conns {
		if c == from || c.role() == "" {
			continue
		}
		for _, chunk := range chunks {
			c.enqueue(outgoing{records: chunk})
		}
	}
}

// Recheck asks Allow again about every connection and closes those it now
// rejects, for example after a revocation. They get what is queued for them
// first, so a revoked device learns of the records that revoke it.
func (n *Node) Recheck() {
	if n.cfg.Allow == nil {
		return
	}
	n.mu.Lock()
	var drop []*conn
	for _, c := range n.conns {
		if err := n.cfg.Allow(c.id, c.peerChain); err != nil {
			n.cfg.Logf("node: closing the connection to %s: %v", c.id, err)
			drop = append(drop, c)
		}
	}
	n.mu.Unlock()
	for _, c := range drop {
		c.close(true)
	}
}

func (n *Node) peersChanged() {
	if n.cfg.OnPeers != nil {
		n.cfg.OnPeers()
	}
}

// apply carries out what the engine decided about an event that came from
// a connection.
func (n *Node) apply(res clip.Result, from *conn) {
	if res.Forward == nil {
		return
	}
	n.forward(*res.Forward, from)
	if res.Write {
		ev := res.Forward
		n.cfg.OnWrite(Write{Text: ev.Text, Kind: ev.Kind, Via: ev.Via, Seq: res.Seq})
	}
}

// forward sends an event to every connection except the one it came from.
func (n *Node) forward(ev clip.Event, from *conn) {
	n.mu.Lock()
	defer n.mu.Unlock()
	for _, c := range n.conns {
		if c != from {
			e := ev
			c.enqueue(outgoing{event: &e})
		}
	}
}

// conn is one connection to a member.
type conn struct {
	n        *Node
	id       group.DeviceID
	tc       *tls.Conn
	peerCert *x509.Certificate // from the handshake
	// peerChain is the chain the handshake verified, leaf first and without
	// its root (group.MemberChain), for Recheck and the admin checks.
	peerChain []*x509.Certificate
	since     time.Duration
	out       chan outgoing
	// lowerDialed says the member with the lower device ID dialed it.
	lowerDialed bool

	mu       sync.Mutex
	peerRole Role   // set by the peer's hello
	peerName string // set by the peer's hello
	peerOS   string // set by the peer's hello
	// peerDevice is what the peer's hello says about its device.
	peerDevice group.DeviceInfo
	// peerAdminKey and peerPhoneCA are the admin key and the key hash of
	// the iPhone CA that the peer's hello names.
	peerAdminKey []byte
	peerPhoneCA  []byte
	peerOldKeys  bool   // the peer's hello says it holds a legacy group CA key
	peerMode     string // the sync mode its hello reports; "" when none or unknown
	certSent     bool   // a renewed certificate was queued for the peer
	sayBye       bool
	done         chan struct{} // closed to end the connection
	closed       bool
	finished     chan struct{} // closed when Serve has cleaned up
}

// outgoing is a queued message: a hello, an event, a renewed certificate,
// records, a tunnel offer, an admin CA or the iPhone CA.
type outgoing struct {
	hello   *clip.Hello
	event   *clip.Event
	cert    *x509.Certificate
	issuer  *x509.Certificate // the admin CA that issued cert; nil for the group CA
	records []group.Record
	tunnel  *TunnelOffer
	admin   *x509.Certificate // an admin CA for the peer
	phoneCA *group.CA         // the iPhone CA with its key
	queued  time.Duration
}

func (c *conn) role() Role {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.peerRole
}

func (c *conn) os() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.peerOS
}

func (c *conn) name() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.peerName
}

// enqueue queues a message without blocking. A peer that falls a whole
// queue behind is too slow, and its connection is closed; it gets the
// current event again in the hello of the next one.
func (c *conn) enqueue(o outgoing) {
	o.queued = c.n.cfg.Uptime()
	c.mu.Lock()
	closed := c.closed
	c.mu.Unlock()
	if closed {
		return
	}
	select {
	case c.out <- o:
	default:
		c.n.cfg.Logf("node: %s is too slow; closing the connection", c.id)
		c.close(false)
	}
}

// close ends the connection. With bye, the writer first sends what is
// queued and a goodbye, within a second; without, at once. Either way a
// read or write that is blocked fails now rather than at its deadline.
// ending reports whether the connection is closing or closed.
func (c *conn) ending() bool {
	select {
	case <-c.done:
		return true
	default:
		return false
	}
}

func (c *conn) close(bye bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	c.closed, c.sayBye = true, bye
	close(c.done)
	now := time.Now()
	c.tc.SetReadDeadline(now)
	if bye {
		c.tc.SetWriteDeadline(now.Add(byeWait))
	} else {
		c.tc.SetWriteDeadline(now)
	}
}

// setDeadline sets a read or write deadline unless the connection is
// closing, whose own deadlines must not be pushed back.
func (c *conn) setDeadline(read bool, t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	if read {
		c.tc.SetReadDeadline(t)
	} else {
		c.tc.SetWriteDeadline(t)
	}
}

// Read and SetReadDeadline let readMessage use the connection.
func (c *conn) Read(p []byte) (int, error) { return c.tc.Read(p) }

// SetReadDeadline sets the read deadline, unless the connection is closing.
func (c *conn) SetReadDeadline(t time.Time) error {
	c.setDeadline(true, t)
	return nil
}

func (c *conn) closing() bool {
	select {
	case <-c.done:
		return true
	default:
		return false
	}
}

// addAge adds d to an age in milliseconds without overflowing.
func addAge(age int64, d time.Duration) int64 {
	add := max(0, d).Milliseconds()
	if age > math.MaxInt64-add {
		return math.MaxInt64
	}
	return age + add
}

// message builds the frame of a queued message, with the time it waited
// added to an event's age.
func (c *conn) message(o outgoing) (*message, error) {
	switch {
	case o.hello != nil:
		h := *o.hello
		if h.Current != nil {
			ev := *h.Current
			ev.Age = addAge(ev.Age, c.n.cfg.Uptime()-o.queued)
			h.Current = &ev
		}
		out := helloOut{Hello: h, Name: c.n.cfg.Name, OS: c.n.cfg.OS, Mode: c.n.cfg.Engine.Mode().String()}
		if d := c.n.cfg.Device.Clean(); !d.IsZero() {
			out.Device = &d
		}
		id := c.n.identity()
		if id.AdminKey != nil && id.AdminCA == nil {
			spki, err := x509.MarshalPKIXPublicKey(&id.AdminKey.PublicKey)
			if err != nil {
				return nil, err
			}
			out.AdminKey = spki
		}
		if id.ServesPhone() {
			h := group.KeyHashOf(id.PhoneCA.Cert)
			out.PhoneCA = h[:]
		}
		out.OldKeys = id.Legacy() && id.GroupCA.Key != nil
		if c.n.cfg.Records != nil {
			out.Records = c.n.cfg.Records.Digest()
		}
		if k := c.n.tunnelKey.Load(); k != nil {
			out.TunnelKey = *k
		}
		data, err := encode(out)
		if err != nil {
			return nil, err
		}
		return &message{Type: typeHello, Role: c.n.cfg.Role, Hello: data}, nil
	case o.cert != nil:
		m := &message{Type: typeCert, Cert: o.cert.Raw}
		if o.issuer != nil {
			m.Issuer = o.issuer.Raw
		}
		return m, nil
	case o.records != nil:
		return &message{Type: typeRecs, Records: o.records}, nil
	case o.tunnel != nil:
		return &message{Type: typeTun, Tunnel: o.tunnel}, nil
	case o.admin != nil:
		return &message{Type: typeAdmin, AdminCA: o.admin.Raw}, nil
	case o.phoneCA != nil:
		key, err := x509.MarshalPKCS8PrivateKey(o.phoneCA.Key)
		if err != nil {
			return nil, err
		}
		return &message{Type: typePhoneCA, PhoneCA: o.phoneCA.Cert.Raw, PhoneCAKey: key}, nil
	default:
		ev := *o.event
		ev.Age = addAge(ev.Age, c.n.cfg.Uptime()-o.queued)
		data, err := encode(ev)
		if err != nil {
			return nil, err
		}
		return &message{Type: typeEvent, Event: data}, nil
	}
}

func (c *conn) writer() {
	ping := time.NewTimer(c.n.cfg.PingEvery)
	defer ping.Stop()
	write := func(m *message, deadline bool) bool {
		f, err := frame(m)
		if err != nil {
			c.n.cfg.Logf("node: to %s: %v", c.id, err)
			return true // drop this one message
		}
		if deadline {
			c.setDeadline(false, time.Now().Add(c.n.cfg.Timeout+transferTime(len(f))))
		}
		if _, err := c.tc.Write(f); err != nil {
			if !c.closing() {
				c.n.cfg.Logf("node: writing to %s: %v", c.id, err)
			}
			c.close(false)
			return false
		}
		ping.Reset(c.n.cfg.PingEvery)
		return true
	}
	send := func(o outgoing, deadline bool) bool {
		m, err := c.message(o)
		if err != nil {
			c.n.cfg.Logf("node: to %s: %v", c.id, err)
			return true
		}
		return write(m, deadline)
	}
	for {
		select {
		case <-c.done:
			c.mu.Lock()
			bye := c.sayBye
			c.mu.Unlock()
			if !bye {
				return
			}
			// Send what is still queued, then the goodbye, within the
			// second that close gave the writes.
			for {
				select {
				case o := <-c.out:
					if !send(o, false) {
						return
					}
					continue
				default:
				}
				break
			}
			write(&message{Type: typeBye}, false)
			return
		default:
		}
		select {
		case o := <-c.out:
			if !send(o, true) {
				return
			}
		case <-ping.C:
			if !write(&message{Type: typePing}, true) {
				return
			}
		case <-c.done:
		}
	}
}

// reader reads the peer's hello and then its events until the connection
// ends; a peer that says goodbye ends it without an error.
func (c *conn) reader() error {
	e := c.n.cfg.Engine
	timeout := c.n.cfg.Timeout
	for first := true; ; first = false {
		c.SetReadDeadline(time.Now().Add(timeout))
		m, err := readMessage(c, timeout)
		if c.closing() {
			return nil // closed on this side; nothing more counts
		}
		if err != nil {
			return err
		}
		if first {
			if m.Type != typeHello || !m.Role.known() {
				return fmt.Errorf("node: %s did not start with a hello", c.id)
			}
			h, extra, err := decodeHello(m.Hello)
			if err != nil {
				return fmt.Errorf("node: bad hello from %s: %w", c.id, err)
			}
			c.mu.Lock()
			c.peerRole = m.Role
			if group.ValidName(extra.Name) {
				c.peerName = extra.Name
			}
			if group.ValidOS(extra.OS) {
				c.peerOS = extra.OS
			}
			c.peerDevice = group.DeviceInfo{}
			if extra.Device != nil {
				c.peerDevice = extra.Device.Clean()
			}
			c.peerAdminKey, c.peerPhoneCA, c.peerOldKeys = extra.AdminKey, extra.PhoneCA, extra.OldKeys
			c.peerMode = ""
			if _, err := clip.ParseMode(extra.Mode); err == nil {
				c.peerMode = extra.Mode
			}
			c.mu.Unlock()
			c.n.peersChanged()
			res, err := e.Reconcile(string(c.id), h)
			if err != nil {
				return fmt.Errorf("node: bad hello from %s: %w", c.id, err)
			}
			c.n.apply(res, c)
			c.n.renewPeer(c)
			c.n.offerRecords(c, extra.Records)
			c.n.offerTunnel(c, extra.TunnelKey)
			c.n.sharePhoneCA(c)
			continue
		}
		switch m.Type {
		case typeEvent:
			var ev clip.Event
			if err := json.Unmarshal(m.Event, &ev); err != nil {
				c.n.cfg.Logf("node: dropped an event from %s that does not decode", c.id)
				continue
			}
			res, err := e.Received(ev)
			if err != nil {
				c.n.cfg.Logf("node: dropped a bad event from %s: %v", c.id, err)
				continue
			}
			c.n.apply(res, c)
		case typeCert:
			if c.n.cfg.OnCert == nil {
				continue
			}
			if err := c.n.cfg.OnCert(m.Cert, m.Issuer); err != nil {
				c.n.cfg.Logf("node: a renewed certificate from %s: %v", c.id, err)
			}
		case typeAdmin:
			if c.n.cfg.OnAdmin == nil {
				continue
			}
			if err := c.n.cfg.OnAdmin(m.AdminCA); err != nil {
				c.n.cfg.Logf("node: an admin CA from %s: %v", c.id, err)
			}
		case typePhoneCA:
			if c.n.cfg.OnPhoneCA == nil {
				continue
			}
			if err := c.n.cfg.OnPhoneCA(c.id, c.peerChain, m.PhoneCA, m.PhoneCAKey); err != nil {
				c.n.cfg.Logf("node: an iPhone CA from %s: %v", c.id, err)
			}
		case typeTun:
			if c.n.cfg.OnTunnel == nil || m.Tunnel == nil {
				continue
			}
			if err := c.n.cfg.OnTunnel(c.id, c.peerChain, *m.Tunnel); err != nil {
				c.n.cfg.Logf("node: a tunnel offer from %s: %v", c.id, err)
			}
		case typeRecs:
			if st := c.n.cfg.Records; st != nil && len(m.Records) > 0 {
				if fresh := st.Add(c.id, m.Records); len(fresh) > 0 {
					c.n.sendRecords(fresh, c)
					st.Settle(fresh)
				}
			}
		case typeBye:
			return nil
		}
		// A ping, or a message type from a newer version: nothing to do.
	}
}

// decodeHello decodes a hello, and returns the rest of it, the peer's
// records digest and name, as it came. A current event that does not
// decode, for example from a newer version, counts as none.
func decodeHello(raw json.RawMessage) (clip.Hello, helloBody, error) {
	var b helloBody
	if err := json.Unmarshal(raw, &b); err != nil || len(raw) == 0 {
		return clip.Hello{}, helloBody{}, errors.New("the hello does not decode")
	}
	h := clip.Hello{Wall: b.Wall}
	if len(b.Current) > 0 && string(b.Current) != "null" {
		var ev clip.Event
		if json.Unmarshal(b.Current, &ev) == nil {
			h.Current = &ev
		}
	}
	return h, b, nil
}
