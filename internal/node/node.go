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
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/HunterEwok/clipbridge/internal/clip"
	"github.com/HunterEwok/clipbridge/internal/group"
	"github.com/HunterEwok/clipbridge/internal/uptime"
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
	Engine   *clip.Engine

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
	// peer sent for this member; it checks it, keeps it and passes the new
	// identity to SetIdentity. An error is logged.
	OnCert func(der []byte) error

	// Allow, if set, rejects peers, for example revoked devices.
	Allow func(group.DeviceID) error

	PingEvery time.Duration        // defaultPingEvery if zero
	Timeout   time.Duration        // defaultTimeout if zero
	Uptime    func() time.Duration // uptime.Now if nil
	Now       func() time.Time     // for certificate checks; time.Now if nil
	Logf      func(format string, args ...any)
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
	ID    group.DeviceID
	Role  Role
	Since time.Duration // uptime when the connection started
}

// A Node is a member's set of connections.
type Node struct {
	cfg Config
	id  atomic.Pointer[group.Identity] // the current identity; renewal replaces it

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
	return n
}

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
// ends. A Mac dials every Linux member it finds; a Linux member dials the
// Linux members whose device ID is greater than its own.
func (n *Node) Dial(ctx context.Context, peer group.DeviceID, addr string) error {
	d := net.Dialer{Timeout: handshakeTimeout, KeepAlive: -1}
	raw, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	return n.Serve(ctx, tls.Client(raw, n.identity().ClientTLS(peer, n.tlsOptions())))
}

// Serve runs a member connection until it ends: one dialed by Dial, or one
// accepted with ServerTLS, or with a configuration from it. It closes the
// connection.
func (n *Node) Serve(ctx context.Context, tc *tls.Conn) error {
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
	c := &conn{n: n, id: id, tc: tc, peerCert: cs.PeerCertificates[0], out: make(chan outgoing, queueLen),
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
			out = append(out, Peer{ID: c.id, Role: role, Since: c.since})
		}
	}
	slices.SortFunc(out, func(a, b Peer) int { return strings.Compare(string(a.ID), string(b.ID)) })
	return out
}

// RenewPeers sends a renewed certificate to every connected member whose
// certificate is due for renewal, if this member holds the group CA key.
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
func (n *Node) renewPeer(c *conn) {
	cert, err := n.identity().RenewMember(c.peerCert, n.cfg.Now())
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
		c.enqueue(outgoing{cert: cert})
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
	since    time.Duration
	out      chan outgoing

	mu       sync.Mutex
	peerRole Role // set by the peer's hello
	certSent bool // a renewed certificate was queued for the peer
	sayBye   bool
	done     chan struct{} // closed to end the connection
	closed   bool
	finished chan struct{} // closed when Serve has cleaned up
}

// outgoing is a queued message: a hello, an event or a renewed certificate.
type outgoing struct {
	hello  *clip.Hello
	event  *clip.Event
	cert   *x509.Certificate
	queued time.Duration
}

func (c *conn) role() Role {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.peerRole
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
		data, err := encode(h)
		if err != nil {
			return nil, err
		}
		return &message{Type: typeHello, Role: c.n.cfg.Role, Hello: data}, nil
	case o.cert != nil:
		return &message{Type: typeCert, Cert: o.cert.Raw}, nil
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
			h, err := decodeHello(m.Hello)
			if err != nil {
				return fmt.Errorf("node: bad hello from %s: %w", c.id, err)
			}
			c.mu.Lock()
			c.peerRole = m.Role
			c.mu.Unlock()
			c.n.peersChanged()
			res, err := e.Reconcile(string(c.id), h)
			if err != nil {
				return fmt.Errorf("node: bad hello from %s: %w", c.id, err)
			}
			c.n.apply(res, c)
			c.n.renewPeer(c)
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
			if err := c.n.cfg.OnCert(m.Cert); err != nil {
				c.n.cfg.Logf("node: a renewed certificate from %s: %v", c.id, err)
			}
		case typeBye:
			return nil
		}
		// A ping, or a message type from a newer version: nothing to do.
	}
}

// decodeHello decodes a hello. A current event that does not decode, for
// example from a newer version, counts as none.
func decodeHello(raw json.RawMessage) (clip.Hello, error) {
	var b helloBody
	if err := json.Unmarshal(raw, &b); err != nil || len(raw) == 0 {
		return clip.Hello{}, errors.New("the hello does not decode")
	}
	h := clip.Hello{Wall: b.Wall}
	if len(b.Current) > 0 && string(b.Current) != "null" {
		var ev clip.Event
		if json.Unmarshal(b.Current, &ev) == nil {
			h.Current = &ev
		}
	}
	return h, nil
}
