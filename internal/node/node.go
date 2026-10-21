// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Package node runs a member's connections to the other members and joins
// them to the sync engine: it sends the hello when a connection starts,
// forwards each event the first time the engine sees it to every other
// connection, and passes the writes the engine decides on to the local
// clipboard.
//
// A connection is closed when the peer sends nothing for Timeout; each side
// sends a ping when it has sent nothing for PingEvery. An event that waits
// in a connection's queue is sent with that time added to its age.
package node

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/HunterEwok/clipbridge/internal/clip"
	"github.com/HunterEwok/clipbridge/internal/group"
	"github.com/HunterEwok/clipbridge/internal/uptime"
)

const (
	defaultPingEvery = 5 * time.Second
	defaultTimeout   = 15 * time.Second
	handshakeTimeout = 10 * time.Second
	rejoinWait       = 2 * time.Second // how long Rejoin waits for the old connections
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

	mu     sync.Mutex
	conns  map[group.DeviceID]*conn
	closed bool
	wg     sync.WaitGroup
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
	return &Node{cfg: cfg, conns: make(map[group.DeviceID]*conn)}
}

func (n *Node) tlsOptions() group.TLSOptions {
	return group.TLSOptions{Allow: n.cfg.Allow, Now: n.cfg.Now}
}

// ServerTLS returns the TLS configuration for accepting member connections.
func (n *Node) ServerTLS() *tls.Config { return n.cfg.Identity.ServerTLS(n.tlsOptions()) }

// Dial connects to the member peer at addr and runs the connection until it
// ends. A Mac dials every Linux member it finds; a Linux member dials the
// Linux members whose device ID is greater than its own.
func (n *Node) Dial(ctx context.Context, peer group.DeviceID, addr string) error {
	d := net.Dialer{Timeout: handshakeTimeout, KeepAlive: -1}
	raw, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	return n.Serve(ctx, tls.Client(raw, n.cfg.Identity.ClientTLS(peer, n.tlsOptions())))
}

// Serve runs a member connection until it ends: one dialed by Dial, or one
// accepted with ServerTLS, or with a configuration from it. It closes the
// connection.
func (n *Node) Serve(ctx context.Context, tc *tls.Conn) error {
	defer tc.Close()
	hctx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	err := tc.HandshakeContext(hctx)
	cancel()
	if err != nil {
		return err
	}
	id, err := group.PeerID(tc.ConnectionState())
	if err != nil {
		return err
	}
	if id == n.cfg.Identity.ID {
		return errors.New("node: connected to itself")
	}
	c := &conn{n: n, id: id, tc: tc, out: make(chan outgoing, queueLen), done: make(chan struct{}),
		finished: make(chan struct{}), since: n.cfg.Uptime()}
	defer close(c.finished)

	n.mu.Lock()
	if n.closed {
		n.mu.Unlock()
		return errors.New("node: closed")
	}
	old := n.conns[id]
	n.conns[id] = c
	// The connection is in the forwarding set before the engine makes the
	// hello, so no event falls between the two.
	hello := n.cfg.Engine.Connected(string(id))
	c.enqueue(&message{Type: typeHello, Role: n.cfg.Role, Hello: &hello})
	n.wg.Add(1)
	n.mu.Unlock()
	defer n.wg.Done()
	if old != nil {
		old.close() // a reconnect replaces the old connection
	}

	stop := context.AfterFunc(ctx, c.close)
	defer stop()
	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		c.writer()
	}()
	err = c.reader()
	c.close()
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

// Rejoin closes every connection, waits until they are gone, and tells the
// engine that the member was away: the service started, the machine woke up
// or its network came back.
func (n *Node) Rejoin() {
	timeout := time.After(rejoinWait)
	for _, c := range n.closeAll() {
		select {
		case <-c.finished:
		case <-timeout:
		}
	}
	n.cfg.Engine.Rejoin()
}

// Close closes every connection, saying goodbye, and refuses new ones.
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
		c.bye()
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
			c.enqueue(&message{Type: typeEvent, Event: &e})
		}
	}
}

// conn is one connection to a member.
type conn struct {
	n     *Node
	id    group.DeviceID
	tc    *tls.Conn
	since time.Duration
	out   chan outgoing

	mu       sync.Mutex
	peerRole Role // set by the peer's hello
	sayBye   bool
	done     chan struct{} // closed to end the connection
	closed   bool
	finished chan struct{} // closed when Serve has cleaned up
}

type outgoing struct {
	m      *message
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
func (c *conn) enqueue(m *message) {
	select {
	case c.out <- outgoing{m: m, queued: c.n.cfg.Uptime()}:
	default:
		c.n.cfg.Logf("node: %s is too slow; closing the connection", c.id)
		go c.close()
	}
}

func (c *conn) close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.closed {
		c.closed = true
		close(c.done)
	}
}

// bye closes the connection after telling the peer, so it notices at once.
func (c *conn) bye() {
	c.mu.Lock()
	c.sayBye = true
	c.mu.Unlock()
	c.close()
}

func (c *conn) writer() {
	ping := time.NewTicker(c.n.cfg.PingEvery)
	defer ping.Stop()
	defer c.tc.Close()
	lastWrite := c.n.cfg.Uptime()
	write := func(m *message) bool {
		c.tc.SetWriteDeadline(time.Now().Add(c.n.cfg.Timeout))
		if err := writeMessage(c.tc, m); err != nil {
			c.n.cfg.Logf("node: writing to %s: %v", c.id, err)
			c.close()
			return false
		}
		lastWrite = c.n.cfg.Uptime()
		return true
	}
	for {
		select {
		case o := <-c.out:
			m := o.m
			if m.Event != nil {
				ev := *m.Event
				ev.Age += max(0, c.n.cfg.Uptime()-o.queued).Milliseconds()
				m = &message{Type: m.Type, Event: &ev}
			}
			if !write(m) {
				return
			}
		case <-ping.C:
			if c.n.cfg.Uptime()-lastWrite >= c.n.cfg.PingEvery && !write(&message{Type: typePing}) {
				return
			}
		case <-c.done:
			c.mu.Lock()
			bye := c.sayBye
			c.mu.Unlock()
			if bye {
				c.tc.SetWriteDeadline(time.Now().Add(time.Second))
				writeMessage(c.tc, &message{Type: typeBye})
			}
			return
		}
	}
}

// reader reads the peer's hello and then its events until the connection
// ends; a peer that says goodbye ends it without an error.
func (c *conn) reader() error {
	e := c.n.cfg.Engine
	for first := true; ; first = false {
		c.tc.SetReadDeadline(time.Now().Add(c.n.cfg.Timeout))
		m, err := readMessage(c.tc)
		if err != nil {
			select {
			case <-c.done:
				return nil // closed on this side
			default:
			}
			return err
		}
		if first {
			if m.Type != typeHello || m.Hello == nil || (m.Role != Linux && m.Role != Mac) {
				return fmt.Errorf("node: %s did not start with a hello", c.id)
			}
			c.mu.Lock()
			c.peerRole = m.Role
			c.mu.Unlock()
			c.n.peersChanged()
			res, err := e.Reconcile(string(c.id), *m.Hello)
			if err != nil {
				return fmt.Errorf("node: bad hello from %s: %w", c.id, err)
			}
			c.n.apply(res, c)
			continue
		}
		switch m.Type {
		case typeEvent:
			if m.Event == nil {
				continue
			}
			res, err := e.Received(*m.Event)
			if err != nil {
				c.n.cfg.Logf("node: dropped a bad event from %s: %v", c.id, err)
				continue
			}
			c.n.apply(res, c)
		case typeBye:
			return nil
		}
		// A ping, or a message type from a newer version: nothing to do.
	}
}
