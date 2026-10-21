// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"context"
	"crypto/tls"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"time"

	"github.com/HunterEwok/clipbridge/internal/group"
	"github.com/HunterEwok/clipbridge/internal/mdns"
	"github.com/HunterEwok/clipbridge/internal/node"
	"github.com/HunterEwok/clipbridge/internal/pair"
	"github.com/HunterEwok/clipbridge/internal/uptime"
)

const (
	handshakeTimeout = 10 * time.Second
	minBackoff       = time.Second
	maxBackoff       = 30 * time.Second
)

// serveMember runs one connection to the member port. The ALPN protocol
// that the client offers picks pairing or the member protocol. release gives
// up the connection's handshake slot: after the handshake for a member, after
// the attempt for pairing.
func (s *Service) serveMember(ctx context.Context, raw net.Conn, release func()) {
	released := false
	defer func() {
		if !released {
			release()
		}
	}()
	cfg := &tls.Config{GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		s.mu.Lock()
		defer s.mu.Unlock()
		if slices.Contains(hello.SupportedProtos, pair.Protocol) {
			// Also without a window, so the joiner hears that it is closed.
			return pair.ServerTLS(s.id), nil
		}
		return s.nd.ServerTLS(), nil
	}}
	tc := tls.Server(raw, cfg)
	hctx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	err := tc.HandshakeContext(hctx)
	cancel()
	if err != nil {
		tc.Close()
		return
	}
	if tc.ConnectionState().NegotiatedProtocol == pair.Protocol {
		s.mu.Lock()
		w := s.window
		s.mu.Unlock()
		if w == nil {
			pair.Refuse(ctx, tc, pair.ErrClosed)
			return
		}
		if err := w.Serve(ctx, tc); err != nil {
			s.logf("clipbridge: pairing attempt from %s: %v", raw.RemoteAddr(), err)
		}
		return
	}
	release()
	released = true
	if err := s.nd.Serve(ctx, tc); err != nil {
		s.logf("clipbridge: connection from %s: %v", raw.RemoteAddr(), err)
	}
}

// dialer keeps the connection to one member up.
type dialer struct {
	cancel context.CancelFunc
	addrs  []string // where discovery last saw the member, best first
}

// found handles the members that discovery found: a Mac dials every Linux
// member; a Linux member dials those whose device ID is greater than its
// own, so two members make one connection between them. A member's dialer
// takes its new addresses or port on its next round.
func (s *Service) found(peers []mdns.Peer) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.id == nil || s.stopping {
		return
	}
	tag := group.Tag(s.id.GroupCA.Cert)
	want := map[group.DeviceID][]string{}
	for _, p := range peers {
		id, err := group.ParseDeviceID(p.ID)
		if err != nil || id == s.id.ID || (s.cfg.Role == node.Linux && id < s.id.ID) {
			continue
		}
		if g, _ := p.TXTValue("g"); g != tag {
			continue // another group, or an old CA
		}
		want[id] = addresses(p)
	}
	for id, d := range s.dialers {
		if _, ok := want[id]; !ok {
			d.cancel()
			delete(s.dialers, id)
		}
	}
	for id, addrs := range want {
		if d, ok := s.dialers[id]; ok {
			d.addrs = addrs
			continue
		}
		ctx, cancel := context.WithCancel(s.groupCtx)
		s.dialers[id] = &dialer{cancel: cancel, addrs: addrs}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.dial(ctx, id)
		}()
	}
}

// addresses returns a member's addresses with its port, best first.
func addresses(p mdns.Peer) []string {
	addrs := slices.Clone(p.Addrs)
	slices.SortStableFunc(addrs, func(a, b netip.Addr) int { return rank(a) - rank(b) })
	out := make([]string, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, net.JoinHostPort(a.String(), strconv.Itoa(int(p.Port))))
	}
	return out
}

// rank orders addresses by how likely they work: IPv4 first, then routable
// IPv6, and link-local addresses last, since they need the right interface.
func rank(a netip.Addr) int {
	a = a.Unmap()
	r := 0
	if a.Is6() {
		r++
	}
	if a.IsLinkLocalUnicast() {
		r += 2
	}
	return r
}

// dial keeps a connection to a member up while it is found: it tries the
// addresses that discovery last saw in turn, and waits longer after each
// round that failed.
func (s *Service) dial(ctx context.Context, id group.DeviceID) {
	backoff := minBackoff
	for ctx.Err() == nil {
		s.mu.Lock()
		var addrs []string
		if d := s.dialers[id]; d != nil {
			addrs = d.addrs
		}
		nd := s.nd
		s.mu.Unlock()
		for _, addr := range addrs {
			start := uptime.Now()
			err := nd.Dial(ctx, id, addr)
			if ctx.Err() != nil {
				return
			}
			if uptime.Now()-start > maxBackoff {
				backoff = minBackoff // the connection worked for a while
			}
			s.logf("clipbridge: connection to %s at %s: %v", id, addr, err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(2*backoff, maxBackoff)
	}
}

// peersChanged elects the holder of clipbridge.local: the Linux member with
// the lowest device ID among this one and the Linux members it is
// connected to.
func (s *Service) peersChanged() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.electLocked()
}

func (s *Service) electLocked() {
	if s.id == nil || s.cfg.Role != node.Linux || s.responder == nil || s.stopping {
		return // a stopping member keeps what it had until its goodbye
	}
	hold := true
	for _, p := range s.nd.Peers() {
		if p.Role == node.Linux && p.ID < s.id.ID {
			hold = false
		}
	}
	if hold != s.holder {
		s.holder = hold
		s.responder.SetHolder(hold)
		s.logf("clipbridge: holds clipbridge.local: %v", hold)
	}
}

// watchSleep tells the node when the machine slept: the clock that counts
// sleep moved further than the one that does not. The connections from
// before are dead, and the member must take the group's text again. A hello
// that came before this notices the sleep is written then too (see
// clip.Engine.Rejoin).
func (s *Service) watchSleep(ctx context.Context) {
	t := time.NewTicker(sleepCheckEvery)
	defer t.Stop()
	d := newSleepDetector(uptime.Now(), time.Now())
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if slept, ok := d.check(uptime.Now(), time.Now()); ok {
			s.logf("clipbridge: the machine slept for %v", slept.Round(time.Second))
			s.mu.Lock()
			nd := s.nd
			s.mu.Unlock()
			if nd != nil {
				nd.Rejoin()
			}
		}
	}
}

const sleepCheckEvery, sleepSlack = 2 * time.Second, 3 * time.Second

// sleepDetector compares the clock that counts sleep with the one that
// does not.
type sleepDetector struct {
	lastUp   time.Duration
	lastMono time.Time
}

func newSleepDetector(up time.Duration, mono time.Time) *sleepDetector {
	return &sleepDetector{lastUp: up, lastMono: mono}
}

// check takes the two clocks now and reports how long the machine slept
// since the last check, if it did.
func (d *sleepDetector) check(up time.Duration, mono time.Time) (time.Duration, bool) {
	slept := (up - d.lastUp) - mono.Sub(d.lastMono)
	d.lastUp, d.lastMono = up, mono
	return slept, slept > sleepSlack
}

// write passes a write that the engine decided on to the watchers, in
// order. When no watcher is connected, the next one gets it.
func (s *Service) write(w node.Write) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if w.Seq <= s.lastSeq {
		return
	}
	s.lastSeq = w.Seq
	if len(s.watchers) == 0 {
		s.pending = &w
		return
	}
	s.pending = nil
	for wt := range s.watchers {
		wt.send(w)
	}
}
