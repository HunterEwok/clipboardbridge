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
	"strings"
	"time"

	"github.com/HunterEwok/clipboardbridge/internal/group"
	"github.com/HunterEwok/clipboardbridge/internal/mdns"
	"github.com/HunterEwok/clipboardbridge/internal/node"
	"github.com/HunterEwok/clipboardbridge/internal/pair"
	"github.com/HunterEwok/clipboardbridge/internal/uptime"
)

const (
	handshakeTimeout = 10 * time.Second
	minBackoff       = time.Second
	maxBackoff       = 30 * time.Second
)

// serveMember runs one connection to the member port (see demux.go): plain
// HTTP goes to the profile while an iPhone pairing window is open; over TLS
// the ALPN protocol that the client offers picks pairing, the member
// protocol, or, for any other, the shortcut's HTTPS. release gives up the
// connection's handshake slot: after the handshake for a member or the
// shortcut, after the attempt for pairing.
func (s *Service) serveMember(ctx context.Context, raw net.Conn, release func()) {
	released := false
	defer func() {
		if !released {
			release()
		}
	}()
	raw.SetReadDeadline(time.Now().Add(handshakeTimeout))
	raw, first, err := peek(raw)
	raw.SetReadDeadline(time.Time{})
	if err != nil {
		raw.Close()
		return
	}
	if first != recordHandshake {
		s.mu.Lock()
		profile := s.profileConns
		s.mu.Unlock()
		if profile == nil {
			raw.Close()
			return
		}
		release()
		released = true
		profile.pass(raw) // the server's own timeouts bound it from here
		return
	}
	cfg := &tls.Config{GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		s.mu.Lock()
		defer s.mu.Unlock()
		switch {
		case slices.Contains(hello.SupportedProtos, pair.Protocol):
			// Also without a window, so the joiner hears that it is closed.
			return pair.ServerTLS(s.id), nil
		case !slices.Contains(hello.SupportedProtos, group.MemberProtocol) && s.phoneTLS != nil:
			return s.phoneTLS, nil
		}
		return s.nd.ServerTLS(), nil
	}}
	tc := tls.Server(raw, cfg)
	hctx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	err = tc.HandshakeContext(hctx)
	cancel()
	if err != nil {
		tc.Close()
		return
	}
	switch tc.ConnectionState().NegotiatedProtocol {
	case group.MemberProtocol:
	case pair.Protocol:
		s.mu.Lock()
		w := s.window
		s.mu.Unlock()
		if w == nil {
			pair.Refuse(ctx, tc, pair.ErrClosed)
			return
		}
		if err := w.Serve(ctx, tc); err != nil {
			s.logf("cbb: pairing attempt from %s: %v", raw.RemoteAddr(), err)
		}
		return
	default:
		s.mu.Lock()
		phone := s.phoneConns
		s.mu.Unlock()
		if phone == nil {
			tc.Close()
			return
		}
		release()
		released = true
		phone.pass(tc)
		return
	}
	release()
	released = true
	if err := s.nd.Serve(ctx, tc); err != nil {
		s.logf("cbb: connection from %s: %v", raw.RemoteAddr(), err)
	}
}

// dialer keeps the connection to one member up.
type dialer struct {
	cancel context.CancelFunc
	addrs  []string // where discovery last saw the member, best first
}

// found handles the members that discovery found. A Mac dials every Linux
// and lite member, since its firewall may keep them from reaching it, and
// the Macs (TXT r=mac) whose device ID is greater than its own; a Linux
// member dials the Linux members whose device ID is greater than its own,
// and leaves the Macs and the lite members (TXT r=lite) to dial it. So two
// members make one connection between them. A member's dialer takes its
// new addresses or port on its next round.
func (s *Service) found(peers []mdns.Peer) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.id == nil || s.stopping {
		return
	}
	tag := group.Tag(s.id.GroupCA.Cert)
	want := map[group.DeviceID][]string{}
	s.nearby = map[group.DeviceID]bool{}
	for _, p := range peers {
		id, err := group.ParseDeviceID(p.ID)
		if err != nil || id == s.id.ID {
			continue
		}
		if g, _ := p.TXTValue("g"); g != tag {
			continue // another group, or an old CA
		}
		s.nearby[id] = true
		r, _ := p.TXTValue("r")
		mac, lite := strings.EqualFold(r, "mac"), strings.EqualFold(r, "lite")
		switch {
		case s.cfg.Role == node.Linux && (mac || lite):
			continue // it dials the Linux members
		case (s.cfg.Role == node.Linux || mac) && !lite && id < s.id.ID:
			continue // of two Linux members, or two Macs, the lower ID dials
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
			s.logf("cbb: connection to %s at %s: %v", id, addr, err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(2*backoff, maxBackoff)
	}
}

// dialJoined keeps a member connection up to the member that admitted this
// device at the address the user gave for the join, such as an SSH forward
// or a VPN address, which discovery cannot find. Then that member syncs
// with it at once, and when it is the group's hub it learns this device's
// tunnel key as soon as sync away from home is turned on here. It dials
// only while discovery does not see the member and no other connection to
// it is up, and stops for good once this device knows the group's hub, or
// when the service stops.
func (s *Service) dialJoined(id group.DeviceID, addr string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.groupCtx == nil || s.stopping {
		return
	}
	ctx := s.groupCtx
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.keepJoined(ctx, id, addr)
	}()
}

func (s *Service) keepJoined(ctx context.Context, id group.DeviceID, addr string) {
	backoff := minBackoff
	for ctx.Err() == nil {
		s.tunMu.Lock()
		hub := s.tunnel != nil && s.tunnel.ToHub != nil
		s.tunMu.Unlock()
		if hub {
			return // the tunnel reaches the hub from here on
		}
		s.mu.Lock()
		nd, near := s.nd, s.nearby[id]
		s.mu.Unlock()
		if nd == nil {
			return
		}
		wait := awayCheck
		if !near && !slices.ContainsFunc(nd.Peers(), func(p node.Peer) bool { return p.ID == id }) {
			start := uptime.Now()
			err := nd.Dial(ctx, id, addr)
			if ctx.Err() != nil {
				return
			}
			if uptime.Now()-start > maxBackoff {
				backoff = minBackoff
			}
			s.logf("cbb: connection to %s at %s, where it joined: %v", id, addr, err)
			wait = backoff
			backoff = min(2*backoff, maxBackoff)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

// peersChanged elects the holder of clipboardbridge.local: the Linux member with
// the lowest device ID among this one and the Linux members it is
// connected to.
func (s *Service) peersChanged() {
	s.mu.Lock()
	s.electLocked()
	nd := s.nd
	s.mu.Unlock()
	if nd == nil {
		return
	}
	s.trackSeen(nd.Peers())
	s.ensureListed()
}

func (s *Service) electLocked() {
	if s.id == nil || s.cfg.Role != node.Linux || s.responder == nil || s.stopping {
		return // a stopping member keeps what it had until its goodbye
	}
	if s.id.Phone == nil {
		return // without the CA keys, as in a group whose root is the phone, it never holds the name
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
		s.logf("cbb: holds clipboardbridge.local: %v", hold)
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
			s.logf("cbb: the machine slept for %v", slept.Round(time.Second))
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
