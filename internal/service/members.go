// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"context"
	"crypto/tls"
	"errors"
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
// that the client offers picks pairing or the member protocol.
func (s *Service) serveMember(ctx context.Context, raw net.Conn) {
	cfg := &tls.Config{GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		s.mu.Lock()
		defer s.mu.Unlock()
		if slices.Contains(hello.SupportedProtos, pair.Protocol) {
			if s.window == nil {
				return nil, errors.New("no pairing window is open")
			}
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
			tc.Close()
			return
		}
		if err := w.Serve(ctx, tc); err != nil {
			s.logf("clipbridge: pairing attempt from %s: %v", raw.RemoteAddr(), err)
		}
		return
	}
	if err := s.nd.Serve(ctx, tc); err != nil {
		s.logf("clipbridge: connection from %s: %v", raw.RemoteAddr(), err)
	}
}

// found handles the members that discovery found: a Mac dials every Linux
// member; a Linux member dials those whose device ID is greater than its
// own, so two members make one connection between them.
func (s *Service) found(peers []mdns.Peer) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.id == nil {
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
		for _, a := range p.Addrs {
			want[id] = append(want[id], net.JoinHostPort(a.String(), strconv.Itoa(int(p.Port))))
		}
	}
	for id, cancel := range s.dialers {
		if _, ok := want[id]; !ok {
			cancel()
			delete(s.dialers, id)
		}
	}
	for id, addrs := range want {
		if _, ok := s.dialers[id]; ok {
			continue
		}
		ctx, cancel := context.WithCancel(s.groupCtx)
		s.dialers[id] = cancel
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.dial(ctx, id, addrs)
		}()
	}
}

// dial keeps a connection to a member up while it is found: it tries its
// addresses in turn, IPv4 first, and waits longer after each failure.
func (s *Service) dial(ctx context.Context, id group.DeviceID, addrs []string) {
	slices.SortStableFunc(addrs, func(a, b string) int {
		return boolInt(isIPv6(a)) - boolInt(isIPv6(b))
	})
	backoff := minBackoff
	for ctx.Err() == nil {
		for _, addr := range addrs {
			start := uptime.Now()
			err := s.nd.Dial(ctx, id, addr)
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

func isIPv6(addr string) bool {
	host, _, _ := net.SplitHostPort(addr)
	a, err := netip.ParseAddr(host)
	return err == nil && a.Is6()
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
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
	if s.id == nil || s.cfg.Role != node.Linux || s.responder == nil {
		return
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
// before are dead, and the member must take the group's text again.
func (s *Service) watchSleep(ctx context.Context) {
	const every, slack = 2 * time.Second, 3 * time.Second
	t := time.NewTicker(every)
	defer t.Stop()
	lastUp, lastMono := uptime.Now(), time.Now()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		up, mono := uptime.Now(), time.Now()
		slept := (up - lastUp) - mono.Sub(lastMono)
		lastUp, lastMono = up, mono
		if slept > slack {
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

// write passes a write that the engine decided on to the watchers, in
// order.
func (s *Service) write(w node.Write) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if w.Seq <= s.lastSeq {
		return
	}
	s.lastSeq = w.Seq
	for wt := range s.watchers {
		wt.send(w)
	}
}
