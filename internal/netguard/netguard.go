// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Package netguard keeps the service's own connections on the home network,
// and with sync away from home on, on the home network and the group's own
// servers: its hub, forwarder and relay, and nothing else on the internet.
// It is the program's own limit, in every system; the installers and cbb
// global add one outside the program where the system has a way to (the
// systemd unit on Linux, a Windows Firewall rule), and on a Mac it is the
// only one until the Mac app brings a Network Extension (docs/roadmap.md).
package netguard

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sync/atomic"
	"syscall"
)

// limit is what the service may reach beyond the home network.
type limit struct {
	away  bool         // sync away from home is on
	dests []netip.Addr // the group's servers, while it is on
}

var current atomic.Pointer[limit]

// Set gives the addresses beyond the home network that the service may
// reach: none while sync away from home is off (away false), the group's
// hub, forwarder and relay while it is on.
func Set(away bool, dests []netip.Addr) {
	l := &limit{away: away}
	if away {
		for _, a := range dests {
			if a = a.Unmap(); a.IsValid() && !slices.Contains(l.dests, a) {
				l.dests = append(l.dests, a)
			}
		}
	}
	current.Store(l)
}

// Away reports whether sync away from home is on.
func Away() bool {
	l := current.Load()
	return l != nil && l.away
}

// Destinations returns the addresses beyond the home network that the
// service may reach now.
func Destinations() []netip.Addr {
	if l := current.Load(); l != nil {
		return slices.Clone(l.dests)
	}
	return nil
}

// ErrOutside is a connection to an address outside the home network that
// is none of the group's servers.
var ErrOutside = errors.New("the address is outside the home network and is none of the group's hub, forwarder and relay")

// Home reports whether a belongs to the home network: loopback, private
// IPv4, link-local, multicast and broadcast, unique-local IPv6.
func Home(a netip.Addr) bool {
	a = a.Unmap()
	return a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() ||
		a.IsMulticast() || a == netip.AddrFrom4([4]byte{255, 255, 255, 255})
}

// Allowed reports whether the service may reach a: the home network, or
// one of the group's servers while sync away from home is on.
func Allowed(a netip.Addr) bool {
	if Home(a) {
		return true
	}
	l := current.Load()
	return l != nil && l.away && slices.Contains(l.dests, a.Unmap())
}

// Control is a net.Dialer's Control: it refuses a connection that Allowed
// refuses, before any packet leaves.
func Control(network, address string, _ syscall.RawConn) error {
	ap, err := netip.ParseAddrPort(address)
	if err != nil || !Allowed(ap.Addr()) {
		return fmt.Errorf("%s: %w", address, ErrOutside)
	}
	return nil
}
