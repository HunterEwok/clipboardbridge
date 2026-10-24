// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Package netguard keeps the service's own connections on the home network
// until sync away from home is on. It is the program's own limit, in every
// system; the installers add one outside the program where the system has
// a way to (the systemd unit on Linux, a Windows Firewall rule), and on a
// Mac it is the only one until the Mac app brings a Network Extension
// (docs/roadmap.md).
package netguard

import (
	"errors"
	"fmt"
	"net/netip"
	"sync/atomic"
	"syscall"
)

var open atomic.Bool

// SetOpen lets the service's connections reach the internet (on), or only
// the home network.
func SetOpen(on bool) { open.Store(on) }

// Open reports whether the service's connections may reach the internet.
func Open() bool { return open.Load() }

// ErrOutside is a connection to an address outside the home network while
// sync away from home is off.
var ErrOutside = errors.New("the address is outside the home network, and sync away from home is off")

// Home reports whether a belongs to the home network: loopback, private
// IPv4, link-local, multicast and broadcast, unique-local IPv6.
func Home(a netip.Addr) bool {
	a = a.Unmap()
	return a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() ||
		a.IsMulticast() || a == netip.AddrFrom4([4]byte{255, 255, 255, 255})
}

// Control is a net.Dialer's Control: it refuses a connection outside the
// home network while sync away from home is off.
func Control(network, address string, _ syscall.RawConn) error {
	if open.Load() {
		return nil
	}
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return fmt.Errorf("%s: %w", address, ErrOutside)
	}
	if !Home(ap.Addr()) {
		return fmt.Errorf("%s: %w", address, ErrOutside)
	}
	return nil
}
