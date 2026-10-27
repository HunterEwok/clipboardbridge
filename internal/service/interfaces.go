// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"net"
	"net/netip"
	"slices"
)

// onlyIn returns a test for the interfaces in names, or nil, which allows
// every interface, when names is empty.
func onlyIn(names []string) func(string) bool {
	if len(names) == 0 {
		return nil
	}
	names = slices.Clone(names)
	return func(name string) bool { return slices.Contains(names, name) }
}

// only tells which interfaces the service works on (Config.Interfaces):
// nil for all of them.
func (s *Service) only() func(string) bool { return onlyIn(s.cfg.Interfaces) }

// arrivedOn tells whether a connection to the member port came from an
// interface the service is limited to (Config.Interfaces). A router keeps
// its member port to its home zones this way even when its firewall lets
// the internet in by mistake: the connection must come to an address of
// such an interface, from an address on that interface's own networks. A
// packet from the internet side cannot carry such an address back and
// forth, as the router's replies to it go to its home network. Without a
// list, and from this device itself, every connection is.
func (s *Service) arrivedOn(c net.Conn) bool {
	only := s.only()
	if only == nil {
		return true
	}
	local, err1 := netip.ParseAddrPort(c.LocalAddr().String())
	remote, err2 := netip.ParseAddrPort(c.RemoteAddr().String())
	if err1 != nil || err2 != nil {
		return false
	}
	if remote.Addr().Unmap().IsLoopback() {
		return true
	}
	ifs, err := s.nets.interfaces()
	if err != nil {
		return false
	}
	return onLink(ifs, only, local.Addr(), remote.Addr())
}

// onLink tells whether a connection from remote to local is on one of the
// interfaces ifs that only allows: local is an address of the interface,
// and remote is on one of its networks; a link-local remote must name the
// interface as its zone.
func onLink(ifs []netInterface, only func(string) bool, local, remote netip.Addr) bool {
	zone := remote.Zone()
	local, remote = local.WithZone("").Unmap(), remote.WithZone("").Unmap()
	for _, f := range ifs {
		if !only(f.name) || !slices.ContainsFunc(f.prefixes, func(p netip.Prefix) bool { return p.Addr() == local }) {
			continue
		}
		if remote.Is6() && remote.IsLinkLocalUnicast() {
			return zone == f.name
		}
		return slices.ContainsFunc(f.prefixes, func(p netip.Prefix) bool { return p.Contains(remote) })
	}
	return false
}
