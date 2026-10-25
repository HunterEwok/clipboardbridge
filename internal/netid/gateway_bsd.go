// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build darwin || freebsd

package netid

import (
	"net"
	"net/netip"
	"syscall"

	"golang.org/x/net/route"
)

// gateways reads the default routes and the ARP entries from the routing
// table.
func gateways() (map[int]string, error) {
	rib, err := route.FetchRIB(syscall.AF_INET, route.RIBTypeRoute, 0)
	if err != nil {
		return nil, err
	}
	msgs, err := route.ParseRIB(route.RIBTypeRoute, rib)
	if err != nil {
		return nil, err
	}
	gw := map[int]netip.Addr{}
	for _, m := range msgs {
		r, ok := m.(*route.RouteMessage)
		if !ok || r.Flags&syscall.RTF_GATEWAY == 0 || len(r.Addrs) <= syscall.RTAX_GATEWAY {
			continue
		}
		dst, ok := r.Addrs[syscall.RTAX_DST].(*route.Inet4Addr)
		if !ok || dst.IP != [4]byte{} {
			continue
		}
		if len(r.Addrs) > syscall.RTAX_NETMASK {
			if mask, ok := r.Addrs[syscall.RTAX_NETMASK].(*route.Inet4Addr); ok && mask.IP != [4]byte{} {
				continue
			}
		}
		if g, ok := r.Addrs[syscall.RTAX_GATEWAY].(*route.Inet4Addr); ok {
			if _, seen := gw[r.Index]; !seen {
				gw[r.Index] = netip.AddrFrom4(g.IP)
			}
		}
	}
	if len(gw) == 0 {
		return nil, nil
	}
	// The ARP entries: routes with link-layer information.
	rib, err = route.FetchRIB(syscall.AF_INET, route.RIBType(syscall.NET_RT_FLAGS), syscall.RTF_LLINFO)
	if err != nil {
		return nil, err
	}
	if msgs, err = route.ParseRIB(route.RIBType(syscall.NET_RT_FLAGS), rib); err != nil {
		return nil, err
	}
	out := map[int]string{}
	for _, m := range msgs {
		r, ok := m.(*route.RouteMessage)
		if !ok || len(r.Addrs) <= syscall.RTAX_GATEWAY {
			continue
		}
		dst, ok := r.Addrs[syscall.RTAX_DST].(*route.Inet4Addr)
		if !ok || gw[r.Index] != netip.AddrFrom4(dst.IP) {
			continue
		}
		if l, ok := r.Addrs[syscall.RTAX_GATEWAY].(*route.LinkAddr); ok && len(l.Addr) == 6 {
			out[r.Index] = net.HardwareAddr(l.Addr).String()
		}
	}
	return out, nil
}
