// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package mdns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"sync"
	"syscall"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// packet is a received datagram and the interface it arrived on.
type packet struct {
	data    []byte
	src     netip.AddrPort
	ifIndex int
}

// iface is a network interface the responder works on.
type iface struct {
	index      int
	name       string
	addrs      []netip.Addr   // the addresses it publishes there, sorted
	prefixes   []netip.Prefix // every address with its network, for the link check
	has4, has6 bool           // it publishes addresses of that family
	publish    bool           // the member is published here (Config.Publish)
}

// transport is the network as the responder sees it; tests replace it.
type transport interface {
	read() (packet, error)
	send(data []byte, ifIndex int, dst netip.AddrPort) error
	interfaces() ([]iface, error)
	close() error
}

// udp is the system's network: one socket per address family on port 5353,
// shared with other mDNS responders on the host.
type udp struct {
	logf    func(string, ...any)
	only    func(string) bool // the interfaces to join on; all if nil
	c4      *ipv4.PacketConn
	c6      *ipv6.PacketConn
	packets chan packet
	done    chan struct{}

	mu      sync.Mutex
	joined4 map[int]bool
	joined6 map[int]bool
	ifaces  []iface // the last list, to find a packet's interface without control messages
	closed  bool
	shared  bool // the sockets are copies of the preopened ones
}

// preopened holds the sockets Preopen opened, which one responder of the
// process at a time takes.
var preopened struct {
	sync.Mutex
	f4, f6 *os.File
	taken  bool
}

// Preopen opens the sockets on port 5353 now, with the privileges the
// process has, for the responders it starts after it gives them up. On
// FreeBSD a socket shares a port only with sockets of its own user unless
// root opened it, so the service, which runs as its own user there, opens
// them as root and shares the port with avahi (docs/design.md).
func Preopen() error {
	lc := listenConfig()
	var errs []error
	preopened.Lock()
	defer preopened.Unlock()
	for _, fam := range []struct {
		network, addr string
		f             **os.File
	}{{"udp4", fmt.Sprintf("0.0.0.0:%d", Port), &preopened.f4}, {"udp6", fmt.Sprintf("[::]:%d", Port), &preopened.f6}} {
		pc, err := lc.ListenPacket(context.Background(), fam.network, fam.addr)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		f, err := pc.(*net.UDPConn).File()
		pc.Close()
		if err != nil {
			errs = append(errs, err)
			continue
		}
		*fam.f = f
	}
	if preopened.f4 == nil && preopened.f6 == nil {
		return fmt.Errorf("mdns: cannot listen on port %d: %w", Port, errors.Join(errs...))
	}
	return nil
}

// takePreopened returns copies of the preopened sockets, or nil ones when
// there are none or another responder holds them.
func takePreopened() (c4, c6 net.PacketConn) {
	preopened.Lock()
	defer preopened.Unlock()
	if preopened.taken || preopened.f4 == nil && preopened.f6 == nil {
		return nil, nil
	}
	if preopened.f4 != nil {
		c4, _ = net.FilePacketConn(preopened.f4)
	}
	if preopened.f6 != nil {
		c6, _ = net.FilePacketConn(preopened.f6)
	}
	preopened.taken = c4 != nil || c6 != nil
	return c4, c6
}

func listenConfig() net.ListenConfig {
	return net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error {
		var serr error
		err := c.Control(func(fd uintptr) { serr = reuse(fd) })
		if err != nil {
			return err
		}
		return serr
	}}
}

// listen opens the sockets, which join the multicast groups on the
// interfaces only allows (all if nil). Either family may be missing, for
// example IPv6 on a host without it, but not both.
func listen(logf func(string, ...any), only func(string) bool) (*udp, error) {
	lc := listenConfig()
	u := &udp{logf: logf, only: only, packets: make(chan packet, 64), done: make(chan struct{}), joined4: map[int]bool{}, joined6: map[int]bool{}}
	var errs []error
	pc4, pc6 := takePreopened()
	u.shared = pc4 != nil || pc6 != nil
	open := func(pc net.PacketConn, network, addr string) (net.PacketConn, error) {
		if u.shared {
			if pc == nil {
				return nil, fmt.Errorf("mdns: no preopened %s socket", network)
			}
			return pc, nil
		}
		return lc.ListenPacket(context.Background(), network, addr)
	}
	if pc, err := open(pc4, "udp4", fmt.Sprintf("0.0.0.0:%d", Port)); err != nil {
		errs = append(errs, err)
	} else {
		c := ipv4.NewPacketConn(pc)
		if err := setup4(c); err != nil {
			pc.Close()
			errs = append(errs, err)
		} else {
			u.c4 = c
		}
	}
	if pc, err := open(pc6, "udp6", fmt.Sprintf("[::]:%d", Port)); err != nil {
		errs = append(errs, err)
	} else {
		c := ipv6.NewPacketConn(pc)
		if err := setup6(c); err != nil {
			pc.Close()
			errs = append(errs, err)
		} else {
			u.c6 = c
		}
	}
	if u.c4 == nil && u.c6 == nil {
		u.release()
		return nil, fmt.Errorf("mdns: cannot listen on port %d: %w%s", Port, errors.Join(errs...), holders())
	}
	var wg sync.WaitGroup
	if u.c4 != nil {
		wg.Add(1)
		go func() { defer wg.Done(); u.read4() }()
	}
	if u.c6 != nil {
		wg.Add(1)
		go func() { defer wg.Done(); u.read6() }()
	}
	go func() { wg.Wait(); close(u.packets) }()
	return u, nil
}

// setup4 and setup6 set the hop limit of 255 that RFC 6762 requires, keep
// multicast loopback on so other responders on this host see the member,
// and ask for the interface of each packet where the system can tell it.
func setup4(c *ipv4.PacketConn) error {
	err := errors.Join(c.SetMulticastTTL(255), c.SetTTL(255), c.SetMulticastLoopback(true))
	if controlMessages {
		err = errors.Join(err, c.SetControlMessage(ipv4.FlagInterface, true))
	}
	return err
}

func setup6(c *ipv6.PacketConn) error {
	err := errors.Join(c.SetMulticastHopLimit(255), c.SetHopLimit(255), c.SetMulticastLoopback(true))
	if controlMessages {
		err = errors.Join(err, c.SetControlMessage(ipv6.FlagInterface, true))
	}
	return err
}

func (u *udp) read4() {
	buf := make([]byte, maxPacket)
	for {
		n, cm, src, err := u.c4.ReadFrom(buf)
		if err != nil {
			return
		}
		u.deliver(buf[:n], cm != nil, ifIndex4(cm), src)
	}
}

func (u *udp) read6() {
	buf := make([]byte, maxPacket)
	for {
		n, cm, src, err := u.c6.ReadFrom(buf)
		if err != nil {
			return
		}
		u.deliver(buf[:n], cm != nil, ifIndex6(cm), src)
	}
}

func ifIndex4(cm *ipv4.ControlMessage) int {
	if cm == nil {
		return 0
	}
	return cm.IfIndex
}

func ifIndex6(cm *ipv6.ControlMessage) int {
	if cm == nil {
		return 0
	}
	return cm.IfIndex
}

func (u *udp) deliver(data []byte, ok bool, ifIndex int, src net.Addr) {
	ua, isUDP := src.(*net.UDPAddr)
	if !isUDP {
		return
	}
	if !controlMessages {
		ifIndex, ok = u.lookup(ua), true
	}
	if !ok || ifIndex == 0 {
		return
	}
	select {
	case u.packets <- packet{data: slices.Clone(data), src: ua.AddrPort(), ifIndex: ifIndex}:
	case <-u.done:
	default: // the responder is behind; drop the packet, as the network might
	}
}

func (u *udp) read() (packet, error) {
	p, ok := <-u.packets
	if !ok {
		return packet{}, net.ErrClosed
	}
	return p, nil
}

func (u *udp) send(data []byte, ifIndex int, dst netip.AddrPort) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.closed {
		return net.ErrClosed
	}
	addr := net.UDPAddrFromAddrPort(dst)
	if dst.Addr().Is4() || dst.Addr().Is4In6() {
		if u.c4 == nil {
			return errors.New("no IPv4 socket")
		}
		if dst.Addr().IsMulticast() {
			ifi, err := net.InterfaceByIndex(ifIndex)
			if err != nil {
				return err
			}
			if err := u.c4.SetMulticastInterface(ifi); err != nil {
				return err
			}
		}
		_, err := u.c4.WriteTo(data, &ipv4.ControlMessage{IfIndex: ifIndex}, addr)
		return err
	}
	if u.c6 == nil {
		return errors.New("no IPv6 socket")
	}
	if !controlMessages && dst.Addr().IsMulticast() {
		ifi, err := net.InterfaceByIndex(ifIndex)
		if err != nil {
			return err
		}
		if err := u.c6.SetMulticastInterface(ifi); err != nil {
			return err
		}
	}
	_, err := u.c6.WriteTo(data, &ipv6.ControlMessage{IfIndex: ifIndex, HopLimit: 255}, addr)
	return err
}

// lookup finds the interface a packet came in on from its source address,
// for a system that does not tell: the interface of a link-local source's
// zone, or the one whose network holds the source. It returns 0 for none.
func (u *udp) lookup(src *net.UDPAddr) int {
	a, ok := netip.AddrFromSlice(src.IP)
	if !ok {
		return 0
	}
	a = a.Unmap()
	if a.Is6() && a.IsLinkLocalUnicast() {
		if ifi, err := net.InterfaceByName(src.Zone); err == nil {
			return ifi.Index
		}
		n, _ := strconv.Atoi(src.Zone)
		return n
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	for _, f := range u.ifaces {
		for _, p := range f.prefixes {
			if p.Contains(a) {
				return f.index
			}
		}
	}
	return 0
}

// interfaces lists the interfaces that are up, can multicast and are not
// loopback or point-to-point links such as VPN tunnels, and joins the
// multicast groups on the ones it has not joined yet.
func (u *udp) interfaces() ([]iface, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var out []iface
	for _, ifi := range ifs {
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagMulticast == 0 ||
			ifi.Flags&(net.FlagLoopback|net.FlagPointToPoint) != 0 || u.only != nil && !u.only(ifi.Name) {
			continue
		}
		f, err := describe(ifi)
		if err != nil || len(f.addrs) == 0 {
			continue
		}
		u.join(ifi, f)
		out = append(out, f)
	}
	u.mu.Lock()
	u.ifaces = out
	u.mu.Unlock()
	return out, nil
}

func describe(ifi net.Interface) (iface, error) {
	addrs, err := ifi.Addrs()
	if err != nil {
		return iface{index: ifi.Index, name: ifi.Name}, err
	}
	var prefixes []netip.Prefix
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip, ok := netip.AddrFromSlice(ipn.IP)
		if !ok {
			continue
		}
		ones, _ := ipn.Mask.Size()
		prefixes = append(prefixes, netip.PrefixFrom(ip.Unmap(), ones))
	}
	return newIface(ifi.Index, ifi.Name, prefixes), nil
}

func (u *udp) join(ifi net.Interface, f iface) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if f.has4 && u.c4 != nil && !u.joined4[ifi.Index] {
		if err := u.c4.JoinGroup(&ifi, &net.UDPAddr{IP: group4.Addr().AsSlice()}); err != nil {
			u.logf("mdns: joining the IPv4 group on %s: %v", ifi.Name, err)
		} else {
			u.joined4[ifi.Index] = true
		}
	}
	if f.has6 && u.c6 != nil && !u.joined6[ifi.Index] {
		if err := u.c6.JoinGroup(&ifi, &net.UDPAddr{IP: group6.Addr().AsSlice()}); err != nil {
			u.logf("mdns: joining the IPv6 group on %s: %v", ifi.Name, err)
		} else {
			u.joined6[ifi.Index] = true
		}
	}
}

func (u *udp) close() error {
	u.mu.Lock()
	if u.closed {
		u.mu.Unlock()
		return nil
	}
	u.closed = true
	close(u.done)
	// The preopened sockets outlive this responder, so it leaves the
	// groups it joined on them for the next one to join.
	if u.shared {
		for i := range u.joined4 {
			if ifi, err := net.InterfaceByIndex(i); err == nil {
				u.c4.LeaveGroup(ifi, &net.UDPAddr{IP: group4.Addr().AsSlice()})
			}
		}
		for i := range u.joined6 {
			if ifi, err := net.InterfaceByIndex(i); err == nil {
				u.c6.LeaveGroup(ifi, &net.UDPAddr{IP: group6.Addr().AsSlice()})
			}
		}
	}
	u.mu.Unlock()
	var errs []error
	if u.c4 != nil {
		errs = append(errs, u.c4.Close())
	}
	if u.c6 != nil {
		errs = append(errs, u.c6.Close())
	}
	u.release()
	return errors.Join(errs...)
}

// release lets the next responder take the preopened sockets.
func (u *udp) release() {
	if u.shared {
		preopened.Lock()
		preopened.taken = false
		preopened.Unlock()
	}
}
