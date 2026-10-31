// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package relay

import (
	"io"
	"net"
	"net/netip"
	"sync"
	"time"
)

// Limits bound what an open relay (Config.Open), which serves any group
// that registers, gives the groups and the addresses they come from, so
// that groups nobody vouches for cannot fill it or take all its bandwidth.
// A zero field takes its value from DefaultOpenLimits; a relay for the
// user's own groups has no limits but the per-group ones.
type Limits struct {
	Groups     int     // groups on the relay at once
	PerAddress int     // registrations from one IP address
	PerNetwork int     // registrations from one IPv4 /24 or IPv6 /64
	ByteRate   float64 // bytes a second the relay copies for one group, both ways together

	// GroupRecordBytes bounds the bytes of authority records the relay keeps
	// for one group, and RecordBytes those it keeps for all groups.
	GroupRecordBytes int
	RecordBytes      int
}

// DefaultOpenLimits are an open relay's limits: enough for clipboards,
// which are small, and for a few thousand groups on a small server.
var DefaultOpenLimits = Limits{Groups: 4096, PerAddress: 16, PerNetwork: 64, ByteRate: 1 << 20,
	GroupRecordBytes: 256 << 10, RecordBytes: 128 << 20}

func (l Limits) withDefaults() Limits {
	d := DefaultOpenLimits
	if l.Groups <= 0 {
		l.Groups = d.Groups
	}
	if l.PerAddress <= 0 {
		l.PerAddress = d.PerAddress
	}
	if l.PerNetwork <= 0 {
		l.PerNetwork = d.PerNetwork
	}
	if l.ByteRate <= 0 {
		l.ByteRate = d.ByteRate
	}
	if l.GroupRecordBytes <= 0 {
		l.GroupRecordBytes = d.GroupRecordBytes
	}
	if l.RecordBytes <= 0 {
		l.RecordBytes = d.RecordBytes
	}
	return l
}

// networkOf returns the network that an address's limits count: an IPv4
// /24 or an IPv6 /64, where one host usually gets one address of many.
func networkOf(a netip.Addr) netip.Prefix {
	a = a.Unmap()
	bits := 64
	if a.Is4() {
		bits = 24
	}
	p, _ := a.Prefix(bits)
	return p
}

// addrOf returns the IP address of a connection's remote end.
func addrOf(c net.Conn) netip.Addr {
	if ap, err := netip.ParseAddrPort(c.RemoteAddr().String()); err == nil {
		return ap.Addr().Unmap()
	}
	return netip.Addr{}
}

// The work a source may start each second, in units: a registration's
// setup costs setupCost, each record the relay must verify one more. An
// address earns addressRate units a second and may save up to addressBurst,
// a network networkRate and networkBurst; the burst lets one registration
// of a group with a full claim (1024 records) through, and the rates keep
// the checks of a source that registers over and over to a small share of
// a processor (a record's check takes about 45 microseconds).
const (
	setupCost    = 4
	addressRate  = 64.0
	addressBurst = 1536.0
	networkRate  = 256.0
	networkBurst = 4096.0
)

// allowance holds how much work each source address and network may still
// start; it is not safe for concurrent use.
type allowance struct {
	addrs   map[netip.Addr]*bucket
	nets    map[netip.Prefix]*bucket
	sweepAt int
}

type bucket struct {
	units float64
	at    time.Time
}

func newAllowance() *allowance {
	return &allowance{addrs: map[netip.Addr]*bucket{}, nets: map[netip.Prefix]*bucket{}, sweepAt: 4096}
}

func (b *bucket) refill(now time.Time, rate, burst float64) {
	b.units = min(burst, b.units+max(0, now.Sub(b.at).Seconds())*rate)
	b.at = now
}

// take charges n units to the address from and its network, or charges
// nothing and returns false when either lacks them.
func (a *allowance) take(from netip.Addr, n float64, now time.Time) bool {
	a.sweep(now)
	nw := networkOf(from)
	ab, ok := a.addrs[from]
	if !ok {
		ab = &bucket{units: addressBurst, at: now}
	}
	nb, ok2 := a.nets[nw]
	if !ok2 {
		nb = &bucket{units: networkBurst, at: now}
	}
	ab.refill(now, addressRate, addressBurst)
	nb.refill(now, networkRate, networkBurst)
	if ab.units < n || nb.units < n {
		// A source that is refused keeps its entry, so asking again does not
		// start it over with a full burst.
		a.addrs[from], a.nets[nw] = ab, nb
		return false
	}
	ab.units -= n
	nb.units -= n
	a.addrs[from], a.nets[nw] = ab, nb
	return true
}

// sweep forgets the sources whose allowance is full again, which a new
// source would start with anyway, once there are many.
func (a *allowance) sweep(now time.Time) {
	if len(a.addrs)+len(a.nets) < a.sweepAt {
		return
	}
	for k, b := range a.addrs {
		if b.units+now.Sub(b.at).Seconds()*addressRate >= addressBurst {
			delete(a.addrs, k)
		}
	}
	for k, b := range a.nets {
		if b.units+now.Sub(b.at).Seconds()*networkRate >= networkBurst {
			delete(a.nets, k)
		}
	}
	a.sweepAt = max(4096, 2*(len(a.addrs)+len(a.nets)))
}

// rate is a token bucket that holds up to two seconds of its rate; take
// waits until the tokens are there. It is shared by a group's connections.
type rate struct {
	mu     sync.Mutex
	rate   float64
	tokens float64
	at     time.Time
}

func newRate(r float64) *rate {
	return &rate{rate: r, tokens: 2 * r, at: time.Now()}
}

// take waits for n tokens, or until done is closed; false then.
func (b *rate) take(n int, done <-chan struct{}) bool {
	b.mu.Lock()
	now := time.Now()
	b.tokens = min(2*b.rate, b.tokens+now.Sub(b.at).Seconds()*b.rate)
	b.at = now
	b.tokens -= float64(n)
	wait := time.Duration(0)
	if b.tokens < 0 {
		wait = time.Duration(-b.tokens / b.rate * float64(time.Second))
	}
	b.mu.Unlock()
	if wait == 0 {
		return true
	}
	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-done:
		return false
	}
}

// limitedCopy copies src to dst as io.Copy does, at the rate of b when b
// is not nil.
func limitedCopy(dst io.Writer, src io.Reader, b *rate, done <-chan struct{}) {
	if b == nil {
		io.Copy(dst, src)
		return
	}
	buf := make([]byte, 16<<10)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			if !b.take(n, done) {
				return
			}
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}
