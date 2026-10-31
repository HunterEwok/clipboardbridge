// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Package budget is the accounting of the open relay and the forwarder: what
// state and work strangers may make them hold, charged to whoever pays for
// it (docs/relay-budget.md). A source address pays at each of its levels,
// the address itself, its network (an IPv4 /24 or an IPv6 /64), its wide
// network (an IPv4 /16 or an IPv6 /48) and, for IPv6, its provider (a /32),
// and all sources together at one more; each level has its own cap, so one
// host, one site or one provider can take only its share of what the server
// has. What is full refuses the new: nothing a source holds is taken from it
// to make room for another.
package budget

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"
)

// Level is who pays: an address, its network, its wide network, its
// provider, or every source together.
type Level int

const (
	Address Level = iota
	Network
	Wide
	Provider
	All
)

func (l Level) String() string {
	switch l {
	case Address:
		return "address"
	case Network:
		return "network"
	case Wide:
		return "wide network"
	case Provider:
		return "provider"
	case All:
		return "all sources"
	}
	return fmt.Sprintf("level %d", int(l))
}

// The prefix lengths of each level, for IPv4 and for IPv6. A home usually
// gets one IPv4 address of a /24 or a whole IPv6 /64, a site or a
// provider's customer an IPv6 /48, and a provider an IPv6 /32, from which
// it hands out tens of thousands of /48s; an IPv4 /16 is the closest IPv4
// has to either, and it is its own provider: IPv4 addresses are too scarce
// for one source to hold many /16s.
var (
	bits4 = [4]int{32, 24, 16, 16}
	bits6 = [4]int{128, 64, 48, 32}
)

// Of returns the prefix that pays for address a at level l (Address,
// Network, Wide or Provider); the provider of an IPv4 address is its wide
// network. An address that is not valid pays as the zero prefix, with every
// other one that is not.
func Of(a netip.Addr, l Level) netip.Prefix {
	a = a.Unmap()
	bits := bits6[l]
	if a.Is4() {
		bits = bits4[l]
	}
	p, _ := a.Prefix(bits)
	return p
}

// Payers returns the prefixes that pay for a, the one of each level in
// order: its address, network and wide network, and for an IPv6 address
// its provider, which for IPv4 is the wide network again and pays once. An
// address that is not valid has one payer, the zero prefix, at every level.
func Payers(a netip.Addr) []netip.Prefix {
	if !a.IsValid() {
		return []netip.Prefix{{}}
	}
	if a.Unmap().Is4() {
		return []netip.Prefix{Of(a, Address), Of(a, Network), Of(a, Wide)}
	}
	return []netip.Prefix{Of(a, Address), Of(a, Network), Of(a, Wide), Of(a, Provider)}
}

// Caps bound what one payer of each level may hold, and All what all hold
// together; zero leaves a level without a cap.
type Caps struct {
	Address, Network, Wide, Provider, All int
}

func (c Caps) of(l Level) int {
	return [5]int{c.Address, c.Network, c.Wide, c.Provider, c.All}[l]
}

// Count holds what each source holds now: registrations, slots or bytes.
// A payer that holds nothing is forgotten, so the count takes memory only
// for what is held. It is not safe for concurrent use.
type Count struct {
	caps Caps
	held map[netip.Prefix]int
	all  int
}

// NewCount returns an empty count with the caps c.
func NewCount(c Caps) *Count {
	return &Count{caps: c, held: map[netip.Prefix]int{}}
}

// Full returns the first level at which a source at a could not hold n more,
// and false when every level has room; it changes nothing.
func (c *Count) Full(a netip.Addr, n int) (Level, bool) {
	for l, p := range Payers(a) {
		if limit := c.caps.of(Level(l)); limit > 0 && c.held[p]+n > limit {
			return Level(l), true
		}
	}
	if c.caps.All > 0 && c.all+n > c.caps.All {
		return All, true
	}
	return 0, false
}

// Add charges n to the source at a and to all, whether or not it fits: the
// caller asks Full first.
func (c *Count) Add(a netip.Addr, n int) {
	for _, p := range Payers(a) {
		c.held[p] += n
	}
	c.all += n
}

// Take charges n to the source at a when it fits, and reports whether it did.
func (c *Count) Take(a netip.Addr, n int) bool {
	if _, full := c.Full(a, n); full {
		return false
	}
	c.Add(a, n)
	return true
}

// Remove gives back n that Add charged to the source at a.
func (c *Count) Remove(a netip.Addr, n int) {
	for _, p := range Payers(a) {
		if c.held[p] <= n {
			delete(c.held, p)
		} else {
			c.held[p] -= n
		}
	}
	c.all = max(0, c.all-n)
}

// Held returns what the payer of a at level l holds, or all sources at All.
func (c *Count) Held(a netip.Addr, l Level) int {
	if l == All {
		return c.all
	}
	return c.held[Of(a, l)]
}

// Payers returns how many payers hold something, which is what the count
// takes in memory.
func (c *Count) Payers() int { return len(c.held) }

// Rate is what a payer earns a second, and the most it may save.
type Rate struct {
	PerSecond, Burst float64
}

// Rates is what each source may still start: work that costs the server
// time, paid for in units that each payer earns by the second, at the
// levels of a source. It is not safe for concurrent use.
type Rates struct {
	rates   [4]Rate
	buckets map[netip.Prefix]*bucket
	sweepAt int
}

type bucket struct {
	units float64
	at    time.Time
}

// minSweep is how many payers Rates holds before it looks for ones to forget.
const minSweep = 4096

// NewRates returns the rates of an address, a network, a wide network and
// a provider.
func NewRates(address, network, wide, provider Rate) *Rates {
	return &Rates{rates: [4]Rate{address, network, wide, provider}, buckets: map[netip.Prefix]*bucket{}, sweepAt: minSweep}
}

func (b *bucket) refill(now time.Time, r Rate) {
	b.units = min(r.Burst, b.units+max(0, now.Sub(b.at).Seconds())*r.PerSecond)
	b.at = now
}

// Take charges n units to the source at a at every level, or charges
// nothing and returns false when any level lacks them. A source that is
// refused keeps its place, so asking again does not start it over with a
// full burst.
func (r *Rates) Take(a netip.Addr, n float64, now time.Time) bool {
	r.sweep(now)
	payers := Payers(a)
	bs := make([]*bucket, len(payers))
	ok := true
	for l, p := range payers {
		b := r.buckets[p]
		if b == nil {
			b = &bucket{units: r.rates[l].Burst, at: now}
			r.buckets[p] = b
		}
		b.refill(now, r.rates[l])
		bs[l] = b
		ok = ok && b.units >= n
	}
	if !ok {
		return false
	}
	for _, b := range bs {
		b.units -= n
	}
	return true
}

// Sweep forgets the payers whose units are full again, which a new payer
// would start with anyway.
func (r *Rates) Sweep(now time.Time) {
	for p, b := range r.buckets {
		l := levelOf(p)
		if b.units+now.Sub(b.at).Seconds()*r.rates[l].PerSecond >= r.rates[l].Burst {
			delete(r.buckets, p)
		}
	}
	r.sweepAt = max(minSweep, 2*len(r.buckets))
}

func (r *Rates) sweep(now time.Time) {
	if len(r.buckets) >= r.sweepAt {
		r.Sweep(now)
	}
}

// Payers returns how many payers Rates holds now.
func (r *Rates) Payers() int { return len(r.buckets) }

// levelOf tells the level of a payer by its prefix length; an IPv4 /16 is
// a wide network, which is its own provider.
func levelOf(p netip.Prefix) Level {
	bits := bits6
	if p.Addr().Is4() {
		bits = bits4
	}
	for l, b := range bits {
		if p.Bits() == b {
			return Level(l)
		}
	}
	return Address
}

// String lists what each payer holds, in order, and the total: two counts
// that hold the same say the same.
func (c *Count) String() string {
	ps := make([]netip.Prefix, 0, len(c.held))
	for p := range c.held {
		ps = append(ps, p)
	}
	slices.SortFunc(ps, func(a, b netip.Prefix) int {
		if n := a.Addr().Compare(b.Addr()); n != 0 {
			return n
		}
		return a.Bits() - b.Bits()
	})
	var s strings.Builder
	for _, p := range ps {
		fmt.Fprintf(&s, "%s %d\n", p, c.held[p])
	}
	fmt.Fprintf(&s, "all %d", c.all)
	return s.String()
}

// Left returns the units the payer of a at level l (Address, Network, Wide
// or Provider) has saved as of its last charge: a full burst for one that holds
// none.
func (r *Rates) Left(a netip.Addr, l Level) float64 {
	if b := r.buckets[Of(a, l)]; b != nil {
		return b.units
	}
	return r.rates[l].Burst
}
