// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package budget

import (
	mrand "math/rand/v2"
	"net/netip"
	"testing"
	"time"
)

func TestPayers(t *testing.T) {
	for _, tc := range []struct {
		addr string
		want []string
	}{
		{"192.0.2.7", []string{"192.0.2.7/32", "192.0.2.0/24", "192.0.0.0/16"}},
		{"::ffff:192.0.2.7", []string{"192.0.2.7/32", "192.0.2.0/24", "192.0.0.0/16"}},
		{"2001:db8:1:2:3:4:5:6", []string{"2001:db8:1:2:3:4:5:6/128", "2001:db8:1:2::/64", "2001:db8:1::/48", "2001:db8::/32"}},
	} {
		a := netip.MustParseAddr(tc.addr)
		ps := Payers(a)
		if len(ps) != len(tc.want) {
			t.Errorf("%s has %d payers, want %d", tc.addr, len(ps), len(tc.want))
			continue
		}
		for l, p := range ps {
			if p.String() != tc.want[l] {
				t.Errorf("%s: %v pays as %s, want %s", tc.addr, Level(l), p, tc.want[l])
			}
			if levelOf(p) != Level(l) {
				t.Errorf("%s: %s is of level %v, want %v", tc.addr, p, levelOf(p), Level(l))
			}
		}
		// An IPv4 address's provider is its wide network.
		if got, want := Of(a, Provider).String(), tc.want[len(tc.want)-1]; got != want {
			t.Errorf("%s: the provider is %s, want %s", tc.addr, got, want)
		}
	}
	if ps := Payers(netip.Addr{}); len(ps) != 1 {
		t.Errorf("an address that is not valid has %d payers, want 1", len(ps))
	}
}

func TestCount(t *testing.T) {
	c := NewCount(Caps{Address: 2, Network: 3, Wide: 4, All: 5})
	a := netip.MustParseAddr("192.0.2.1")
	take := func(s string) bool { return c.Take(netip.MustParseAddr(s), 1) }
	for i := range 3 {
		if take("192.0.2.1") != (i < 2) {
			t.Fatal("an address holds other than its cap of 2")
		}
	}
	if l, full := c.Full(a, 1); !full || l != Address {
		t.Errorf("full at %v %v, want at the address", l, full)
	}
	if !take("192.0.2.2") || take("192.0.2.3") {
		t.Fatal("a network holds other than its cap of 3")
	}
	if !take("192.0.3.1") || take("192.0.4.1") {
		t.Fatal("a wide network holds other than its cap of 4")
	}
	if !take("198.51.100.1") || take("203.0.113.1") {
		t.Fatal("all hold other than their cap of 5")
	}
	if l, _ := c.Full(netip.MustParseAddr("203.0.113.1"), 1); l != All {
		t.Errorf("full at %v, want all", l)
	}
	// Given back, everything is forgotten.
	for _, s := range []string{"192.0.2.1", "192.0.2.1", "192.0.2.2", "192.0.3.1", "198.51.100.1"} {
		c.Remove(netip.MustParseAddr(s), 1)
	}
	if c.Payers() != 0 || c.Held(a, All) != 0 {
		t.Errorf("after all was given back the count holds\n%s", c)
	}
}

// The wide networks of one IPv6 provider, however many, hold no more than
// the provider's cap between them; an IPv4 /16 is its own provider and pays
// for it once.
func TestCountProvider(t *testing.T) {
	c := NewCount(Caps{Wide: 2, Provider: 5})
	got := 0
	for w := range 8 {
		for i := range 3 {
			if c.Take(netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 0, byte(w), 15: byte(i + 1)}), 1) {
				got++
			}
		}
	}
	if got != 5 {
		t.Errorf("the wide networks of one provider hold %d, want 5", got)
	}
	if l, full := c.Full(netip.MustParseAddr("2001:db8:ff::1"), 1); !full || l != Provider {
		t.Errorf("full at %v %v, want at the provider", l, full)
	}
	if !c.Take(netip.MustParseAddr("2001:db9::1"), 1) {
		t.Error("a source of another provider refused")
	}
	c = NewCount(Caps{Wide: 2, Provider: 1})
	if !c.Take(netip.MustParseAddr("192.0.2.1"), 1) || !c.Take(netip.MustParseAddr("192.0.3.1"), 1) || c.Take(netip.MustParseAddr("192.0.4.1"), 1) {
		t.Error("an IPv4 /16 does not hold its wide network's cap")
	}
	if c.Held(netip.MustParseAddr("192.0.9.9"), Provider) != 2 {
		t.Errorf("an IPv4 /16 as a provider holds %d, want 2", c.Held(netip.MustParseAddr("192.0.9.9"), Provider))
	}
}

// For any sources in any order, sources of fewer wide networks than fill
// all leave room for one from another wide network, and nothing taken is
// lost: what a count holds is the sum of what it took.
func TestCountProperty(t *testing.T) {
	rng := mrand.New(mrand.NewPCG(6, 2026))
	for range 200 {
		caps := Caps{Address: 1 + rng.IntN(8), Network: 1 + rng.IntN(32), Wide: 1 + rng.IntN(64)}
		k := 1 + rng.IntN(16)
		caps.All = k*caps.Wide + 1 + rng.IntN(8)
		c := NewCount(caps)
		taken := map[netip.Addr]int{}
		for range 4 * caps.All {
			w := rng.IntN(k)
			var a netip.Addr
			if w%2 == 0 {
				a = netip.AddrFrom4([4]byte{10, byte(w), byte(rng.IntN(4)), byte(rng.IntN(8))})
			} else {
				a = netip.AddrFrom16([16]byte{0x20, 0x01, 0, byte(w), 0, 0, 0, byte(rng.IntN(4)), 15: byte(rng.IntN(8))})
			}
			if c.Take(a, 1) {
				taken[a]++
			}
		}
		if !c.Take(netip.MustParseAddr("203.0.113.9"), 1) {
			t.Fatalf("caps %+v, %d wide networks: no room for another source\n%s", caps, k, c)
		}
		taken[netip.MustParseAddr("203.0.113.9")]++
		sum := 0
		for a, n := range taken {
			sum += n
			c.Remove(a, n)
		}
		if c.Payers() != 0 || sum > caps.All {
			t.Fatalf("caps %+v: took %d, left\n%s", caps, sum, c)
		}
	}
}

func TestRates(t *testing.T) {
	now := time.Unix(1000, 0)
	r := NewRates(Rate{1, 4}, Rate{2, 6}, Rate{4, 8}, Rate{8, 10})
	a, b := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")
	if !r.Take(a, 4, now) || r.Take(a, 1, now) {
		t.Fatal("an address spent other than its burst of 4")
	}
	// The network has 2 left; a refusal charges nothing.
	if r.Take(b, 3, now) || !r.Take(b, 2, now) || r.Take(b, 1, now) {
		t.Fatal("a network spent other than its burst of 6")
	}
	if r.Left(a, Wide) != 2 {
		t.Errorf("the wide network has %v left, want 2", r.Left(a, Wide))
	}
	if !r.Take(a, 1, now.Add(time.Second)) {
		t.Error("an address earned nothing in a second")
	}
	// The wide networks of one IPv6 provider share its burst of 10.
	for w := range 3 {
		if !r.Take(netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 0, byte(w), 15: 1}), 4, now) != (w == 2) {
			t.Fatalf("wide network %d of one provider: the provider's burst is not shared", w)
		}
	}
	if r.Left(netip.MustParseAddr("2001:db8:ff::1"), Provider) != 2 {
		t.Errorf("the provider has %v left, want 2", r.Left(netip.MustParseAddr("2001:db8:ff::1"), Provider))
	}
	r.Sweep(now.Add(time.Hour))
	if r.Payers() != 0 {
		t.Errorf("an hour later %d payers are kept", r.Payers())
	}
}
