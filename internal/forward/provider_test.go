// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package forward

import (
	"fmt"
	"net/netip"
	"testing"
)

// addr6 returns an address of the IPv6 provider 2001:db8:p::/32 in its
// wide network w, network n, with the host h.
func addr6(p, w, n, h int) netip.Addr {
	return netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, byte(p), 0, byte(w), 0, byte(n), 15: byte(h)})
}

// The registrations held or being set up are bounded by the network, the
// wide network and the IPv6 provider they come from, as the limits say.
func TestRegistrationsBoundByEveryLevel(t *testing.T) {
	l := Limits{Groups: 100, Connections: 100, PerAddress: 1, PerNetwork: 2, PerWide: 4, PerProvider: 8}
	f, _ := startForwarder(t, l)
	take := func(p, wides, networks, hosts int) int {
		f.mu.Lock()
		defer f.mu.Unlock()
		held := 0
		for w := range wides {
			for n := range networks {
				for h := range hosts {
					if f.from.Take(addr6(p, w, n, h+1), 1) {
						held++
					}
				}
			}
		}
		return held
	}
	for i, c := range []struct {
		name                   string
		wides, networks, hosts int
		want                   int
	}{
		{"the addresses of one network", 1, 1, 2 * l.PerNetwork, l.PerNetwork},
		{"the networks of one wide network", 1, 2 * l.PerWide / l.PerNetwork, l.PerNetwork, l.PerWide},
		{"the wide networks of one provider", 2 * l.PerProvider / l.PerWide, l.PerWide / l.PerNetwork, l.PerNetwork, l.PerProvider},
	} {
		if got := take(0xb8+i, c.wides, c.networks, c.hosts); got != c.want {
			t.Errorf("%s hold %d registrations, want %d", c.name, got, c.want)
		}
	}
	if take(0xf0, 1, 1, 1) != 1 {
		t.Error("another provider refused")
	}
}

// The records that the wide networks of one IPv6 provider bring are bounded
// by the provider, even when each wide network brings less than its own
// share; another provider still brings records.
func TestMemoryChargesTheProvider(t *testing.T) {
	const wides = 5
	if wides*wideRecordBytes <= providerRecordBytes {
		t.Fatal("the wide networks must be able to bring more than the provider's share")
	}
	m := newMemory(func(string) bool { return true })
	body := make([]byte, 8<<10)
	per := 30
	bound := networkRecordBytes/(per*len(body)) + 2
	for w := range wides {
		for n := range wideRecordBytes / networkRecordBytes {
			from := addr6(0xb8, w, n, 7)
			for i := 0; i < bound; i++ {
				tag := fmt.Sprintf("g%d %d %d", w, n, i)
				recs := sharedRecords(per, len(body), body)
				if m.room(tag, from, recs) != nil {
					break
				}
				m.keep(tag, from, recs)
			}
		}
	}
	if _, _, n := m.total(); n > providerRecordBytes || n < providerRecordBytes-networkRecordBytes {
		t.Errorf("the wide networks of one provider brought %d bytes, limit %d", n, providerRecordBytes)
	}
	if err := m.room("other", addr6(0xb9, 0, 0, 7), fakeRecords(per, len(body))); err != nil {
		t.Errorf("another provider refused: %v", err)
	}
}

// A group that is away is held for the IPv6 provider that brought its
// records, not for each wide network: strangers of a few providers, each
// spreading its groups over many wide networks, smaller each than the
// genuine group's records, register and leave, and the genuine group of
// another provider keeps its records.
func TestMemoryHoldsAwayGroupsByProvider(t *testing.T) {
	registered := map[string]bool{}
	m := newMemory(func(tag string) bool { return registered[tag] })
	genuine := addr6(0x01, 0, 0, 7)
	m.keep("genuine", genuine, fakeRecords(20, 8<<10))
	body := make([]byte, 6<<10)
	const providers, per = 3, 20 // a stranger's group is smaller than the genuine one
	wides := providerRecordBytes / (per * (len(body) + 64 + 16))
	if providers*wides*per*len(body) <= rememberedBytes {
		t.Fatal("the strangers must bring more than the memory keeps of groups that are away")
	}
	var strangers []string
	for p := range providers {
		for w := range wides {
			tag := fmt.Sprintf("stranger %d %d", p, w)
			from := addr6(0x10+p, w, 0, 7)
			recs := sharedRecords(per, len(body), body)
			if m.room(tag, from, recs) != nil {
				break
			}
			registered[tag] = true
			m.keep(tag, from, recs)
			strangers = append(strangers, tag)
		}
	}
	for _, tag := range strangers {
		delete(registered, tag)
		m.left(tag)
	}
	if n := len(m.records("genuine")); n != 20 {
		t.Errorf("after strangers left a group that is away keeps %d records, want 20", n)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.awayBytes > rememberedBytes {
		t.Errorf("the groups that are away take %d bytes, limit %d", m.awayBytes, rememberedBytes)
	}
}
