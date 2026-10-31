// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package forward

import (
	"crypto/rand"
	"fmt"
	"net/netip"
	"testing"
	"time"
)

// A flood of handshakes over VLESS from the clients of one group, over
// many connections, leaves the clients of another group over VLESS their
// own budget, and the budget of all sources.
func TestVLESSUsersScanApart(t *testing.T) {
	cert, err := NewCert()
	if err != nil {
		t.Fatal(err)
	}
	f, err := Listen(Config{Listen: "127.0.0.1:0", Cert: cert, VLESS: &VLESSConfig{Listen: "127.0.0.1:0", Site: "example.com", Dest: "127.0.0.1:1"}})
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	// The VLESS side sends the flooding group's packets from ports below
	// 40000, the other group's from those above.
	f.mu.Lock()
	f.vlessUser = func(a netip.AddrPort) (string, bool) {
		if !a.Addr().IsLoopback() {
			return "", false
		}
		if a.Port() < 40000 {
			return "flooding group", true
		}
		return "other group", true
	}
	f.mu.Unlock()
	for i := range 200 {
		fakeReg(f, fmt.Sprintf("group %d", i), netip.AddrPortFrom(netip.MustParseAddr("198.51.100.1"), uint16(8000+i)))
	}
	_, pub := fakeReg(f, "victim", netip.MustParseAddrPort("198.51.100.2:8764"))
	now := time.Now()
	var nobody [32]byte
	rand.Read(nobody[:])
	if _, ok := f.route(netip.MustParseAddrPort("127.0.0.1:50000"), initiation(pub, 1), now); !ok {
		t.Fatal("a handshake over VLESS was dropped before any flood")
	}
	for i := range 8000 {
		f.route(netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(30000+i%1000)), initiation(nobody, uint32(i)), now)
	}
	if _, ok := f.route(netip.MustParseAddrPort("127.0.0.1:50001"), initiation(pub, 2), now); !ok {
		t.Fatal("a handshake of another group's client over VLESS was dropped after a flood")
	}
	if _, ok := f.route(netip.MustParseAddrPort("203.0.113.10:4000"), initiation(pub, 3), now); !ok {
		t.Fatal("a direct client's handshake was dropped after a flood over VLESS")
	}
}

// Addresses that fill the tables of sources and networks do not keep a
// new client's handshake out: the table drops the entry used least
// recently, and stays at its bound.
func TestSourceTablesKeepNewClients(t *testing.T) {
	cert, err := NewCert()
	if err != nil {
		t.Fatal(err)
	}
	limits := DefaultLimits
	limits.Groups = 100
	f, err := Listen(Config{Listen: "127.0.0.1:0", Cert: cert, Limits: limits})
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	_, pub := fakeReg(f, "victim", netip.MustParseAddrPort("198.51.100.2:8764"))
	now := time.Now()
	var nobody [32]byte
	rand.Read(nobody[:])
	for i := 0; i < 5*limits.Groups; i++ {
		a := netip.AddrFrom4([4]byte{10, byte(i >> 8), byte(i), 1})
		f.route(netip.AddrPortFrom(a, 1000), initiation(nobody, uint32(i)), now)
	}
	f.mu.Lock()
	sources, nets := f.sources.len(), f.netScans.len()
	f.mu.Unlock()
	if sources > 4*limits.Groups || nets > 4*limits.Groups {
		t.Fatalf("tables hold %d sources and %d networks, over the bound %d", sources, nets, 4*limits.Groups)
	}
	if _, ok := f.route(netip.MustParseAddrPort("192.0.2.77:40000"), initiation(pub, 2), now); !ok {
		t.Fatal("a new client's handshake was dropped while the tables were full")
	}
}
