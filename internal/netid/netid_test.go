// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package netid

import (
	"net/netip"
	"testing"
)

func TestID(t *testing.T) {
	key := []byte("key")
	home := []netip.Prefix{netip.MustParsePrefix("192.168.0.225/24"), netip.MustParsePrefix("fe80::1/64"), netip.MustParsePrefix("2001:db8:1::5/64")}
	id := ID(key, home, "aa:bb:cc:dd:ee:ff")
	if id == "" || len(id) != 32 {
		t.Fatalf("ID %q", id)
	}
	// Another address on the same network, another IPv6 prefix: the same.
	if got := ID(key, []netip.Prefix{netip.MustParsePrefix("192.168.0.7/24"), netip.MustParsePrefix("2001:db8:2::5/64")}, "aa:bb:cc:dd:ee:ff"); got != id {
		t.Error("the ID changed with the address or the IPv6 prefix")
	}
	// The same subnet behind another gateway (a café's router), another
	// key: different.
	if ID(key, home, "11:22:33:44:55:66") == id || ID([]byte("other"), home, "aa:bb:cc:dd:ee:ff") == id {
		t.Error("another gateway or key gives the same ID")
	}
	if ID(key, []netip.Prefix{netip.MustParsePrefix("fe80::1/64")}, "") != "" {
		t.Error("a link-local address alone names a network")
	}
}
