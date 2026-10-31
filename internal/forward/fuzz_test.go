// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package forward

import (
	"net/netip"
	"testing"
	"time"
)

// FuzzForwardWire routes the packets anyone may send to the forwarder's
// UDP port, from a stranger and from a registered hub's endpoint: a packet
// goes only to an endpoint the forwarder knows, and none makes it panic.
func FuzzForwardWire(f *testing.F) {
	var pub [32]byte
	f.Add(initiation(pub, 1))
	f.Add(make([]byte, responseSize))
	f.Add(make([]byte, cookieSize))
	f.Add(append([]byte{msgData, 0, 0, 0}, make([]byte, dataMinSize)...))
	f.Add(make([]byte, helloMin))
	cert, _ := NewCert()
	fw, err := Listen(Config{Listen: "127.0.0.1:0", Cert: cert})
	if err != nil {
		f.Fatal(err)
	}
	f.Cleanup(func() { fw.Close() })
	hubA, hubB := netip.MustParseAddrPort("198.51.100.1:8764"), netip.MustParseAddrPort("198.51.100.2:8764")
	_, pubA := fakeReg(fw, "a", hubA)
	fakeReg(fw, "b", hubB)
	f.Add(initiation(pubA, 7))
	client := netip.MustParseAddrPort("203.0.113.5:40000")
	now := time.Now()
	f.Fuzz(func(t *testing.T, p []byte) {
		messageType(p)
		if h, ok := openHello(&fw.mask, p); ok {
			readHello(h)
		}
		for _, from := range []netip.AddrPort{client, hubA} {
			to, ok := fw.route(from, append([]byte{}, p...), now)
			if ok && to != hubA && to != hubB && to != client {
				t.Fatalf("a packet from %v went to %v", from, to)
			}
		}
	})
}
