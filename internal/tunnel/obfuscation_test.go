// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tunnel

import (
	"context"
	"encoding/json"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

func TestNewObfuscation(t *testing.T) {
	seen := map[Range]bool{}
	for range 200 {
		o, err := NewObfuscation()
		if err != nil {
			t.Fatal(err)
		}
		if err := o.Check(); err != nil {
			t.Fatalf("%+v: %v", o, err)
		}
		if seen[o.H1] {
			t.Fatalf("h1 %v came twice", o.H1)
		}
		seen[o.H1] = true

		data, err := json.Marshal(o)
		if err != nil {
			t.Fatal(err)
		}
		var back Obfuscation
		if err := json.Unmarshal(data, &back); err != nil {
			t.Fatal(err)
		}
		if !o.Equal(&back) {
			t.Fatalf("round trip: %s gave %+v", data, back)
		}
	}
}

func TestObfuscationIsChecked(t *testing.T) {
	good, err := NewObfuscation()
	if err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(o *Obfuscation){
		"too much junk":        func(o *Obfuscation) { o.JC = maxJunkCount + 1 },
		"junk too long":        func(o *Obfuscation) { o.JMax = maxJunkSize + 1 },
		"junk min over max":    func(o *Obfuscation) { o.JMin = o.JMax + 1 },
		"no header key":        func(o *Obfuscation) { o.HeaderKey = Key{} },
		"short padding":        func(o *Obfuscation) { o.S4 = minPadding - 1 },
		"long padding":         func(o *Obfuscation) { o.S1 = maxPadding + 1 },
		"same sizes":           func(o *Obfuscation) { o.S1, o.S2 = 20, 76 },
		"overlapping headers":  func(o *Obfuscation) { o.H2 = o.H1 },
		"WireGuard's own type": func(o *Obfuscation) { o.H3 = Range{1, 1} },
		"empty range":          func(o *Obfuscation) { o.H4 = Range{Min: 100, Max: 99} },
	} {
		o := *good
		change(&o)
		if err := o.Check(); err == nil {
			t.Errorf("%s: no error", name)
		}
		if _, err := StartHub(HubConfig{PrivateKey: good.HeaderKey, Addr: newDevice(t).addr, Obfuscation: &o}); err == nil {
			t.Errorf("%s: a hub started", name)
		}
	}
	var r Range
	for _, bad := range []string{"", "5", "9-8", "a-b"} {
		if err := r.UnmarshalText([]byte(bad)); err == nil {
			t.Errorf("range %q read as %v", bad, r)
		}
	}
}

// TestObfuscatedTunnel checks that a client with the hub's settings
// reaches it, and that one without them does not.
func TestObfuscatedTunnel(t *testing.T) {
	obf, err := NewObfuscation()
	if err != nil {
		t.Fatal(err)
	}
	a, b := newDevice(t), newDevice(t)
	h := startObfuscatedHub(t, obf, a.peer(), b.peer())

	c, err := StartClient(ClientConfig{PrivateKey: a.priv, PresharedKey: a.psk, Addr: a.addr,
		HubPublicKey: h.dev.priv.Public(), HubAddr: h.dev.addr, Endpoint: h.endpoint(), Obfuscation: obf, Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	got, err := roundTrip(ctx, c)
	cancel()
	if err != nil {
		t.Fatal(err)
	}
	if want := a.addr.String() + " hello"; got != want {
		t.Fatalf("hub answered %q, want %q", got, want)
	}

	plain := startClient(t, h, b)
	ctx, cancel = context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if got, err := roundTrip(ctx, plain); err == nil {
		t.Fatalf("a plain WireGuard client reached an obfuscated hub: %q", got)
	}
}

// TestObfuscatedPacketsHideWireGuard passes a client's packets to the hub
// through a UDP relay that looks at each one, and checks that none looks
// like WireGuard: none starts with one of its message types followed by
// three zero bytes. (Sizes say little: junk packets have any size.)
func TestObfuscatedPacketsHideWireGuard(t *testing.T) {
	obf, err := NewObfuscation()
	if err != nil {
		t.Fatal(err)
	}
	a := newDevice(t)
	h := startObfuscatedHub(t, obf, a.peer())

	relay, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer relay.Close()
	var (
		mu      sync.Mutex
		packets [][]byte
	)
	go func() {
		hubEP := net.UDPAddrFromAddrPort(h.endpoint())
		var client *net.UDPAddr
		buf := make([]byte, 2048)
		for {
			n, from, err := relay.ReadFromUDP(buf)
			if err != nil {
				return
			}
			p := append([]byte(nil), buf[:n]...)
			mu.Lock()
			packets = append(packets, p)
			mu.Unlock()
			if from.AddrPort() == hubEP.AddrPort() {
				if client != nil {
					relay.WriteToUDP(p, client)
				}
				continue
			}
			client = from
			relay.WriteToUDP(p, hubEP)
		}
	}()

	ep := relay.LocalAddr().(*net.UDPAddr).AddrPort()
	c, err := StartClient(ClientConfig{PrivateKey: a.priv, PresharedKey: a.psk, Addr: a.addr,
		HubPublicKey: h.dev.priv.Public(), HubAddr: h.dev.addr, Endpoint: netip.AddrPortFrom(ep.Addr().Unmap(), ep.Port()),
		Obfuscation: obf, Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := roundTrip(ctx, c); err != nil {
		t.Fatal(err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(packets) < 4 {
		t.Fatalf("the relay saw only %d packets", len(packets))
	}
	for i, p := range packets {
		if len(p) >= 4 && p[0] >= 1 && p[0] <= 4 && p[1] == 0 && p[2] == 0 && p[3] == 0 {
			t.Errorf("packet %d (%d bytes) starts like WireGuard: % x", i, len(p), p[:4])
		}
	}
}
