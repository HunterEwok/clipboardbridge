// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tunnel

import (
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func pubKey(t *testing.T) Key {
	t.Helper()
	k, err := NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k.Public()
}

func TestLoadStateMakesAKey(t *testing.T) {
	dir := t.TempDir()
	s, err := LoadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	if s.Key.IsZero() {
		t.Fatal("no key")
	}
	fi, err := os.Stat(filepath.Join(dir, StateFile))
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Errorf("the state file has mode %v", fi.Mode().Perm())
	}
	again, err := LoadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	if again.Key != s.Key {
		t.Error("the key changed between loads")
	}
}

func TestStateRoundTrip(t *testing.T) {
	dir := t.TempDir()
	s, err := NewState()
	if err != nil {
		t.Fatal(err)
	}
	s.Group = "485666d454cba4e8"
	s.IsHub = true
	s.Endpoints = []netip.AddrPort{netip.MustParseAddrPort("[2001:db8::1]:8764"), netip.MustParseAddrPort("192.0.2.1:8764")}
	a := newDevice(t)
	if _, _, err := s.Admit(a.id, pubKey(t), [][]byte{[]byte("cert")}); err != nil {
		t.Fatal(err)
	}
	if err := s.Save(dir); err != nil {
		t.Fatal(err)
	}
	got, err := LoadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got.Key != s.Key || got.Group != s.Group || !got.IsHub || len(got.Endpoints) != 2 || got.Endpoints[0] != s.Endpoints[0] {
		t.Errorf("loaded %+v, saved %+v", got, s)
	}
	if len(got.Members) != 1 || got.Members[0].PublicKey != s.Members[0].PublicKey ||
		got.Members[0].PresharedKey != s.Members[0].PresharedKey || string(got.Members[0].Chain[0]) != "cert" {
		t.Errorf("loaded members %+v, saved %+v", got.Members, s.Members)
	}

	// A client's side.
	c, err := NewState()
	if err != nil {
		t.Fatal(err)
	}
	hub := newDevice(t)
	link := HubLink{Device: hub.id, PublicKey: hub.priv.Public(), PresharedKey: a.psk, Endpoints: s.Endpoints}
	if _, err := c.SetHub(link); err != nil {
		t.Fatal(err)
	}
	cdir := t.TempDir()
	if err := c.Save(cdir); err != nil {
		t.Fatal(err)
	}
	gotC, err := LoadState(cdir)
	if err != nil {
		t.Fatal(err)
	}
	if h := gotC.ToHub; h == nil || h.Device != hub.id || h.PublicKey != link.PublicKey || h.PresharedKey != link.PresharedKey || len(h.Endpoints) != 2 {
		t.Errorf("loaded hub %+v, saved %+v", gotC.ToHub, link)
	}

	// A device that meets the others at a relay.
	r, err := NewState()
	if err != nil {
		t.Fatal(err)
	}
	r.Relay = &RelayLink{Endpoint: netip.MustParseAddrPort("198.51.100.9:8764"), Pin: "sha256:AAAA"}
	rdir := t.TempDir()
	if err := r.Save(rdir); err != nil {
		t.Fatal(err)
	}
	gotR, err := LoadState(rdir)
	if err != nil {
		t.Fatal(err)
	}
	if gotR.Relay == nil || *gotR.Relay != *r.Relay {
		t.Errorf("loaded relay %+v, saved %+v", gotR.Relay, r.Relay)
	}
}

func TestBadStateFiles(t *testing.T) {
	for name, body := range map[string]string{
		"not JSON":         "{",
		"unknown version":  `{"v":2,"key":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="}`,
		"no key":           `{"v":1}`,
		"short key":        `{"v":1,"key":"AQEB"}`,
		"member twice":     `{"v":1,"key":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=","members":[{"device":"0123456789abcdef0123456789abcdef","key":"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=","psk":"AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=","chain":["AA=="]},{"device":"0123456789abcdef0123456789abcdef","key":"BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ=","psk":"AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=","chain":["AA=="]}]}`,
		"member, no PSK":   `{"v":1,"key":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=","members":[{"device":"0123456789abcdef0123456789abcdef","key":"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=","psk":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","chain":["AA=="]}]}`,
		"member, no chain": `{"v":1,"key":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=","members":[{"device":"0123456789abcdef0123456789abcdef","key":"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=","psk":"AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=","chain":[]}]}`,
		"relay and hub":    `{"v":1,"key":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=","is_hub":true,"relay":{"endpoint":"198.51.100.9:8764","key":"sha256:AAAA"}}`,
		"relay, no key":    `{"v":1,"key":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=","relay":{"endpoint":"198.51.100.9:8764","key":""}}`,
		"hub, bad device":  `{"v":1,"key":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=","to_hub":{"device":"x","key":"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=","psk":"AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM="}}`,
	} {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, StateFile), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadState(dir); err == nil {
			t.Errorf("%s: loaded", name)
		}
	}
}

func TestAdmit(t *testing.T) {
	s, err := NewState()
	if err != nil {
		t.Fatal(err)
	}
	a, b := newDevice(t), newDevice(t)
	keyA := pubKey(t)
	chain := [][]byte{[]byte("cert a")}
	m, changed, err := s.Admit(a.id, keyA, chain)
	if err != nil || !changed || m.PresharedKey.IsZero() {
		t.Fatalf("Admit = %+v, %v, %v", m, changed, err)
	}
	psk := m.PresharedKey

	// The same key again: nothing changes, the preshared key stays.
	m, changed, err = s.Admit(a.id, keyA, chain)
	if err != nil || changed || m.PresharedKey != psk {
		t.Errorf("Admit again = %+v, %v, %v", m, changed, err)
	}
	// A renewed certificate: the chain changes, the preshared key stays.
	renewed := [][]byte{[]byte("cert a, renewed")}
	m, changed, err = s.Admit(a.id, keyA, renewed)
	if err != nil || !changed || m.PresharedKey != psk || string(s.Members[0].Chain[0]) != "cert a, renewed" {
		t.Errorf("Admit renewed = %+v, %v, %v", m, changed, err)
	}
	// A new key gets a new preshared key.
	m, changed, err = s.Admit(a.id, pubKey(t), renewed)
	if err != nil || !changed || m.PresharedKey == psk {
		t.Errorf("Admit new key = %+v, %v, %v", m, changed, err)
	}
	if len(s.Members) != 1 {
		t.Errorf("%d members, want 1", len(s.Members))
	}

	// Refused: another device's key, the hub's own key, no key, no chain,
	// a bad device ID.
	for name, try := range map[string]func() error{
		"another device's key": func() error { _, _, err := s.Admit(b.id, s.Members[0].PublicKey, chain); return err },
		"the hub's key":        func() error { _, _, err := s.Admit(b.id, s.Key.Public(), chain); return err },
		"no key":               func() error { _, _, err := s.Admit(b.id, Key{}, chain); return err },
		"no chain":             func() error { _, _, err := s.Admit(b.id, pubKey(t), nil); return err },
		"bad device":           func() error { _, _, err := s.Admit("nope", pubKey(t), chain); return err },
	} {
		if try() == nil {
			t.Errorf("%s: admitted", name)
		}
	}
	if len(s.Members) != 1 {
		t.Errorf("%d members after refusals, want 1", len(s.Members))
	}

	if _, _, err := s.Admit(b.id, pubKey(t), chain); err != nil {
		t.Fatal(err)
	}
	peers := s.Peers()
	if len(peers) != 2 {
		t.Fatalf("%d peers, want 2", len(peers))
	}
	if want, _ := Addr(b.id); peers[1].Addr != want {
		t.Errorf("peer address %v, want %v", peers[1].Addr, want)
	}
}

func TestPrune(t *testing.T) {
	s, err := NewState()
	if err != nil {
		t.Fatal(err)
	}
	a, b := newDevice(t), newDevice(t)
	for _, d := range []testDevice{a, b} {
		if _, _, err := s.Admit(d.id, pubKey(t), [][]byte{[]byte(d.id)}); err != nil {
			t.Fatal(err)
		}
	}
	gone := s.Prune(func(m Member) bool { return string(m.Chain[0]) != b.id })
	if len(gone) != 1 || gone[0] != b.id {
		t.Errorf("pruned %v, want [%s]", gone, b.id)
	}
	if len(s.Members) != 1 || s.Members[0].Device != a.id {
		t.Errorf("members %+v, want only %s", s.Members, a.id)
	}
}

func TestSetHub(t *testing.T) {
	s, err := NewState()
	if err != nil {
		t.Fatal(err)
	}
	hub := newDevice(t)
	link := HubLink{Device: hub.id, PublicKey: hub.priv.Public(), PresharedKey: hub.psk,
		Endpoints: []netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:8764")}}
	if changed, err := s.SetHub(link); err != nil || !changed {
		t.Fatalf("SetHub = %v, %v", changed, err)
	}
	if changed, err := s.SetHub(link); err != nil || changed {
		t.Errorf("SetHub again = %v, %v", changed, err)
	}
	moved := link
	moved.Endpoints = []netip.AddrPort{netip.MustParseAddrPort("192.0.2.2:8764")}
	if changed, err := s.SetHub(moved); err != nil || !changed || s.ToHub.Endpoints[0] != moved.Endpoints[0] {
		t.Errorf("SetHub with a new address = %v, %v", changed, err)
	}

	bad := func(f func(*HubLink)) HubLink {
		l := link
		f(&l)
		return l
	}
	for name, l := range map[string]HubLink{
		"bad device":      bad(func(l *HubLink) { l.Device = "x" }),
		"no key":          bad(func(l *HubLink) { l.PublicKey = Key{} }),
		"no PSK":          bad(func(l *HubLink) { l.PresharedKey = Key{} }),
		"own key":         bad(func(l *HubLink) { l.PublicKey = s.Key.Public() }),
		"port 0":          bad(func(l *HubLink) { l.Endpoints = []netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:0")} }),
		"invalid address": bad(func(l *HubLink) { l.Endpoints = []netip.AddrPort{{}} }),
		"many endpoints":  bad(func(l *HubLink) { l.Endpoints = make([]netip.AddrPort, maxEndpoints+1) }),
	} {
		if _, err := s.SetHub(l); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if s.ToHub.Endpoints[0] != moved.Endpoints[0] {
		t.Error("a refused offer changed the hub")
	}
}

func TestForGroup(t *testing.T) {
	s, err := NewState()
	if err != nil {
		t.Fatal(err)
	}
	key := s.Key
	if !s.ForGroup("aaaaaaaaaaaaaaaa") {
		t.Error("a new group did not change the state")
	}
	s.IsHub = true
	if _, _, err := s.Admit(newDevice(t).id, pubKey(t), [][]byte{[]byte("c")}); err != nil {
		t.Fatal(err)
	}
	if s.ForGroup("aaaaaaaaaaaaaaaa") {
		t.Error("the same group changed the state")
	}
	if !s.ForGroup("bbbbbbbbbbbbbbbb") || s.IsHub || len(s.Members) != 0 || s.Key != key || s.Group != "bbbbbbbbbbbbbbbb" {
		t.Errorf("after another group: %+v", s)
	}
}

func TestKeyText(t *testing.T) {
	k := pubKey(t)
	b, err := k.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	var got Key
	if err := got.UnmarshalText(b); err != nil || got != k {
		t.Errorf("round trip: %v, %x", err, got)
	}
	for _, bad := range []string{"", "AQEB", "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB", "!!!"} {
		if err := got.UnmarshalText([]byte(bad)); err == nil {
			t.Errorf("%q decoded", bad)
		}
	}
}
