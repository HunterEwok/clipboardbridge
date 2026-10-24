// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tunnel

import (
	"net/netip"
	"testing"
)

func TestVLESSIsChecked(t *testing.T) {
	id, err := NewVLESSID()
	if err != nil {
		t.Fatal(err)
	}
	good := VLESS{Endpoint: netip.MustParseAddrPort("198.51.100.9:443"), PublicKey: make([]byte, 32),
		ShortID: "0123456789abcdef", ServerName: "www.example.com", ID: id}
	if err := good.Check(); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*VLESS){
		"no endpoint":  func(v *VLESS) { v.Endpoint = netip.AddrPort{} },
		"short key":    func(v *VLESS) { v.PublicKey = v.PublicKey[:31] },
		"bad short ID": func(v *VLESS) { v.ShortID = "xyz" },
		"bad name":     func(v *VLESS) { v.ServerName = "not a name" },
		"bad ID":       func(v *VLESS) { v.ID = "a3482e88" },
	} {
		v := good
		change(&v)
		if v.Check() == nil {
			t.Errorf("%s: passed", name)
		}
	}
}
