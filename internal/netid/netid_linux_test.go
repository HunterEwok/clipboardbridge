// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package netid

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

func TestARP(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "arp")
	table := "IP address       HW type     Flags       HW address            Mask     Device\n" +
		"192.168.0.1      0x1         0x2         aa:bb:cc:dd:ee:ff     *        lo\n" +
		"192.168.0.9      0x1         0x2         11:22:33:44:55:66     *        lo\n"
	if err := os.WriteFile(p, []byte(table), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := arp(p, map[string]netip.Addr{"lo": netip.MustParseAddr("192.168.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("got %v", got)
	}
	for _, mac := range got {
		if mac != "aa:bb:cc:dd:ee:ff" {
			t.Errorf("gateway %s", mac)
		}
	}
	t.Logf("this machine's gateways: %v", Gateways())
}
