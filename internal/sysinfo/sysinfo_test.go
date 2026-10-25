// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package sysinfo

import (
	"net"
	"testing"
)

func TestPickMAC(t *testing.T) {
	hw := func(s string) net.HardwareAddr { a, _ := net.ParseMAC(s); return a }
	ifs := []net.Interface{
		{Name: "lo", Flags: net.FlagUp | net.FlagLoopback},
		{Name: "docker0", Flags: net.FlagUp, HardwareAddr: hw("02:42:00:00:00:01")},
		{Name: "eth0", Flags: 0, HardwareAddr: hw("dc:a6:32:00:00:02")},
		{Name: "wlan0", Flags: net.FlagUp, HardwareAddr: hw("DC:A6:32:00:00:03")},
	}
	addrs := func(i net.Interface) []net.Addr {
		return []net.Addr{&net.IPNet{IP: net.IPv4(192, 168, 0, 9), Mask: net.CIDRMask(24, 32)}}
	}
	if got := pickMAC(ifs, addrs); got != "dc:a6:32:00:00:03" {
		t.Errorf("pickMAC = %q, want wlan0's", got)
	}
	public := func(net.Interface) []net.Addr {
		return []net.Addr{&net.IPNet{IP: net.IPv4(203, 0, 113, 9), Mask: net.CIDRMask(24, 32)}}
	}
	if got := pickMAC(ifs, public); got != "" {
		t.Errorf("pickMAC = %q without a home network address", got)
	}
}

func TestDevice(t *testing.T) {
	d := Device("0.5.0")
	if d.Version != "0.5.0" || d != d.Clean() {
		t.Errorf("Device = %+v", d)
	}
}
