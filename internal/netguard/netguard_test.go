// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package netguard

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
)

func TestControl(t *testing.T) {
	t.Cleanup(func() { Set(false, nil) })
	hub := netip.MustParseAddr("203.0.113.9")
	for addr, want := range map[string]struct{ off, on bool }{
		"127.0.0.1:8764":         {true, true},
		"[::1]:8764":             {true, true},
		"192.168.0.10:8764":      {true, true},
		"10.1.2.3:8764":          {true, true},
		"172.16.5.4:8764":        {true, true},
		"169.254.1.1:8764":       {true, true},
		"[fe80::1%eth0]:8764":    {true, true},
		"[fd00::1]:8764":         {true, true},
		"224.0.0.251:5353":       {true, true},
		"[ff02::fb]:5353":        {true, true},
		"[::ffff:10.0.0.1]:8764": {true, true},
		"203.0.113.9:8764":       {false, true},
		"203.0.113.9:443":        {false, true},
		"[::ffff:203.0.113.9]:1": {false, true},
		"203.0.113.10:8764":      {false, false},
		"100.64.0.1:8764":        {false, false},
		"[2001:db8::1]:8764":     {false, false},
		"[::ffff:8.8.8.8]:8764":  {false, false},
		"example.com:8764":       {false, false},
	} {
		Set(false, []netip.Addr{hub})
		if err := Control("tcp", addr, nil); (err == nil) != want.off || (err != nil && !errors.Is(err, ErrOutside)) {
			t.Errorf("away off: Control(%s) = %v, want allowed %v", addr, err, want.off)
		}
		Set(true, []netip.Addr{hub})
		if err := Control("tcp", addr, nil); (err == nil) != want.on || (err != nil && !errors.Is(err, ErrOutside)) {
			t.Errorf("away on: Control(%s) = %v, want allowed %v", addr, err, want.on)
		}
	}
	// Away on without servers yet reaches only the home network.
	Set(true, nil)
	if Control("tcp", "203.0.113.9:8764", nil) == nil {
		t.Error("away on with no servers reached the internet")
	}
}

// A dialer with Control refuses before any packet leaves.
func TestDialer(t *testing.T) {
	t.Cleanup(func() { Set(false, nil) })
	Set(true, []netip.Addr{netip.MustParseAddr("198.51.100.1")})
	d := net.Dialer{Control: Control}
	if _, err := d.DialContext(context.Background(), "tcp", "203.0.113.9:8764"); !errors.Is(err, ErrOutside) {
		t.Fatalf("dial: %v", err)
	}
}
