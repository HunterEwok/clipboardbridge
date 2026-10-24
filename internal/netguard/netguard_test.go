// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package netguard

import (
	"context"
	"errors"
	"net"
	"testing"
)

func TestControl(t *testing.T) {
	t.Cleanup(func() { SetOpen(false) })
	for addr, home := range map[string]bool{
		"127.0.0.1:8764":         true,
		"[::1]:8764":             true,
		"192.168.0.10:8764":      true,
		"10.1.2.3:8764":          true,
		"172.16.5.4:8764":        true,
		"169.254.1.1:8764":       true,
		"[fe80::1%eth0]:8764":    true,
		"[fd00::1]:8764":         true,
		"224.0.0.251:5353":       true,
		"[ff02::fb]:5353":        true,
		"[::ffff:10.0.0.1]:8764": true,
		"203.0.113.9:8764":       false,
		"100.64.0.1:8764":        false,
		"[2001:db8::1]:8764":     false,
		"[::ffff:8.8.8.8]:8764":  false,
		"example.com:8764":       false,
	} {
		SetOpen(false)
		if err := Control("tcp", addr, nil); (err == nil) != home || (err != nil && !errors.Is(err, ErrOutside)) {
			t.Errorf("closed: Control(%s) = %v, home %v", addr, err, home)
		}
		SetOpen(true)
		if err := Control("tcp", addr, nil); err != nil {
			t.Errorf("open: Control(%s) = %v", addr, err)
		}
	}
}

// A dialer with Control refuses before any packet leaves.
func TestDialer(t *testing.T) {
	SetOpen(false)
	d := net.Dialer{Control: Control}
	if _, err := d.DialContext(context.Background(), "tcp", "203.0.113.9:8764"); !errors.Is(err, ErrOutside) {
		t.Fatalf("dial: %v", err)
	}
}
