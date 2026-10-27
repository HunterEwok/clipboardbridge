// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tunnel

import "testing"

func TestRedact(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"write udp [::]:8764->203.0.113.7:51820: sendmsg: no route to host",
			"write udp (address)->(address): sendmsg: no route to host"},
		{"peer(AbCd…wXyZ) - Failed to send handshake response: write udp 192.0.2.1:9->[2001:db8::5]:443: i/o timeout",
			"peer - Failed to send handshake response: write udp (address)->(address): i/o timeout"},
		{"from fe80::1.", "from (address)."},
		{"from 10.1.2.3: refused", "from (address): refused"},
		{"cbb relay: listening on UDP and TCP port 8764 for 2 groups at 02:59:26, version 0.6.0",
			"cbb relay: listening on UDP and TCP port 8764 for 2 groups at 02:59:26, version 0.6.0"},
		{"key sha256:0a1b2c3d", "key sha256:0a1b2c3d"},
	} {
		if got := Redact(c.in); got != c.want {
			t.Errorf("Redact(%q)\n got %q\nwant %q", c.in, got, c.want)
		}
	}
	var got string
	Redacted(func(f string, a ...any) { got = f + "|" + a[0].(string) })("from %s", "198.51.100.2:1")
	if got != "%s|from (address)" {
		t.Errorf("Redacted passed %q", got)
	}
}
