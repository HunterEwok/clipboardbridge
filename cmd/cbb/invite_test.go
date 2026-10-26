// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"bytes"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/HunterEwok/clipboardbridge/internal/control"
	"github.com/HunterEwok/clipboardbridge/internal/invite"
	"github.com/HunterEwok/clipboardbridge/internal/tunnel"
)

// TestPairInvite joins with an invitation as the service takes it: the
// join on the admin socket, the status after it on a connection of its
// own. It was refused on the control socket before.
func TestPairInvite(t *testing.T) {
	key := func() tunnel.Key {
		k, err := tunnel.NewPrivateKey()
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	in := &invite.Invitation{
		Group: "0f1e2d3c4b5a6978", Hub: "0123456789abcdef0123456789abcdef", HubKey: key().Public(),
		Endpoints: []netip.AddrPort{netip.MustParseAddrPort("203.0.113.7:8764")},
		GuestKey:  key(), GuestPSK: key(), Secret: bytes.Repeat([]byte{7}, 16),
		Expires: time.Now().Add(time.Hour).Truncate(time.Second),
	}
	path := filepath.Join(t.TempDir(), "invite.cbb")
	if err := os.WriteFile(path, []byte(in.String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got := fakeHandler(t, func(m *control.Message, _ *control.Reader, c net.Conn) {
		switch m.Op {
		case control.OpJoin:
			answer(c, control.Message{Header: control.Header{Fingerprint: "sha256:abcd"}})
			answer(c, control.Message{Header: control.Header{Done: true}})
		case control.OpStatus:
			answer(c, control.Message{Header: control.Header{Status: &control.Status{Role: "full", Group: in.Group}, Done: true}})
		}
	})
	var stdout, stderr bytes.Buffer
	if code := run([]string{"pair", "-invite", path}, strings.NewReader("yes\n"), &stdout, &stderr); code != 0 {
		t.Fatalf("pair -invite: %d, %s", code, stderr.String())
	}
	if m := request(t, got); m.Op != control.OpJoin || m.Invite != in.String() || !m.Consent {
		t.Errorf("pair -invite sent %+v", m.Header)
	}
	if m := request(t, got); m.Op != control.OpStatus {
		t.Errorf("after the join it asked %+v", m.Header)
	}
	if stderr.Len() != 0 || !strings.Contains(stdout.String(), "Joined the group") {
		t.Errorf("stdout %q, stderr %q", stdout.String(), stderr.String())
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("the used invitation is still there: %v", err)
	}
}
