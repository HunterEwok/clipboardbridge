// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package group

import (
	"crypto/x509"
	"testing"
	"time"
)

func TestCommands(t *testing.T) {
	pg := newPhoneGroup(t)
	s := NewRecords(pg.root.Cert)
	to, now := NewDeviceID(), time.UnixMilli(1_761_400_000_000)
	body := func() CommandBody {
		return CommandBody{Type: CommandMode, Group: Tag(pg.root.Cert), By: NewDeviceID(), To: to, ID: NewCommandID(),
			TimeMS: now.UnixMilli(), ExpiresMS: now.Add(CommandLifetime).UnixMilli(), Mode: "own"}
	}
	sign := func(b CommandBody, ca *CA, chain ...*x509.Certificate) Record {
		t.Helper()
		c, err := SignCommand(b, ca.Key, chain...)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	check := func(what string, c Record, at time.Time, ok bool) {
		t.Helper()
		got, err := s.VerifyCommand(c, to, at)
		if (err == nil) != ok {
			t.Errorf("%s: %v, want ok %v", what, err, ok)
		}
		if err == nil && got.Mode != "own" {
			t.Errorf("%s: mode %q", what, got.Mode)
		}
	}
	check("the root", sign(body(), pg.root), now, true)
	byA := sign(body(), pg.a, pg.a.Cert)
	check("an admin", byA, now, true)
	check("expired", byA, now.Add(CommandLifetime), false)
	check("from the future", byA, now.Add(-CommandAhead-time.Second), false)
	if _, err := s.VerifyCommand(byA, NewDeviceID(), now); err == nil {
		t.Error("a command for another device was taken")
	}
	other := newPhoneGroup(t)
	check("another group's admin", sign(body(), other.a, other.a.Cert), now, false)
	b := body()
	b.Group = Tag(other.root.Cert)
	check("for another group", sign(b, pg.root), now, false)
	forged := byA
	forged.Body = append([]byte(nil), byA.Body...)
	forged.Body[len(forged.Body)-3] = 'x' // "own" becomes "owx"
	check("a changed body", forged, now, false)

	mustAdd(t, s, revokeRecord(t, pg.root.Cert, pg.root, nil, []KeyHash{KeyHashOf(pg.a.Cert)}, nil))
	check("a removed admin", sign(body(), pg.a, pg.a.Cert), now, false)
	check("the other admin", sign(body(), pg.b, pg.b.Cert), now, true)

	if _, err := SignCommand(CommandBody{Type: CommandMode, To: to, ID: NewCommandID(), TimeMS: 1, ExpiresMS: 1 + time.Hour.Milliseconds(), Mode: "own"}, pg.root.Key); err == nil {
		t.Error("a command that lives an hour was signed")
	}
}
