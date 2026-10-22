// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package group

import (
	"testing"
	"time"
)

// adminIdentity is a member of a phone's group whose certificate an admin
// CA issued, when ca is one, or the root, when it is nil.
func adminIdentity(t *testing.T, pg phoneGroup, ca *CA) *Identity {
	t.Helper()
	key, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	dev := NewDeviceID()
	id := &Identity{ID: dev, Key: key, GroupCA: CA{Cert: pg.root.Cert}}
	issuer := pg.root
	if ca != nil {
		issuer, id.Issuer = ca, ca.Cert
	}
	if id.Cert, err = issuer.IssueMember(dev, &key.PublicKey, t0); err != nil {
		t.Fatal(err)
	}
	if err := id.Check(); err != nil {
		t.Fatal(err)
	}
	return id
}

// TestAdminIssuedIdentity checks an identity whose certificate an admin CA
// issued: it is valid with its issuer, survives a save and a load, and is
// not valid without the issuer or with a member certificate as issuer.
func TestAdminIssuedIdentity(t *testing.T) {
	pg := newPhoneGroup(t)
	id := adminIdentity(t, pg, pg.a)
	dir := t.TempDir()
	if err := id.Save(dir); err != nil {
		t.Fatal(err)
	}
	got, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got.Issuer == nil || !got.Issuer.Equal(pg.a.Cert) {
		t.Fatal("the issuer was not kept")
	}
	bad := *id
	bad.Issuer = nil
	if bad.Check() == nil {
		t.Error("accepted without its issuer")
	}
	bad.Issuer = pg.b.Cert
	if bad.Check() == nil {
		t.Error("accepted with another admin CA")
	}
	bad.Issuer = member(t, pg.root)
	if bad.Check() == nil {
		t.Error("accepted a member certificate as issuer")
	}
}

// TestAdminIssuedHandshake checks member connections between a device the
// root admitted and one an admin CA admitted, both ways.
func TestAdminIssuedHandshake(t *testing.T) {
	pg := newPhoneGroup(t)
	byRoot := adminIdentity(t, pg, nil)
	byAdmin := adminIdentity(t, pg, pg.a)
	at := TLSOptions{Now: func() time.Time { return t0 }}
	for _, p := range [][2]*Identity{{byRoot, byAdmin}, {byAdmin, byRoot}} {
		client, server := p[0], p[1]
		_, scs, cerr, serr := handshake(t, client.ClientTLS(server.ID, at), server.ServerTLS(at))
		if cerr != nil || serr != nil {
			t.Fatalf("handshake: client %v, server %v", cerr, serr)
		}
		if got, err := PeerID(scs); err != nil || got != client.ID {
			t.Errorf("the server saw %q, %v; want %q", got, err, client.ID)
		}
	}
	// A certificate from an admin CA of another group is refused.
	other := newPhoneGroup(t)
	stranger := adminIdentity(t, other, other.a)
	if _, _, _, serr := handshake(t, stranger.ClientTLS(byRoot.ID, at), byRoot.ServerTLS(at)); serr == nil {
		t.Error("the server accepted a member of another group")
	}
}

// TestAdminIssuedRenewal checks that a certificate an admin CA issued can be
// renewed by that CA or by the root, and that the root's renewal drops the
// issuer.
func TestAdminIssuedRenewal(t *testing.T) {
	pg := newPhoneGroup(t)
	id := adminIdentity(t, pg, pg.a)
	later := t0.Add(24 * time.Hour)
	fromAdmin, err := pg.a.IssueMember(id.ID, &id.Key.PublicKey, later)
	if err != nil {
		t.Fatal(err)
	}
	next, err := id.WithCert(fromAdmin.Raw)
	if err != nil || next.Issuer == nil {
		t.Fatalf("renewed by its admin CA: %v, issuer %v", err, next != nil && next.Issuer != nil)
	}
	fromRoot, err := pg.root.IssueMember(id.ID, &id.Key.PublicKey, later)
	if err != nil {
		t.Fatal(err)
	}
	next, err = id.WithCert(fromRoot.Raw)
	if err != nil || next.Issuer != nil {
		t.Fatalf("renewed by the root: %v, issuer kept %v", err, next != nil && next.Issuer != nil)
	}
	fromOther, err := pg.b.IssueMember(id.ID, &id.Key.PublicKey, later)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := id.WithCert(fromOther.Raw); err == nil {
		t.Error("accepted a renewal from another admin CA")
	}
}
