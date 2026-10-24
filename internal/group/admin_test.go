// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package group

import (
	"crypto/tls"
	"crypto/x509"
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

// TestRenewalFromAnotherAdmin checks a certificate that one admin CA issued
// and another renews, sending its admin CA along, as after the first admin
// was removed: the identity takes it with the new issuer, and nothing that
// does not chain up.
func TestRenewalFromAnotherAdmin(t *testing.T) {
	pg := newPhoneGroup(t)
	id := adminIdentity(t, pg, pg.a)
	later := t0.Add(24 * time.Hour)
	fromB, err := pg.b.IssueMember(id.ID, &id.Key.PublicKey, later)
	if err != nil {
		t.Fatal(err)
	}
	next, err := id.WithCertFrom(fromB.Raw, pg.b.Cert.Raw)
	if err != nil {
		t.Fatalf("renewed by another admin CA: %v", err)
	}
	if !next.Issuer.Equal(pg.b.Cert) {
		t.Error("the identity did not take the new issuer")
	}
	dir := t.TempDir()
	if err := next.Save(dir); err != nil {
		t.Fatal(err)
	}
	other := newPhoneGroup(t)
	fromOther, err := other.a.IssueMember(id.ID, &id.Key.PublicKey, later)
	if err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string][2][]byte{
		"the wrong issuer":           {fromB.Raw, pg.a.Cert.Raw},
		"another group's admin CA":   {fromOther.Raw, other.a.Cert.Raw},
		"a member as issuer":         {fromB.Raw, member(t, pg.root).Raw},
		"a corrupt issuer":           {fromB.Raw, []byte("junk")},
		"an issuer for a root's one": {member(t, pg.root).Raw, pg.b.Cert.Raw},
	} {
		if _, err := id.WithCertFrom(c[0], c[1]); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// TestRefusedChecksTheRealIssuer checks that a member certificate from a
// revoked admin CA stays refused whatever other certificates come with
// it: the issuer checked is the one that signed the leaf, not the second
// certificate presented.
func TestRefusedChecksTheRealIssuer(t *testing.T) {
	pg := newPhoneGroup(t)
	recs := NewRecords(pg.root.Cert)
	mustAdd(t, recs, revokeRecord(t, pg.root.Cert, pg.root, nil, []KeyHash{KeyHashOf(pg.a.Cert)}, nil))
	fromA, fromB := member(t, pg.a), member(t, pg.b)
	for _, c := range []struct {
		name  string
		chain []*x509.Certificate
		ok    bool
	}{
		{"revoked issuer", []*x509.Certificate{fromA, pg.a.Cert}, false},
		{"revoked issuer behind another admin CA", []*x509.Certificate{fromA, pg.b.Cert, pg.a.Cert}, false},
		{"issuer missing", []*x509.Certificate{fromA, pg.b.Cert}, false},
		{"standing issuer", []*x509.Certificate{fromB, pg.b.Cert}, true},
		{"standing issuer behind another CA", []*x509.Certificate{fromB, pg.a.Cert, pg.b.Cert}, true},
		{"from the root, with extras", []*x509.Certificate{member(t, pg.root), pg.a.Cert}, true},
	} {
		if err := recs.Refused(c.chain); (err == nil) != c.ok {
			t.Errorf("%s: Refused = %v", c.name, err)
		}
	}
}

// TestAllowSeesTheVerifiedChain checks that Allow gets the chain crypto/tls
// verified, without certificates the peer added that the verification did
// not use, so a revoked admin CA cannot hide behind another one.
func TestAllowSeesTheVerifiedChain(t *testing.T) {
	pg := newPhoneGroup(t)
	server := adminIdentity(t, pg, nil)
	client := adminIdentity(t, pg, pg.a)
	recs := NewRecords(pg.root.Cert)
	var seen []*x509.Certificate
	at := TLSOptions{Now: func() time.Time { return t0 }, Allow: func(_ DeviceID, c []*x509.Certificate) error {
		seen = c
		return recs.Refused(c)
	}}
	cfg := client.ClientTLS(server.ID, at)
	cfg.Certificates = []tls.Certificate{{Certificate: [][]byte{client.Cert.Raw, pg.b.Cert.Raw, pg.a.Cert.Raw}, PrivateKey: client.Key}}
	if _, _, cerr, serr := handshake(t, cfg, server.ServerTLS(at)); cerr != nil || serr != nil {
		t.Fatalf("handshake: client %v, server %v", cerr, serr)
	}
	if len(seen) != 2 || !seen[0].Equal(client.Cert) || !seen[1].Equal(pg.a.Cert) {
		t.Fatalf("Allow got %d certificates; want the leaf and its admin CA", len(seen))
	}
	mustAdd(t, recs, revokeRecord(t, pg.root.Cert, pg.root, nil, []KeyHash{KeyHashOf(pg.a.Cert)}, nil))
	if _, _, _, serr := handshake(t, cfg, server.ServerTLS(at)); serr == nil {
		t.Error("the server accepted a certificate from a revoked admin CA")
	}
}
