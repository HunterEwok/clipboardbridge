// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package group

import (
	"crypto/ecdsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
	"time"
)

// adminCAFor issues an admin CA for the key pub of the device dev, as the
// root phone does when it makes a computer an admin.
func adminCAFor(t *testing.T, root *CA, cn string, pub *ecdsa.PublicKey) *x509.Certificate {
	t.Helper()
	cert, err := create(&x509.Certificate{
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             root.Cert.NotBefore,
		NotAfter:              root.Cert.NotAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}, root.Cert, pub, root.Key)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// computerAdmin is a computer of the phone group pg that the root made an
// admin.
func computerAdmin(t *testing.T, pg phoneGroup) *Identity {
	t.Helper()
	id, err := adminIdentity(t, pg, nil).WithAdminKey()
	if err != nil {
		t.Fatal(err)
	}
	if id, err = id.WithAdminCA(adminCAFor(t, pg.root, AdminName(id.ID), &id.AdminKey.PublicKey).Raw, t0); err != nil {
		t.Fatal(err)
	}
	return id
}

// TestComputerAdmin checks a computer that the root phone makes an admin:
// it gets an admin key, takes an admin CA for it, signs with it, issues
// its own certificate from it, and keeps both across a save and a load.
func TestComputerAdmin(t *testing.T) {
	pg := newPhoneGroup(t)
	plain := adminIdentity(t, pg, nil)
	if ca, _ := plain.Signer(); ca != nil {
		t.Error("a computer without an admin CA can sign")
	}
	pending, err := plain.WithAdminKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pending.WithAdminKey(); err == nil {
		t.Error("got a second admin key")
	}
	if ca, _ := pending.Signer(); ca != nil {
		t.Error("a computer with only an admin key can sign")
	}
	dir := t.TempDir()
	if err := pending.Save(dir); err != nil {
		t.Fatal(err)
	}
	if got, err := Load(dir); err != nil || got.AdminKey == nil || !got.AdminKey.Equal(pending.AdminKey) || got.AdminCA != nil {
		t.Fatalf("the admin key was not kept: %v", err)
	}

	cn := AdminName(pending.ID)
	other := newPhoneGroup(t)
	key, _ := NewKey()
	for name, c := range map[string]*x509.Certificate{
		"another key":           adminCAFor(t, pg.root, cn, &key.PublicKey),
		"another device":        adminCAFor(t, pg.root, AdminName(NewDeviceID()), &pending.AdminKey.PublicKey),
		"another group's root":  adminCAFor(t, other.root, cn, &pending.AdminKey.PublicKey),
		"from an admin CA":      adminCAFor(t, pg.a, cn, &pending.AdminKey.PublicKey),
		"a member certificate":  member(t, pg.root),
		"the root's own":        pg.root.Cert,
		"another admin's admin": pg.a.Cert,
	} {
		if _, err := pending.WithAdminCA(c.Raw, t0); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := pending.WithAdminCA([]byte("junk"), t0); err == nil {
		t.Error("accepted a corrupt admin CA")
	}

	admin, err := pending.WithAdminCA(adminCAFor(t, pg.root, cn, &pending.AdminKey.PublicKey).Raw, t0)
	if err != nil {
		t.Fatal(err)
	}
	ca, chain := admin.Signer()
	if ca == nil || !ca.Cert.Equal(admin.AdminCA) || len(chain) != 1 || !chain[0].Equal(admin.AdminCA) {
		t.Fatal("the admin computer does not sign with its admin CA")
	}
	if !admin.Issuer.Equal(admin.AdminCA) || admin.Cert.CheckSignatureFrom(admin.AdminCA) != nil {
		t.Error("its member certificate is not from its admin CA")
	}
	if err := admin.Save(dir); err != nil {
		t.Fatal(err)
	}
	got, err := Load(dir)
	if err != nil || got.AdminCA == nil || !got.AdminCA.Equal(admin.AdminCA) {
		t.Fatalf("the admin CA was not kept: %v", err)
	}
	r, err := SignRecord(RecordBody{Type: RecordDevice, Group: Tag(pg.root.Cert), Device: NewDeviceID(), Name: "deck",
		Role: RoleFull, Key: &KeyHash{1}, By: admin.ID}, ca.Key, chain...)
	if err != nil {
		t.Fatal(err)
	}
	recs := NewRecords(pg.root.Cert)
	if ok, err := recs.Add(r); !ok || err != nil || len(recs.Devices()) != 1 {
		t.Errorf("a record the admin computer signed: %v, %v", ok, err)
	}

	// A group a computer created has no admin keys.
	if _, err := newGroup(t).WithAdminKey(); err == nil {
		t.Error("a computer group's member got an admin key")
	}
}

// TestComputerAdminRenews checks that an admin computer renews its own
// certificate and those of its peers from its admin CA, which the peers
// take with the issuer.
func TestComputerAdminRenews(t *testing.T) {
	pg := newPhoneGroup(t)
	admin := computerAdmin(t, pg)
	peer := adminIdentity(t, pg, pg.a)
	if c, _, err := admin.RenewMember(peer.Cert, t0.AddDate(0, 6, 0)); c != nil || err != nil {
		t.Errorf("renewed half a year in: %v, %v", c, err)
	}
	at := t0.AddDate(1, 6, 0)
	cert, issuer, err := admin.RenewMember(peer.Cert, at)
	if err != nil || cert == nil || !issuer.Equal(admin.AdminCA) {
		t.Fatalf("RenewMember = %v, %v, %v", cert, issuer, err)
	}
	next, err := peer.WithCertFrom(cert.Raw, issuer.Raw)
	if err != nil || !next.Issuer.Equal(admin.AdminCA) {
		t.Fatalf("the peer did not take it: %v", err)
	}
	if c, _, err := adminIdentity(t, pg, nil).RenewMember(peer.Cert, at); c != nil || err != nil {
		t.Errorf("a computer that is no admin renewed: %v, %v", c, err)
	}

	own, changed, err := admin.Renew(at)
	if err != nil || !changed || !own.Issuer.Equal(admin.AdminCA) || !own.Cert.NotAfter.After(admin.Cert.NotAfter) {
		t.Fatalf("Renew = %v, %v", changed, err)
	}
	if err := own.Check(); err != nil {
		t.Error(err)
	}
	if _, changed, _ := admin.Renew(t0.Add(time.Hour)); changed {
		t.Error("renewed its own certificate early")
	}
}

// TestRootDeviceAndAdmitted checks the records' root phone and the devices
// an admin admitted, which a revocation of that admin keeps.
func TestRootDeviceAndAdmitted(t *testing.T) {
	pg := newPhoneGroup(t)
	tag := Tag(pg.root.Cert)
	rootPhone, aPhone, deck := NewDeviceID(), NewDeviceID(), NewDeviceID()
	k1, k2, k3, ka := KeyHash{1}, KeyHash{2}, KeyHash{3}, KeyHashOf(pg.a.Cert)
	sign := func(body RecordBody, ca *CA, chain ...*x509.Certificate) Record {
		body.Group = tag
		r, err := SignRecord(body, ca.Key, chain...)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	recs := NewRecords(pg.root.Cert)
	if recs.RootDevice() != "" {
		t.Error("an empty set has a root phone")
	}
	if _, errs := recs.AddAll([]Record{
		sign(RecordBody{Type: RecordDevice, Device: rootPhone, Name: "root", Role: RolePhone, Key: &k1, By: rootPhone, TimeMS: 1}, pg.root),
		sign(RecordBody{Type: RecordDevice, Device: aPhone, Name: "a", Role: RolePhone, Key: &k2, Admin: &ka, By: rootPhone, TimeMS: 2}, pg.root),
		sign(RecordBody{Type: RecordDevice, Device: deck, Name: "deck", Role: RoleFull, Key: &k3, By: aPhone, TimeMS: 3}, pg.a, pg.a.Cert),
		// An admin's own record signed by itself does not make it the root.
		sign(RecordBody{Type: RecordDevice, Device: aPhone, Name: "a", Role: RolePhone, Key: &k2, Admin: &ka, By: aPhone, TimeMS: 4}, pg.a, pg.a.Cert),
	}); len(errs) > 0 {
		t.Fatal(errs)
	}
	if got := recs.RootDevice(); got != rootPhone {
		t.Errorf("RootDevice = %q, want %q", got, rootPhone)
	}
	if got := recs.Admitted(ka); len(got) != 2 || got[0] == got[1] {
		t.Errorf("Admitted = %v, want the deck and the phone itself", got)
	}
	for _, d := range recs.Devices() {
		if d.ID == aPhone && (d.AdminKey == nil || *d.AdminKey != ka) {
			t.Error("the admin phone's admin key is not listed")
		}
	}
}
