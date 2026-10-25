// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package group

import (
	"crypto/tls"
	"crypto/x509"
	mrand "math/rand/v2"
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

// computerAdminRecord is the root's record of a computer whose admin CA is
// admin: its key sits in a file, so it has less power than an admin phone.
func computerAdminRecord(t *testing.T, pg phoneGroup, cert *x509.Certificate, name string, admin KeyHash) Record {
	t.Helper()
	key := KeyHashOf(cert)
	r, err := SignRecord(RecordBody{Type: RecordDevice, Group: Tag(pg.root.Cert), TimeMS: 1,
		Device: DeviceID(cert.Subject.CommonName), Name: name, Role: RoleFull, OS: OSLinux, Key: &key, Admin: &admin}, pg.root.Key)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// TestAdminPowers checks what a computer's admin CA may do: admit and
// remove devices, but neither remove the root or another admin nor hand
// the group over; and that nothing it signs counts once it is removed.
func TestAdminPowers(t *testing.T) {
	pg := newPhoneGroup(t)
	g := pg.root.Cert
	pc, phone := pg.a, pg.b // a computer admin and an admin phone
	pcChain, phoneChain := []*x509.Certificate{pc.Cert}, []*x509.Certificate{phone.Cert}
	pcKey, phoneKey, rootKey := KeyHashOf(pc.Cert), KeyHashOf(phone.Cert), KeyHashOf(g)
	laptop, tv := member(t, pc), member(t, pc)
	s := NewRecords(g)
	for _, r := range []Record{
		computerAdminRecord(t, pg, member(t, pc), "pc", pcKey),
		adminRecord(t, g, pg.root, nil, member(t, phone), "phone", phoneKey),
		deviceRecord(t, g, pc, pcChain, laptop, "laptop", 2),
		deviceRecord(t, g, pc, pcChain, tv, "tv", 3),
	} {
		mustAdd(t, s, r)
	}

	// The computer admin removes neither the admin phone nor the root, nor
	// hands the group over; a record that tries counts for nothing.
	mustAdd(t, s, revokeRecord(t, g, pc, pcChain, []KeyHash{phoneKey, KeyHashOf(laptop)}, nil))
	mustAdd(t, s, revokeRecord(t, g, pc, pcChain, []KeyHash{rootKey}, nil))
	own := newRoot(t)
	mustAdd(t, s, rootRecord(t, g, pc, pcChain, own.Cert))
	// The root it named is never known: the set takes nothing signed under
	// it, and refuses certificates from it.
	if _, err := s.Add(revokeRecord(t, g, own, nil, []KeyHash{phoneKey, KeyHashOf(laptop)}, nil)); err == nil {
		t.Error("the set took a record signed by a root a computer admin named")
	}
	if err := s.Refused([]*x509.Certificate{member(t, own)}); err == nil {
		t.Error("a certificate from a root a computer admin named is not refused")
	}
	// Nor does the admin phone remove the root.
	mustAdd(t, s, revokeRecord(t, g, phone, phoneChain, []KeyHash{rootKey}, nil))
	if s.Revoked(phoneKey) || s.Revoked(rootKey) || s.Revoked(KeyHashOf(laptop)) {
		t.Error("a computer admin removed an admin or the root")
	}
	if len(s.Roots()) != 0 {
		t.Error("a computer admin handed the group over")
	}
	// It does remove an ordinary device.
	mustAdd(t, s, revokeRecord(t, g, pc, pcChain, []KeyHash{KeyHashOf(tv)}, nil))
	if !s.Revoked(KeyHashOf(tv)) {
		t.Error("a computer admin cannot remove a device")
	}

	// The admin phone removes the computer admin, keeping the laptop and
	// carrying over the tv's removal. From then on nothing the computer
	// admin signs counts.
	mustAdd(t, s, revokeRecord(t, g, phone, phoneChain, []KeyHash{pcKey, KeyHashOf(tv)}, []KeyHash{KeyHashOf(laptop)}))
	mustAdd(t, s, revokeRecord(t, g, pc, pcChain, []KeyHash{KeyHashOf(laptop)}, nil))
	if !s.Revoked(pcKey) || !s.Revoked(KeyHashOf(tv)) {
		t.Error("the admin phone did not remove the computer admin")
	}
	if s.Revoked(KeyHashOf(laptop)) {
		t.Error("a removed admin's revocation counts")
	}
	if err := s.Refused([]*x509.Certificate{laptop, pc.Cert}); err != nil {
		t.Errorf("the kept laptop is refused: %v", err)
	}

	// Each admin CA signs at most MaxPerAdmin records.
	s2 := NewRecords(g)
	for i := range MaxPerAdmin {
		mustAdd(t, s2, deviceRecord(t, g, pc, pcChain, laptop, "laptop", int64(i+1)))
	}
	if _, err := s2.Add(deviceRecord(t, g, pc, pcChain, laptop, "laptop", MaxPerAdmin+1)); err == nil {
		t.Error("an admin CA signed more than MaxPerAdmin records")
	}
	mustAdd(t, s2, deviceRecord(t, g, phone, phoneChain, laptop, "laptop", 1))
}

// ownRecord is the record a root signs for the device that holds it.
func ownRecord(t *testing.T, root *CA, cert *x509.Certificate, name, r string) Record {
	t.Helper()
	key, dev := KeyHashOf(cert), DeviceID(cert.Subject.CommonName)
	rec, err := SignRecord(RecordBody{Type: RecordDevice, Group: Tag(root.Cert), TimeMS: 1, By: dev,
		Device: dev, Name: name, Role: r, Key: &key}, root.Key)
	if err != nil {
		t.Fatal(err)
	}
	return rec
}

// TestComputerTakeover checks that an admin computer hands over a group
// whose root is a computer, as cbb takeover does, that a root still there
// undoes it by removing that admin, and that in a phone's group the same
// records count for nothing.
func TestComputerTakeover(t *testing.T) {
	for _, rootRole := range []string{RoleFull, RolePhone} {
		pg := newPhoneGroup(t)
		g, pc := pg.root.Cert, pg.a
		pcChain, pcKey, rootKey := []*x509.Certificate{pc.Cert}, KeyHashOf(pc.Cert), KeyHashOf(g)
		holder, laptop, pcCert := member(t, pg.root), member(t, pg.root), member(t, pc)
		next := newRoot(t)
		s := NewRecords(g)
		for _, r := range []Record{
			ownRecord(t, pg.root, holder, "root", rootRole),
			computerAdminRecord(t, pg, pcCert, "pc", pcKey),
			deviceRecord(t, g, pg.root, nil, laptop, "laptop", 2),
			rootRecord(t, g, pc, pcChain, next.Cert),
		} {
			mustAdd(t, s, r)
		}
		_, err := s.Add(revokeRecord(t, g, next, nil, []KeyHash{rootKey, KeyHashOf(holder)}, []KeyHash{KeyHashOf(laptop), pcKey}))
		took := len(s.Roots()) == 1 && s.Revoked(rootKey) && s.Revoked(KeyHashOf(holder))
		if rootRole == RolePhone {
			if took || len(s.Roots()) != 0 || err == nil {
				t.Error("a computer admin took a phone's group over")
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if !took {
			t.Fatal("the admin computer did not take the group over from a lost root computer")
		}
		if err := s.Refused([]*x509.Certificate{laptop}); err != nil {
			t.Errorf("the kept laptop is refused: %v", err)
		}
		// Another admin computer freezes it: the takeover stops counting
		// until the root's own key thaws the freeze.
		pc2 := adminCA(t, pg.root)
		pc2Key := KeyHashOf(pc2.Cert)
		mustAdd(t, s, computerAdminRecord(t, pg, member(t, pc2), "pc2", pc2Key))
		freeze := freezeRecord(t, g, pc2, []*x509.Certificate{pc2.Cert}, []KeyHash{pcKey}, nil)
		mustAdd(t, s, freeze)
		if len(s.Roots()) != 0 || s.Revoked(rootKey) {
			t.Error("a frozen admin computer took the group over")
		}
		mustAdd(t, s, thawRecord(t, g, pg.root, nil, []KeyHash{freeze.ID()}))
		if len(s.Roots()) != 1 {
			t.Error("the takeover does not count after the root's thaw")
		}
		// The old root is still there and removes the admin: the takeover
		// no longer counts.
		mustAdd(t, s, revokeRecord(t, g, pg.root, nil, []KeyHash{pcKey}, nil))
		if len(s.Roots()) != 0 || s.Revoked(rootKey) || !s.Revoked(pcKey) {
			t.Error("the old root did not undo the takeover by removing the admin")
		}
	}
}

// recordTime gives each freeze and thaw record of a test its own time, so
// two signers' records with the same content still differ.
var recordTime = t0.UnixMilli()

func freezeRecord(t *testing.T, root *x509.Certificate, signer *CA, chain []*x509.Certificate, keys, records []KeyHash) Record {
	t.Helper()
	r, err := SignRecord(RecordBody{Type: RecordFreeze, Group: Tag(root), TimeMS: nextTime(), Keys: keys, Records: records}, signer.Key, chain...)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func thawRecord(t *testing.T, root *x509.Certificate, signer *CA, chain []*x509.Certificate, freezes []KeyHash) Record {
	t.Helper()
	r, err := SignRecord(RecordBody{Type: RecordThaw, Group: Tag(root), TimeMS: nextTime(), Records: freezes}, signer.Key, chain...)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func nextTime() int64 {
	recordTime++
	return recordTime
}

// TestFreeze checks that an admin computer freezes another one: what the
// frozen admin signed before keeps counting and nothing later does, its own
// device is refused, it cannot freeze the root or an admin phone, two
// admins that freeze each other both stay frozen, and the root or an admin
// phone ends a freeze. The result does not depend on the order of the
// records.
func TestFreeze(t *testing.T) {
	pg := newPhoneGroup(t)
	g := pg.root.Cert
	pc1, phone, pc2 := pg.a, pg.b, adminCA(t, pg.root)
	pc1Chain, pc2Chain, phoneChain := []*x509.Certificate{pc1.Cert}, []*x509.Certificate{pc2.Cert}, []*x509.Certificate{phone.Cert}
	pc1Key, pc2Key, phoneKey, rootKey := KeyHashOf(pc1.Cert), KeyHashOf(pc2.Cert), KeyHashOf(phone.Cert), KeyHashOf(g)
	m1, m2, laptop, tv := member(t, pc1), member(t, pc2), member(t, pc1), member(t, pc1)
	before := deviceRecord(t, g, pc1, pc1Chain, laptop, "laptop", 2)
	freeze1 := freezeRecord(t, g, pc2, pc2Chain, []KeyHash{pc1Key}, []KeyHash{before.ID()})
	freeze2 := freezeRecord(t, g, pc1, pc1Chain, []KeyHash{pc2Key}, nil)
	all := []Record{
		computerAdminRecord(t, pg, m1, "pc1", pc1Key),
		computerAdminRecord(t, pg, m2, "pc2", pc2Key),
		adminRecord(t, g, pg.root, nil, member(t, phone), "phone", phoneKey),
		before,
		freeze1,
		// After the freeze: neither the tv nor removing the laptop counts.
		deviceRecord(t, g, pc1, pc1Chain, tv, "tv", 3),
		revokeRecord(t, g, pc1, pc1Chain, []KeyHash{KeyHashOf(laptop)}, nil),
		// Nobody freezes the root or an admin phone.
		freezeRecord(t, g, pc1, pc1Chain, []KeyHash{phoneKey}, nil),
		freezeRecord(t, g, pc1, pc1Chain, []KeyHash{rootKey}, nil),
		freezeRecord(t, g, pc1, pc1Chain, []KeyHash{pc2Key, phoneKey}, nil),
	}
	check := func(s *Records, pc2Frozen bool) {
		t.Helper()
		if !s.Frozen(pc1Key) || !s.Frozen(KeyHashOf(m1)) {
			t.Fatal("the freeze does not count")
		}
		if s.Frozen(phoneKey) || s.Frozen(rootKey) {
			t.Error("an admin computer froze the root or an admin phone")
		}
		if s.Frozen(pc2Key) != pc2Frozen || s.Frozen(KeyHashOf(m2)) != pc2Frozen {
			t.Errorf("pc2 frozen %v, want %v", s.Frozen(pc2Key), pc2Frozen)
		}
		if got := names(s.Devices()); got != "laptop pc1 pc2 phone" {
			t.Errorf("devices %q, want laptop pc1 pc2 phone", got)
		}
		for _, d := range s.Devices() {
			if d.Name == "pc1" && (!d.Frozen || d.Admin) {
				t.Errorf("pc1 is listed as frozen %v, admin %v", d.Frozen, d.Admin)
			}
		}
		if err := s.Refused([]*x509.Certificate{laptop, pc1.Cert}); err != nil {
			t.Errorf("the laptop it admitted before is refused: %v", err)
		}
		if s.Refused([]*x509.Certificate{tv, pc1.Cert}) == nil {
			t.Error("a device a frozen admin certified later is taken")
		}
		if s.Refused([]*x509.Certificate{m1, pc1.Cert}) == nil {
			t.Error("the frozen admin's own device is taken")
		}
	}
	for range 5 {
		s := NewRecords(g)
		for _, i := range mrand.Perm(len(all)) {
			mustAdd(t, s, all[i])
		}
		check(s, false)
		// The frozen admin freezes back: both stay frozen.
		mustAdd(t, s, freeze2)
		check(s, true)
		// An admin computer does not end a freeze; the admin phone does.
		mustAdd(t, s, thawRecord(t, g, pc2, pc2Chain, []KeyHash{freeze2.ID()}))
		check(s, true)
		mustAdd(t, s, thawRecord(t, g, phone, phoneChain, s.FreezesOf(pc2Key)))
		check(s, false)
		// Removing the frozen admin carries what it signed before, and its
		// freezes stop counting with it.
		mustAdd(t, s, revokeRecord(t, g, phone, phoneChain, []KeyHash{pc1Key, KeyHashOf(m1)}, s.Admitted(pc1Key)))
		mustAdd(t, s, freezeRecord(t, g, pc1, pc1Chain, []KeyHash{pc2Key}, []KeyHash{freeze2.ID()}))
		if s.Frozen(pc2Key) || !s.Revoked(pc1Key) {
			t.Error("a removed admin's freeze counts")
		}
		if err := s.Refused([]*x509.Certificate{laptop, pc1.Cert}); err != nil {
			t.Errorf("the laptop is refused after its admin's removal: %v", err)
		}
	}
	// The root's own thaw ends a freeze too.
	s := NewRecords(g)
	for _, r := range all {
		mustAdd(t, s, r)
	}
	mustAdd(t, s, thawRecord(t, g, pg.root, nil, []KeyHash{freeze1.ID()}))
	if s.Frozen(pc1Key) {
		t.Error("the root's thaw does not count")
	}
	// Its records count again, removing the laptop among them.
	if got := names(s.Devices()); got != "pc1 pc2 phone tv" {
		t.Errorf("devices after the thaw %q, want pc1 pc2 phone tv", got)
	}
}
