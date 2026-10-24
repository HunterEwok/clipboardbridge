// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package group

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/rand/v2"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// phoneGroup is a group rooted in a phone: a root CA with path length 1 and
// two admin CAs below it, as docs/protocol.md, section 10, describes.
type phoneGroup struct {
	root, a, b *CA
}

func newPhoneGroup(t *testing.T) phoneGroup {
	t.Helper()
	root := newRoot(t)
	return phoneGroup{root: root, a: adminCA(t, root), b: adminCA(t, root)}
}

// newRoot makes a phone's root CA.
func newRoot(t *testing.T) *CA {
	t.Helper()
	rootKey, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		Subject:               pkix.Name{CommonName: "clipboardbridge group root 2026-10-21"},
		NotBefore:             t0.Add(-backdate),
		NotAfter:              t0.AddDate(caYears, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            1,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	rootCert, err := create(tmpl, tmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	return &CA{Cert: rootCert, Key: rootKey}
}

func adminCA(t *testing.T, root *CA) *CA {
	t.Helper()
	key, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	cert, err := create(&x509.Certificate{
		Subject:               pkix.Name{CommonName: "clipboardbridge admin " + string(NewDeviceID())},
		NotBefore:             root.Cert.NotBefore,
		NotAfter:              root.Cert.NotAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}, root.Cert, &key.PublicKey, root.Key)
	if err != nil {
		t.Fatal(err)
	}
	return &CA{Cert: cert, Key: key}
}

// member issues a member certificate from ca.
func member(t *testing.T, ca *CA) *x509.Certificate {
	t.Helper()
	key, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	cert, err := ca.IssueMember(NewDeviceID(), &key.PublicKey, t0)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func deviceRecord(t *testing.T, root *x509.Certificate, signer *CA, chain []*x509.Certificate, cert *x509.Certificate, name string, ms int64) Record {
	t.Helper()
	key := KeyHashOf(cert)
	r, err := SignRecord(RecordBody{
		Type: RecordDevice, Group: Tag(root), TimeMS: ms,
		Device: DeviceID(cert.Subject.CommonName), Name: name, Role: RoleFull, Key: &key,
	}, signer.Key, chain...)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func revokeRecord(t *testing.T, root *x509.Certificate, signer *CA, chain []*x509.Certificate, keys, keep []KeyHash) Record {
	t.Helper()
	// Each its own time: two signers' revocations of the same keys are
	// still two records.
	r, err := SignRecord(RecordBody{Type: RecordRevoke, Group: Tag(root), TimeMS: nextTime(), Keys: keys, Keep: keep}, signer.Key, chain...)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func mustAdd(t *testing.T, s *Records, r Record) {
	t.Helper()
	if _, err := s.Add(r); err != nil {
		t.Fatal(err)
	}
}

func TestRecordsInComputerGroup(t *testing.T) {
	admin := newGroup(t)
	mac := join(t, admin, false, t0)
	s := NewRecords(admin.GroupCA.Cert)
	mustAdd(t, s, deviceRecord(t, admin.GroupCA.Cert, &admin.GroupCA, nil, admin.Cert, "pi", 1))
	mustAdd(t, s, deviceRecord(t, admin.GroupCA.Cert, &admin.GroupCA, nil, mac.Cert, "mac", 2))
	// A rename is a later record for the same device.
	mustAdd(t, s, deviceRecord(t, admin.GroupCA.Cert, &admin.GroupCA, nil, mac.Cert, "laptop", 3))
	if got := names(s.Devices()); got != "laptop pi" {
		t.Fatalf("devices %q, want laptop pi", got)
	}
	if err := s.Refused([]*x509.Certificate{mac.Cert}); err != nil {
		t.Fatalf("the Mac is refused before its revocation: %v", err)
	}
	digest := s.Digest()

	mustAdd(t, s, revokeRecord(t, admin.GroupCA.Cert, &admin.GroupCA, nil, []KeyHash{KeyHashOf(mac.Cert)}, nil))
	if got := names(s.Devices()); got != "pi" {
		t.Errorf("devices %q after the revocation, want pi", got)
	}
	if s.Refused([]*x509.Certificate{mac.Cert}) == nil {
		t.Error("the revoked Mac is not refused")
	}
	if s.Refused([]*x509.Certificate{admin.Cert}) != nil {
		t.Error("the Linux member is refused")
	}
	if s.Digest() == digest {
		t.Error("the digest did not change with a new record")
	}
	// Adding a record again is not new.
	if isNew, err := s.Add(s.All()[0]); isNew || err != nil {
		t.Errorf("adding a known record: new %v, error %v", isNew, err)
	}
}

func TestRecordsRejected(t *testing.T) {
	admin := newGroup(t)
	other := newGroup(t)
	s := NewRecords(admin.GroupCA.Cert)
	good := deviceRecord(t, admin.GroupCA.Cert, &admin.GroupCA, nil, admin.Cert, "pi", 1)

	forged := good
	forged.Sig = append([]byte(nil), good.Sig...)
	forged.Sig[len(forged.Sig)-1] ^= 1
	tampered := good
	tampered.Body = []byte(strings.Replace(string(good.Body), `"pi"`, `"px"`, 1))
	cases := map[string]Record{
		"bad signature":        forged,
		"changed body":         tampered,
		"another group's CA":   deviceRecord(t, admin.GroupCA.Cert, &other.GroupCA, nil, admin.Cert, "pi", 1),
		"another group's tag":  deviceRecord(t, other.GroupCA.Cert, &admin.GroupCA, nil, admin.Cert, "pi", 1),
		"admin CA from a leaf": deviceRecord(t, admin.GroupCA.Cert, &admin.GroupCA, []*x509.Certificate{admin.Cert}, admin.Cert, "pi", 1),
		"not JSON":             {Body: []byte("{"), Sig: good.Sig},
	}
	for name, r := range cases {
		if _, err := s.Add(r); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// A computer's group CA has path length 0, so no admin CA counts.
	pg := newPhoneGroup(t)
	if _, err := NewRecords(admin.GroupCA.Cert).Add(deviceRecord(t, admin.GroupCA.Cert, pg.a, []*x509.Certificate{pg.a.Cert}, admin.Cert, "pi", 1)); err == nil {
		t.Error("a record from a foreign admin CA was accepted")
	}
	if s.Len() != 0 {
		t.Errorf("%d records kept, want none", s.Len())
	}
	for name, body := range map[string]RecordBody{
		"bad name":      {Type: RecordDevice, Device: admin.ID, Name: "a\nb", Role: RoleFull, OS: OSMacOS, Key: &KeyHash{}},
		"unknown role":  {Type: RecordDevice, Device: admin.ID, Name: "a", Role: "toaster", Key: &KeyHash{}},
		"no keys":       {Type: RecordRevoke},
		"unknown type":  {Type: "gift"},
		"no device key": {Type: RecordDevice, Device: admin.ID, Name: "a", Role: RoleFull, OS: OSMacOS},
	} {
		if _, err := SignRecord(body, admin.GroupCA.Key); err == nil {
			t.Errorf("%s: signed", name)
		}
	}
}

// TestLosingAPhone is the story of section 10: phone A admitted a computer,
// A is lost, and phone B removes A while keeping the computer.
func TestLosingAPhone(t *testing.T) {
	pg := newPhoneGroup(t)
	root := pg.root.Cert
	aChain := []*x509.Certificate{pg.a.Cert}
	bChain := []*x509.Certificate{pg.b.Cert}
	phoneA := member(t, pg.a)
	phoneB := member(t, pg.b)
	computer := member(t, pg.a)
	stolen := member(t, pg.a) // admitted by the thief after the loss
	viaB := member(t, pg.b)

	s := NewRecords(root)
	adminA, adminB := KeyHashOf(pg.a.Cert), KeyHashOf(pg.b.Cert)
	for _, r := range []Record{
		// The root records its admin phones.
		adminRecord(t, root, pg.root, nil, phoneA, "phone A", adminA),
		adminRecord(t, root, pg.root, nil, phoneB, "phone B", adminB),
		deviceRecord(t, root, pg.a, aChain, computer, "computer", 2),
		deviceRecord(t, root, pg.b, bChain, viaB, "via B", 3),
	} {
		mustAdd(t, s, r)
	}
	if got := admins(s.Devices()); got != "phone A phone B" {
		t.Fatalf("admins %q, want phone A phone B", got)
	}

	removal := revokeRecord(t, root, pg.b, bChain, []KeyHash{KeyHashOf(phoneA), adminA}, []KeyHash{KeyHashOf(computer)})
	mustAdd(t, s, removal)
	mustAdd(t, s, deviceRecord(t, root, pg.a, aChain, stolen, "stolen", 4))

	for name, chain := range map[string][]*x509.Certificate{
		"phone A":                     {phoneA, pg.a.Cert},
		"a device the thief admitted": {stolen, pg.a.Cert},
	} {
		if s.Refused(chain) == nil {
			t.Errorf("%s is not refused", name)
		}
	}
	for name, chain := range map[string][]*x509.Certificate{
		"the kept computer": {computer, pg.a.Cert},
		"a device from B":   {viaB, pg.b.Cert},
	} {
		if err := s.Refused(chain); err != nil {
			t.Errorf("%s is refused: %v", name, err)
		}
	}
	// The thief's records no longer count, and A is gone from the list.
	if got := names(s.Devices()); got != "computer phone B via B" {
		t.Errorf("devices %q, want computer phone B via B", got)
	}
	// A revocation from the revoked A still counts: two admins that revoke
	// each other both lose their rights.
	mustAdd(t, s, revokeRecord(t, root, pg.a, aChain, []KeyHash{adminB}, nil))
	if !s.Revoked(adminB) {
		t.Error("the revocation from the revoked admin does not count")
	}
}

func adminRecord(t *testing.T, root *x509.Certificate, signer *CA, chain []*x509.Certificate, cert *x509.Certificate, name string, admin KeyHash) Record {
	t.Helper()
	key := KeyHashOf(cert)
	r, err := SignRecord(RecordBody{
		Type: RecordDevice, Group: Tag(root), TimeMS: 1,
		Device: DeviceID(cert.Subject.CommonName), Name: name, Role: RolePhone, Key: &key, Admin: &admin,
	}, signer.Key, chain...)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// TestRecordsOrderIndependent adds the same records in random orders and
// expects the same list and digest every time.
func TestRecordsOrderIndependent(t *testing.T) {
	pg := newPhoneGroup(t)
	root := pg.root.Cert
	aChain := []*x509.Certificate{pg.a.Cert}
	bChain := []*x509.Certificate{pg.b.Cert}
	c1, c2 := member(t, pg.a), member(t, pg.b)
	all := []Record{
		// Two admin phones that revoke each other.
		adminRecord(t, root, pg.root, nil, member(t, pg.a), "phone A", KeyHashOf(pg.a.Cert)),
		adminRecord(t, root, pg.root, nil, member(t, pg.b), "phone B", KeyHashOf(pg.b.Cert)),
		deviceRecord(t, root, pg.a, aChain, c1, "one", 1),
		deviceRecord(t, root, pg.b, bChain, c1, "renamed", 5),
		deviceRecord(t, root, pg.b, bChain, c2, "two", 2),
		revokeRecord(t, root, pg.b, bChain, []KeyHash{KeyHashOf(pg.a.Cert)}, []KeyHash{KeyHashOf(c1)}),
		revokeRecord(t, root, pg.a, aChain, []KeyHash{KeyHashOf(pg.b.Cert)}, nil),
	}
	var want string
	for i := range 20 {
		rng := rand.New(rand.NewPCG(uint64(i), 1))
		order := rng.Perm(len(all))
		s := NewRecords(root)
		for _, j := range order {
			mustAdd(t, s, all[j])
		}
		got, _ := json.Marshal(s.Devices())
		got = append(got, s.Digest()...)
		if i == 0 {
			want = string(got)
		} else if string(got) != want {
			t.Fatalf("order %v gives %s, want %s", order, got, want)
		}
	}
}

func TestRecordsSaveLoad(t *testing.T) {
	admin := newGroup(t)
	dir := t.TempDir()
	if s, err := LoadRecords(dir, admin.GroupCA.Cert); err != nil || s.Len() != 0 {
		t.Fatalf("no file: %d records, error %v", s.Len(), err)
	}
	s := NewRecords(admin.GroupCA.Cert)
	mustAdd(t, s, deviceRecord(t, admin.GroupCA.Cert, &admin.GroupCA, nil, admin.Cert, "pi", 1))
	if err := s.Save(dir); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(filepath.Join(dir, RecordsFileName)); err != nil || runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Fatalf("records file: %v, %v", fi, err)
	}
	back, err := LoadRecords(dir, admin.GroupCA.Cert)
	if err != nil || back.Digest() != s.Digest() {
		t.Fatalf("loaded %d records, error %v", back.Len(), err)
	}
	// Records of another group are left out.
	other := newGroup(t)
	if back, err := LoadRecords(dir, other.GroupCA.Cert); err != nil || back.Len() != 0 {
		t.Errorf("another group: %d records, error %v", back.Len(), err)
	}
}

func admins(ds []Device) string {
	var n []string
	for _, d := range ds {
		if d.Admin {
			n = append(n, d.Name)
		}
	}
	return strings.Join(n, " ")
}

func names(ds []Device) string {
	var n []string
	for _, d := range ds {
		n = append(n, d.Name)
	}
	return strings.Join(n, " ")
}

// TestPhoneRootIdentity checks that a member of a group rooted in a phone,
// whose group CA has path length 1, is a valid identity, and that a longer
// or unlimited path is not.
func TestPhoneRootIdentity(t *testing.T) {
	pg := newPhoneGroup(t)
	key, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	dev := NewDeviceID()
	cert, err := pg.root.IssueMember(dev, &key.PublicKey, t0)
	if err != nil {
		t.Fatal(err)
	}
	id := &Identity{ID: dev, Key: key, Cert: cert, GroupCA: CA{Cert: pg.root.Cert}}
	if err := id.Check(); err != nil {
		t.Fatalf("a member of a phone's group: %v", err)
	}
	for name, mod := range map[string]func(*x509.Certificate){
		"path length 2": func(c *x509.Certificate) { c.MaxPathLen = 2 },
		"no path limit": func(c *x509.Certificate) { c.MaxPathLen = -1 },
	} {
		tmpl := *pg.root.Cert
		mod(&tmpl)
		root, err := create(&tmpl, &tmpl, &pg.root.Key.PublicKey, pg.root.Key)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := (&CA{Cert: root, Key: pg.root.Key}).IssueMember(dev, &key.PublicKey, t0)
		if err != nil {
			t.Fatal(err)
		}
		bad := &Identity{ID: dev, Key: key, Cert: cert, GroupCA: CA{Cert: root}}
		if bad.Check() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// TestRecordRoles checks that records keep the role apart from the system
// and read the roles of earlier records as today's.
func TestRecordRoles(t *testing.T) {
	admin, err := Create(t0)
	if err != nil {
		t.Fatal(err)
	}
	s := NewRecords(admin.GroupCA.Cert)
	for i, tc := range []struct{ role, os, wantRole, wantOS string }{
		{"linux", "", RoleFull, ""},
		{"linux", OSWindows, RoleFull, OSWindows},
		{"mac", "", RoleFull, OSMacOS},
		{"iphone", "", RoleShortcut, OSiOS},
		{RoleFull, OSWindows, RoleFull, OSWindows},
		{RoleLite, OSNone, RoleLite, OSNone},
		{RolePhone, OSAndroid, RolePhone, OSAndroid},
	} {
		key := KeyHash{byte(i + 1)}
		dev := NewDeviceID()
		r, err := SignRecord(RecordBody{Type: RecordDevice, Group: Tag(admin.GroupCA.Cert), Device: dev, Name: "d",
			Role: tc.role, OS: tc.os, Key: &key}, admin.GroupCA.Key)
		if err != nil {
			t.Fatalf("%s/%s: %v", tc.role, tc.os, err)
		}
		s.AddAll([]Record{r})
		for _, d := range s.Devices() {
			if d.ID == dev && (d.Role != tc.wantRole || d.OS != tc.wantOS) {
				t.Errorf("%s/%s reads as %s/%s", tc.role, tc.os, d.Role, d.OS)
			}
		}
	}
	key := KeyHash{99}
	for _, bad := range []RecordBody{
		{Type: RecordDevice, Device: admin.ID, Name: "d", Role: "computer", Key: &key},
		{Type: RecordDevice, Device: admin.ID, Name: "d", Role: RoleFull, OS: "darwin", Key: &key},
	} {
		bad.Group = Tag(admin.GroupCA.Cert)
		if _, err := SignRecord(bad, admin.GroupCA.Key); err == nil {
			t.Errorf("signed %+v", bad)
		}
	}
}
