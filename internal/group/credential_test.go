// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package group

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

// credentialGroup is a phone group with a root phone, an admin phone, two
// admin computers, one removed, and a plain computer, as the hub vectors'.
type credentialGroup struct {
	pg                   phoneGroup
	records              []Record
	rootKey, phoneKey    KeyHash // member keys
	pcOne, pcTwo, gone   *CA     // the computers' admin CAs
	pcOneKey, pcTwoKey   KeyHash
	plainKey, removedKey KeyHash
}

func newCredentialGroup(t *testing.T) credentialGroup {
	t.Helper()
	pg := newPhoneGroup(t)
	g := pg.root.Cert
	cg := credentialGroup{pg: pg}
	rootMember := member(t, pg.root)
	rootDev := DeviceID(rootMember.Subject.CommonName)
	cg.rootKey = KeyHashOf(rootMember)
	own, err := SignRecord(RecordBody{Type: RecordDevice, Group: Tag(g), TimeMS: 1, By: rootDev,
		Device: rootDev, Name: "root phone", Role: RolePhone, Key: &cg.rootKey}, pg.root.Key)
	if err != nil {
		t.Fatal(err)
	}
	phone, one, two, removed, plain := member(t, pg.root), member(t, pg.root), member(t, pg.root), member(t, pg.root), member(t, pg.root)
	cg.phoneKey, cg.pcOneKey, cg.pcTwoKey, cg.removedKey, cg.plainKey = KeyHashOf(phone), KeyHashOf(one), KeyHashOf(two), KeyHashOf(removed), KeyHashOf(plain)
	cg.pcOne, cg.pcTwo, cg.gone = adminCA(t, pg.root), adminCA(t, pg.root), adminCA(t, pg.root)
	cg.records = []Record{
		own,
		adminRecord(t, g, pg.root, nil, phone, "admin phone", KeyHashOf(pg.a.Cert)),
		computerAdminRecord(t, pg, one, "pc one", KeyHashOf(cg.pcOne.Cert)),
		computerAdminRecord(t, pg, two, "pc two", KeyHashOf(cg.pcTwo.Cert)),
		computerAdminRecord(t, pg, removed, "removed pc", KeyHashOf(cg.gone.Cert)),
		deviceRecord(t, g, pg.root, nil, plain, "plain pc", 1),
		revokeRecord(t, g, pg.root, nil, []KeyHash{KeyHashOf(cg.gone.Cert)}, nil),
	}
	return cg
}

func (cg credentialGroup) set(t *testing.T) *Records {
	t.Helper()
	s := NewRecords(cg.pg.root.Cert)
	if _, errs := s.AddAll(cg.records); len(errs) != 0 {
		t.Fatal(errs)
	}
	return s
}

// TestCredentialLists checks what a phone group's hubs' credential lists:
// the hubs in their order, the admins that are not removed, and of them
// the admin phones as heirs, since a computer never takes over a phone's
// group.
func TestCredentialLists(t *testing.T) {
	cg := newCredentialGroup(t)
	l := cg.set(t).CredentialLists()
	pcs := []KeyHash{cg.pcOneKey, cg.pcTwoKey}
	if len(l.Hubs) != 4 || l.Hubs[0] != cg.rootKey || l.Hubs[1] != cg.phoneKey || !slices.Contains(pcs, l.Hubs[2]) || !slices.Contains(pcs, l.Hubs[3]) {
		t.Errorf("hubs: %x", l.Hubs)
	}
	admins := []KeyHash{KeyHashOf(cg.pg.a.Cert), KeyHashOf(cg.pcOne.Cert), KeyHashOf(cg.pcTwo.Cert)}
	if !(CredentialLists{Admins: l.Admins}).Equal(CredentialLists{Admins: admins}) {
		t.Errorf("admins: %x", l.Admins)
	}
	if !slices.Equal(l.Heirs, []KeyHash{KeyHashOf(cg.pg.a.Cert)}) {
		t.Errorf("heirs: %x", l.Heirs)
	}
}

// TestCredentialLifecycle checks signing, padding, staleness, and keeping
// the chain across a handover to a new root.
func TestCredentialLifecycle(t *testing.T) {
	cg := newCredentialGroup(t)
	s := cg.set(t)
	want := s.CredentialLists()
	now := t0
	tag := Tag(cg.pg.root.Cert)
	c, err := SignHubs(tag, want, NextVersion(0, now), now, cg.pg.root.Key)
	if err != nil {
		t.Fatal(err)
	}
	b, err := c.Open()
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Hubs) != 4 || len(b.Admins) != 4 || len(b.Heirs) != 4 || b.Version != uint64(now.Unix()) {
		t.Errorf("padded to %d, %d, %d; version %d", len(b.Hubs), len(b.Admins), len(b.Heirs), b.Version)
	}
	for _, k := range [][]byte{cg.pg.root.Cert.Raw, []byte("root phone"), []byte("admin phone")} {
		if bytes.Contains(c.Body, k) {
			t.Errorf("the credential holds %q", k)
		}
	}
	if Stale(b, want, s.KnownKey, now) {
		t.Error("a fresh credential is stale")
	}
	if !Stale(b, want, s.KnownKey, now.Add(CredentialLifetime-CredentialRenew+time.Hour)) {
		t.Error("a credential due for renewal is not stale")
	}
	fewer := want
	fewer.Hubs = want.Hubs[:3]
	if !Stale(b, fewer, s.KnownKey, now) {
		t.Error("a credential that lists a removed hub is not stale")
	}
	fewer = want
	fewer.Admins = want.Admins[1:]
	if !Stale(b, fewer, s.KnownKey, now) {
		t.Error("a credential that lists a removed admin is not stale")
	}
	tampered := c
	tampered.Body = bytes.Replace(c.Body, []byte(`"version":`), []byte(`"version":1`), 1)
	if _, err := tampered.Open(); err == nil {
		t.Error("a changed credential opens")
	}

	// The admin phone, an heir, hands the group to a new root.
	next := newRoot(t)
	link, err := SignLink(tag, next.Cert, cg.pg.a.Key)
	if err != nil {
		t.Fatal(err)
	}
	c2, err := SignHubs(tag, want, NextVersion(b.Version, now), now, next.Key)
	if err != nil {
		t.Fatal(err)
	}
	roots := []*x509.Certificate{cg.pg.root.Cert, next.Cert}
	creds := NewCredentials(cg.pg.root.Cert)
	// Out of order: the link before the credential it counts against.
	if fresh, errs := creds.Add(roots, []Credential{link, c2, c}); len(fresh) != 3 || len(errs) != 0 {
		t.Fatalf("took %d: %v", len(fresh), errs)
	}
	chain := creds.Chain(roots)
	if len(chain) != 3 || chain[0].ID() != c.ID() || chain[1].ID() != link.ID() || chain[2].ID() != c2.ID() {
		t.Fatalf("the chain: %d", len(chain))
	}
	ch, err := CheckChain(cg.pg.root.Cert, chain)
	if err != nil {
		t.Fatal(err)
	}
	if len(ch.Roots) != 2 || !ch.Roots[1].Equal(next.Cert) || ch.Last().Version <= b.Version {
		t.Errorf("the checked chain: %d roots, version %d", len(ch.Roots), ch.Last().Version)
	}
	if creds.MaxVersion() != ch.Last().Version {
		t.Errorf("MaxVersion %d", creds.MaxVersion())
	}

	// A link from a computer, which is no heir, counts for nothing.
	rogue, _ := SignLink(tag, next.Cert, cg.pcOne.Key)
	if _, err := CheckChain(cg.pg.root.Cert, []Credential{c, rogue, c2}); err == nil {
		t.Error("a link from no heir")
	}
	other := NewCredentials(cg.pg.root.Cert)
	other.Add(roots, []Credential{c})
	if fresh, errs := other.Add(roots, []Credential{rogue}); len(fresh) != 0 || len(errs) != 1 {
		t.Errorf("a set took a link from no heir: %d, %v", len(fresh), errs)
	}
	// An older credential of the same root is not kept.
	older, _ := SignHubs(tag, want, b.Version-1, now, cg.pg.root.Key)
	if fresh, _ := creds.Add(roots, []Credential{older}); len(fresh) != 0 {
		t.Error("an older credential replaced a newer one")
	}

	// Saved and loaded.
	dir := t.TempDir()
	if err := creds.Save(dir); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadCredentials(dir, roots)
	if err != nil {
		t.Fatal(err)
	}
	if got := loaded.Chain(roots); len(got) != 3 {
		t.Errorf("the loaded chain: %d", len(got))
	}
}

// TestHubCertificate checks the certificate a hub registers with when it
// has a credential: its own key, no device, then the group CA.
func TestHubCertificate(t *testing.T) {
	pg := newPhoneGroup(t)
	key, _ := NewKey()
	c, err := HubCertificate(key, pg.root.Cert)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DeviceOf(c.Leaf); err == nil || len(c.Leaf.DNSNames) != 0 || c.Leaf.Subject.CommonName != HubCertificateName {
		t.Errorf("the hub's certificate names %v %v", c.Leaf.Subject, c.Leaf.DNSNames)
	}
	if len(c.Certificate) != 2 || !bytes.Equal(c.Certificate[1], pg.root.Cert.Raw) {
		t.Error("the group CA does not follow")
	}
	spki, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if !bytes.Equal(c.Leaf.RawSubjectPublicKeyInfo, spki) {
		t.Error("another key")
	}
}

type credentialVectors struct {
	GroupCA []byte          `json:"group_ca"`
	Records []Record        `json:"records"`
	Lists   CredentialLists `json:"lists"`
	Roots   [][]byte        `json:"roots"`
	Chain   []Credential    `json:"chain"`
	Bad     []badChain      `json:"bad"`
}

type badChain struct {
	Name  string       `json:"name"`
	Chain []Credential `json:"chain"`
}

// TestGoCredentialVectors writes (with -update) and checks
// testdata/interop/go-credentials.json: a phone group's records, the lists
// its hubs' credential must hold, a chain across a handover to a new root,
// and chains a server refuses, for the phone kits to agree with
// (docs/protocol.md, section 18).
func TestGoCredentialVectors(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "interop", "go-credentials.json")
	if *update {
		cg := newCredentialGroup(t)
		s := cg.set(t)
		l := s.CredentialLists()
		tag := Tag(cg.pg.root.Cert)
		c, err := SignHubs(tag, l, 1000, t0, cg.pg.root.Key)
		if err != nil {
			t.Fatal(err)
		}
		next := newRoot(t)
		link, _ := SignLink(tag, next.Cert, cg.pg.a.Key)
		c2, _ := SignHubs(tag, l, 1001, t0, next.Key)
		rogue, _ := SignLink(tag, next.Cert, cg.pcOne.Key)
		same, _ := SignHubs(tag, l, 1000, t0, next.Key)
		stranger := newRoot(t)
		forged, _ := SignHubs(tag, l, 2000, t0, stranger.Key)
		v := credentialVectors{GroupCA: cg.pg.root.Cert.Raw, Records: cg.records, Lists: l,
			Roots: [][]byte{cg.pg.root.Cert.Raw, next.Cert.Raw}, Chain: []Credential{c, link, c2},
			Bad: []badChain{
				{"a link from a computer, which is no heir", []Credential{c, rogue, c2}},
				{"a new root's credential no newer than the old root's", []Credential{c, link, same}},
				{"a credential another root signed", []Credential{forged}},
				{"a chain that ends with a link", []Credential{c, link}},
			}}
		data, err := json.MarshalIndent(v, "", "\t")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var v credentialVectors
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(v.GroupCA)
	if err != nil {
		t.Fatal(err)
	}
	s := NewRecords(ca)
	if _, errs := s.AddAll(v.Records); len(errs) != 0 {
		t.Fatal(errs)
	}
	if got := s.CredentialLists(); !got.Equal(v.Lists) {
		t.Errorf("CredentialLists = %+v, the file has %+v", got, v.Lists)
	}
	ch, err := CheckChain(ca, v.Chain)
	if err != nil {
		t.Fatal(err)
	}
	if len(ch.Roots) != len(v.Roots) || !bytes.Equal(ch.Roots[1].Raw, v.Roots[1]) || ch.Last().Version != 1001 {
		t.Errorf("the chain leads to %d roots, version %d", len(ch.Roots), ch.Last().Version)
	}
	for _, b := range v.Bad {
		if _, err := CheckChain(ca, b.Chain); err == nil {
			t.Errorf("%s: the chain checks", b.Name)
		}
	}
}
