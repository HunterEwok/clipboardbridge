// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/HunterEwok/clipbridge/internal/group"
	"github.com/HunterEwok/clipbridge/internal/node"
)

// testCA makes a CA as a phone does: a root with path length 1 when parent
// is nil, else an admin CA with path length 0 under it.
func testCA(t *testing.T, parent *group.CA) *group.CA {
	t.Helper()
	key, err := group.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "clipbridge group root 2026-10-22"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(20, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            1,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	parentCert, parentKey := tmpl, key
	if parent != nil {
		tmpl.Subject.CommonName = "clipbridge admin " + string(group.NewDeviceID())
		tmpl.MaxPathLen, tmpl.MaxPathLenZero = 0, true
		parentCert, parentKey = parent.Cert, parent.Key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parentCert, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &group.CA{Cert: c, Key: key}
}

// memberIn saves a computer's identity without CA keys, its certificate
// from issuer, in a new state directory.
func memberIn(t *testing.T, first, issuer *group.CA, roots ...*x509.Certificate) (string, *group.Identity) {
	t.Helper()
	key, err := group.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	dev := group.NewDeviceID()
	cert, err := issuer.IssueMember(dev, &key.PublicKey, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp("", "cb")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	id := &group.Identity{ID: dev, Key: key, Cert: cert, GroupCA: group.CA{Cert: first.Cert}, Roots: roots}
	if err := id.Save(dir); err != nil {
		t.Fatal(err)
	}
	return dir, id
}

func sign(t *testing.T, first *x509.Certificate, body group.RecordBody, key *ecdsa.PrivateKey, chain ...*x509.Certificate) group.Record {
	t.Helper()
	body.Group, body.TimeMS = group.Tag(first), time.Now().UnixMilli()
	r, err := group.SignRecord(body, key, chain...)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// TestRootHandover checks computers in a phone group whose root phone was
// lost and whose admin phone B handed the group to a new root: one holds
// the records when it starts, one gets them from it, and both talk to a
// computer the new root admitted.
func TestRootHandover(t *testing.T) {
	old, newRoot := testCA(t, nil), testCA(t, nil)
	adminB := testCA(t, old)
	holderDir, holder := memberIn(t, old, old)
	laterDir, later := memberIn(t, old, old)
	newDir, _ := memberIn(t, old, newRoot, newRoot.Cert)

	g := old.Cert
	hk, lk, bk := group.KeyHashOf(holder.Cert), group.KeyHashOf(later.Cert), group.KeyHashOf(adminB.Cert)
	lost := group.KeyHash{1}
	recs := group.NewRecords(g)
	if _, errs := recs.AddAll([]group.Record{
		sign(t, g, group.RecordBody{Type: group.RecordDevice, Device: holder.ID, Name: "holder", Role: group.RoleLinux, Key: &hk}, old.Key),
		sign(t, g, group.RecordBody{Type: group.RecordDevice, Device: later.ID, Name: "later", Role: group.RoleLinux, Key: &lk}, old.Key),
		sign(t, g, group.RecordBody{Type: group.RecordRoot, Root: newRoot.Cert.Raw}, adminB.Key, adminB.Cert),
		sign(t, g, group.RecordBody{Type: group.RecordRevoke, Keys: []group.KeyHash{group.KeyHashOf(old.Cert), lost},
			Keep: []group.KeyHash{hk, lk, bk}}, newRoot.Key),
	}); len(errs) > 0 {
		t.Fatal(errs)
	}
	if err := recs.Save(holderDir); err != nil {
		t.Fatal(err)
	}

	var h hub
	a := startIn(t, &h, &testService{name: "holder", dir: holderDir, role: node.Linux})
	// The control socket answers before the group has started.
	waitFor(t, "the holder keeps the new root", func() bool {
		id, err := group.Load(holderDir)
		return err == nil && len(id.Roots) == 1
	})
	b := startIn(t, &h, &testService{name: "later", dir: laterDir, role: node.Linux})
	waitFor(t, "the later one has the new root", func() bool {
		id, err := group.Load(laterDir)
		return err == nil && len(id.Roots) == 1 && id.Root().Equal(newRoot.Cert)
	})
	c := startIn(t, &h, &testService{name: "new", dir: newDir, role: node.Linux})
	for _, s := range []*testService{a, b, c} {
		waitFor(t, s.name+" connected to both", func() bool { return len(s.status(t).Peers) == 2 })
	}
}
