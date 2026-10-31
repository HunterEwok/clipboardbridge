// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package group

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// resign returns the body of r signed by signer instead, under chain.
func resign(t *testing.T, r Record, signer *CA, chain ...*x509.Certificate) Record {
	t.Helper()
	sum := sha256.Sum256(r.Body)
	sig, err := signer.Key.Sign(rand.Reader, sum[:], crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	out := Record{Body: r.Body, Sig: sig}
	for _, c := range chain {
		out.Chain = append(out.Chain, c.Raw)
	}
	return out
}

type envelopeVectors struct {
	GroupCA []byte     `json:"group_ca"`
	Records []Record   `json:"records"` // in the order a device that saw the admin's copy first got them
	Keys    []adminKey `json:"keys"`
	Digest  string     `json:"digest"`
	Count   int        `json:"count"` // records in the set: the body signed twice counts twice
}

// One body signed by two signers is two records: a set keeps both, and
// what it says, its digest included, does not depend on which came first.
// The root removes an admin phone, and a computer admin, which may not
// remove an admin phone, signs the root's record of it too: a device that
// got the computer admin's copy first removes the phone all the same.
//
// TestEnvelopeVectors writes (with -update) and checks
// testdata/interop/go-envelopes.json for the other implementations.
func TestEnvelopeVectors(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "interop", "go-envelopes.json")
	if *update {
		pg := newPhoneGroup(t)
		g := pg.root.Cert
		pc, phone := pg.a, pg.b
		pcKey, phoneKey := KeyHashOf(pc.Cert), KeyHashOf(phone.Cert)
		byRoot := revokeRecord(t, g, pg.root, nil, []KeyHash{phoneKey}, nil)
		recs := []Record{
			computerAdminRecord(t, pg, member(t, pc), "pc", pcKey),
			adminRecord(t, g, pg.root, nil, member(t, phone), "phone", phoneKey),
			resign(t, byRoot, pc, pc.Cert),
			byRoot,
		}
		s := NewRecords(g)
		if _, errs := s.AddAll(recs); len(errs) > 0 {
			t.Fatal(errs)
		}
		v := envelopeVectors{GroupCA: g.Raw, Records: recs, Digest: s.Digest(), Count: s.Len()}
		for _, k := range []struct {
			name string
			key  KeyHash
		}{{"the admin phone the root removes", phoneKey}, {"the computer admin", pcKey}} {
			v.Keys = append(v.Keys, adminKey{Name: k.name, Key: k.key, Revoked: s.Revoked(k.key)})
		}
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
	var v envelopeVectors
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(v.GroupCA)
	if err != nil {
		t.Fatal(err)
	}
	if v.Count != len(v.Records) || !v.Keys[0].Revoked || v.Keys[1].Revoked {
		t.Fatalf("the vectors say %d records, revoked %v", v.Count, v.Keys)
	}
	orders := map[string][]Record{"as written": v.Records, "reversed": slices.Clone(v.Records)}
	slices.Reverse(orders["reversed"])
	// Without the root's copy, the computer admin's removes nobody.
	orders["the computer admin's copy only"] = v.Records[:3]
	for name, recs := range orders {
		s := NewRecords(ca)
		for _, r := range recs {
			if _, err := s.Add(r); err != nil {
				t.Fatalf("%s: %v", name, err)
			}
		}
		// The same records again add nothing.
		for _, r := range recs {
			if isNew, _ := s.Add(r); isNew {
				t.Errorf("%s: a record held already was new again", name)
			}
		}
		full := len(recs) == len(v.Records)
		for _, k := range v.Keys {
			if want := k.Revoked && full; s.Revoked(k.Key) != want {
				t.Errorf("%s: %s revoked %v, want %v", name, k.Name, s.Revoked(k.Key), want)
			}
		}
		if full && (s.Digest() != v.Digest || s.Len() != v.Count) {
			t.Errorf("%s: %d records with digest %s, want %d and %s", name, s.Len(), s.Digest(), v.Count, v.Digest)
		}
	}
}
