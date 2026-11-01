// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package group

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
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

// In v:2 a body names its signer, so one body signed by another signer is
// no record: a set refuses the copy a computer admin signed of the root's
// removal of an admin phone, and the root's own copy removes the phone
// whichever came first. The records of testdata/interop/go-envelopes.json
// are v:1 and refused.
func TestEnvelopeVectors(t *testing.T) {
	checkV1Refused(t, "go-envelopes.json")
	pg := newPhoneGroup(t)
	g := pg.root.Cert
	pc, phone := pg.a, pg.b
	pcKey, phoneKey := KeyHashOf(pc.Cert), KeyHashOf(phone.Cert)
	byRoot := revokeRecord(t, g, pg.root, nil, []KeyHash{phoneKey})
	copied := resign(t, byRoot, pc, pc.Cert)
	recs := []Record{
		computerAdminRecord(t, pg, member(t, pc), "pc", pcKey),
		adminRecord(t, g, pg.root, nil, member(t, phone), "phone", phoneKey),
		copied,
		byRoot,
	}
	orders := map[string][]Record{"as written": recs, "reversed": slices.Clone(recs)}
	slices.Reverse(orders["reversed"])
	orders["the computer admin's copy only"] = recs[:3]
	for name, list := range orders {
		s := NewRecords(g)
		for _, r := range list {
			_, err := s.Add(r)
			if copy := bytes.Equal(r.Sig, copied.Sig); copy != (err != nil) {
				t.Fatalf("%s: the copy %v, %v", name, copy, err)
			}
		}
		// The same records again add nothing.
		for _, r := range list {
			if isNew, _ := s.Add(r); isNew {
				t.Errorf("%s: a record held already was new again", name)
			}
		}
		full := len(list) == len(recs)
		if s.Revoked(phoneKey) != full || s.Revoked(pcKey) {
			t.Errorf("%s: the phone revoked %v, the computer admin %v", name, s.Revoked(phoneKey), s.Revoked(pcKey))
		}
		if full && s.Len() != 3 {
			t.Errorf("%s: %d records", name, s.Len())
		}
	}
}
