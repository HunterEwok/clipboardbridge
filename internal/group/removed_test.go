// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package group

import (
	"crypto/x509"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

type removedVectors struct {
	GroupCA []byte     `json:"group_ca"`
	Records []Record   `json:"records"`
	Keys    []adminKey `json:"keys"`
	Roots   int        `json:"roots"` // the roots the group was handed to
}

// An admin phone that the root removed signs a root record afterwards, for
// a root of its own, whose key then revokes the group's root and admins:
// that root is not known, so none of it counts, in any order.
//
// TestRemovedAdminVectors writes (with -update) and checks
// testdata/interop/go-removed-admin.json for the other implementations.
func TestRemovedAdminVectors(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "interop", "go-removed-admin.json")
	if *update {
		pg := newPhoneGroup(t)
		g := pg.root.Cert
		phone, pc := pg.a, pg.b
		phoneKey, pcKey, rootKey := KeyHashOf(phone.Cert), KeyHashOf(pc.Cert), KeyHashOf(g)
		own := newRoot(t)
		recs := []Record{
			adminRecord(t, g, pg.root, nil, member(t, phone), "phone", phoneKey),
			computerAdminRecord(t, pg, member(t, pc), "pc", pcKey),
			revokeRecord(t, g, pg.root, nil, []KeyHash{phoneKey}, nil),
			rootRecord(t, g, phone, []*x509.Certificate{phone.Cert}, own.Cert),
			revokeRecord(t, g, own, nil, []KeyHash{rootKey, pcKey}, nil),
		}
		s := NewRecords(g)
		s.AddAll(recs)
		v := removedVectors{GroupCA: g.Raw, Records: recs, Roots: len(s.Roots())}
		for _, k := range []struct {
			name string
			key  KeyHash
		}{{"the removed admin phone", phoneKey}, {"the computer admin", pcKey}, {"the root", rootKey}} {
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
	var v removedVectors
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(v.GroupCA)
	if err != nil {
		t.Fatal(err)
	}
	if v.Roots != 0 || !v.Keys[0].Revoked || v.Keys[1].Revoked || v.Keys[2].Revoked {
		t.Fatalf("the vectors say %d roots, revoked %v", v.Roots, v.Keys)
	}
	reversed := slices.Clone(v.Records)
	slices.Reverse(reversed)
	for name, recs := range map[string][]Record{"as written": v.Records, "reversed": reversed} {
		s := NewRecords(ca)
		for _, r := range recs {
			s.Add(r)
		}
		if got := len(s.Roots()); got != v.Roots {
			t.Errorf("%s: %d roots, want %d", name, got, v.Roots)
		}
		for _, k := range v.Keys {
			if s.Revoked(k.Key) != k.Revoked {
				t.Errorf("%s: %s revoked %v, want %v", name, k.Name, s.Revoked(k.Key), k.Revoked)
			}
		}
	}
}
