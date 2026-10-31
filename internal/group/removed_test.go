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

type removedCase struct {
	Name string `json:"name"`
	removedVectors
}

// An admin phone that is removed by the current root after a handover, or
// by another admin phone, signs a root record afterwards, for a root of its
// own, whose key then revokes the group's roots and admins: that root is
// not known either, so none of it counts, in any order.
//
// TestRemovedAdminCases writes (with -update) and checks
// testdata/interop/go-removed-admins.json for the other implementations.
func TestRemovedAdminCases(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "interop", "go-removed-admins.json")
	if *update {
		var cases []removedCase
		add := func(name string, g *x509.Certificate, recs []Record, keys map[string]KeyHash, order []string) {
			s := NewRecords(g)
			s.AddAll(recs)
			c := removedCase{Name: name, removedVectors: removedVectors{GroupCA: g.Raw, Records: recs, Roots: len(s.Roots())}}
			for _, n := range order {
				c.Keys = append(c.Keys, adminKey{Name: n, Key: keys[n], Revoked: s.Revoked(keys[n])})
			}
			cases = append(cases, c)
		}
		{
			pg := newPhoneGroup(t)
			g := pg.root.Cert
			phone := pg.a
			next, own := newRoot(t), newRoot(t)
			phoneKey, rootKey, nextKey := KeyHashOf(phone.Cert), KeyHashOf(g), KeyHashOf(next.Cert)
			add("removed by the current root after a handover", g, []Record{
				adminRecord(t, g, pg.root, nil, member(t, phone), "phone", phoneKey),
				rootRecord(t, g, pg.root, nil, next.Cert),
				revokeRecord(t, g, next, nil, []KeyHash{phoneKey}, nil),
				rootRecord(t, g, phone, []*x509.Certificate{phone.Cert}, own.Cert),
				revokeRecord(t, g, own, nil, []KeyHash{rootKey, nextKey}, nil),
			}, map[string]KeyHash{"the removed admin phone": phoneKey, "the first root": rootKey, "the current root": nextKey},
				[]string{"the removed admin phone", "the first root", "the current root"})
		}
		{
			pg := newPhoneGroup(t)
			g := pg.root.Cert
			a, b := pg.a, pg.b
			own := newRoot(t)
			aKey, bKey, rootKey := KeyHashOf(a.Cert), KeyHashOf(b.Cert), KeyHashOf(g)
			add("removed by another admin phone", g, []Record{
				adminRecord(t, g, pg.root, nil, member(t, a), "phone a", aKey),
				adminRecord(t, g, pg.root, nil, member(t, b), "phone b", bKey),
				revokeRecord(t, g, a, []*x509.Certificate{a.Cert}, []KeyHash{bKey}, nil),
				rootRecord(t, g, b, []*x509.Certificate{b.Cert}, own.Cert),
				revokeRecord(t, g, own, nil, []KeyHash{rootKey, aKey}, nil),
			}, map[string]KeyHash{"the removed admin phone": bKey, "the other admin phone": aKey, "the root": rootKey},
				[]string{"the removed admin phone", "the other admin phone", "the root"})
		}
		data, err := json.MarshalIndent(cases, "", "\t")
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
	var cases []removedCase
	if err := json.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}
	want := map[string]int{"removed by the current root after a handover": 1, "removed by another admin phone": 0}
	if len(cases) != len(want) {
		t.Fatalf("%d cases, want %d", len(cases), len(want))
	}
	for _, c := range cases {
		if c.Roots != want[c.Name] || !c.Keys[0].Revoked || c.Keys[1].Revoked || c.Keys[2].Revoked {
			t.Fatalf("%s: the vectors say %d roots, revoked %v", c.Name, c.Roots, c.Keys)
		}
		ca, err := x509.ParseCertificate(c.GroupCA)
		if err != nil {
			t.Fatal(err)
		}
		reversed := slices.Clone(c.Records)
		slices.Reverse(reversed)
		for order, recs := range map[string][]Record{"as written": c.Records, "reversed": reversed} {
			// One batch: a record signed under the current root is taken
			// together with the handover that makes it known.
			s := NewRecords(ca)
			s.AddAll(recs)
			if got := len(s.Roots()); got != c.Roots {
				t.Errorf("%s, %s: %d roots, want %d", c.Name, order, got, c.Roots)
			}
			for _, k := range c.Keys {
				if s.Revoked(k.Key) != k.Revoked {
					t.Errorf("%s, %s: %s revoked %v, want %v", c.Name, order, k.Name, s.Revoked(k.Key), k.Revoked)
				}
			}
		}
	}
}
