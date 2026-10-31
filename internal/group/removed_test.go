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
// not known either, so none of it counts, in any order. A root that an
// admin phone hands on counts only when no root that may count removes that
// phone; where two such roots would remove each other's phones, neither
// counts and both phones are removed.
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
		{
			// B takes the group over by a root record of its own, as a
			// phone does when the root phone is lost, and the new root
			// removes A; A's root then revokes everything. Each new root
			// would remove the other phone: neither counts, and both
			// phones are removed.
			pg := newPhoneGroup(t)
			g := pg.root.Cert
			a, b := pg.a, pg.b
			next, own := newRoot(t), newRoot(t)
			aKey, bKey, rootKey, nextKey := KeyHashOf(a.Cert), KeyHashOf(b.Cert), KeyHashOf(g), KeyHashOf(next.Cert)
			add("taken over by an admin phone, each new root removing the other phone", g, []Record{
				adminRecord(t, g, pg.root, nil, member(t, a), "phone a", aKey),
				adminRecord(t, g, pg.root, nil, member(t, b), "phone b", bKey),
				rootRecord(t, g, b, []*x509.Certificate{b.Cert}, next.Cert),
				revokeRecord(t, g, next, nil, []KeyHash{rootKey, aKey}, []KeyHash{bKey}),
				rootRecord(t, g, a, []*x509.Certificate{a.Cert}, own.Cert),
				revokeRecord(t, g, own, nil, []KeyHash{rootKey, nextKey, bKey}, nil),
			}, map[string]KeyHash{"phone a": aKey, "phone b": bKey, "the first root": rootKey, "the new root": nextKey},
				[]string{"phone a", "phone b", "the first root", "the new root"})
		}
		{
			// The same takeover, but A's root does not remove B: B's root
			// counts, A is removed, and A's root does not count.
			pg := newPhoneGroup(t)
			g := pg.root.Cert
			a, b := pg.a, pg.b
			next, own := newRoot(t), newRoot(t)
			aKey, bKey, rootKey, nextKey := KeyHashOf(a.Cert), KeyHashOf(b.Cert), KeyHashOf(g), KeyHashOf(next.Cert)
			add("taken over by an admin phone, whose new root removes the other", g, []Record{
				adminRecord(t, g, pg.root, nil, member(t, a), "phone a", aKey),
				adminRecord(t, g, pg.root, nil, member(t, b), "phone b", bKey),
				rootRecord(t, g, b, []*x509.Certificate{b.Cert}, next.Cert),
				revokeRecord(t, g, next, nil, []KeyHash{rootKey, aKey}, []KeyHash{bKey}),
				rootRecord(t, g, a, []*x509.Certificate{a.Cert}, own.Cert),
				revokeRecord(t, g, own, nil, []KeyHash{nextKey}, nil),
			}, map[string]KeyHash{"phone a": aKey, "phone b": bKey, "the first root": rootKey, "the new root": nextKey},
				[]string{"phone a", "phone b", "the first root", "the new root"})
		}
		{
			// Two admin phones remove each other and each hands the group
			// to a root of its own: both are removed, and neither root
			// counts.
			pg := newPhoneGroup(t)
			g := pg.root.Cert
			a, b := pg.a, pg.b
			ownA, ownB := newRoot(t), newRoot(t)
			aKey, bKey, rootKey := KeyHashOf(a.Cert), KeyHashOf(b.Cert), KeyHashOf(g)
			add("two admin phones removing each other", g, []Record{
				adminRecord(t, g, pg.root, nil, member(t, a), "phone a", aKey),
				adminRecord(t, g, pg.root, nil, member(t, b), "phone b", bKey),
				revokeRecord(t, g, a, []*x509.Certificate{a.Cert}, []KeyHash{bKey}, nil),
				revokeRecord(t, g, b, []*x509.Certificate{b.Cert}, []KeyHash{aKey}, nil),
				rootRecord(t, g, a, []*x509.Certificate{a.Cert}, ownA.Cert),
				rootRecord(t, g, b, []*x509.Certificate{b.Cert}, ownB.Cert),
				revokeRecord(t, g, ownA, nil, []KeyHash{rootKey}, nil),
			}, map[string]KeyHash{"phone a": aKey, "phone b": bKey, "the root": rootKey},
				[]string{"phone a", "phone b", "the root"})
		}
		{
			// The new root is handed on both by the root's own key and by
			// phone B; it removes A, whose root removes B: the root's own
			// handover stands, so A is removed and B is not.
			pg := newPhoneGroup(t)
			g := pg.root.Cert
			a, b := pg.a, pg.b
			next, own := newRoot(t), newRoot(t)
			aKey, bKey, rootKey, nextKey := KeyHashOf(a.Cert), KeyHashOf(b.Cert), KeyHashOf(g), KeyHashOf(next.Cert)
			add("a new root handed on two ways", g, []Record{
				adminRecord(t, g, pg.root, nil, member(t, a), "phone a", aKey),
				adminRecord(t, g, pg.root, nil, member(t, b), "phone b", bKey),
				rootRecord(t, g, pg.root, nil, next.Cert),
				rootRecord(t, g, b, []*x509.Certificate{b.Cert}, next.Cert),
				revokeRecord(t, g, next, nil, []KeyHash{aKey}, nil),
				rootRecord(t, g, a, []*x509.Certificate{a.Cert}, own.Cert),
				revokeRecord(t, g, own, nil, []KeyHash{rootKey, nextKey, bKey}, nil),
			}, map[string]KeyHash{"phone a": aKey, "phone b": bKey, "the first root": rootKey, "the new root": nextKey},
				[]string{"phone a", "phone b", "the first root", "the new root"})
		}
		{
			// Three roots: the first hands on to the second by its own
			// key, the second's admin phone C to the third, and the third
			// removes A, whose root revokes the three roots: A is removed
			// and the roots stand.
			pg := newPhoneGroup(t)
			g := pg.root.Cert
			a := pg.a
			second, third, own := newRoot(t), newRoot(t), newRoot(t)
			c := adminCA(t, second)
			aKey, cKey, rootKey, secondKey, thirdKey := KeyHashOf(a.Cert), KeyHashOf(c.Cert), KeyHashOf(g), KeyHashOf(second.Cert), KeyHashOf(third.Cert)
			add("a chain of three roots, the last removing a phone", g, []Record{
				adminRecord(t, g, pg.root, nil, member(t, a), "phone a", aKey),
				rootRecord(t, g, pg.root, nil, second.Cert),
				adminRecord(t, g, second, nil, member(t, c), "phone c", cKey),
				rootRecord(t, g, c, []*x509.Certificate{c.Cert}, third.Cert),
				revokeRecord(t, g, third, nil, []KeyHash{aKey}, nil),
				rootRecord(t, g, a, []*x509.Certificate{a.Cert}, own.Cert),
				revokeRecord(t, g, own, nil, []KeyHash{rootKey, secondKey, thirdKey}, nil),
			}, map[string]KeyHash{"phone a": aKey, "phone c": cKey, "the first root": rootKey, "the second root": secondKey, "the third root": thirdKey},
				[]string{"phone a", "phone c", "the first root", "the second root", "the third root"})
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
	// What each case must say: the roots, and which keys are revoked.
	want := map[string]struct {
		roots   int
		revoked []bool
	}{
		"removed by the current root after a handover":                         {1, []bool{true, false, false}},
		"removed by another admin phone":                                       {0, []bool{true, false, false}},
		"taken over by an admin phone, each new root removing the other phone": {0, []bool{true, true, false, false}},
		"taken over by an admin phone, whose new root removes the other":       {1, []bool{true, false, true, false}},
		"two admin phones removing each other":                                 {0, []bool{true, true, false}},
		"a new root handed on two ways":                                        {1, []bool{true, false, false, false}},
		"a chain of three roots, the last removing a phone":                    {2, []bool{true, false, false, false, false}},
	}
	if len(cases) != len(want) {
		t.Fatalf("%d cases, want %d", len(cases), len(want))
	}
	for _, c := range cases {
		w, ok := want[c.Name]
		if !ok || c.Roots != w.roots || len(c.Keys) != len(w.revoked) {
			t.Fatalf("%s: the vectors say %d roots, revoked %v", c.Name, c.Roots, c.Keys)
		}
		for i, k := range c.Keys {
			if k.Revoked != w.revoked[i] {
				t.Fatalf("%s: the vectors say %s revoked %v", c.Name, k.Name, k.Revoked)
			}
		}
		ca, err := x509.ParseCertificate(c.GroupCA)
		if err != nil {
			t.Fatal(err)
		}
		// Every order, in one batch: a record signed under a new root is
		// taken together with the handover that makes it known.
		permute(len(c.Records), func(order []int) {
			if t.Failed() {
				return
			}
			recs := make([]Record, len(order))
			for i, j := range order {
				recs[i] = c.Records[j]
			}
			s := NewRecords(ca)
			s.AddAll(recs)
			if got := len(s.Roots()); got != c.Roots {
				t.Errorf("%s, order %v: %d roots, want %d", c.Name, order, got, c.Roots)
			}
			for _, k := range c.Keys {
				if s.Revoked(k.Key) != k.Revoked {
					t.Errorf("%s, order %v: %s revoked %v, want %v", c.Name, order, k.Name, s.Revoked(k.Key), k.Revoked)
				}
			}
		})
		if t.Failed() {
			return
		}
	}
}

// permute calls f with every order of 0..n-1 (Heap's algorithm).
func permute(n int, f func([]int)) {
	p := make([]int, n)
	for i := range p {
		p[i] = i
	}
	c := make([]int, n)
	f(p)
	for i := 0; i < n; {
		if c[i] < i {
			if i%2 == 0 {
				p[0], p[i] = p[i], p[0]
			} else {
				p[c[i]], p[i] = p[i], p[c[i]]
			}
			f(p)
			c[i]++
			i = 0
		} else {
			c[i] = 0
			i++
		}
	}
}
