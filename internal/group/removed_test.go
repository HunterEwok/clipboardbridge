// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package group

import (
	"crypto/x509"
	"math/rand/v2"
	"runtime"
	"slices"
	"testing"
)

// An admin phone that the root removed claims the group afterwards, for a
// root of its own, whose key then revokes the group's admins: the claim
// counts for nothing, so none of it counts, in any order and after any
// delay. The cases of testdata/interop/v2-records.json about removed admins
// say the same through a Records set; the records of version 1 that
// go-removed-admin.json keeps for the phone kits are refused.
func TestRemovedAdminVectors(t *testing.T) {
	checkV2Cases(t, "removed admin's claim", "removed phone after a takeover", "claim after removal")
	checkV1Refused(t, "go-removed-admin.json")

	pg := newPhoneGroup(t)
	g := pg.root.Cert
	phone, pc := pg.a, pg.b
	phoneKey, pcKey := KeyHashOf(phone.Cert), KeyHashOf(pc.Cert)
	own := newRoot(t)
	recs := []Record{
		adminRecord(t, g, pg.root, nil, member(t, phone), "phone", phoneKey),
		computerAdminRecord(t, pg, member(t, pc), "pc", pcKey),
		revokeRecord(t, g, pg.root, nil, []KeyHash{phoneKey}),
		claimRecord(t, g, phone, []*x509.Certificate{phone.Cert}, own.Cert),
		revokeRecord(t, g, own, nil, []KeyHash{pcKey}),
	}
	orders := permute
	if !fastP256() {
		orders = someOrders
	}
	orders(len(recs), func(order []int) {
		if t.Failed() {
			return
		}
		s := NewRecords(g)
		for _, i := range order {
			s.AddAll([]Record{recs[i]})
		}
		s.AddAll(recs)
		s.SetClock(afterDelay)
		if len(s.Roots()) != 0 || !s.Revoked(phoneKey) || s.Revoked(pcKey) {
			t.Errorf("order %v: roots %d, the phone revoked %v, the computer revoked %v", order, len(s.Roots()), s.Revoked(phoneKey), s.Revoked(pcKey))
		}
	})
}

// Admins that remove each other in order or crossed, a root's removal that
// cuts an admin off, a chain of claims and two claims under one root: the
// cases of testdata/interop/v2-records.json for them through a Records set.
// The records of version 1 that go-removed-admins.json keeps for the phone
// kits are refused.
func TestRemovedAdminCases(t *testing.T) {
	checkV2Cases(t, "admin removals in order", "admin removals crossed", "root removal cuts an admin", "chain of claims", "two claims")
	checkV1Refused(t, "go-removed-admins.json")
}

// fastP256 reports whether Go's P-256 has assembly on this architecture,
// so that verifying signatures is fast.
func fastP256() bool {
	switch runtime.GOARCH {
	case "amd64", "arm64", "ppc64le", "s390x":
		return true
	}
	return false
}

// someOrders calls f with a fixed choice of orders of 0..n-1: the order
// given, reversed, each element first and each last with the rest in
// order, and 100 orders from a fixed seed.
func someOrders(n int, f func([]int)) {
	p := make([]int, n)
	for i := range p {
		p[i] = i
	}
	f(slices.Clone(p))
	rev := slices.Clone(p)
	slices.Reverse(rev)
	f(rev)
	for i := range n {
		rest := slices.Delete(slices.Clone(p), i, i+1)
		f(append([]int{i}, rest...))
		f(append(slices.Clone(rest), i))
	}
	r := rand.New(rand.NewPCG(1, 2))
	for range 100 {
		q := slices.Clone(p)
		r.Shuffle(n, func(i, j int) { q[i], q[j] = q[j], q[i] })
		f(q)
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
