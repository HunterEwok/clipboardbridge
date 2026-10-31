// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package authority_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"maps"
	"math/rand/v2"
	"sort"
	"testing"
	"time"

	"github.com/HunterEwok/clipboardbridge/internal/authority"
	"github.com/HunterEwok/clipboardbridge/internal/group"
)

// world builds a record set the way devices sign it: each signer numbers
// its records and, unless told otherwise, has seen everything signed so
// far.
type world struct {
	t       *testing.T
	roots   map[string]*group.CA
	keys    map[string]*ecdsa.PrivateKey      // admin keys
	cas     map[string]*x509.Certificate      // admin CAs, by admin name
	members map[string]authority.Hash         // member key hashes, by device name
	ids     map[string]string                 // device IDs, by device name
	seq     map[authority.Hash]int64          // each signer's last seq
	last    map[authority.Hash]authority.Hash // each signer's last record ID
	recs    []authority.Record
	byName  map[string]authority.Record
	now     int64
	seen    map[authority.Hash]int64
}

var phonePowers = authority.Powers

var computerPowers = []string{authority.PowerAdmit, authority.PowerFreeze, authority.PowerHub, authority.PowerRemove, authority.PowerRenew}

func newWorld(t *testing.T) *world {
	t.Helper()
	root, err := group.NewRootCA(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	w := &world{t: t, roots: map[string]*group.CA{"root": root}, keys: map[string]*ecdsa.PrivateKey{}, cas: map[string]*x509.Certificate{},
		members: map[string]authority.Hash{}, ids: map[string]string{}, seq: map[authority.Hash]int64{}, last: map[authority.Hash]authority.Hash{},
		byName: map[string]authority.Record{}, seen: map[authority.Hash]int64{}}
	w.device("root", "rootphone", "phone", nil, nil, true)
	return w
}

func (w *world) signerHash(signer string) authority.Hash {
	if r := w.roots[signer]; r != nil {
		return authority.KeyHashOf(r.Cert)
	}
	return hashOf(w.t, &w.keys[signer].PublicKey)
}

// sign signs b as signer (a root's name or an admin's) and keeps it under
// name. seen, when not nil, replaces the seen of everything signed so far.
func (w *world) sign(name, signer string, b authority.Body, seen []authority.Seen) authority.Record {
	w.t.Helper()
	h := w.signerHash(signer)
	b.Group, b.TimeMS = tag, 1
	b.Seq = w.seq[h] + 1
	if b.Seq > 1 {
		p := w.last[h]
		b.Prev = &p
	}
	if b.Type == authority.TypeRevoke || b.Type == authority.TypeFreeze || b.Type == authority.TypeClaim {
		if seen == nil {
			for k, n := range w.seq {
				seen = append(seen, authority.Seen{Key: k, Seq: n})
			}
		}
		b.Seen = seen
	}
	var key crypto.Signer
	var ca *x509.Certificate
	if r := w.roots[signer]; r != nil {
		key = r.Key
	} else {
		key, ca = w.keys[signer], w.cas[signer]
	}
	r, err := authority.Sign(b, key, ca)
	if err != nil {
		w.t.Fatalf("%s: %v", name, err)
	}
	w.seq[h], w.last[h] = b.Seq, r.ID()
	w.recs = append(w.recs, r)
	w.byName[name] = r
	return r
}

// admin makes an admin key and its admin CA under root.
func (w *world) admin(name, root string) {
	k, ok := w.keys[name]
	if !ok {
		k = newKey(w.t)
		w.keys[name] = k
	}
	id, ok := w.ids[name]
	if !ok {
		id = string(group.NewDeviceID())
		w.ids[name] = id
	}
	ca, err := w.roots[root].IssueAdmin(group.DeviceID(id), &k.PublicKey, time.Now())
	if err != nil {
		w.t.Fatal(err)
	}
	w.cas[name] = ca
}

// device signs a device record for device name by signer; with powers it
// makes name an admin (the admin key made by admin()).
func (w *world) device(signer, name, role string, powers, commands []string, holdsRoot bool) authority.Record {
	if _, ok := w.members[name]; !ok {
		w.members[name] = hashOf(w.t, &newKey(w.t).PublicKey)
	}
	if _, ok := w.ids[name]; !ok {
		w.ids[name] = string(group.NewDeviceID())
	}
	k := w.members[name]
	b := authority.Body{Type: authority.TypeDevice, Device: w.ids[name], Name: name, Role: role, Key: &k, HoldsRoot: holdsRoot}
	if powers != nil {
		a := hashOf(w.t, &w.keys[name].PublicKey)
		b.Admin, b.Powers, b.Commands = &a, powers, commands
	}
	return w.sign("device "+name+" by "+signer, signer, b, nil)
}

func (w *world) makeAdmin(name, role string, powers []string) {
	w.admin(name, "root")
	w.device("root", name, role, powers, authority.Commands, false)
}

func (w *world) adminKey(name string) authority.Hash { return hashOf(w.t, &w.keys[name].PublicKey) }

func (w *world) eval(recs []authority.Record, firstSeen map[authority.Hash]int64) *authority.State {
	w.t.Helper()
	s, err := authority.Evaluate(authority.Input{GroupCA: w.roots["root"].Cert, Group: tag, Records: recs, NowMS: w.now, FirstSeen: firstSeen})
	if err != nil {
		w.t.Fatal(err)
	}
	return s
}

// evalAll evaluates the world's records in many orders and checks that
// every order gives the same bytes.
func (w *world) evalAll(firstSeen map[authority.Hash]int64) *authority.State {
	w.t.Helper()
	want := w.eval(w.recs, firstSeen)
	wb, _ := want.Encode()
	w.collect(firstSeen, wb)
	rng := rand.New(rand.NewPCG(1, 2))
	for i := 0; i < 24; i++ {
		rs := append([]authority.Record(nil), w.recs...)
		rng.Shuffle(len(rs), func(i, j int) { rs[i], rs[j] = rs[j], rs[i] })
		if gb, _ := w.eval(rs, firstSeen).Encode(); string(gb) != string(wb) {
			w.t.Fatalf("order %d gives another state:\n%s\nwant\n%s", i, gb, wb)
		}
	}
	return want
}

func findDevice(s *authority.State, id string) *authority.Device {
	for i := range s.Devices {
		if s.Devices[i].Device == id {
			return &s.Devices[i]
		}
	}
	return nil
}

func revoked(s *authority.State, k authority.Hash) bool {
	for _, r := range s.Revoked {
		if r == k {
			return true
		}
	}
	return false
}

func revoke(keys ...authority.Hash) authority.Body {
	return authority.Body{Type: authority.TypeRevoke, Keys: keys}
}

func TestEvaluateBasic(t *testing.T) {
	w := newWorld(t)
	w.makeAdmin("A", "phone", phonePowers)
	w.makeAdmin("C", "full", computerPowers)
	w.device("C", "laptop", "full", nil, nil, false)
	s := w.evalAll(nil)
	if s.Stop != "none" || s.RootDevice != w.ids["rootphone"] || len(s.Roots) != 1 {
		t.Fatalf("state %+v", s)
	}
	if d := findDevice(s, w.ids["A"]); d == nil || d.Admin == nil || len(d.Powers) != 8 {
		t.Errorf("A is not an admin phone: %+v", d)
	}
	if d := findDevice(s, w.ids["laptop"]); d == nil || d.Admin != nil {
		t.Errorf("the laptop C admitted is missing: %+v", d)
	}
}

func TestRootRemovalCutsAdmin(t *testing.T) {
	w := newWorld(t)
	w.makeAdmin("C", "full", computerPowers)
	w.device("C", "before", "full", nil, nil, false)
	w.sign("remove C", "root", revoke(w.adminKey("C"), w.members["C"]), nil)
	w.device("C", "after", "full", nil, nil, false)
	s := w.evalAll(nil)
	if findDevice(s, w.ids["before"]) == nil {
		t.Error("the device C admitted before its removal is gone")
	}
	if findDevice(s, w.ids["after"]) != nil {
		t.Error("the device C admitted after its removal counts")
	}
	if d := findDevice(s, w.ids["C"]); d != nil {
		t.Errorf("C is still listed: %+v", d)
	}
}

func TestAdminRemovalsInOrder(t *testing.T) {
	w := newWorld(t)
	w.makeAdmin("A", "phone", phonePowers)
	w.makeAdmin("B", "phone", phonePowers)
	w.sign("A removes B", "A", revoke(w.adminKey("B")), nil)
	// B signs after holding A's removal of it: it was removed already.
	w.sign("B removes A", "B", revoke(w.adminKey("A")), nil)
	s := w.evalAll(nil)
	if s.Stop != "none" || !revoked(s, w.adminKey("B")) || revoked(s, w.adminKey("A")) {
		t.Fatalf("A should win: %s", mustEncode(t, s))
	}
}

func TestAdminRemovalsCross(t *testing.T) {
	w := newWorld(t)
	w.makeAdmin("A", "phone", phonePowers)
	w.makeAdmin("B", "phone", phonePowers)
	before := w.snapshot()
	w.sign("A removes B", "A", revoke(w.adminKey("B")), before)
	w.sign("B removes A", "B", revoke(w.adminKey("A")), before)
	s := w.evalAll(nil)
	if s.Stop != "full" || len(s.Conflicts) != 1 || s.Conflicts[0].Kind != "admins" {
		t.Fatalf("crossing removals should stop the group: %s", mustEncode(t, s))
	}
	if revoked(s, w.adminKey("A")) || revoked(s, w.adminKey("B")) {
		t.Error("a removal in conflict counts")
	}
	// The root voids B's removal: A's counts, the group goes on.
	w.sign("resolve", "root", authority.Body{Type: authority.TypeResolve, Records: []authority.Hash{w.byName["B removes A"].ID()}}, nil)
	s = w.evalAll(nil)
	if s.Stop != "none" || !revoked(s, w.adminKey("B")) || revoked(s, w.adminKey("A")) {
		t.Fatalf("after the root's resolve A should win: %s", mustEncode(t, s))
	}
}

// claimState returns the state of claim id.
func claimState(s *authority.State, id authority.Hash) string {
	for _, c := range s.Claims {
		if c.Record == id {
			return c.State
		}
	}
	return ""
}

// fork returns a copy of w that signs on its own.
func (w *world) fork() *world {
	c := *w
	c.recs = append([]authority.Record(nil), w.recs...)
	c.roots, c.seq, c.last, c.byName = maps.Clone(w.roots), maps.Clone(w.seq), maps.Clone(w.last), maps.Clone(w.byName)
	return &c
}

// without returns the seen of everything signed so far except the
// records of one signer, by name or hash.
func (w *world) without(signer any) []authority.Seen {
	h, ok := signer.(authority.Hash)
	if !ok {
		h = w.signerHash(signer.(string))
	}
	var seen []authority.Seen
	for _, s := range w.snapshot() {
		if s.Key != h {
			seen = append(seen, s)
		}
	}
	return seen
}

// snapshot returns the seen of everything signed so far.
func (w *world) snapshot() []authority.Seen {
	var seen []authority.Seen
	for k, n := range w.seq {
		seen = append(seen, authority.Seen{Key: k, Seq: n})
	}
	return seen
}

func mustEncode(t *testing.T, s *authority.State) string {
	b, err := s.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// claim signs a claim by admin name for a new root newRoot.
func (w *world) claim(name, newRoot string, seen []authority.Seen) authority.Record {
	r, err := group.NewRootCA(time.Now())
	if err != nil {
		w.t.Fatal(err)
	}
	w.roots[newRoot] = r
	return w.sign("claim "+name, name, authority.Body{Type: authority.TypeClaim, Root: r.Cert.Raw}, seen)
}

func TestClaimWaitsAndTakesEffect(t *testing.T) {
	w := newWorld(t)
	w.makeAdmin("B", "phone", phonePowers)
	c := w.claim("B", "R2", nil)
	first := map[authority.Hash]int64{c.ID(): 0}
	w.now = authority.DefaultDelay - 1
	s := w.evalAll(first)
	if len(s.Roots) != 1 || len(s.Claims) != 1 || s.Claims[0].State != "pending" || s.Claims[0].LeftMS != 1 {
		t.Fatalf("the claim should be pending: %s", mustEncode(t, s))
	}
	if len(s.NoSecretsTo) != 1 || s.NoSecretsTo[0] != w.ids["B"] {
		t.Errorf("the claimant gets secrets: %v", s.NoSecretsTo)
	}
	w.now = authority.DefaultDelay
	s = w.evalAll(first)
	if len(s.Roots) != 2 || s.Claims[0].State != "effective" {
		t.Fatalf("the claim should take effect: %s", mustEncode(t, s))
	}
	// The root comes back and cancels it: the group is the old root's.
	w.sign("cancel", "root", authority.Body{Type: authority.TypeResolve, Records: []authority.Hash{c.ID()}}, nil)
	s = w.evalAll(first)
	if len(s.Roots) != 1 || s.Claims[0].State != "cancelled" {
		t.Fatalf("the root's cancel should win after the delay: %s", mustEncode(t, s))
	}
}

func TestSettingsDelay(t *testing.T) {
	w := newWorld(t)
	w.sign("settings", "root", authority.Body{Type: authority.TypeSettings, TakeoverDelayMS: ptr(int64(0))}, nil)
	w.makeAdmin("B", "phone", phonePowers)
	w.claim("B", "R2", nil)
	if s := w.evalAll(nil); len(s.Roots) != 2 {
		t.Fatalf("a delay of 0 should take the claim at once: %s", mustEncode(t, s))
	}
}

func TestTwoClaimsStop(t *testing.T) {
	w := newWorld(t)
	w.makeAdmin("A", "phone", phonePowers)
	w.makeAdmin("B", "phone", phonePowers)
	w.claim("A", "Q", nil)
	w.claim("B", "R2", w.without("A"))
	w.now = authority.DefaultDelay * 2
	s := w.evalAll(nil)
	if s.Stop != "full" || len(s.Roots) != 1 {
		t.Fatalf("two claims should stop the group: %s", mustEncode(t, s))
	}
	for _, c := range s.Claims {
		if c.State != "competing" {
			t.Errorf("claim %v is %s", c.Record, c.State)
		}
	}
}

// TestRemovedPhoneCannotTakeBack plays the scenarios of the second
// verification of version 1 (X1 and X2): after B's claim took effect and
// its new root removed A, A removes B with its old admin CA and claims the
// group for its own root. A removal under the old root's admin CA disputes
// the claim whatever its author had seen, so the group stops: A does not
// get it (the residual of every rule without the root: a stolen admin key
// can stop a group whose root is lost, never take it).
func TestRemovedPhoneCannotTakeBack(t *testing.T) {
	w := newWorld(t)
	w.makeAdmin("A", "phone", phonePowers)
	w.makeAdmin("B", "phone", phonePowers)
	c := w.claim("B", "R2", nil)
	w.now = authority.DefaultDelay
	first := map[authority.Hash]int64{c.ID(): 0}
	// As the new root: B's own device, B an admin again, A removed.
	w.device("R2", "B", "phone", nil, nil, true)
	w.sign("R2 removes A", "R2", revoke(w.adminKey("A"), w.members["A"]), nil)
	s := w.evalAll(first)
	if len(s.Roots) != 2 || s.Roots[1] != authority.KeyHashOf(w.roots["R2"].Cert) || s.Stop != "none" {
		t.Fatalf("the group should be R2's: %s", mustEncode(t, s))
	}
	if !revoked(s, w.adminKey("A")) || s.RootDevice != w.ids["B"] {
		t.Fatalf("A should be removed and B hold the root: %s", mustEncode(t, s))
	}
	// A, removed, removes B and claims the group with its old admin CA.
	w2 := w.fork()
	w2.sign("A removes B", "A", revoke(w.adminKey("B"), w.members["B"]), nil)
	q := w2.claim("A", "Q", nil)
	first[q.ID()] = 0
	w2.now = authority.DefaultDelay * 3
	s = w2.evalAll(first)
	if s.Stop != "full" || len(s.Roots) != 1 || claimState(s, c.ID()) != "disputed" {
		t.Fatalf("A's removal should stop the group: %s", mustEncode(t, s))
	}
	// A claim that pretends it never saw B's claim competes with it: the
	// group stops, and A still does not get it.
	w3 := w.fork()
	p := w3.claim("A", "P", []authority.Seen{{Key: w.adminKey("A"), Seq: 1}})
	first[p.ID()] = 0
	if s := w3.evalAll(first); s.Stop != "full" || len(s.Roots) != 1 {
		t.Fatalf("a pretended claim should stop the group: %s", mustEncode(t, s))
	}
}

// TestClaimedRootSignsEarly is a thief whose claimed root signs while its
// claim waits: an admin who holds that record and removes the claimant
// still disputes the claim.
func TestClaimedRootSignsEarly(t *testing.T) {
	w := newWorld(t)
	w.makeAdmin("T", "phone", phonePowers)
	w.makeAdmin("H", "phone", phonePowers)
	c := w.claim("H", "M", nil)
	w.device("M", "H", "phone", nil, nil, true)
	w.sign("T removes H", "T", revoke(w.adminKey("H"), w.members["H"]), nil)
	first := map[authority.Hash]int64{c.ID(): 0}
	w.now = authority.DefaultDelay * 2
	s := w.evalAll(first)
	if s.Stop != "full" || len(s.Roots) != 1 || claimState(s, c.ID()) != "disputed" {
		t.Fatalf("the removal should dispute the claim: %s", mustEncode(t, s))
	}
}

// TestNewerVersion is a record of a later version: the state lists it for
// the user to update when a current root or admin signed it, applies
// nothing of it, and goes on.
func TestNewerVersion(t *testing.T) {
	w := newWorld(t)
	w.makeAdmin("A", "phone", phonePowers)
	w.makeAdmin("B", "phone", phonePowers)
	w.sign("remove B", "root", revoke(w.adminKey("B")), nil)
	before := mustEncode(t, w.evalAll(nil))
	body := func(signer authority.Hash, group string) []byte {
		return []byte(`{"group":"` + group + `","signer":"` + signer.String() + `","type":"keys","v":3}`)
	}
	sign := func(b []byte, key crypto.Signer, chain ...[]byte) authority.Record {
		d := sha256.Sum256(b)
		sig, err := key.Sign(crand.Reader, d[:], crypto.SHA256)
		if err != nil {
			t.Fatal(err)
		}
		return authority.Record{Body: b, Sig: sig, Chain: chain}
	}
	root := w.signerHash("root")
	byRoot := sign(body(root, tag), w.roots["root"].Key)
	byAdmin := sign(body(w.adminKey("A"), tag), w.keys["A"], w.cas["A"].Raw)
	stranger, err := ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	h, err := authority.PublicKeyHash(&stranger.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	w.recs = append(w.recs, byRoot, byAdmin,
		sign(body(root, "fedcba9876543210"), w.roots["root"].Key),                        // another group
		authority.Record{Body: body(root, tag), Sig: []byte{1}},                          // no signature
		sign(body(h, tag), stranger),                                                     // not a key of the group
		sign(body(w.adminKey("B"), tag), w.keys["B"], w.cas["B"].Raw),                    // a removed admin
		authority.Record{Body: []byte(`{"v":3, "group":"` + tag + `"}`), Sig: []byte{1}}, // not canonical
	)
	s := w.evalAll(nil)
	want := []authority.Hash{byRoot.ID(), byAdmin.ID()}
	sort.Slice(want, func(i, j int) bool { return want[i].String() < want[j].String() })
	if len(s.Newer) != 2 || s.Newer[0] != want[0] || s.Newer[1] != want[1] || s.Stop != "none" {
		t.Fatalf("the state should list the two signed records of version 3: %s", mustEncode(t, s))
	}
	s.Newer = nil
	if got := mustEncode(t, s); got != before {
		t.Fatalf("a record of a later version changed the state:\n got %s\nwant %s", got, before)
	}
}

// TestClaimDisputed is an admin removing a claimant while its claim
// waits: the group stops until the root decides.
func TestClaimDisputed(t *testing.T) {
	w := newWorld(t)
	w.makeAdmin("A", "phone", phonePowers)
	w.makeAdmin("B", "phone", phonePowers)
	c := w.claim("B", "R2", nil)
	rm := w.sign("A removes B", "A", revoke(w.adminKey("B"), w.members["B"]), nil)
	first := map[authority.Hash]int64{c.ID(): 0}
	w.now = authority.DefaultDelay * 2
	s := w.evalAll(first)
	if s.Stop != "full" || len(s.Roots) != 1 || len(s.Claims) != 1 || s.Claims[0].State != "disputed" {
		t.Fatalf("the removal should dispute the claim: %s", mustEncode(t, s))
	}
	// The root voids the removal: the claim goes on.
	w2 := w.fork()
	w2.sign("void the removal", "root", authority.Body{Type: authority.TypeResolve, Records: []authority.Hash{rm.ID()}}, nil)
	if s := w2.evalAll(first); s.Stop != "none" || len(s.Roots) != 2 {
		t.Fatalf("after the root voids the removal the claim should take effect: %s", mustEncode(t, s))
	}
	// The root cancels the claim: A's removal stands.
	w.sign("cancel", "root", authority.Body{Type: authority.TypeResolve, Records: []authority.Hash{c.ID()}}, nil)
	if s := w.evalAll(first); s.Stop != "none" || len(s.Roots) != 1 || !revoked(s, w.adminKey("B")) {
		t.Fatalf("after the root cancels the claim A's removal should stand: %s", mustEncode(t, s))
	}
}

// TestClaimAfterRemoval is a removed admin claiming after it saw its own
// removal: the claim is void and nothing stops.
func TestClaimAfterRemoval(t *testing.T) {
	w := newWorld(t)
	w.makeAdmin("A", "phone", phonePowers)
	w.makeAdmin("B", "phone", phonePowers)
	w.sign("A removes B", "A", revoke(w.adminKey("B"), w.members["B"]), nil)
	w.claim("B", "R2", nil)
	w.now = authority.DefaultDelay * 2
	if s := w.evalAll(nil); s.Stop != "none" || len(s.Roots) != 1 || s.Claims[0].State != "void" {
		t.Fatalf("a claim after its author's removal should be void: %s", mustEncode(t, s))
	}
}

// TestPendingClaimRace is the thief acting first: while B's claim waits, A
// claims too. The group stops; it does not choose.
func TestPendingClaimRace(t *testing.T) {
	w := newWorld(t)
	w.makeAdmin("A", "phone", phonePowers)
	w.makeAdmin("B", "phone", phonePowers)
	w.claim("B", "R2", nil)
	w.claim("A", "Q", w.without("B"))
	if s := w.evalAll(nil); s.Stop != "full" || len(s.Roots) != 1 {
		t.Fatalf("two claims should stop the group: %s", mustEncode(t, s))
	}
}

func TestRemovedAdminClaimVoid(t *testing.T) {
	w := newWorld(t)
	w.makeAdmin("A", "phone", phonePowers)
	w.sign("remove A", "root", revoke(w.adminKey("A")), nil)
	w.claim("A", "Q", nil)
	w.now = authority.DefaultDelay * 2
	s := w.evalAll(nil)
	if len(s.Roots) != 1 || len(s.Claims) != 1 || s.Claims[0].State != "cancelled" {
		t.Fatalf("a removed admin's claim should not count: %s", mustEncode(t, s))
	}
}

// TestChainOfClaims hands the group over twice: the second claim is an
// admin of the second root's, under it.
func TestChainOfClaims(t *testing.T) {
	w := newWorld(t)
	w.makeAdmin("B", "phone", phonePowers)
	c1 := w.claim("B", "R2", nil)
	w.device("R2", "B", "phone", nil, nil, true)
	w.admin("C", "R2")
	w.device("R2", "C", "phone", phonePowers, authority.Commands, false)
	c2 := w.claim("C", "R3", nil)
	w.device("R3", "C", "phone", nil, nil, true)
	first := map[authority.Hash]int64{c1.ID(): 0, c2.ID(): authority.DefaultDelay}
	w.now = authority.DefaultDelay
	s := w.evalAll(first)
	if len(s.Roots) != 2 || claimState(s, c2.ID()) != "pending" || s.RootDevice != w.ids["B"] {
		t.Fatalf("the second claim should wait under the second root: %s", mustEncode(t, s))
	}
	w.now = authority.DefaultDelay * 2
	s = w.evalAll(first)
	if len(s.Roots) != 3 || claimState(s, c1.ID()) != "effective" || claimState(s, c2.ID()) != "effective" || s.RootDevice != w.ids["C"] {
		t.Fatalf("both claims should have taken effect: %s", mustEncode(t, s))
	}
}

// TestRemovedAdminDevice is a removed admin admitting a device after its
// removal: the device does not count, the ones it admitted before do.
func TestRemovedAdminDevice(t *testing.T) {
	w := newWorld(t)
	w.makeAdmin("C", "full", computerPowers)
	w.device("C", "before", "full", nil, nil, false)
	w.sign("remove C", "root", revoke(w.adminKey("C")), nil)
	w.device("C", "after", "full", nil, nil, false)
	s := w.evalAll(nil)
	if findDevice(s, w.ids["before"]) == nil || findDevice(s, w.ids["after"]) != nil || !revoked(s, w.adminKey("C")) {
		t.Fatalf("wrong devices after the removal: %s", mustEncode(t, s))
	}
}

// TestSameRecordTwoCAs is one admin body under two admin CAs of its key:
// the order of the copies does not matter.
func TestSameRecordTwoCAs(t *testing.T) {
	w := newWorld(t)
	w.makeAdmin("C", "full", computerPowers)
	r := w.device("C", "laptop", "full", nil, nil, false)
	w.admin("C", "root")
	again := r
	again.Chain = [][]byte{w.cas["C"].Raw}
	w.recs = append(w.recs, again)
	if s := w.evalAll(nil); findDevice(s, w.ids["laptop"]) == nil {
		t.Fatalf("the laptop should count: %s", mustEncode(t, s))
	}
}

func TestTwoHistories(t *testing.T) {
	w := newWorld(t)
	w.makeAdmin("C", "full", computerPowers)
	w.device("C", "early", "full", nil, nil, false)
	h := w.adminKey("C")
	seq, last := w.seq[h], w.last[h]
	w.device("C", "left", "full", nil, nil, false)
	w.seq[h], w.last[h] = seq, last
	w.device("C", "right", "full", nil, nil, false)
	s := w.evalAll(nil)
	if s.Stop != "secrets" {
		t.Fatalf("two histories of an admin should stop secrets: %s", mustEncode(t, s))
	}
	if findDevice(s, w.ids["early"]) == nil || findDevice(s, w.ids["left"]) != nil || findDevice(s, w.ids["right"]) != nil {
		t.Errorf("wrong devices: %s", mustEncode(t, s))
	}
	if len(s.NothingTo) != 3 {
		t.Errorf("the devices C alone admitted should get nothing: %v", s.NothingTo)
	}
	w.sign("void right", "root", authority.Body{Type: authority.TypeResolve, Records: []authority.Hash{w.byName["device right by C"].ID()}}, nil)
	s = w.evalAll(nil)
	if s.Stop != "none" || findDevice(s, w.ids["left"]) == nil || findDevice(s, w.ids["right"]) != nil {
		t.Fatalf("after the resolve the left branch should count: %s", mustEncode(t, s))
	}
}

func TestRootTwoHistories(t *testing.T) {
	w := newWorld(t)
	h := w.signerHash("root")
	seq, last := w.seq[h], w.last[h]
	w.device("root", "left", "full", nil, nil, false)
	w.seq[h], w.last[h] = seq, last
	w.device("root", "right", "full", nil, nil, false)
	if s := w.evalAll(nil); s.Stop != "full" {
		t.Fatalf("two histories of the root should stop the group: %s", mustEncode(t, s))
	}
	w.sign("void right", "root", authority.Body{Type: authority.TypeResolve, Records: []authority.Hash{w.byName["device right by root"].ID()}}, nil)
	if s := w.evalAll(nil); s.Stop != "none" || findDevice(s, w.ids["left"]) == nil {
		t.Fatalf("the root's resolve should end its two histories: %s", mustEncode(t, s))
	}
}

func TestFreezeAndThaw(t *testing.T) {
	w := newWorld(t)
	w.makeAdmin("A", "phone", phonePowers)
	w.makeAdmin("C", "full", computerPowers)
	w.makeAdmin("D", "full", computerPowers)
	w.sign("C freezes D", "C", authority.Body{Type: authority.TypeFreeze, Keys: []authority.Hash{w.adminKey("D")}}, nil)
	w.device("D", "late", "full", nil, nil, false)
	s := w.evalAll(nil)
	if d := findDevice(s, w.ids["D"]); d == nil || !d.Frozen || findDevice(s, w.ids["late"]) != nil {
		t.Fatalf("D should be frozen and its later record not count: %s", mustEncode(t, s))
	}
	w.sign("A thaws", "A", authority.Body{Type: authority.TypeThaw, Records: []authority.Hash{w.byName["C freezes D"].ID()}}, nil)
	s = w.evalAll(nil)
	if d := findDevice(s, w.ids["D"]); d == nil || d.Frozen || findDevice(s, w.ids["late"]) == nil {
		t.Fatalf("after the thaw D's records should count: %s", mustEncode(t, s))
	}
}

func TestFreezesCross(t *testing.T) {
	w := newWorld(t)
	w.makeAdmin("C", "full", computerPowers)
	w.makeAdmin("D", "full", computerPowers)
	before := w.snapshot()
	w.sign("C freezes D", "C", authority.Body{Type: authority.TypeFreeze, Keys: []authority.Hash{w.adminKey("D")}}, before)
	w.sign("D freezes C", "D", authority.Body{Type: authority.TypeFreeze, Keys: []authority.Hash{w.adminKey("C")}}, before)
	if s := w.evalAll(nil); s.Stop != "full" {
		t.Fatalf("crossing freezes should stop the group: %s", mustEncode(t, s))
	}
}

func TestPowers(t *testing.T) {
	w := newWorld(t)
	w.makeAdmin("A", "phone", phonePowers)
	w.makeAdmin("C", "full", computerPowers)
	w.sign("C removes A", "C", revoke(w.adminKey("A")), nil)
	w.sign("C freezes A", "C", authority.Body{Type: authority.TypeFreeze, Keys: []authority.Hash{w.adminKey("A")}}, nil)
	w.sign("C removes the root's device", "C", revoke(w.members["rootphone"]), nil)
	w.device("C", "phone2", "phone", nil, nil, false)
	w.claim("C", "Q", nil)
	w.now = authority.DefaultDelay * 2
	s := w.evalAll(nil)
	if revoked(s, w.adminKey("A")) || revoked(s, w.members["rootphone"]) || len(s.Roots) != 1 {
		t.Fatalf("a computer admin did what it may not: %s", mustEncode(t, s))
	}
	if d := findDevice(s, w.ids["A"]); d == nil || d.Frozen {
		t.Errorf("A was frozen by a computer admin: %+v", d)
	}
	if findDevice(s, w.ids["phone2"]) != nil {
		t.Error("a computer admin admitted a phone")
	}
}

// TestRandomOrder builds random sets and checks that the order never
// matters and the evaluation ends.
func TestRandomOrder(t *testing.T) {
	rng := rand.New(rand.NewPCG(7, 9))
	for trial := 0; trial < 40; trial++ {
		w := newWorld(t)
		names := []string{"A", "B", "C", "D"}
		for i, n := range names {
			if i < 2 {
				w.makeAdmin(n, "phone", phonePowers)
			} else {
				w.makeAdmin(n, "full", computerPowers)
			}
		}
		for step := 0; step < 6; step++ {
			by := names[rng.IntN(len(names))]
			target := names[rng.IntN(len(names))]
			var seen []authority.Seen
			if rng.IntN(2) == 0 {
				seen = []authority.Seen{{Key: w.adminKey(target), Seq: int64(rng.IntN(3))}}
			}
			switch rng.IntN(4) {
			case 0:
				w.sign(fmt.Sprint("r", trial, step), by, revoke(w.adminKey(target)), seen)
			case 1:
				w.sign(fmt.Sprint("f", trial, step), by, authority.Body{Type: authority.TypeFreeze, Keys: []authority.Hash{w.adminKey(target)}}, seen)
			case 2:
				w.device(by, fmt.Sprint("d", trial, step), "full", nil, nil, false)
			case 3:
				w.claim(by, fmt.Sprint("q", trial, step), seen)
			}
		}
		w.now = authority.DefaultDelay * int64(rng.IntN(3))
		w.evalAll(nil)
	}
}
