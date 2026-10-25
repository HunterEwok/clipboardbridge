// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package group

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"math/rand/v2"
	"testing"
	"time"
)

func rootRecord(t *testing.T, group *x509.Certificate, signer *CA, chain []*x509.Certificate, root *x509.Certificate) Record {
	t.Helper()
	r, err := SignRecord(RecordBody{Type: RecordRoot, Group: Tag(group), TimeMS: t0.UnixMilli(), Root: root.Raw}, signer.Key, chain...)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// handover is the story of root records (docs/protocol.md, section 10): the
// root phone, which admitted a computer itself, is lost, and admin phone B
// hands the group to a new root of its own and removes the lost phone.
type handover struct {
	pg          phoneGroup // root: the lost phone's; b: phone B's admin CA
	newRoot     *CA
	lost, b     *x509.Certificate // the phones' member certificates
	byRoot      *x509.Certificate // a computer the lost phone admitted
	byB         *x509.Certificate // a computer B admitted
	before, all []Record          // the records before the handover, and all of them
}

func newHandover(t *testing.T) handover {
	t.Helper()
	pg := newPhoneGroup(t)
	h := handover{pg: pg, newRoot: newRoot(t)}
	g, bChain := pg.root.Cert, []*x509.Certificate{pg.b.Cert}
	h.lost, h.b, h.byRoot, h.byB = member(t, pg.root), member(t, pg.b), member(t, pg.root), member(t, pg.b)
	adminB := KeyHashOf(pg.b.Cert)
	h.before = []Record{
		deviceRecord(t, g, pg.root, nil, h.lost, "lost phone", 1),
		adminRecord(t, g, pg.root, nil, h.b, "phone B", adminB),
		deviceRecord(t, g, pg.root, nil, h.byRoot, "by root", 2),
		deviceRecord(t, g, pg.b, bChain, h.byB, "by B", 3),
	}
	// B signs the root record with its admin CA, then, as the new root,
	// revokes the old root and the lost phone, keeping everything else
	// the old root certified, and lists itself under the new root.
	keep := []KeyHash{KeyHashOf(h.b), adminB, KeyHashOf(h.byRoot)}
	h.all = append(append([]Record(nil), h.before...),
		rootRecord(t, g, pg.b, bChain, h.newRoot.Cert),
		revokeRecord(t, g, h.newRoot, nil, []KeyHash{KeyHashOf(pg.root.Cert), KeyHashOf(h.lost)}, keep),
		listedAgain(t, g, h.newRoot, h.b, "phone B", adminB),
	)
	return h
}

// listedAgain is the record a phone signs for itself under a new root:
// later than its first one, so that its body and ID differ.
func listedAgain(t *testing.T, group *x509.Certificate, signer *CA, cert *x509.Certificate, name string, admin KeyHash) Record {
	t.Helper()
	key := KeyHashOf(cert)
	r, err := SignRecord(RecordBody{
		Type: RecordDevice, Group: Tag(group), TimeMS: 10, By: DeviceID(cert.Subject.CommonName),
		Device: DeviceID(cert.Subject.CommonName), Name: name, Role: RolePhone, Key: &key, Admin: &admin,
	}, signer.Key)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func (h handover) records(t *testing.T) *Records {
	t.Helper()
	s := NewRecords(h.pg.root.Cert)
	if _, errs := s.AddAll(h.all); len(errs) > 0 {
		t.Fatal(errs)
	}
	return s
}

func TestRootHandover(t *testing.T) {
	h := newHandover(t)
	s := h.records(t)
	if roots := s.Roots(); len(roots) != 1 || !roots[0].Equal(h.newRoot.Cert) {
		t.Fatalf("roots %v, want the new root", roots)
	}
	if got := names(s.Devices()); got != "by B by root phone B" {
		t.Errorf("devices %q, want by B, by root, phone B", got)
	}
	if got := admins(s.Devices()); got != "phone B" {
		t.Errorf("admins %q, want phone B", got)
	}
	if s.Refused([]*x509.Certificate{h.lost}) == nil {
		t.Error("the lost phone is not refused")
	}
	fromNew := member(t, h.newRoot)
	for name, chain := range map[string][]*x509.Certificate{
		"the computer the old root admitted": {h.byRoot},
		"the computer B admitted":            {h.byB, h.pg.b.Cert},
		"phone B":                            {h.b, h.pg.b.Cert},
		"a device from the new root":         {fromNew},
	} {
		if err := s.Refused(chain); err != nil {
			t.Errorf("%s is refused: %v", name, err)
		}
	}
}

// TestRootHandoverThief checks what whoever holds the lost phone's root key
// can still do after the handover: nothing that counts.
func TestRootHandoverThief(t *testing.T) {
	h := newHandover(t)
	s := h.records(t)
	g := h.pg.root.Cert
	thiefCA := adminCA(t, h.pg.root)
	thiefChain := []*x509.Certificate{thiefCA.Cert}
	stolen, viaThiefCA := member(t, h.pg.root), member(t, thiefCA)
	for _, r := range []Record{
		deviceRecord(t, g, h.pg.root, nil, stolen, "stolen", 9),
		deviceRecord(t, g, thiefCA, thiefChain, viaThiefCA, "via thief", 9),
		rootRecord(t, g, h.pg.root, nil, newRoot(t).Cert),
		rootRecord(t, g, thiefCA, thiefChain, newRoot(t).Cert),
	} {
		mustAdd(t, s, r)
	}
	if roots := s.Roots(); len(roots) != 1 || !roots[0].Equal(h.newRoot.Cert) {
		t.Error("the thief moved the group to another root")
	}
	if got := names(s.Devices()); got != "by B by root phone B" {
		t.Errorf("devices %q after the thief's records", got)
	}
	for name, chain := range map[string][]*x509.Certificate{
		"a certificate from the old root":                      {stolen},
		"a certificate from a new admin CA under the old root": {viaThiefCA, thiefCA.Cert},
	} {
		if s.Refused(chain) == nil {
			t.Errorf("%s is not refused", name)
		}
	}
}

func TestRootRecordsOrderIndependent(t *testing.T) {
	h := newHandover(t)
	var want string
	for i := range 20 {
		rng := rand.New(rand.NewPCG(uint64(i), 2))
		rs := make([]Record, len(h.all))
		for j, k := range rng.Perm(len(h.all)) {
			rs[j] = h.all[k]
		}
		s := NewRecords(h.pg.root.Cert)
		if _, errs := s.AddAll(rs); len(errs) > 0 {
			t.Fatal(errs)
		}
		got, _ := json.Marshal(s.Devices())
		got = append(got, s.Digest()...)
		got = append(got, s.Roots()[0].Raw...)
		if i == 0 {
			want = string(got)
		} else if string(got) != want {
			t.Fatalf("order %d differs", i)
		}
	}
	// Without its root record, a record signed by the new root is not
	// valid.
	if _, err := NewRecords(h.pg.root.Cert).Add(h.all[len(h.all)-1]); err == nil {
		t.Error("accepted a record from an unknown root")
	}
}

// TestRootTieBreak checks that of two root records under the same root, the
// one whose new root has the smaller SHA-256 wins.
func TestRootTieBreak(t *testing.T) {
	pg := newPhoneGroup(t)
	g := pg.root.Cert
	x, y := newRoot(t), newRoot(t)
	s := NewRecords(g)
	// Only admin phones hand the group over; the root recorded both.
	mustAdd(t, s, adminRecord(t, g, pg.root, nil, member(t, pg.a), "phone A", KeyHashOf(pg.a.Cert)))
	mustAdd(t, s, adminRecord(t, g, pg.root, nil, member(t, pg.b), "phone B", KeyHashOf(pg.b.Cert)))
	mustAdd(t, s, rootRecord(t, g, pg.a, []*x509.Certificate{pg.a.Cert}, x.Cert))
	mustAdd(t, s, rootRecord(t, g, pg.b, []*x509.Certificate{pg.b.Cert}, y.Cert))
	want := x.Cert
	if hx, hy := sha256.Sum256(x.Cert.Raw), sha256.Sum256(y.Cert.Raw); string(hy[:]) < string(hx[:]) {
		want = y.Cert
	}
	if roots := s.Roots(); len(roots) != 1 || !roots[0].Equal(want) {
		t.Error("the root with the larger hash won")
	}
	// A root whose signer is revoked does not count.
	mustAdd(t, s, revokeRecord(t, g, pg.root, nil, []KeyHash{KeyHashOf(pg.a.Cert), KeyHashOf(pg.b.Cert)}, nil))
	if roots := s.Roots(); len(roots) != 0 {
		t.Error("a root record from a revoked admin counts")
	}
}

func TestRootRecordsRejected(t *testing.T) {
	admin := newLegacyGroup(t)
	pg := newPhoneGroup(t)
	g := pg.root.Cert
	for name, root := range map[string]*x509.Certificate{
		"an admin CA":       pg.a.Cert,
		"a member":          member(t, pg.root),
		"a legacy group CA": admin.GroupCA.Cert,
	} {
		if _, err := NewRecords(g).Add(rootRecord(t, g, pg.root, nil, root)); err == nil {
			t.Errorf("accepted %s as the new root", name)
		}
	}
}

// TestIdentityWithRoots checks a computer's identity after the handover: it
// keeps its certificate from the old root, takes a renewal from the new
// one, and talks to a member the new root admitted.
func TestIdentityWithRoots(t *testing.T) {
	h := newHandover(t)
	key, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	dev := NewDeviceID()
	cert, err := h.pg.root.IssueMember(dev, &key.PublicKey, t0)
	if err != nil {
		t.Fatal(err)
	}
	id := &Identity{ID: dev, Key: key, Cert: cert, GroupCA: CA{Cert: h.pg.root.Cert}, Roots: []*x509.Certificate{h.newRoot.Cert}}
	dir := t.TempDir()
	if err := id.Save(dir); err != nil {
		t.Fatal(err)
	}
	back, err := Load(dir)
	if err != nil || len(back.Roots) != 1 || !back.Root().Equal(h.newRoot.Cert) {
		t.Fatalf("loaded %v, error %v", back, err)
	}
	renewed, err := h.newRoot.IssueMember(dev, &key.PublicKey, t0.Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	next, err := id.WithCert(renewed.Raw)
	if err != nil {
		t.Fatalf("a renewal from the new root: %v", err)
	}
	if _, err := (&Identity{ID: dev, Key: key, Cert: cert, GroupCA: CA{Cert: h.pg.root.Cert}}).WithCert(renewed.Raw); err == nil {
		t.Error("an identity that does not know the new root took its certificate")
	}

	peerKey, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	peerDev := NewDeviceID()
	peerCert, err := h.newRoot.IssueMember(peerDev, &peerKey.PublicKey, t0)
	if err != nil {
		t.Fatal(err)
	}
	peer := &Identity{ID: peerDev, Key: peerKey, Cert: peerCert, GroupCA: CA{Cert: h.pg.root.Cert}, Roots: []*x509.Certificate{h.newRoot.Cert}}
	at := TLSOptions{Now: func() time.Time { return t0.Add(48 * time.Hour) }}
	for _, p := range [][2]*Identity{{id, peer}, {peer, next}} {
		if _, _, cerr, serr := handshake(t, p[0].ClientTLS(p[1].ID, at), p[1].ServerTLS(at)); cerr != nil || serr != nil {
			t.Fatalf("handshake: client %v, server %v", cerr, serr)
		}
	}
	bad := *id
	bad.Roots = []*x509.Certificate{h.pg.a.Cert}
	if bad.Check() == nil {
		t.Error("accepted an admin CA as a later root")
	}
}

// TestUpgradeRecords checks the root record in which a legacy group CA
// hands the group to its first root (cbb upgrade): it counts after the new
// root revokes the old key, the devices that the old key admitted stay, a
// rival root record from a leftover copy of the old key never counts, and
// a revocation of the old key under any other root breaks the handover.
func TestUpgradeRecords(t *testing.T) {
	legacy := newLegacyGroup(t)
	g := legacy.GroupCA.Cert
	m := member(t, &legacy.GroupCA)
	root := newRoot(t)
	s := NewRecords(g)
	mustAdd(t, s, deviceRecord(t, g, &legacy.GroupCA, nil, m, "m", t0.UnixMilli()))
	mustAdd(t, s, rootRecord(t, g, &legacy.GroupCA, nil, root.Cert))
	old := KeyHashOf(g)
	mustAdd(t, s, revokeRecord(t, g, root, nil, []KeyHash{old}, []KeyHash{KeyHashOf(m)}))
	if roots := s.Roots(); len(roots) != 1 || !roots[0].Equal(root.Cert) {
		t.Fatal("the upgrade's root record does not count after the old key's revocation")
	}
	if devs := s.Devices(); len(devs) != 1 || s.Refused([]*x509.Certificate{m}) != nil {
		t.Error("the device the old key admitted did not stay")
	}
	if s.Refused([]*x509.Certificate{member(t, &legacy.GroupCA)}) == nil {
		t.Error("a certificate the old key issued after the upgrade counts")
	}
	// A rival handover from a leftover copy of the old key.
	rival := newRoot(t)
	mustAdd(t, s, rootRecord(t, g, &legacy.GroupCA, nil, rival.Cert))
	if roots := s.Roots(); len(roots) != 1 || !roots[0].Equal(root.Cert) {
		t.Error("a rival root record from the old key counts")
	}
	// The old key revoking itself breaks the handover, without a new root.
	mustAdd(t, s, revokeRecord(t, g, &legacy.GroupCA, nil, []KeyHash{old}, nil))
	if roots := s.Roots(); len(roots) != 0 {
		t.Error("the handover stands after the old key revoked itself")
	}
	// Only the group CA's own key hands a legacy group over.
	if _, err := NewRecords(g).Add(rootRecord(t, g, root, nil, newRoot(t).Cert)); err == nil {
		t.Error("a root record that another key signed was taken in a legacy group")
	}
}

// TestUpgraded checks the identities around an upgrade: the key holder
// that upgrades becomes the root with a new iPhone CA and without the old
// keys, and another key holder deletes them once it follows the new root.
func TestUpgraded(t *testing.T) {
	legacy := newLegacyGroup(t)
	other := join(t, legacy, true, t0)
	root, phoneCA := newRoot(t), CA{}
	if ca, err := NewPhoneCA(t0); err != nil {
		t.Fatal(err)
	} else {
		phoneCA = *ca
	}
	up, err := legacy.Upgraded(root, []*x509.Certificate{root.Cert}, phoneCA, t0)
	if err != nil {
		t.Fatal(err)
	}
	if up.Legacy() || !up.IsRoot() || up.GroupCA.Key != nil || !up.ServesPhone() || !up.PhoneCA.Cert.Equal(phoneCA.Cert) {
		t.Error("the upgrading member is not the root with the new iPhone CA")
	}
	if _, err := up.Upgraded(root, []*x509.Certificate{root.Cert}, phoneCA, t0); err == nil {
		t.Error("upgraded twice")
	}
	follows, err := other.WithRoots([]*x509.Certificate{root.Cert})
	if err != nil {
		t.Fatal(err)
	}
	if follows.Legacy() || follows.IsAdmin() || follows.GroupCA.Key != nil || follows.ServesPhone() || !follows.NeedsAdminKey() {
		t.Error("a key holder kept the old keys after the upgrade")
	}
}

// TestPathRecords checks that the records a Welcome carries lead a new
// device to the same roots as the whole set.
func TestPathRecords(t *testing.T) {
	h := newHandover(t)
	s := h.records(t)
	path := s.PathRecords()
	fresh := NewRecords(h.pg.root.Cert)
	if _, errs := fresh.AddAll(path); len(errs) > 0 {
		t.Fatal(errs)
	}
	if roots := fresh.Roots(); len(roots) != 1 || !roots[0].Equal(h.newRoot.Cert) {
		t.Fatalf("the path records lead to %d roots, want the new root", len(roots))
	}
	if len(path) >= len(h.all) {
		t.Errorf("%d path records of %d: the Welcome carries more than the path needs", len(path), len(h.all))
	}
	if got := NewRecords(h.pg.root.Cert).PathRecords(); len(got) != 0 {
		t.Errorf("%d path records in a group never handed over", len(got))
	}
}

// TestFullSetTakesTheRoot checks that admins that fill the set to
// MaxRecords leave room for the root's own records, so the root still
// removes them, and that no one admin goes past MaxPerAdmin.
func TestFullSetTakesTheRoot(t *testing.T) {
	if testing.Short() {
		t.Skip("signs MaxRecords records")
	}
	pg := newPhoneGroup(t)
	g := pg.root.Cert
	admins := []*CA{pg.a, pg.b, adminCA(t, pg.root), adminCA(t, pg.root)}
	s := NewRecords(g)
	for _, a := range admins {
		mustAdd(t, s, computerAdminRecord(t, pg, member(t, a), "pc", KeyHashOf(a.Cert)))
	}
	laptop := member(t, pg.a)
	var err error
	for i := 0; err == nil; i++ {
		a := admins[i/MaxPerAdmin%len(admins)]
		_, err = s.Add(deviceRecord(t, g, a, []*x509.Certificate{a.Cert}, laptop, "laptop", int64(i+1)))
	}
	if s.Len() != MaxRecords {
		t.Fatalf("the set stopped at %d records, want %d: %v", s.Len(), MaxRecords, err)
	}
	if _, err := s.Add(deviceRecord(t, g, pg.a, []*x509.Certificate{pg.a.Cert}, laptop, "laptop", 1<<40)); err == nil {
		t.Error("an admin went past MaxPerAdmin")
	}
	var keys []KeyHash
	for _, a := range admins {
		keys = append(keys, KeyHashOf(a.Cert))
	}
	mustAdd(t, s, revokeRecord(t, g, pg.root, nil, keys, nil))
	for _, k := range keys {
		if !s.Revoked(k) {
			t.Error("the full set did not take the root's removal of an admin")
		}
	}
}
