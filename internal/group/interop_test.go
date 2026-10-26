// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package group

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

var update = flag.Bool("update", false, "rewrite the interop test vectors")

// TestSwiftCertificates checks the group CA and member certificate that the
// phone app's ClipboardBridgeKit issues (testdata/interop/swift-certs.json,
// written by its CertificateTests): a computer must take them as its own
// identity and use them in member TLS.
func TestSwiftCertificates(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "interop", "swift-certs.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		GroupCA   []byte `json:"group_ca"`
		Member    []byte `json:"member"`
		Device    string `json:"device"`
		MemberKey []byte `json:"member_key"`
	}
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(v.GroupCA)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(v.Member)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), v.MemberKey)
	if err != nil {
		t.Fatal(err)
	}
	id := &Identity{ID: DeviceID(v.Device), Key: key, Cert: cert, GroupCA: CA{Cert: ca}}
	if err := id.Check(); err != nil {
		t.Fatalf("a computer refuses the phone's certificates: %v", err)
	}
	if len(ca.SubjectKeyId) == 0 || string(cert.AuthorityKeyId) != string(ca.SubjectKeyId) {
		t.Error("the key identifiers do not link the member certificate to the CA")
	}
	// The member certificate works in member TLS with itself on the other
	// side, both checking the chain to the phone's CA.
	at := TLSOptions{Now: func() time.Time { return cert.NotBefore.Add(48 * time.Hour) }}
	ccs, scs, cerr, serr := handshake(t, id.ClientTLS(id.ID, at), id.ServerTLS(at))
	if cerr != nil || serr != nil {
		t.Fatalf("member TLS with the phone's certificates: client %v, server %v", cerr, serr)
	}
	if got, _ := PeerID(ccs); got != id.ID {
		t.Errorf("client saw %s", got)
	}
	if got, _ := PeerID(scs); got != id.ID {
		t.Errorf("server saw %s", got)
	}
}

// TestSwiftRecords reads the records the phone app's ClipboardBridgeKit signs
// (testdata/interop/swift-records.json, or the file in the directory
// CBB_INTEROP_OUT names, which CI fills from a fresh Swift run) and
// checks that Go reads the same devices, revocations and digest.
func TestSwiftRecords(t *testing.T) {
	dir := os.Getenv("CBB_INTEROP_OUT")
	if dir == "" {
		dir = filepath.Join("..", "..", "testdata", "interop")
	}
	data, err := os.ReadFile(filepath.Join(dir, "swift-records.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		GroupCA []byte   `json:"group_ca"`
		Records []Record `json:"records"`
		Digest  string   `json:"digest"`
		Devices []string `json:"devices"`
		Revoked [][]byte `json:"revoked"`
	}
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(v.GroupCA)
	if err != nil {
		t.Fatal(err)
	}
	if ca.MaxPathLen != 1 {
		t.Errorf("the phone's root has path length %d, want 1", ca.MaxPathLen)
	}
	s := NewRecords(ca)
	for i, r := range v.Records {
		if _, err := s.Add(r); err != nil {
			t.Fatalf("record %d: %v", i, err)
		}
	}
	if s.Digest() != v.Digest {
		t.Errorf("digest %s, Swift says %s", s.Digest(), v.Digest)
	}
	var got []string
	for _, d := range s.Devices() {
		got = append(got, string(d.ID))
		if d.Role != RolePhone {
			t.Errorf("device %s has role %q", d.ID, d.Role)
		}
	}
	if strings.Join(got, ",") != strings.Join(v.Devices, ",") {
		t.Errorf("devices %v, Swift says %v", got, v.Devices)
	}
	for _, k := range v.Revoked {
		var h KeyHash
		copy(h[:], k)
		if len(k) != len(h) || !s.Revoked(h) {
			t.Errorf("key %x is not revoked in Go", k)
		}
	}
}

// TestSwiftRenewal checks that a member keeps a certificate that the phone
// app renewed for it (testdata/interop/swift-renewal.json, or the file in
// CBB_INTEROP_OUT), as it does when a cert message arrives.
func TestSwiftRenewal(t *testing.T) {
	dir := os.Getenv("CBB_INTEROP_OUT")
	if dir == "" {
		dir = filepath.Join("..", "..", "testdata", "interop")
	}
	data, err := os.ReadFile(filepath.Join(dir, "swift-renewal.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Device  string `json:"device"`
		GroupCA []byte `json:"group_ca"`
		Key     []byte `json:"key"`
		Cert    []byte `json:"cert"`
		Renewed []byte `json:"renewed"`
		// From an admin phone, with its admin CA as the cert message's
		// issuer; absent in copies written before it.
		AdminCA      []byte `json:"admin_ca"`
		AdminRenewed []byte `json:"admin_renewed"`
	}
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(v.GroupCA)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(v.Cert)
	if err != nil {
		t.Fatal(err)
	}
	k, err := x509.ParsePKCS8PrivateKey(v.Key)
	var key *ecdsa.PrivateKey
	if err == nil {
		key, _ = k.(*ecdsa.PrivateKey)
	} else if key, err = x509.ParseECPrivateKey(v.Key); err != nil {
		t.Fatalf("the key: %v", err)
	}
	id := &Identity{ID: DeviceID(v.Device), Key: key, Cert: cert, GroupCA: CA{Cert: ca}}
	if err := id.Check(); err != nil {
		t.Fatalf("the member before the renewal: %v", err)
	}
	next, err := id.WithCert(v.Renewed)
	if err != nil {
		t.Fatalf("the renewed certificate: %v", err)
	}
	if !next.Cert.NotAfter.After(cert.NotAfter) {
		t.Errorf("the renewal ends %v, not after %v", next.Cert.NotAfter, cert.NotAfter)
	}
	if v.AdminRenewed == nil {
		return
	}
	byAdmin, err := id.WithCertFrom(v.AdminRenewed, v.AdminCA)
	if err != nil {
		t.Fatalf("the certificate an admin phone renewed: %v", err)
	}
	if byAdmin.Issuer == nil || string(byAdmin.Issuer.Raw) != string(v.AdminCA) {
		t.Error("the member did not take the admin CA as its issuer")
	}
}

// TestSwiftAdmin checks what an admin phone makes in the phone app's
// ClipboardBridgeKit (testdata/interop/swift-admin.json, or the file in
// CBB_INTEROP_OUT): its admin CA under the root, a computer's
// certificate from that CA, which the computer takes as its identity, and
// records signed through the admin CA.
func TestSwiftAdmin(t *testing.T) {
	dir := os.Getenv("CBB_INTEROP_OUT")
	if dir == "" {
		dir = filepath.Join("..", "..", "testdata", "interop")
	}
	data, err := os.ReadFile(filepath.Join(dir, "swift-admin.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		GroupCA []byte   `json:"group_ca"`
		AdminCA []byte   `json:"admin_ca"`
		Cert    []byte   `json:"cert"`
		Key     []byte   `json:"key"`
		Device  string   `json:"device"`
		Records []Record `json:"records"`
		Devices []string `json:"devices"`
		Digest  string   `json:"digest"`
	}
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(v.GroupCA)
	if err != nil {
		t.Fatal(err)
	}
	admin, err := x509.ParseCertificate(v.AdminCA)
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckAdminCA(admin, ca); err != nil {
		t.Fatalf("the phone's admin CA: %v", err)
	}
	cert, err := x509.ParseCertificate(v.Cert)
	if err != nil {
		t.Fatal(err)
	}
	k, err := x509.ParsePKCS8PrivateKey(v.Key)
	key, ok := k.(*ecdsa.PrivateKey)
	if err != nil || !ok {
		t.Fatalf("the key: %v", err)
	}
	id := &Identity{ID: DeviceID(v.Device), Key: key, Cert: cert, Issuer: admin, GroupCA: CA{Cert: ca}}
	if err := id.Check(); err != nil {
		t.Fatalf("a computer refuses a certificate from the admin CA: %v", err)
	}
	at := TLSOptions{Now: func() time.Time { return cert.NotBefore.Add(48 * time.Hour) }}
	if _, _, cerr, serr := handshake(t, id.ClientTLS(id.ID, at), id.ServerTLS(at)); cerr != nil || serr != nil {
		t.Fatalf("member TLS through the admin CA: client %v, server %v", cerr, serr)
	}
	s := NewRecords(ca)
	for i, r := range v.Records {
		if _, err := s.Add(r); err != nil {
			t.Fatalf("record %d: %v", i, err)
		}
	}
	if s.Digest() != v.Digest {
		t.Errorf("digest %s, Swift says %s", s.Digest(), v.Digest)
	}
	var got []string
	for _, d := range s.Devices() {
		got = append(got, string(d.ID))
	}
	if strings.Join(got, ",") != strings.Join(v.Devices, ",") {
		t.Errorf("devices %v, Swift says %v", got, v.Devices)
	}
	if err := s.Refused([]*x509.Certificate{cert, admin}); err != nil {
		t.Errorf("the computer is refused: %v", err)
	}
}

// rootVectors is testdata/interop/go-root.json: the records of a handover
// (TestRootHandover) and what a member makes of them, for the phone kit's
// RecordSet to agree with.
type rootVectors struct {
	GroupCA []byte       `json:"group_ca"`
	Records []Record     `json:"records"` // in an order where records signed under the new root come first
	Roots   [][]byte     `json:"roots"`
	Devices []rootDevice `json:"devices"`
	Chains  []rootChain  `json:"chains"`
	Digest  string       `json:"digest"`
	// Dropped is how many of Records are not valid for the set: those
	// signed under a root that can never be known.
	Dropped int `json:"dropped,omitempty"`
}

type rootDevice struct {
	ID    DeviceID `json:"id"`
	Name  string   `json:"name"`
	Admin bool     `json:"admin"`
}

type rootChain struct {
	Name    string   `json:"name"`
	Chain   [][]byte `json:"chain"` // leaf first, then its admin CA
	Refused bool     `json:"refused"`
}

// TestGoRootVectors writes (with -update) and checks
// testdata/interop/go-root.json.
func TestGoRootVectors(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "interop", "go-root.json")
	if *update {
		h := newHandover(t)
		s := h.records(t)
		thiefCA := adminCA(t, h.pg.root)
		v := rootVectors{GroupCA: h.pg.root.Cert.Raw, Digest: s.Digest()}
		for i := len(h.all) - 1; i >= 0; i-- {
			v.Records = append(v.Records, h.all[i])
		}
		for _, r := range s.Roots() {
			v.Roots = append(v.Roots, r.Raw)
		}
		for _, d := range s.Devices() {
			v.Devices = append(v.Devices, rootDevice{ID: d.ID, Name: d.Name, Admin: d.Admin})
		}
		for _, c := range []struct {
			name  string
			chain []*x509.Certificate
		}{
			{"the lost phone", []*x509.Certificate{h.lost}},
			{"the computer the old root admitted", []*x509.Certificate{h.byRoot}},
			{"the computer B admitted", []*x509.Certificate{h.byB, h.pg.b.Cert}},
			{"phone B", []*x509.Certificate{h.b, h.pg.b.Cert}},
			{"a device from the new root", []*x509.Certificate{member(t, h.newRoot)}},
			{"a new certificate from the old root", []*x509.Certificate{member(t, h.pg.root)}},
			{"a new admin CA under the old root", []*x509.Certificate{member(t, thiefCA), thiefCA.Cert}},
			// Certificates the issuer is not: the issuer checked is the one
			// that signed the leaf, wherever it comes.
			{"the computer B admitted, another CA first", []*x509.Certificate{h.byB, thiefCA.Cert, h.pg.b.Cert}},
			{"a new admin CA under the old root, behind B's", []*x509.Certificate{member(t, thiefCA), h.pg.b.Cert, thiefCA.Cert}},
			{"a new certificate from the old root, with B's CA", []*x509.Certificate{member(t, h.pg.root), h.pg.b.Cert}},
			{"the computer B admitted, without its issuer", []*x509.Certificate{h.byB, thiefCA.Cert}},
		} {
			rc := rootChain{Name: c.name, Refused: s.Refused(c.chain) != nil}
			for _, cert := range c.chain {
				rc.Chain = append(rc.Chain, cert.Raw)
			}
			v.Chains = append(v.Chains, rc)
		}
		data, err := json.MarshalIndent(v, "", "\t")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if refused := checkRootVectors(t, path); refused != 6 {
		t.Errorf("%d chains refused, want the lost phone, the two from the old root's key, those two with another CA, and one without its issuer", refused)
	}
}

// checkRootVectors checks a file of rootVectors against Records and
// returns how many chains it refuses.
func checkRootVectors(t *testing.T, path string) int {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var v rootVectors
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(v.GroupCA)
	if err != nil {
		t.Fatal(err)
	}
	s := NewRecords(ca)
	if _, errs := s.AddAll(v.Records); len(errs) > 0 {
		t.Fatal(errs)
	}
	if s.Digest() != v.Digest {
		t.Error("the digest differs")
	}
	roots := s.Roots()
	if len(roots) != len(v.Roots) || len(roots) == 0 || string(roots[0].Raw) != string(v.Roots[0]) {
		t.Fatalf("%d roots, the file has %d", len(roots), len(v.Roots))
	}
	var got []rootDevice
	for _, d := range s.Devices() {
		got = append(got, rootDevice{ID: d.ID, Name: d.Name, Admin: d.Admin})
	}
	if a, b := mustJSON(t, got), mustJSON(t, v.Devices); a != b {
		t.Errorf("devices %s, the file has %s", a, b)
	}
	refused := 0
	for _, c := range v.Chains {
		var chain []*x509.Certificate
		for _, der := range c.Chain {
			cert, err := x509.ParseCertificate(der)
			if err != nil {
				t.Fatal(err)
			}
			chain = append(chain, cert)
		}
		if (s.Refused(chain) != nil) != c.Refused {
			t.Errorf("%s: refused %v, the file says %v", c.Name, !c.Refused, c.Refused)
		}
		if c.Refused {
			refused++
		}
	}
	return refused
}

// TestGoUpgradeVectors writes (with -update) and checks
// testdata/interop/go-upgrade.json: a legacy group that cbb upgrade gave a
// root, for the lite member's records to agree with.
func TestGoUpgradeVectors(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "interop", "go-upgrade.json")
	if *update {
		legacy := newLegacyGroup(t)
		g := legacy.GroupCA.Cert
		root := newRoot(t)
		m := member(t, &legacy.GroupCA)
		old := KeyHashOf(g)
		all := []Record{
			deviceRecord(t, g, &legacy.GroupCA, nil, m, "pi", t0.UnixMilli()),
			rootRecord(t, g, &legacy.GroupCA, nil, root.Cert),
			revokeRecord(t, g, root, nil, []KeyHash{old}, []KeyHash{KeyHashOf(m)}),
			deviceRecord(t, g, root, nil, m, "pi", t0.UnixMilli()+1),
		}
		s := NewRecords(g)
		for _, r := range all {
			mustAdd(t, s, r)
		}
		v := rootVectors{GroupCA: g.Raw, Digest: s.Digest()}
		for i := len(all) - 1; i >= 0; i-- {
			v.Records = append(v.Records, all[i])
		}
		for _, r := range s.Roots() {
			v.Roots = append(v.Roots, r.Raw)
		}
		for _, d := range s.Devices() {
			v.Devices = append(v.Devices, rootDevice{ID: d.ID, Name: d.Name, Admin: d.Admin})
		}
		for _, c := range []struct {
			name  string
			chain []*x509.Certificate
		}{
			{"a member the old key admitted", []*x509.Certificate{m}},
			{"a device from the new root", []*x509.Certificate{member(t, root)}},
			{"a new certificate from the old key", []*x509.Certificate{member(t, &legacy.GroupCA)}},
		} {
			rc := rootChain{Name: c.name, Refused: s.Refused(c.chain) != nil}
			for _, cert := range c.chain {
				rc.Chain = append(rc.Chain, cert.Raw)
			}
			v.Chains = append(v.Chains, rc)
		}
		data, err := json.MarshalIndent(v, "", "\t")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if refused := checkRootVectors(t, path); refused != 1 {
		t.Errorf("%d chains refused, want only the new certificate from the old key", refused)
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// TestSwiftRoot reads a takeover that the phone kit signs (swift-root.json
// from its RootTests, in the directory CBB_INTEROP_OUT names, or
// testdata/interop): Go must follow it to the same root and devices, refuse
// the lost phone and keep the computer the old root admitted.
func TestSwiftRoot(t *testing.T) {
	dir := os.Getenv("CBB_INTEROP_OUT")
	if dir == "" {
		dir = filepath.Join("..", "..", "testdata", "interop")
	}
	data, err := os.ReadFile(filepath.Join(dir, "swift-root.json"))
	if os.IsNotExist(err) && os.Getenv("CBB_INTEROP_OUT") == "" {
		t.Skip("no swift-root.json; the phone kit's tests write it")
	}
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		GroupCA []byte   `json:"group_ca"`
		Records []Record `json:"records"`
		Roots   [][]byte `json:"roots"`
		Devices []string `json:"devices"`
		Digest  string   `json:"digest"`
		Lost    []byte   `json:"lost"`
		Kept    []byte   `json:"kept"`
	}
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(v.GroupCA)
	if err != nil {
		t.Fatal(err)
	}
	s := NewRecords(ca)
	if _, errs := s.AddAll(v.Records); len(errs) > 0 {
		t.Fatalf("Go refuses the phone's records: %v", errs)
	}
	if s.Digest() != v.Digest {
		t.Error("the digest differs")
	}
	roots := s.Roots()
	if len(roots) != len(v.Roots) || len(roots) != 1 || string(roots[0].Raw) != string(v.Roots[0]) {
		t.Fatalf("Go follows %d roots, the phone %d", len(roots), len(v.Roots))
	}
	var got []string
	for _, d := range s.Devices() {
		got = append(got, string(d.ID))
	}
	if strings.Join(got, " ") != strings.Join(v.Devices, " ") {
		t.Errorf("devices %v, the phone lists %v", got, v.Devices)
	}
	lost, err := x509.ParseCertificate(v.Lost)
	if err != nil {
		t.Fatal(err)
	}
	kept, err := x509.ParseCertificate(v.Kept)
	if err != nil {
		t.Fatal(err)
	}
	if s.Refused([]*x509.Certificate{lost}) == nil {
		t.Error("the lost phone is not refused")
	}
	if err := s.Refused([]*x509.Certificate{kept}); err != nil {
		t.Errorf("the computer the old root admitted is refused: %v", err)
	}
}

// TestSwiftComputerAdmin reads the admin CA that the phone kit's root
// issued for a computer's admin key, and the records that list the
// computer as an admin (ComputerAdminTests.testComputerAdminForGo): the CA
// is the one an Identity takes, and Go lists the computer as an admin.
func TestSwiftComputerAdmin(t *testing.T) {
	dir := os.Getenv("CBB_INTEROP_OUT")
	if dir == "" {
		dir = filepath.Join("..", "..", "testdata", "interop")
	}
	data, err := os.ReadFile(filepath.Join(dir, "swift-computer-admin.json"))
	if os.IsNotExist(err) && os.Getenv("CBB_INTEROP_OUT") == "" {
		t.Skip("no swift-computer-admin.json; the phone kit's tests write it")
	}
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		GroupCA  []byte   `json:"group_ca"`
		Device   DeviceID `json:"device"`
		AdminKey []byte   `json:"admin_key"`
		AdminCA  []byte   `json:"admin_ca"`
		Records  []Record `json:"records"`
	}
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(v.GroupCA)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(v.AdminCA)
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckAdminCA(ca, root); err != nil {
		t.Fatalf("Go refuses the admin CA: %v", err)
	}
	if ca.Subject.CommonName != AdminName(v.Device) || string(ca.RawSubjectPublicKeyInfo) != string(v.AdminKey) {
		t.Error("the admin CA does not name the computer or its admin key")
	}
	s := NewRecords(root)
	if _, errs := s.AddAll(v.Records); len(errs) > 0 {
		t.Fatalf("Go refuses the phone's records: %v", errs)
	}
	for _, d := range s.Devices() {
		if d.ID == v.Device {
			if !d.Admin || d.AdminKey == nil || *d.AdminKey != KeyHashOf(ca) {
				t.Errorf("Go does not list the computer as an admin: %+v", d)
			}
			return
		}
	}
	t.Error("Go does not list the computer")
}

type adminVectors struct {
	GroupCA []byte       `json:"group_ca"`
	Records []Record     `json:"records"`
	Roots   [][]byte     `json:"roots"` // the roots after the group CA: none, since no record that hands it over counts
	Devices []rootDevice `json:"devices"`
	Keys    []adminKey   `json:"keys"`
	Chains  []rootChain  `json:"chains"`
	Digest  string       `json:"digest"`
	// Dropped is how many of Records are not valid for the set: those
	// signed under a root that can never be known.
	Dropped int `json:"dropped,omitempty"`
}

type adminKey struct {
	Name    string  `json:"name"`
	Key     KeyHash `json:"key"`
	Revoked bool    `json:"revoked"`
}

// TestGoAdminVectors writes (with -update) and checks
// testdata/interop/go-admins.json: what a computer's admin CA may do in a
// phone's group (docs/protocol.md, section 10), as TestAdminPowers tells
// it, for the phone kits and the lite member to agree with.
func TestGoAdminVectors(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "interop", "go-admins.json")
	if *update {
		pg := newPhoneGroup(t)
		g := pg.root.Cert
		pc, phone := pg.a, pg.b
		pcChain, phoneChain := []*x509.Certificate{pc.Cert}, []*x509.Certificate{phone.Cert}
		pcKey, phoneKey, rootKey := KeyHashOf(pc.Cert), KeyHashOf(phone.Cert), KeyHashOf(g)
		pcMember, phoneMember := member(t, pc), member(t, phone)
		laptop, tv, printer := member(t, pc), member(t, pc), member(t, pc)
		own := newRoot(t) // the root the computer admin names, and holds the key of
		all := []Record{
			computerAdminRecord(t, pg, pcMember, "pc", pcKey),
			adminRecord(t, g, pg.root, nil, phoneMember, "phone", phoneKey),
			deviceRecord(t, g, pc, pcChain, laptop, "laptop", 2),
			deviceRecord(t, g, pc, pcChain, tv, "tv", 3),
			deviceRecord(t, g, pc, pcChain, printer, "printer", 4),
			// Refused powers: an admin phone, the root, a new root.
			revokeRecord(t, g, pc, pcChain, []KeyHash{phoneKey, KeyHashOf(laptop)}, nil),
			revokeRecord(t, g, pc, pcChain, []KeyHash{rootKey}, nil),
			rootRecord(t, g, pc, pcChain, own.Cert),
			revokeRecord(t, g, own, nil, []KeyHash{phoneKey, KeyHashOf(laptop)}, nil),
			revokeRecord(t, g, phone, phoneChain, []KeyHash{rootKey}, nil),
			// A device, before it was removed.
			revokeRecord(t, g, pc, pcChain, []KeyHash{KeyHashOf(tv)}, nil),
			// The admin phone removes it, keeping the laptop and the
			// printer and naming the tv again.
			revokeRecord(t, g, phone, phoneChain, []KeyHash{pcKey, KeyHashOf(pcMember), KeyHashOf(tv)}, []KeyHash{KeyHashOf(laptop), KeyHashOf(printer)}),
			// After: nothing it signs counts.
			revokeRecord(t, g, pc, pcChain, []KeyHash{KeyHashOf(printer)}, nil),
			deviceRecord(t, g, pc, pcChain, member(t, pc), "thief's", 9),
		}
		s := NewRecords(g)
		_, errs := s.AddAll(all)
		if len(errs) != 1 {
			t.Fatalf("%d records dropped, want the one signed under the root the computer admin named: %v", len(errs), errs)
		}
		v := adminVectors{GroupCA: g.Raw, Records: all, Digest: s.Digest(), Dropped: len(errs)}
		for _, r := range s.Roots() {
			v.Roots = append(v.Roots, r.Raw)
		}
		for _, d := range s.Devices() {
			v.Devices = append(v.Devices, rootDevice{ID: d.ID, Name: d.Name, Admin: d.Admin})
		}
		for _, k := range []struct {
			name string
			key  KeyHash
		}{
			{"the root", rootKey}, {"the admin phone", phoneKey}, {"the computer admin", pcKey},
			{"the laptop", KeyHashOf(laptop)}, {"the tv", KeyHashOf(tv)}, {"the printer", KeyHashOf(printer)},
		} {
			v.Keys = append(v.Keys, adminKey{Name: k.name, Key: k.key, Revoked: s.Revoked(k.key)})
		}
		for _, c := range []struct {
			name  string
			chain []*x509.Certificate
		}{
			{"the laptop", []*x509.Certificate{laptop, pc.Cert}},
			{"the printer", []*x509.Certificate{printer, pc.Cert}},
			{"the tv", []*x509.Certificate{tv, pc.Cert}},
			{"the computer admin", []*x509.Certificate{pcMember, pc.Cert}},
			{"the admin phone", []*x509.Certificate{phoneMember, phone.Cert}},
			{"the named root's device", []*x509.Certificate{member(t, own)}},
		} {
			rc := rootChain{Name: c.name, Refused: s.Refused(c.chain) != nil}
			for _, cert := range c.chain {
				rc.Chain = append(rc.Chain, cert.Raw)
			}
			v.Chains = append(v.Chains, rc)
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
	var v adminVectors
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(v.GroupCA)
	if err != nil {
		t.Fatal(err)
	}
	s := NewRecords(ca)
	if _, errs := s.AddAll(v.Records); len(errs) != v.Dropped || v.Dropped != 1 {
		t.Fatalf("%d records dropped, the file says %d: %v", len(errs), v.Dropped, errs)
	}
	if s.Digest() != v.Digest {
		t.Error("the digest differs")
	}
	if len(s.Roots()) != 0 || len(v.Roots) != 0 {
		t.Error("a computer admin handed the group over")
	}
	var got []rootDevice
	for _, d := range s.Devices() {
		got = append(got, rootDevice{ID: d.ID, Name: d.Name, Admin: d.Admin})
	}
	if a, b := mustJSON(t, got), mustJSON(t, v.Devices); a != b {
		t.Errorf("devices %s, the file has %s", a, b)
	}
	want := map[string]bool{"the root": false, "the admin phone": false, "the computer admin": true, "the laptop": false, "the tv": true, "the printer": false}
	for _, k := range v.Keys {
		if s.Revoked(k.Key) != k.Revoked || k.Revoked != want[k.Name] {
			t.Errorf("%s: revoked %v, the file says %v", k.Name, s.Revoked(k.Key), k.Revoked)
		}
	}
	wantRefused := map[string]bool{"the laptop": false, "the printer": false, "the tv": true, "the computer admin": true, "the admin phone": false, "the named root's device": true}
	for _, c := range v.Chains {
		var chain []*x509.Certificate
		for _, der := range c.Chain {
			cert, err := x509.ParseCertificate(der)
			if err != nil {
				t.Fatal(err)
			}
			chain = append(chain, cert)
		}
		if (s.Refused(chain) != nil) != c.Refused || c.Refused != wantRefused[c.Name] {
			t.Errorf("%s: refused %v, the file says %v", c.Name, s.Refused(chain) != nil, c.Refused)
		}
	}
}

type freezeVectors struct {
	GroupCA []byte       `json:"group_ca"`
	Records []Record     `json:"records"`
	Devices []rootDevice `json:"devices"`
	Keys    []freezeKey  `json:"keys"`
	Chains  []rootChain  `json:"chains"`
	Digest  string       `json:"digest"`
	// Dropped is how many of Records are not valid for the set: those
	// signed under a root that can never be known.
	Dropped int `json:"dropped,omitempty"`
}

type freezeKey struct {
	Name   string  `json:"name"`
	Key    KeyHash `json:"key"`
	Frozen bool    `json:"frozen"`
}

// TestGoFreezeVectors writes (with -update) and checks
// testdata/interop/go-freeze.json: an admin computer freezing another
// (docs/protocol.md, section 10, rule 4), as TestFreeze tells it, for the
// phone kits and the lite member to agree with.
func TestGoFreezeVectors(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "interop", "go-freeze.json")
	if *update {
		pg := newPhoneGroup(t)
		g := pg.root.Cert
		pc1, phone, pc2 := pg.a, pg.b, adminCA(t, pg.root)
		pc1Chain, pc2Chain, phoneChain := []*x509.Certificate{pc1.Cert}, []*x509.Certificate{pc2.Cert}, []*x509.Certificate{phone.Cert}
		pc1Key, pc2Key, phoneKey, rootKey := KeyHashOf(pc1.Cert), KeyHashOf(pc2.Cert), KeyHashOf(phone.Cert), KeyHashOf(g)
		m1, m2, laptop, tv := member(t, pc1), member(t, pc2), member(t, pc1), member(t, pc1)
		before := deviceRecord(t, g, pc1, pc1Chain, laptop, "laptop", 2)
		back := freezeRecord(t, g, pc1, pc1Chain, []KeyHash{pc2Key}, nil)
		all := []Record{
			computerAdminRecord(t, pg, m1, "pc1", pc1Key),
			computerAdminRecord(t, pg, m2, "pc2", pc2Key),
			adminRecord(t, g, pg.root, nil, member(t, phone), "phone", phoneKey),
			before,
			// pc2 freezes pc1, keeping the laptop's record.
			freezeRecord(t, g, pc2, pc2Chain, []KeyHash{pc1Key}, []KeyHash{before.ID()}),
			// After: neither the tv nor removing the laptop counts.
			deviceRecord(t, g, pc1, pc1Chain, tv, "tv", 3),
			revokeRecord(t, g, pc1, pc1Chain, []KeyHash{KeyHashOf(laptop)}, nil),
			// Nobody freezes the root or an admin phone.
			freezeRecord(t, g, pc1, pc1Chain, []KeyHash{phoneKey}, nil),
			freezeRecord(t, g, pc1, pc1Chain, []KeyHash{rootKey}, nil),
			// pc1 freezes back; an admin computer's thaw does not end it,
			// the admin phone's does.
			back,
			thawRecord(t, g, pc2, pc2Chain, []KeyHash{back.ID()}),
			thawRecord(t, g, phone, phoneChain, []KeyHash{back.ID()}),
		}
		s := NewRecords(g)
		if _, errs := s.AddAll(all); len(errs) > 0 {
			t.Fatal(errs)
		}
		v := freezeVectors{GroupCA: g.Raw, Records: all, Digest: s.Digest()}
		for _, d := range s.Devices() {
			v.Devices = append(v.Devices, rootDevice{ID: d.ID, Name: d.Name, Admin: d.Admin})
		}
		for _, k := range []struct {
			name string
			key  KeyHash
		}{
			{"the root", rootKey}, {"the admin phone", phoneKey}, {"pc1", pc1Key}, {"pc1's device", KeyHashOf(m1)},
			{"pc2", pc2Key}, {"pc2's device", KeyHashOf(m2)}, {"the laptop", KeyHashOf(laptop)},
		} {
			v.Keys = append(v.Keys, freezeKey{Name: k.name, Key: k.key, Frozen: s.Frozen(k.key)})
		}
		for _, c := range []struct {
			name  string
			chain []*x509.Certificate
		}{
			{"the laptop", []*x509.Certificate{laptop, pc1.Cert}},
			{"the tv", []*x509.Certificate{tv, pc1.Cert}},
			{"pc1's device", []*x509.Certificate{m1, pc1.Cert}},
			{"pc2's device", []*x509.Certificate{m2, pc2.Cert}},
		} {
			rc := rootChain{Name: c.name, Refused: s.Refused(c.chain) != nil}
			for _, cert := range c.chain {
				rc.Chain = append(rc.Chain, cert.Raw)
			}
			v.Chains = append(v.Chains, rc)
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
	var v freezeVectors
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(v.GroupCA)
	if err != nil {
		t.Fatal(err)
	}
	s := NewRecords(ca)
	if _, errs := s.AddAll(v.Records); len(errs) > 0 {
		t.Fatal(errs)
	}
	if s.Digest() != v.Digest {
		t.Error("the digest differs")
	}
	var got []rootDevice
	for _, d := range s.Devices() {
		got = append(got, rootDevice{ID: d.ID, Name: d.Name, Admin: d.Admin})
	}
	if a, b := mustJSON(t, got), mustJSON(t, v.Devices); a != b || !strings.Contains(a, `"laptop"`) || strings.Contains(a, `"tv"`) {
		t.Errorf("devices %s, the file has %s", a, b)
	}
	want := map[string]bool{"pc1": true, "pc1's device": true}
	for _, k := range v.Keys {
		if s.Frozen(k.Key) != k.Frozen || k.Frozen != want[k.Name] || s.Revoked(k.Key) {
			t.Errorf("%s: frozen %v, the file says %v", k.Name, s.Frozen(k.Key), k.Frozen)
		}
	}
	wantRefused := map[string]bool{"the tv": true, "pc1's device": true}
	for _, c := range v.Chains {
		var chain []*x509.Certificate
		for _, der := range c.Chain {
			cert, err := x509.ParseCertificate(der)
			if err != nil {
				t.Fatal(err)
			}
			chain = append(chain, cert)
		}
		if (s.Refused(chain) != nil) != c.Refused || c.Refused != wantRefused[c.Name] {
			t.Errorf("%s: refused %v, the file says %v", c.Name, s.Refused(chain) != nil, c.Refused)
		}
	}
}

type takeoverVectors struct {
	Cases []takeoverCase `json:"cases"`
}

type takeoverCase struct {
	Name    string     `json:"name"`
	GroupCA []byte     `json:"group_ca"`
	Records []Record   `json:"records"`
	Roots   [][]byte   `json:"roots"` // the roots after the group CA
	Keys    []adminKey `json:"keys"`
	Digest  string     `json:"digest"`
	Dropped int        `json:"dropped,omitempty"` // as adminVectors.Dropped
}

// TestGoTakeoverVectors writes (with -update) and checks
// testdata/interop/go-takeover.json: an admin computer hands over a group
// whose root is a computer, as cbb takeover does (docs/protocol.md, section
// 10, rule 2), but not a phone's group, not while another admin computer
// has frozen it, and not once the old root removed it.
func TestGoTakeoverVectors(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "interop", "go-takeover.json")
	wantRoots := map[string]int{"computer root": 1}
	wantDropped := map[string]int{"phone root": 1}
	if *update {
		var v takeoverVectors
		for _, name := range []string{"computer root", "phone root", "frozen admin", "old root removes the admin"} {
			pg := newPhoneGroup(t)
			g, pc, pc2 := pg.root.Cert, pg.a, pg.b
			pcChain, pcKey, pc2Key, rootKey := []*x509.Certificate{pc.Cert}, KeyHashOf(pc.Cert), KeyHashOf(pc2.Cert), KeyHashOf(g)
			holder, laptop := member(t, pg.root), member(t, pg.root)
			next := newRoot(t)
			rootRole := RoleFull
			if name == "phone root" {
				rootRole = RolePhone
			}
			all := []Record{
				ownRecord(t, pg.root, holder, "root", rootRole),
				computerAdminRecord(t, pg, member(t, pc), "pc", pcKey),
				computerAdminRecord(t, pg, member(t, pc2), "pc2", pc2Key),
				deviceRecord(t, g, pg.root, nil, laptop, "laptop", 2),
				rootRecord(t, g, pc, pcChain, next.Cert),
				revokeRecord(t, g, next, nil, []KeyHash{rootKey, KeyHashOf(holder)}, []KeyHash{KeyHashOf(laptop), pcKey, pc2Key}),
			}
			switch name {
			case "frozen admin":
				all = append(all, freezeRecord(t, g, pc2, []*x509.Certificate{pc2.Cert}, []KeyHash{pcKey}, nil))
			case "old root removes the admin":
				all = append(all, revokeRecord(t, g, pg.root, nil, []KeyHash{pcKey}, nil))
			}
			s := NewRecords(g)
			_, errs := s.AddAll(all)
			c := takeoverCase{Name: name, GroupCA: g.Raw, Records: all, Digest: s.Digest(), Dropped: len(errs)}
			for _, r := range s.Roots() {
				c.Roots = append(c.Roots, r.Raw)
			}
			for _, k := range []struct {
				name string
				key  KeyHash
			}{{"the old root", rootKey}, {"the root's device", KeyHashOf(holder)}, {"pc", pcKey}, {"the laptop", KeyHashOf(laptop)}} {
				c.Keys = append(c.Keys, adminKey{Name: k.name, Key: k.key, Revoked: s.Revoked(k.key)})
			}
			v.Cases = append(v.Cases, c)
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
	var v takeoverVectors
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Cases) != 4 {
		t.Fatalf("%d cases", len(v.Cases))
	}
	for _, c := range v.Cases {
		ca, err := x509.ParseCertificate(c.GroupCA)
		if err != nil {
			t.Fatal(err)
		}
		s := NewRecords(ca)
		// In a phone's group the new root is never known, and the
		// revocation signed under it is dropped.
		if _, errs := s.AddAll(c.Records); len(errs) != c.Dropped || c.Dropped != wantDropped[c.Name] {
			t.Fatalf("%s: %d records dropped, the file says %d: %v", c.Name, len(errs), c.Dropped, errs)
		}
		if len(s.Roots()) != len(c.Roots) || len(c.Roots) != wantRoots[c.Name] {
			t.Errorf("%s: %d roots, the file has %d", c.Name, len(s.Roots()), len(c.Roots))
		}
		for i, r := range s.Roots() {
			if i < len(c.Roots) && !bytes.Equal(r.Raw, c.Roots[i]) {
				t.Errorf("%s: root %d differs", c.Name, i)
			}
		}
		for _, k := range c.Keys {
			want := k.Name == "pc" && c.Name == "old root removes the admin" ||
				c.Name == "computer root" && (k.Name == "the old root" || k.Name == "the root's device")
			if s.Revoked(k.Key) != k.Revoked || k.Revoked != want {
				t.Errorf("%s: %s revoked %v, the file says %v", c.Name, k.Name, s.Revoked(k.Key), k.Revoked)
			}
		}
		if s.Digest() != c.Digest {
			t.Errorf("%s: the digest differs", c.Name)
		}
	}
}

// TestSwiftCommand checks the commands a phone kit signed
// (swift-command.json, which the kits' tests write): mode commands with the
// root's key and with an admin CA's, a hub, a paste, a paste-off, an action
// and an actions-off command are taken, for the device they name.
func TestSwiftCommand(t *testing.T) {
	dir := os.Getenv("CBB_INTEROP_OUT")
	if dir == "" {
		dir = filepath.Join("..", "..", "testdata", "interop")
	}
	data, err := os.ReadFile(filepath.Join(dir, "swift-command.json"))
	if os.IsNotExist(err) && os.Getenv("CBB_INTEROP_OUT") == "" {
		t.Skip("no swift-command.json; the phone kit's tests write it")
	}
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		GroupCA  []byte   `json:"group_ca"`
		To       DeviceID `json:"to"`
		Commands []Record `json:"commands"`
	}
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(v.GroupCA)
	if err != nil {
		t.Fatal(err)
	}
	s := NewRecords(ca)
	// Two mode commands, by the root and by an admin, a hub command by the
	// root with one client, a typed paste by the admin, paste-off by the
	// root, lock by the admin and actions-off by the root.
	if len(v.Commands) != 7 {
		t.Fatalf("%d commands, want 7", len(v.Commands))
	}
	for i, c := range v.Commands {
		var b CommandBody
		if err := json.Unmarshal(c.Body, &b); err != nil {
			t.Fatal(err)
		}
		got, err := s.VerifyCommand(c, v.To, time.UnixMilli(b.TimeMS))
		if err != nil {
			t.Fatalf("command %d: %v", i, err)
		}
		if i < 2 && (got.Type != CommandMode || got.Mode != "receive") {
			t.Errorf("command %d: %+v", i, got)
		}
		if i == 2 && (got.Type != CommandHub || got.Hub.Forwarder == nil || got.Hub.Forwarder.Endpoint != "203.0.113.9:8764" ||
			len(got.Hub.Clients) != 1 || len(got.Hub.Clients[0].PSK) != 32) {
			t.Errorf("the hub command: %+v", got.Hub)
		}
		if i == 3 && (got.Type != CommandPaste || got.Mode != PasteByTyping || !got.Enter || got.Kind != "text" || got.Text != "echo <ok> & \"done\"\n") {
			t.Errorf("the paste command: %+v", got)
		}
		if i == 4 && got.Type != CommandPasteOff {
			t.Errorf("the paste-off command: %+v", got)
		}
		if i == 5 && (got.Type != CommandAction || got.Action != "lock") {
			t.Errorf("the action command: %+v", got)
		}
		if i == 6 && got.Type != CommandActionsOff {
			t.Errorf("the actions-off command: %+v", got)
		}
		if _, err := s.VerifyCommand(c, NewDeviceID(), time.UnixMilli(b.TimeMS)); err == nil {
			t.Errorf("command %d was taken by another device", i)
		}
	}
}

type hubVectors struct {
	GroupCA  []byte     `json:"group_ca"`
	Records  []Record   `json:"records"`
	HubOrder []DeviceID `json:"hub_order"`
}

// TestGoHubVectors writes (with -update) and checks
// testdata/interop/go-hubs.json: the order of a group's hubs
// (docs/protocol.md, section 11, "Several hubs"), the phones first and the
// root's own device first among them, then the admin computers by device
// ID, without a plain computer or a removed admin, for the phone kits and
// the lite member to agree with.
func TestGoHubVectors(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "interop", "go-hubs.json")
	if *update {
		pg := newPhoneGroup(t)
		g := pg.root.Cert
		rootMember := member(t, pg.root)
		rootDev := DeviceID(rootMember.Subject.CommonName)
		key := KeyHashOf(rootMember)
		own, err := SignRecord(RecordBody{Type: RecordDevice, Group: Tag(g), TimeMS: 1, By: rootDev,
			Device: rootDev, Name: "root phone", Role: RolePhone, Key: &key}, pg.root.Key)
		if err != nil {
			t.Fatal(err)
		}
		pcOne, pcTwo, gone := adminCA(t, pg.root), adminCA(t, pg.root), adminCA(t, pg.root)
		all := []Record{
			own,
			adminRecord(t, g, pg.root, nil, member(t, pg.root), "admin phone", KeyHashOf(pg.a.Cert)),
			computerAdminRecord(t, pg, member(t, pg.root), "pc one", KeyHashOf(pcOne.Cert)),
			computerAdminRecord(t, pg, member(t, pg.root), "pc two", KeyHashOf(pcTwo.Cert)),
			computerAdminRecord(t, pg, member(t, pg.root), "removed pc", KeyHashOf(gone.Cert)),
			deviceRecord(t, g, pg.root, nil, member(t, pg.root), "plain pc", 1),
			revokeRecord(t, g, pg.root, nil, []KeyHash{KeyHashOf(gone.Cert)}, nil),
		}
		s := NewRecords(g)
		if _, errs := s.AddAll(all); len(errs) != 0 {
			t.Fatal(errs)
		}
		v := hubVectors{GroupCA: g.Raw, Records: all, HubOrder: s.HubOrder()}
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
	var v hubVectors
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
	got := s.HubOrder()
	if !slices.Equal(got, v.HubOrder) {
		t.Errorf("HubOrder = %v, the file has %v", got, v.HubOrder)
	}
	names := map[DeviceID]string{}
	for _, d := range s.Devices() {
		names[d.ID] = d.Name
	}
	var gotNames []string
	for _, d := range got {
		gotNames = append(gotNames, names[d])
	}
	if len(gotNames) != 4 || gotNames[0] != "root phone" || gotNames[1] != "admin phone" || !slices.Contains(gotNames[2:], "pc one") || !slices.Contains(gotNames[2:], "pc two") {
		t.Errorf("the hubs are %v", gotNames)
	}
	if string(got[2]) > string(got[3]) {
		t.Error("the computers are not in the order of their device IDs")
	}
}

type commandVectors struct {
	GroupCA  []byte          `json:"group_ca"`
	Records  []Record        `json:"records"`
	Self     DeviceID        `json:"self"`
	NowMS    int64           `json:"now_ms"`
	Commands []commandVector `json:"commands"`
}

type commandVector struct {
	Name    string `json:"name"`
	Command Record `json:"command"`
	OK      bool   `json:"ok"`
	Mode    string `json:"mode,omitempty"`
}

// TestGoCommandVectors writes (with -update) and checks
// testdata/interop/go-commands.json: mode, paste and paste-off commands for one phone, signed by
// the root, an admin phone and admin computers (one frozen, one removed),
// or for another device or group, expired, from the future or altered, and
// whether each counts (docs/protocol.md, section 15), for the phone kits
// and the lite member to agree with.
func TestGoCommandVectors(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "interop", "go-commands.json")
	if *update {
		pg := newPhoneGroup(t)
		g := pg.root.Cert
		phone, pc, frozen, removed := pg.a, adminCA(t, pg.root), adminCA(t, pg.root), adminCA(t, pg.root)
		self := member(t, pg.root)
		selfID := DeviceID(self.Subject.CommonName)
		all := []Record{
			adminRecord(t, g, pg.root, nil, member(t, phone), "admin phone", KeyHashOf(phone.Cert)),
			computerAdminRecord(t, pg, member(t, pc), "pc", KeyHashOf(pc.Cert)),
			computerAdminRecord(t, pg, member(t, frozen), "frozen pc", KeyHashOf(frozen.Cert)),
			computerAdminRecord(t, pg, member(t, removed), "removed pc", KeyHashOf(removed.Cert)),
			deviceRecord(t, g, pg.root, nil, self, "my phone", 1),
			freezeRecord(t, g, pc, []*x509.Certificate{pc.Cert}, []KeyHash{KeyHashOf(frozen.Cert)}, nil),
			revokeRecord(t, g, pg.root, nil, []KeyHash{KeyHashOf(removed.Cert)}, nil),
		}
		now := int64(1_800_000_000_000)
		sign := func(signer *CA, chain []*x509.Certificate, to DeviceID, tag string, at int64, mode string) Record {
			r, err := SignCommand(CommandBody{Type: CommandMode, Group: tag, By: selfID, To: to, ID: NewCommandID(),
				TimeMS: at, ExpiresMS: at + CommandLifetime.Milliseconds(), Mode: mode}, signer.Key, chain...)
			if err != nil {
				t.Fatal(err)
			}
			return r
		}
		tag := Tag(g)
		paste := func(signer *CA, chain []*x509.Certificate, typ string) Record {
			b := CommandBody{Type: typ, Group: tag, By: selfID, To: selfID, ID: NewCommandID(), TimeMS: now, ExpiresMS: now + CommandLifetime.Milliseconds()}
			if typ == CommandPaste {
				b.Mode, b.Kind, b.Text, b.Enter = PasteByClipboard, "text", "ls -l <dir> & echo \"done\"\n", true
			}
			r, err := SignCommand(b, signer.Key, chain...)
			if err != nil {
				t.Fatal(err)
			}
			return r
		}
		altered := sign(pg.root, nil, selfID, tag, now, "own")
		altered.Body = []byte(strings.Replace(string(altered.Body), `"own"`, `"send"`, 1))
		v := commandVectors{GroupCA: g.Raw, Records: all, Self: selfID, NowMS: now}
		for _, c := range []commandVector{
			{Name: "the root", Command: sign(pg.root, nil, selfID, tag, now, "shared"), Mode: "shared"},
			{Name: "the admin phone", Command: sign(phone, []*x509.Certificate{phone.Cert}, selfID, tag, now-1000, "receive"), Mode: "receive"},
			{Name: "an admin computer", Command: sign(pc, []*x509.Certificate{pc.Cert}, selfID, tag, now, "send"), Mode: "send"},
			{Name: "a frozen admin computer", Command: sign(frozen, []*x509.Certificate{frozen.Cert}, selfID, tag, now, "own")},
			{Name: "a removed admin computer", Command: sign(removed, []*x509.Certificate{removed.Cert}, selfID, tag, now, "own")},
			{Name: "a key of another group", Command: sign(newRoot(t), nil, selfID, tag, now, "own")},
			{Name: "for another device", Command: sign(pg.root, nil, NewDeviceID(), tag, now, "own")},
			{Name: "for another group", Command: sign(pg.root, nil, selfID, Tag(newRoot(t).Cert), now, "own")},
			{Name: "expired", Command: sign(pg.root, nil, selfID, tag, now-CommandLifetime.Milliseconds(), "own")},
			{Name: "signed in the future", Command: sign(pg.root, nil, selfID, tag, now+CommandAhead.Milliseconds()+1, "own")},
			{Name: "altered", Command: altered},
			{Name: "a paste by an admin computer", Command: paste(pc, []*x509.Certificate{pc.Cert}, CommandPaste), Mode: PasteByClipboard},
			{Name: "a paste by a frozen admin computer", Command: paste(frozen, []*x509.Certificate{frozen.Cert}, CommandPaste)},
			{Name: "paste-off by the root", Command: paste(pg.root, nil, CommandPasteOff), OK: true},
		} {
			c.OK = c.OK || c.Mode != ""
			v.Commands = append(v.Commands, c)
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
	var v commandVectors
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
	if len(v.Commands) != 14 {
		t.Fatalf("the file has %d commands", len(v.Commands))
	}
	for _, c := range v.Commands {
		body, err := s.VerifyCommand(c.Command, v.Self, time.UnixMilli(v.NowMS))
		if (err == nil) != c.OK {
			t.Errorf("%s: VerifyCommand = %v, the file says ok %v", c.Name, err, c.OK)
		}
		if err == nil && body.Mode != c.Mode {
			t.Errorf("%s: the mode is %q, the file has %q", c.Name, body.Mode, c.Mode)
		}
	}
}
