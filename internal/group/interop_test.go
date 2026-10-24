// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package group

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
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
	if refused != 6 {
		t.Errorf("%d chains refused, want the lost phone, the two from the old root's key, those two with another CA, and one without its issuer", refused)
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
		if _, errs := s.AddAll(all); len(errs) > 0 {
			t.Fatal(errs)
		}
		v := adminVectors{GroupCA: g.Raw, Records: all, Digest: s.Digest()}
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
	if _, errs := s.AddAll(v.Records); len(errs) > 0 {
		t.Fatal(errs)
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
	wantRefused := map[string]bool{"the laptop": false, "the printer": false, "the tv": true, "the computer admin": true, "the admin phone": false}
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
