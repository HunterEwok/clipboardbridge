// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package group

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestSwiftCertificates checks the group CA and member certificate that the
// phone app's ClipbridgeKit issues (testdata/interop/swift-certs.json,
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

// TestSwiftRecords reads the records the phone app's ClipbridgeKit signs
// (testdata/interop/swift-records.json, or the file in the directory
// CLIPBRIDGE_INTEROP_OUT names, which CI fills from a fresh Swift run) and
// checks that Go reads the same devices, revocations and digest.
func TestSwiftRecords(t *testing.T) {
	dir := os.Getenv("CLIPBRIDGE_INTEROP_OUT")
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
// CLIPBRIDGE_INTEROP_OUT), as it does when a cert message arrives.
func TestSwiftRenewal(t *testing.T) {
	dir := os.Getenv("CLIPBRIDGE_INTEROP_OUT")
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
}

// TestSwiftAdmin checks what an admin phone makes in the phone app's
// ClipbridgeKit (testdata/interop/swift-admin.json, or the file in
// CLIPBRIDGE_INTEROP_OUT): its admin CA under the root, a computer's
// certificate from that CA, which the computer takes as its identity, and
// records signed through the admin CA.
func TestSwiftAdmin(t *testing.T) {
	dir := os.Getenv("CLIPBRIDGE_INTEROP_OUT")
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
