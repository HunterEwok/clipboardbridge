// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package forward

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/HunterEwok/clipboardbridge/internal/group"
)

// TestCredentialRegistration checks a hub that registers with its group's
// hubs' credential (docs/protocol.md, section 18): its certificate names no
// device, the forwarder takes only a hub the credential lists, refuses an
// expired or older credential, also after a restart, and a group that
// registered with a credential never with records again; a link from an
// heir hands the group to a new root, after which the old root's
// credentials and the other heirs' links count for nothing.
func TestCredentialRegistration(t *testing.T) {
	now := time.Now()
	state := filepath.Join(t.TempDir(), "state.json")
	fcert, err := NewCert()
	if err != nil {
		t.Fatal(err)
	}
	f, pin := startForwarderWith(t, Config{Cert: fcert, StateFile: state})
	root, err := group.NewRootCA(now)
	if err != nil {
		t.Fatal(err)
	}
	tag := group.Tag(root.Cert)
	hubKey, _ := group.NewKey()
	hub, err := group.HubCertificate(hubKey, root.Cert)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(hub.Leaf.Raw), "cb-") || hub.Leaf.Subject.CommonName != group.HubCertificateName {
		t.Fatalf("the hub's certificate names a device: %v", hub.Leaf.Subject)
	}
	heirKey, _ := group.NewKey()
	rogueKey, _ := group.NewKey()
	keyHash := func(k *ecdsa.PrivateKey) group.KeyHash {
		t.Helper()
		spki, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		return sha256.Sum256(spki)
	}
	lists := group.CredentialLists{
		Hubs:  []group.KeyHash{keyHash(hubKey)},
		Heirs: []group.KeyHash{keyHash(heirKey), keyHash(rogueKey)},
	}
	sign := func(ca *group.CA, v uint64, at time.Time) group.Credential {
		t.Helper()
		c, err := group.SignHubs(tag, lists, v, at, ca.Key)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	wg, _ := ecdh.X25519().GenerateKey(rand.Reader)
	register := func(f *Forwarder, pin string, cert tls.Certificate, auth hubAuth) answer {
		t.Helper()
		return rawRegister(t, f, pin, cert, wg.PublicKey().Bytes(), wg, auth)
	}

	if a := register(f, pin, hub, hubAuth{creds: []group.Credential{sign(root, 10, now)}}); a.Error != "" || a.ID == 0 {
		t.Fatalf("the hub with its credential: %+v", a)
	}
	other, _ := group.HubCertificate(rogueKey, root.Cert)
	if a := register(f, pin, other, hubAuth{creds: []group.Credential{sign(root, 10, now)}}); !strings.Contains(a.Error, "does not list") {
		t.Errorf("a key the credential does not list: %+v", a)
	}
	if a := register(f, pin, hub, hubAuth{creds: []group.Credential{sign(root, 11, now.Add(-group.CredentialLifetime-time.Hour))}}); !strings.Contains(a.Error, "expired") {
		t.Errorf("an expired credential: %+v", a)
	}
	if a := register(f, pin, hub, hubAuth{creds: []group.Credential{sign(root, 9, now)}}); !strings.Contains(a.Error, "older") {
		t.Errorf("an older credential: %+v", a)
	}
	forged, _ := group.NewRootCA(now)
	if a := register(f, pin, hub, hubAuth{creds: []group.Credential{sign(forged, 12, now)}}); !strings.Contains(a.Error, "do not verify") {
		t.Errorf("a credential another root signed: %+v", a)
	}
	leaf, _ := root.IssueMember(group.NewDeviceID(), &hubKey.PublicKey, now)
	memberOf := tls.Certificate{Certificate: [][]byte{leaf.Raw, root.Cert.Raw}, PrivateKey: hubKey, Leaf: leaf}
	if a := register(f, pin, memberOf, hubAuth{key: root.Key}); !strings.Contains(a.Error, "credential") {
		t.Errorf("the group with records after a credential: %+v", a)
	}

	// After a restart on the same state the older credential stays refused.
	g, gpin := startForwarderWith(t, Config{Cert: fcert, StateFile: state})
	if a := register(g, gpin, hub, hubAuth{creds: []group.Credential{sign(root, 9, now)}}); !strings.Contains(a.Error, "older") {
		t.Errorf("an older credential after a restart: %+v", a)
	}

	// An heir hands the group to a new root.
	next, _ := group.NewRootCA(now)
	link, err := group.SignLink(tag, next.Cert, heirKey)
	if err != nil {
		t.Fatal(err)
	}
	old := sign(root, 10, now)
	if a := register(g, gpin, hub, hubAuth{creds: []group.Credential{old, link, sign(next, 20, now)}}); a.Error != "" {
		t.Fatalf("the new root's credential: %+v", a)
	}
	if a := register(g, gpin, hub, hubAuth{creds: []group.Credential{sign(root, 15, now)}}); !strings.Contains(a.Error, "older") {
		t.Errorf("the old root's credential after the handover: %+v", a)
	}
	rival, _ := group.NewRootCA(now)
	rivalLink, _ := group.SignLink(tag, rival.Cert, rogueKey)
	if a := register(g, gpin, hub, hubAuth{creds: []group.Credential{old, rivalLink, sign(rival, 1000, now)}}); !strings.Contains(a.Error, "replaced") {
		t.Errorf("another heir's handover after the first: %+v", a)
	}
	strangerKey, _ := group.NewKey()
	strangerLink, _ := group.SignLink(tag, rival.Cert, strangerKey)
	if a := register(f, pin, hub, hubAuth{creds: []group.Credential{sign(root, 30, now), strangerLink, sign(rival, 31, now)}}); !strings.Contains(a.Error, "do not verify") {
		t.Errorf("a link that no heir signed: %+v", a)
	}

	// The state names neither the group nor its roots.
	b, err := os.ReadFile(state)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []string{tag, hex.EncodeToString(root.Cert.RawSubjectPublicKeyInfo[:16]), group.Tag(next.Cert)} {
		if strings.Contains(string(b), c) {
			t.Errorf("the state file holds %q: %s", c, b)
		}
	}
}

// TestRemoveGroupFiles checks that the files earlier versions kept for each
// group are deleted, and nothing else.
func TestRemoveGroupFiles(t *testing.T) {
	dir := t.TempDir()
	groups := filepath.Join(dir, "groups")
	os.Mkdir(groups, 0o700)
	for _, name := range []string{"0123456789abcdef.json", "fedcba9876543210.json.tmp"} {
		os.WriteFile(filepath.Join(groups, name), []byte("[]"), 0o600)
	}
	if n, err := RemoveGroupFiles(groups); n != 2 || err != nil {
		t.Errorf("removed %d: %v", n, err)
	}
	if _, err := os.Stat(groups); !os.IsNotExist(err) {
		t.Errorf("the empty directory stayed: %v", err)
	}
	os.Mkdir(groups, 0o700)
	os.WriteFile(filepath.Join(groups, "notes.txt"), nil, 0o600)
	if n, err := RemoveGroupFiles(groups); n != 0 || err != nil {
		t.Errorf("removed %d: %v", n, err)
	}
	if _, err := os.Stat(filepath.Join(groups, "notes.txt")); err != nil {
		t.Errorf("another file went: %v", err)
	}
}
