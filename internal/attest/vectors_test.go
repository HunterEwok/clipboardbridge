// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package attest

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"testing"
)

var update = flag.Bool("update", false, "rewrite testdata/interop/go-attest.json")

// vector is one Android attestation and what CheckAndroid makes of it.
type vector struct {
	Name      string   `json:"name"`
	Chain     [][]byte `json:"chain"`
	SPKI      []byte   `json:"spki"`
	Challenge []byte   `json:"challenge"`
	// Roots are the roots to check against; Google's when null.
	Roots   [][]byte `json:"roots"`
	Strict  bool     `json:"strict,omitempty"`
	Revoked []string `json:"revoked,omitempty"`
	OK      bool     `json:"ok"`
	Store   string   `json:"store,omitempty"`
	Kind    string   `json:"kind,omitempty"`
	RKP     bool     `json:"rkp,omitempty"`
	Serials []string `json:"serials,omitempty"`
}

type challengeVector struct {
	GroupTag  string `json:"group_tag"`
	MemberKey []byte `json:"member_key"`
	Salt      []byte `json:"salt"`
	Challenge []byte `json:"challenge"`
}

// evidenceVector is an attestation of a member key made outside a group
// with an all-zero salt, as the evidence message carries it, and its root:
// the kits record it as proven.
type evidenceVector struct {
	Salt  []byte   `json:"salt"`
	Chain [][]byte `json:"chain"`
	Root  []byte   `json:"root"`
}

type vectors struct {
	GoogleRoots [][]byte          `json:"google_roots"`
	Challenges  []challengeVector `json:"challenges"`
	Vectors     []vector          `json:"vectors"`
	Evidence    evidenceVector    `json:"evidence"`
}

func makeVectors(t *testing.T) vectors {
	t.Helper()
	v := vectors{GoogleRoots: GoogleRoots}
	salt := make([]byte, 16)
	for i := range salt {
		salt[i] = byte(i)
	}
	for _, c := range []struct {
		tag string
		key []byte
	}{{"ab", []byte{1}}, {"a", []byte("b\x01")}, {"", nil}} {
		ch, err := Challenge(c.tag, c.key, salt)
		if err != nil {
			t.Fatal(err)
		}
		v.Challenges = append(v.Challenges, challengeVector{c.tag, c.key, salt, ch})
	}

	ch := []byte("challenge of 32 bytes, as a hash")
	good := description{attestation: levelTEE, keyMint: levelTEE, challenge: ch, locked: true, boot: bootVerified}
	add := func(name string, k chain, spki, challenge []byte, roots [][]byte, strict bool, revoked []string) {
		r, err := CheckAndroid(k.certs, spki, challenge, Policy{Strict: strict, Roots: roots, Revoked: set(revoked)})
		if err != nil && !errors.Is(err, ErrInvalid) {
			t.Fatalf("%s: %v", name, err)
		}
		v.Vectors = append(v.Vectors, vector{
			Name: name, Chain: k.certs, SPKI: spki, Challenge: challenge, Roots: roots, Strict: strict, Revoked: revoked,
			OK: err == nil, Store: r.Store, Kind: r.Kind, RKP: r.RKP, Serials: r.Serials,
		})
	}
	valid := func(name string, d description, rkp, strict bool) {
		k := makeChain(t, d, rkp)
		add(name, k, spki(t, k.key), ch, [][]byte{k.root}, strict, nil)
	}
	valid("TEE", good, false, false)
	valid("StrongBox", description{levelStrongBox, levelStrongBox, ch, true, bootVerified, false}, false, false)
	valid("StrongBox attests a TEE key", description{levelStrongBox, levelTEE, ch, true, bootVerified, false}, false, false)
	valid("strict wants RKP", good, false, true)
	valid("strict with RKP", good, true, true)
	valid("unlocked", description{levelTEE, levelTEE, ch, false, 2, false}, false, false)
	valid("own boot key", description{levelTEE, levelTEE, ch, true, bootSelfSigned, false}, false, false)
	valid("boot failed", description{levelTEE, levelTEE, ch, true, 3, false}, false, false)
	valid("no root of trust", description{levelTEE, levelTEE, ch, true, 0, true}, false, false)
	valid("software", description{levelSoftware, levelSoftware, ch, true, bootVerified, false}, false, false)
	valid("software KeyMint", description{levelTEE, levelSoftware, ch, true, bootVerified, false}, false, false)

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	k := makeChainUnder(t, rsaKey, good, false)
	add("an RSA root", k, spki(t, k.key), ch, [][]byte{k.root}, false, nil)

	k = makeChain(t, good, false)
	other := makeChain(t, good, false)
	roots := [][]byte{k.root}
	add("Google's roots", k, spki(t, k.key), ch, nil, false, nil)
	add("another key", k, spki(t, newKey(t)), ch, roots, false, nil)
	add("another challenge", k, spki(t, k.key), []byte("another challenge"), roots, false, nil)
	add("a leaf alone", chain{certs: k.certs[:1]}, spki(t, k.key), ch, roots, false, nil)
	add("mixed chains", chain{certs: [][]byte{k.certs[0], other.certs[1]}}, spki(t, k.key), ch, [][]byte{other.root}, false, nil)
	add("a certificate twice", chain{certs: [][]byte{k.certs[0], k.certs[1], k.certs[1]}}, spki(t, k.key), ch, roots, false, nil)
	att, _ := x509.ParseCertificate(k.certs[1])
	add("a revoked attestation key", k, spki(t, k.key), ch, roots, false, []string{serial(att.SerialNumber)})
	leaf, _ := x509.ParseCertificate(k.certs[0])
	add("a revoked leaf", k, spki(t, k.key), ch, roots, false, []string{serial(leaf.SerialNumber)})
	add("another revoked serial", k, spki(t, k.key), ch, roots, false, []string{"1"})
	add("garbage", chain{certs: [][]byte{{1}, {2}}}, spki(t, k.key), ch, roots, false, nil)
	zero := make([]byte, 16)
	evCh, _ := Challenge("", nil, zero)
	ev := makeChain(t, description{levelTEE, levelTEE, evCh, true, bootVerified, false}, false)
	v.Evidence = evidenceVector{Salt: zero, Chain: ev.certs, Root: ev.root}
	noDesc := makeChain(t, good, false)
	noDesc.certs[0] = withoutDescription(t, noDesc)
	add("no key description", noDesc, spki(t, noDesc.key), ch, [][]byte{noDesc.root}, false, nil)
	return v
}

func set(serials []string) map[string]bool {
	if serials == nil {
		return nil
	}
	m := map[string]bool{}
	for _, s := range serials {
		m[s] = true
	}
	return m
}

// withoutDescription issues k's leaf again without its key description.
func withoutDescription(t *testing.T, k chain) []byte {
	t.Helper()
	tmpl := &x509.Certificate{Subject: pkix.Name{CommonName: "Android Keystore Key"}, KeyUsage: x509.KeyUsageDigitalSignature}
	_, der := issue(t, tmpl, &k.key.PublicKey, k.attC, k.att)
	return der
}

// TestAttestVectors writes (with -update) and checks
// testdata/interop/go-attest.json, for the phone kits to agree with.
func TestAttestVectors(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "interop", "go-attest.json")
	if *update {
		data, err := json.MarshalIndent(makeVectors(t), "", "\t")
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
	var v vectors
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.GoogleRoots) != len(GoogleRoots) || len(v.Vectors) != 23 || len(v.Challenges) != 3 {
		t.Fatalf("the file has %d roots, %d vectors, %d challenges", len(v.GoogleRoots), len(v.Vectors), len(v.Challenges))
	}
	for i, r := range v.GoogleRoots {
		if !bytes.Equal(r, GoogleRoots[i]) {
			t.Errorf("Google's root %d differs", i)
		}
	}
	for _, c := range v.Challenges {
		if got, _ := Challenge(c.GroupTag, c.MemberKey, c.Salt); !bytes.Equal(got, c.Challenge) {
			t.Errorf("the challenge of %q differs", c.GroupTag)
		}
	}
	e := v.Evidence
	leaf, err := x509.ParseCertificate(e.Chain[0])
	if err != nil {
		t.Fatal(err)
	}
	evCh, _ := Challenge("", nil, e.Salt)
	if r, err := CheckAndroid(e.Chain, leaf.RawSubjectPublicKeyInfo, evCh, Policy{Roots: [][]byte{e.Root}}); err != nil || r.Store != StoreProven {
		t.Errorf("the evidence vector: %+v %v", r, err)
	}
	for _, c := range v.Vectors {
		r, err := CheckAndroid(c.Chain, c.SPKI, c.Challenge, Policy{Strict: c.Strict, Roots: c.Roots, Revoked: set(c.Revoked)})
		if (err == nil) != c.OK {
			t.Errorf("%s: CheckAndroid = %v, the file says ok %v", c.Name, err, c.OK)
			continue
		}
		if err == nil && (r.Store != c.Store || r.Kind != c.Kind || r.RKP != c.RKP || len(r.Serials) != len(c.Serials)) {
			t.Errorf("%s: got %+v, the file has %+v", c.Name, r, c)
		}
	}
}
