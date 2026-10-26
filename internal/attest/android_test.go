// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package attest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"math/big"
	"testing"
	"time"
)

// description is a KeyDescription with the fields CheckAndroid reads.
type description struct {
	attestation, keyMint int
	challenge            []byte
	locked               bool
	boot                 int
	noRoot               bool
}

func (d description) der(t *testing.T) []byte {
	t.Helper()
	m := func(v any) []byte {
		b, err := asn1.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	var hw []byte
	if !d.noRoot {
		root := m(struct {
			Key    []byte
			Locked bool
			State  asn1.Enumerated
			Hash   []byte
		}{make([]byte, 32), d.locked, asn1.Enumerated(d.boot), make([]byte, 32)})
		// Another hardware-enforced field before it, as [1] purpose.
		hw = append(m(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 1, IsCompound: true, Bytes: m([]int{2})}),
			m(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: tagRootOfTrust, IsCompound: true, Bytes: root})...)
	}
	var body []byte
	for _, f := range [][]byte{
		m(300), m(asn1.Enumerated(d.attestation)), m(300), m(asn1.Enumerated(d.keyMint)),
		m(d.challenge), m([]byte{}),
		m(asn1.RawValue{Tag: asn1.TagSequence, IsCompound: true}),
		m(asn1.RawValue{Tag: asn1.TagSequence, IsCompound: true, Bytes: hw}),
	} {
		body = append(body, f...)
	}
	return m(asn1.RawValue{Tag: asn1.TagSequence, IsCompound: true, Bytes: body})
}

type chain struct {
	certs [][]byte
	key   *ecdsa.PrivateKey // the attested key
	root  []byte            // the root's SubjectPublicKeyInfo
	att   *ecdsa.PrivateKey // the attestation key
	attC  *x509.Certificate // and its certificate
}

var serials int64

func issue(t *testing.T, tmpl *x509.Certificate, pub any, parent *x509.Certificate, signer crypto.Signer) (*x509.Certificate, []byte) {
	t.Helper()
	serials++
	tmpl.SerialNumber = big.NewInt(0x1000 + serials)
	tmpl.NotBefore, tmpl.NotAfter = time.Unix(0, 0), time.Date(2048, 1, 1, 0, 0, 0, 0, time.UTC)
	if parent == nil {
		parent = tmpl
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c, der
}

func newKey(t *testing.T) *ecdsa.PrivateKey {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// makeChain makes a root, an attestation key's certificate (with the
// provisioning extension of RKP when rkp) and a leaf for a new key.
func makeChain(t *testing.T, d description, rkp bool) chain {
	t.Helper()
	return makeChainUnder(t, newKey(t), d, rkp)
}

// makeChainUnder makes the chain of makeChain under a root with the key
// rootKey, an ECDSA or RSA key as Google's roots are.
func makeChainUnder(t *testing.T, rootKey crypto.Signer, d description, rkp bool) chain {
	t.Helper()
	attKey, key := newKey(t), newKey(t)
	ca := &x509.Certificate{Subject: pkix.Name{CommonName: "root"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	root, _ := issue(t, ca, rootKey.Public(), nil, rootKey)
	inter := &x509.Certificate{Subject: pkix.Name{CommonName: "attestation key"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	if rkp {
		inter.ExtraExtensions = []pkix.Extension{{Id: oidProvisioning, Value: []byte{0xa0, 0x00}}}
	}
	att, attDER := issue(t, inter, &attKey.PublicKey, root, rootKey)
	leaf := &x509.Certificate{Subject: pkix.Name{CommonName: "Android Keystore Key"}, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtraExtensions: []pkix.Extension{{Id: oidKeyDescription, Value: d.der(t)}}}
	_, leafDER := issue(t, leaf, &key.PublicKey, att, attKey)
	return chain{certs: [][]byte{leafDER, attDER}, key: key, root: root.RawSubjectPublicKeyInfo, att: attKey, attC: att}
}

func spki(t *testing.T, k *ecdsa.PrivateKey) []byte {
	b, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestCheckAndroid(t *testing.T) {
	ch := []byte("challenge")
	good := description{attestation: levelTEE, keyMint: levelTEE, challenge: ch, locked: true, boot: bootVerified}
	for _, c := range []struct {
		name   string
		d      description
		rkp    bool
		strict bool
		store  string
		kind   string
	}{
		{"TEE", good, false, false, StoreProven, KindAndroidTEE},
		{"StrongBox", description{levelStrongBox, levelStrongBox, ch, true, bootVerified, false}, false, false, StoreProven, KindAndroidStrongBox},
		{"strict wants RKP", good, false, true, StoreHardware, KindAndroidTEE},
		{"strict with RKP", good, true, true, StoreProven, KindAndroidTEE},
		{"unlocked", description{levelTEE, levelTEE, ch, false, 2, false}, false, false, StoreHardware, KindAndroidTEE},
		{"own boot key", description{levelTEE, levelTEE, ch, true, bootSelfSigned, false}, false, false, StoreHardware, KindAndroidTEE},
		{"no root of trust", description{levelTEE, levelTEE, ch, true, 0, true}, false, false, StoreHardware, KindAndroidTEE},
		{"software", description{levelSoftware, levelSoftware, ch, true, bootVerified, false}, false, false, StoreFile, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			k := makeChain(t, c.d, c.rkp)
			r, err := CheckAndroid(k.certs, spki(t, k.key), ch, Policy{Strict: c.strict, Roots: [][]byte{k.root}})
			if err != nil {
				t.Fatal(err)
			}
			if r.Store != c.store || r.Kind != c.kind || r.RKP != c.rkp || (r.Why == "") != (c.store == StoreProven) || len(r.Serials) != 2 {
				t.Errorf("got %+v", r)
			}
		})
	}
}

func TestCheckAndroidInvalid(t *testing.T) {
	ch := []byte("challenge")
	k := makeChain(t, description{levelTEE, levelTEE, ch, true, bootVerified, false}, false)
	p := Policy{Roots: [][]byte{k.root}}
	other := makeChain(t, description{levelTEE, levelTEE, ch, true, bootVerified, false}, false)
	for name, f := range map[string]func() error{
		"Google's roots": func() error { _, err := CheckAndroid(k.certs, spki(t, k.key), ch, Policy{}); return err },
		"another key":    func() error { _, err := CheckAndroid(k.certs, spki(t, newKey(t)), ch, p); return err },
		"another challenge": func() error {
			_, err := CheckAndroid(k.certs, spki(t, k.key), []byte("other"), p)
			return err
		},
		"a leaf alone": func() error { _, err := CheckAndroid(k.certs[:1], spki(t, k.key), ch, p); return err },
		"mixed chains": func() error {
			_, err := CheckAndroid([][]byte{k.certs[0], other.certs[1]}, spki(t, k.key), ch, Policy{Roots: [][]byte{other.root}})
			return err
		},
		"revoked": func() error {
			c, _ := x509.ParseCertificate(k.certs[1])
			_, err := CheckAndroid(k.certs, spki(t, k.key), ch, Policy{Roots: p.Roots, Revoked: map[string]bool{serial(c.SerialNumber): true}})
			return err
		},
		"garbage": func() error { _, err := CheckAndroid([][]byte{{1}, {2}}, spki(t, k.key), ch, p); return err },
	} {
		if err := f(); !errors.Is(err, ErrInvalid) || errors.Is(err, ErrRevoked) != (name == "revoked") {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestChallenge(t *testing.T) {
	salt := make([]byte, 16)
	for i := range salt {
		salt[i] = byte(i)
	}
	a, err := Challenge("ab", []byte{1}, salt)
	if err != nil {
		t.Fatal(err)
	}
	// The same value as the Kotlin kit's AttestationTest.
	if got := hex.EncodeToString(a); got != "aac189125c2fbb83190c46e0864cc0c74f3463664c6b0c71bf8911a18a1723d8" {
		t.Errorf("the challenge is %s", got)
	}
	b, _ := Challenge("a", []byte("b\x01"), salt)
	if string(a) == string(b) {
		t.Error("moving bytes between the fields keeps the challenge")
	}
	if _, err := Challenge("", nil, salt[:15]); err == nil {
		t.Error("took a short salt")
	}
}
