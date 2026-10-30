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

// chainOpts shapes the certificates of makeChainOpts.
type chainOpts struct {
	attUsage    x509.KeyUsage // the attestation key's key usage; certificate signing when 0
	attNotCA    bool          // the attestation key's certificate is no CA
	attPathLen  int           // its path length, unlimited when negative
	middle      bool          // a CA between the attestation key and the leaf
	leafRKP     bool          // the provisioning extension on the leaf
	attRKPAbove bool          // the extension on the attestation key's certificate
}

// makeChainOpts makes a chain [leaf, (middle,) attestation key] under a new
// root, shaped by o.
func makeChainOpts(t *testing.T, d description, o chainOpts) chain {
	t.Helper()
	rootKey, attKey, midKey, key := newKey(t), newKey(t), newKey(t), newKey(t)
	ca := &x509.Certificate{Subject: pkix.Name{CommonName: "root"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	root, _ := issue(t, ca, rootKey.Public(), nil, rootKey)
	usage := o.attUsage
	if usage == 0 {
		usage = x509.KeyUsageCertSign
	}
	inter := &x509.Certificate{Subject: pkix.Name{CommonName: "attestation key"}, IsCA: !o.attNotCA, BasicConstraintsValid: true, KeyUsage: usage,
		MaxPathLen: o.attPathLen, MaxPathLenZero: o.attPathLen == 0}
	if o.attRKPAbove {
		inter.ExtraExtensions = []pkix.Extension{{Id: oidProvisioning, Value: []byte{0xa0, 0x00}}}
	}
	att, attDER := issue(t, inter, &attKey.PublicKey, root, rootKey)
	certs := [][]byte{attDER}
	parent, parentKey := att, attKey
	if o.middle {
		mid := &x509.Certificate{Subject: pkix.Name{CommonName: "middle"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, MaxPathLen: -1}
		c, der := issue(t, mid, &midKey.PublicKey, att, attKey)
		certs = append([][]byte{der}, certs...)
		parent, parentKey = c, midKey
	}
	leaf := &x509.Certificate{Subject: pkix.Name{CommonName: "Android Keystore Key"}, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtraExtensions: []pkix.Extension{{Id: oidKeyDescription, Value: d.der(t)}}}
	if o.leafRKP {
		leaf.ExtraExtensions = append(leaf.ExtraExtensions, pkix.Extension{Id: oidProvisioning, Value: []byte{0xa0, 0x00}})
	}
	_, leafDER := issue(t, leaf, &key.PublicKey, parent, parentKey)
	return chain{certs: append([][]byte{leafDER}, certs...), key: key, root: root.RawSubjectPublicKeyInfo, att: attKey, attC: att}
}

// makeLeafSigned makes the chain of a genuine key whose own leaf signs a
// certificate for another key claiming d: [certificate, genuine leaf,
// attestation key]. The genuine leaf is no CA.
func makeLeafSigned(t *testing.T, d description) chain {
	t.Helper()
	genuine := makeChain(t, d, false)
	genuineLeaf, err := x509.ParseCertificate(genuine.certs[0])
	if err != nil {
		t.Fatal(err)
	}
	other := newKey(t)
	tmpl := &x509.Certificate{Subject: pkix.Name{CommonName: "Android Keystore Key"}, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtraExtensions: []pkix.Extension{{Id: oidKeyDescription, Value: d.der(t)}}}
	_, der := issue(t, tmpl, &other.PublicKey, genuineLeaf, genuine.key)
	return chain{certs: [][]byte{der, genuine.certs[0], genuine.certs[1]}, key: other, root: genuine.root, att: genuine.att, attC: genuine.attC}
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

// A certificate that signs another must be a CA that may sign it, with a
// path length that fits; the provisioning extension counts on a CA only.
func TestCheckAndroidIssuers(t *testing.T) {
	ch := []byte("challenge")
	d := description{levelStrongBox, levelStrongBox, ch, true, bootVerified, false}
	for _, c := range []struct {
		name   string
		chain  func() chain
		strict bool
		ok     bool
		rkp    bool
	}{
		{"a genuine leaf signs another", func() chain { return makeLeafSigned(t, d) }, false, false, false},
		{"an issuer that is no CA", func() chain { return makeChainOpts(t, d, chainOpts{attNotCA: true, attPathLen: -1}) }, false, false, false},
		{"an issuer that may not sign", func() chain {
			return makeChainOpts(t, d, chainOpts{attUsage: x509.KeyUsageDigitalSignature, attPathLen: -1})
		}, false, false, false},
		{"a path length that is too short", func() chain { return makeChainOpts(t, d, chainOpts{middle: true, attPathLen: 0}) }, false, false, false},
		{"a path length that fits", func() chain { return makeChainOpts(t, d, chainOpts{middle: true, attPathLen: 1}) }, false, true, false},
		{"no path length", func() chain { return makeChainOpts(t, d, chainOpts{middle: true, attPathLen: -1}) }, false, true, false},
		{"a path length of zero over the leaf", func() chain { return makeChainOpts(t, d, chainOpts{attPathLen: 0}) }, false, true, false},
		{"provisioning on the leaf", func() chain { return makeChainOpts(t, d, chainOpts{leafRKP: true, attPathLen: -1}) }, true, true, false},
		{"provisioning on a CA", func() chain { return makeChainOpts(t, d, chainOpts{attRKPAbove: true, attPathLen: -1}) }, true, true, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			k := c.chain()
			r, err := CheckAndroid(k.certs, spki(t, k.key), ch, Policy{Strict: c.strict, Roots: [][]byte{k.root}})
			if (err == nil) != c.ok || (err != nil && !errors.Is(err, ErrInvalid)) {
				t.Fatalf("CheckAndroid = %+v, %v", r, err)
			}
			if err != nil {
				return
			}
			if r.RKP != c.rkp || (r.Store == StoreProven) != (!c.strict || c.rkp) {
				t.Errorf("got %+v", r)
			}
		})
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
