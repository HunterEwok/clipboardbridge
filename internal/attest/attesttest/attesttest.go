// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Package attesttest makes Android Key Attestation chains for tests: a
// root, an attestation key and a leaf whose key description says a TEE
// key on a phone with a locked bootloader and a verified boot.
package attesttest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"time"
)

// Android returns a chain, leaf first, that attests the key pub with
// challenge, and the SubjectPublicKeyInfo of its root.
func Android(pub any, challenge []byte) (chain [][]byte, root []byte, err error) {
	desc, err := description(challenge)
	if err != nil {
		return nil, nil, err
	}
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	attKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	ca := func(name string, serial int64) *x509.Certificate {
		return &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name},
			NotBefore: time.Unix(0, 0), NotAfter: time.Date(2048, 1, 1, 0, 0, 0, 0, time.UTC),
			IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	}
	rootTmpl := ca("root", 1)
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		return nil, nil, err
	}
	rootCert, _ := x509.ParseCertificate(rootDER)
	attDER, err := x509.CreateCertificate(rand.Reader, ca("attestation key", 2), rootCert, &attKey.PublicKey, rootKey)
	if err != nil {
		return nil, nil, err
	}
	attCert, _ := x509.ParseCertificate(attDER)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "Android Keystore Key"},
		NotBefore: time.Unix(0, 0), NotAfter: time.Date(2048, 1, 1, 0, 0, 0, 0, time.UTC), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 1, 17}, Value: desc}}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, attCert, pub, attKey)
	if err != nil {
		return nil, nil, err
	}
	return [][]byte{leafDER, attDER}, rootCert.RawSubjectPublicKeyInfo, nil
}

// description is a KeyDescription of a TEE key with a root of trust that
// says a locked bootloader and a verified boot.
func description(challenge []byte) ([]byte, error) {
	root, err := asn1.Marshal(struct {
		Key    []byte
		Locked bool
		State  asn1.Enumerated
		Hash   []byte
	}{make([]byte, 32), true, 0, make([]byte, 32)})
	if err != nil {
		return nil, err
	}
	hw, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 704, IsCompound: true, Bytes: root})
	if err != nil {
		return nil, err
	}
	var body []byte
	for _, v := range []any{
		300, asn1.Enumerated(1), 300, asn1.Enumerated(1), challenge, []byte{},
		asn1.RawValue{Tag: asn1.TagSequence, IsCompound: true},
		asn1.RawValue{Tag: asn1.TagSequence, IsCompound: true, Bytes: hw},
	} {
		b, err := asn1.Marshal(v)
		if err != nil {
			return nil, err
		}
		body = append(body, b...)
	}
	return asn1.Marshal(asn1.RawValue{Tag: asn1.TagSequence, IsCompound: true, Bytes: body})
}
