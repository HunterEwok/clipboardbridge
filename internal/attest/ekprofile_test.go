// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package attest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"
)

// Only a certificate in the form of TCG's EK profile passes as an EK's,
// whatever CA of a TPM's maker issued it.
func TestEKProfile(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dirName := func(oid asn1.ObjectIdentifier) []byte {
		dn, err := asn1.Marshal(pkix.Name{ExtraNames: []pkix.AttributeTypeAndValue{{Type: oid, Value: "id:54455354"}}}.ToRDNSequence())
		if err != nil {
			t.Fatal(err)
		}
		san, err := asn1.Marshal([]asn1.RawValue{{Class: asn1.ClassContextSpecific, Tag: 4, IsCompound: true, Bytes: dn}})
		if err != nil {
			t.Fatal(err)
		}
		return san
	}
	maker := dirName(oidTPMManufacturer)
	cert := func(f func(*x509.Certificate)) *x509.Certificate {
		tmpl := &x509.Certificate{
			SerialNumber:    big.NewInt(1),
			NotBefore:       time.Now().Add(-time.Hour),
			NotAfter:        time.Now().Add(time.Hour),
			KeyUsage:        x509.KeyUsageKeyAgreement,
			ExtraExtensions: []pkix.Extension{{Id: oidSubjectAltName, Critical: true, Value: maker}},
		}
		f(tmpl)
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		c, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	for name, c := range map[string]struct {
		cert *x509.Certificate
		ok   bool
	}{
		"an ECC EK":              {cert(func(*x509.Certificate) {}), true},
		"an RSA EK's key usage":  {cert(func(c *x509.Certificate) { c.KeyUsage = x509.KeyUsageKeyEncipherment }), true},
		"the EK purpose":         {cert(func(c *x509.Certificate) { c.UnknownExtKeyUsage = []asn1.ObjectIdentifier{oidEKCertificate} }), true},
		"a CA":                   {cert(func(c *x509.Certificate) { c.IsCA, c.BasicConstraintsValid = true, true }), false},
		"a key that signs certs": {cert(func(c *x509.Certificate) { c.KeyUsage |= x509.KeyUsageCertSign }), false},
		"a signing key":          {cert(func(c *x509.Certificate) { c.KeyUsage = x509.KeyUsageDigitalSignature }), false},
		"no key usage":           {cert(func(c *x509.Certificate) { c.KeyUsage = 0 }), false},
		"another purpose":        {cert(func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth} }), false},
		"any purpose":            {cert(func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageAny} }), false},
		"no TPM maker": {cert(func(c *x509.Certificate) {
			c.ExtraExtensions = []pkix.Extension{{Id: oidSubjectAltName, Critical: true, Value: dirName(asn1.ObjectIdentifier{2, 5, 4, 3})}}
		}), false},
		"no alternative name": {cert(func(c *x509.Certificate) { c.ExtraExtensions = nil }), false},
	} {
		if err := ekProfile(c.cert); (err == nil) != c.ok {
			t.Errorf("%s: %v, want ok %v", name, err, c.ok)
		}
	}
}
