// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tpmkey_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/HunterEwok/clipboardbridge/internal/tpmkey"
	"github.com/HunterEwok/clipboardbridge/internal/tpmkey/tpmtest"
)

func TestKey(t *testing.T) {
	tpmtest.Start(t)
	tpm, err := tpmkey.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer tpm.Close()
	k, err := tpm.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	pub := k.Public().(*ecdsa.PublicKey)
	for _, h := range []crypto.Hash{crypto.SHA256, crypto.SHA384} {
		var d []byte
		if h == crypto.SHA256 {
			s := sha256.Sum256([]byte("hello"))
			d = s[:]
		} else {
			s := sha512.Sum384([]byte("hello"))
			d = s[:]
		}
		sig, err := k.Sign(rand.Reader, d, h)
		if err != nil {
			t.Fatal(err)
		}
		if !ecdsa.VerifyASN1(pub, d, sig) {
			t.Errorf("%v: the signature does not verify", h)
		}
	}

	// The blob loads again after the TPM is opened anew, and signs a TLS
	// handshake.
	blob := k.Blob()
	tpm.Close()
	tpm, err = tpmkey.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer tpm.Close()
	k, err = tpm.LoadKey(blob)
	if err != nil {
		t.Fatal(err)
	}
	if !k.Public().(*ecdsa.PublicKey).Equal(pub) {
		t.Fatal("the loaded key is another")
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "tpm"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"tpm"}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, k)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	a, b := net.Pipe()
	done := make(chan error, 1)
	go func() {
		s := tls.Server(a, &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: k}}})
		done <- s.Handshake()
	}()
	c := tls.Client(b, &tls.Config{RootCAs: pool, ServerName: "tpm"})
	if err := c.Handshake(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}

	// A blob changed by a bit does not load.
	bad := tpmkey.Blob{Public: blob.Public, Private: append([]byte(nil), blob.Private...)}
	bad.Private[len(bad.Private)-1] ^= 1
	if _, err := tpm.LoadKey(bad); err == nil {
		t.Error("a changed blob loaded")
	}
}

func TestSeal(t *testing.T) {
	tpmtest.Start(t)
	tpm, err := tpmkey.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer tpm.Close()
	secret := bytes.Repeat([]byte{0x5a}, 32)
	b, err := tpm.Seal(secret)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(b.Private, secret) || bytes.Contains(b.Public, secret) {
		t.Fatal("the blob holds the data in the clear")
	}
	// Another process, as after a restart, unseals it with the same TPM.
	tpm.Close()
	if tpm, err = tpmkey.Open(); err != nil {
		t.Fatal(err)
	}
	got, err := tpm.Unseal(b)
	if err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("Unseal = %x, %v", got, err)
	}
	if _, err := tpm.Seal(make([]byte, tpmkey.MaxSealed+1)); err == nil {
		t.Error("sealed more than MaxSealed")
	}
	b.Private[len(b.Private)-1] ^= 1
	if _, err := tpm.Unseal(b); err == nil {
		t.Error("unsealed a tampered blob")
	}
	k, err := tpm.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tpm.Unseal(k.Blob()); err == nil {
		t.Error("unsealed a signing key")
	}
}
