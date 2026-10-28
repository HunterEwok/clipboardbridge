// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package release

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Yubico's PIV attestation extensions.
var (
	oidFirmware = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 3, 3}
	oidSerial   = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 3, 7}
	oidPolicy   = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 3, 8}
)

func readCerts(t *testing.T, name string) []*x509.Certificate {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("roots", "attestation", name))
	if err != nil {
		t.Fatal(err)
	}
	var certs []*x509.Certificate
	for {
		var b *pem.Block
		if b, data = pem.Decode(data); b == nil {
			return certs
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		certs = append(certs, c)
	}
}

func extension(c *x509.Certificate, oid asn1.ObjectIdentifier) []byte {
	for _, e := range c.Extensions {
		if e.Id.Equal(oid) {
			return e.Value
		}
	}
	return nil
}

// TestRootsAttested checks that each root key was made on a YubiKey,
// with the PIN and a touch for every signature (roots/README.md).
func TestRootsAttested(t *testing.T) {
	if len(Roots) != 2 {
		t.Fatalf("%d roots, want 2", len(Roots))
	}
	pool := x509.NewCertPool()
	for _, c := range readCerts(t, "yubico-root.pem") {
		pool.AddCert(c)
	}
	inter := x509.NewCertPool()
	for _, c := range append(readCerts(t, "yubico-intermediates.pem"), readCerts(t, "yubikey-f9.pem")...) {
		inter.AddCert(c)
	}
	serials := []int64{36667388, 36667392}
	for i, spki := range Roots {
		pub, err := x509.ParsePKIXPublicKey(spki)
		if k, ok := pub.(*ecdsa.PublicKey); err != nil || !ok || k.Curve != elliptic.P256() {
			t.Fatalf("root %d is not a P-256 key: %v", i+1, err)
		}
		name := "root-" + strconv.Itoa(i+1) + ".pem"
		certs := readCerts(t, name)
		if len(certs) != 1 {
			t.Fatalf("%s holds %d certificates", name, len(certs))
		}
		c := certs[0]
		if !bytes.Equal(c.RawSubjectPublicKeyInfo, spki) {
			t.Errorf("%s attests another key than root %d", name, i+1)
		}
		_, err = c.Verify(x509.VerifyOptions{Roots: pool, Intermediates: inter,
			CurrentTime: time.Date(2026, 10, 28, 0, 0, 0, 0, time.UTC), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
		if err != nil {
			t.Errorf("%s does not lead to Yubico's root: %v", name, err)
		}
		if p := extension(c, oidPolicy); !bytes.Equal(p, []byte{3, 2}) {
			t.Errorf("%s: PIN and touch policies %x, want always (3) and always (2)", name, p)
		}
		var serial int64
		if _, err := asn1.Unmarshal(extension(c, oidSerial), &serial); err != nil || serial != serials[i] {
			t.Errorf("%s: serial %d (%v), want %d", name, serial, err, serials[i])
		}
		if fw := extension(c, oidFirmware); !bytes.Equal(fw, []byte{5, 7, 4}) {
			t.Errorf("%s: firmware %v", name, fw)
		}
	}
}

// TestRootCopies checks the copies of the roots that the installers, the
// lite member and the phone kits carry.
func TestRootCopies(t *testing.T) {
	read := func(p string) string {
		data, err := os.ReadFile(filepath.Join("..", "..", filepath.FromSlash(p)))
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	pemText := strings.TrimSpace(string(rootsPEM))
	if !strings.Contains(read("packaging/get.sh"), "release_roots='"+pemText+"'") {
		t.Error("packaging/get.sh: release_roots is not roots/roots.pem")
	}
	b64 := regexp.MustCompile(`"(MF[A-Za-z0-9+/=]{100,})"|'(MF[A-Za-z0-9+/=]{100,})'`)
	for _, p := range []string{
		"packaging/windows/get.ps1",
		"apps/android/kit/src/main/kotlin/io/github/hunterewok/clipboardbridge/kit/Releases.kt",
		"apps/ios/ClipboardBridgeKit/Sources/ClipboardBridgeKit/Releases.swift",
	} {
		var got [][]byte
		for _, m := range b64.FindAllStringSubmatch(read(p), -1) {
			der, err := base64.StdEncoding.DecodeString(m[1] + m[2])
			if err != nil {
				t.Fatalf("%s: %v", p, err)
			}
			got = append(got, der)
		}
		if !sameRoots(got) {
			t.Errorf("%s: the roots are not roots/roots.pem", p)
		}
	}
	rust := read("lite/src/update.rs")
	_, rest, ok := strings.Cut(rust, "pub const ROOTS: &[&[u8]] = &[")
	body, _, ok2 := strings.Cut(rest, "\n];")
	if !ok || !ok2 {
		t.Fatal("lite/src/update.rs: no ROOTS")
	}
	var got [][]byte
	for _, block := range strings.Split(body, "&[")[1:] {
		var der []byte
		for _, h := range regexp.MustCompile(`0x([0-9a-f]{2})`).FindAllStringSubmatch(block, -1) {
			v, _ := strconv.ParseUint(h[1], 16, 8)
			der = append(der, byte(v))
		}
		got = append(got, der)
	}
	if !sameRoots(got) {
		t.Error("lite/src/update.rs: ROOTS are not roots/roots.pem")
	}
}

func sameRoots(got [][]byte) bool {
	if len(got) != len(Roots) {
		return false
	}
	for i := range got {
		if !bytes.Equal(got[i], Roots[i]) {
			return false
		}
	}
	return true
}
