// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tpmtest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport/tcp"
)

// ProvisionEK plays the TPM's maker on the swtpm that Start started: it
// makes a root and an intermediate CA, certifies the TPM's ECC EK under
// them, as makers do with a critical subject alternative name, and writes
// the certificate where makers do (tpmkey.EKIndexECC). It returns the two
// CA certificates, the bundle a verifier needs.
func ProvisionEK(t testing.TB) []*x509.Certificate {
	t.Helper()
	addr := os.Getenv("CBB_TPM_SIMULATOR")
	var host string
	var port int
	if _, err := fmt.Sscanf(addr, "127.0.0.1:%d", &port); err != nil {
		t.Fatalf("CBB_TPM_SIMULATOR=%q: %v", addr, err)
	}
	host = "127.0.0.1"
	tpm, err := tcp.Open(tcp.Config{CommandAddress: addr, PlatformAddress: fmt.Sprintf("%s:%d", host, port+1)})
	if err != nil {
		t.Fatal(err)
	}
	defer tpm.Close()
	ek, err := tpm2.CreatePrimary{PrimaryHandle: tpm2.TPMRHEndorsement, InPublic: tpm2.New2B(tpm2.ECCEKTemplate)}.Execute(tpm)
	if err != nil {
		t.Fatal(err)
	}
	defer tpm2.FlushContext{FlushHandle: ek.ObjectHandle}.Execute(tpm)
	pub, err := ek.OutPublic.Contents()
	if err != nil {
		t.Fatal(err)
	}
	ekKey, err := tpm2.Pub(*pub)
	if err != nil {
		t.Fatal(err)
	}

	root, rootKey := ca(t, "Test TPM Maker Root", nil, nil)
	inter, interKey := ca(t, "Test TPM Maker Intermediate", root, rootKey)
	// The TPM's maker, model and version, as TCG's EK profile puts them.
	san, err := asn1.Marshal([]asn1.RawValue{{Class: asn1.ClassContextSpecific, Tag: 4, IsCompound: true,
		Bytes: mustMarshal(t, pkix.Name{ExtraNames: []pkix.AttributeTypeAndValue{
			{Type: asn1.ObjectIdentifier{2, 23, 133, 2, 1}, Value: "id:54455354"},
			{Type: asn1.ObjectIdentifier{2, 23, 133, 2, 2}, Value: "swtpm"},
			{Type: asn1.ObjectIdentifier{2, 23, 133, 2, 3}, Value: "id:00010000"},
		}}.ToRDNSequence())}})
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:    big.NewInt(3),
		NotBefore:       time.Now().Add(-time.Hour),
		NotAfter:        time.Now().Add(24 * time.Hour),
		KeyUsage:        x509.KeyUsageKeyAgreement,
		ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Critical: true, Value: san}},
	}
	cert, err := x509.CreateCertificate(rand.Reader, tmpl, inter, ekKey, interKey)
	if err != nil {
		t.Fatal(err)
	}

	index := tpm2.TPMHandle(0x01c0000a)
	if _, err := (tpm2.NVDefineSpace{
		AuthHandle: tpm2.TPMRHOwner,
		PublicInfo: tpm2.New2B(tpm2.TPMSNVPublic{
			NVIndex: index,
			NameAlg: tpm2.TPMAlgSHA256,
			Attributes: tpm2.TPMANV{OwnerWrite: true, OwnerRead: true, AuthRead: true, NoDA: true,
				NT: tpm2.TPMNTOrdinary},
			DataSize: uint16(len(cert)),
		}),
	}).Execute(tpm); err != nil {
		t.Fatal(err)
	}
	for off := 0; off < len(cert); off += 512 {
		end := min(off+512, len(cert))
		if _, err := (tpm2.NVWrite{AuthHandle: tpm2.TPMRHOwner, NVIndex: tpm2.NamedHandle{Handle: index, Name: nvName(t, tpm, index)},
			Data: tpm2.TPM2BMaxNVBuffer{Buffer: cert[off:end]}, Offset: uint16(off)}).Execute(tpm); err != nil {
			t.Fatal(err)
		}
	}
	return []*x509.Certificate{root, inter}
}

func nvName(t testing.TB, tpm interface {
	Send([]byte) ([]byte, error)
}, index tpm2.TPMHandle) tpm2.TPM2BName {
	rsp, err := tpm2.NVReadPublic{NVIndex: index}.Execute(tpm)
	if err != nil {
		t.Fatal(err)
	}
	return rsp.NVName
}

func ca(t testing.TB, name string, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	if parent == nil {
		parent, parentKey = tmpl, key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c, key
}

func mustMarshal(t testing.TB, v any) []byte {
	b, err := asn1.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// OtherRoots returns the CA of a maker that certified nothing here.
func OtherRoots(t testing.TB) []*x509.Certificate {
	root, _ := ca(t, "Another TPM Maker", nil, nil)
	return []*x509.Certificate{root}
}

// FileKeyArea returns the public area of a P-256 key that was made outside
// the TPM and may leave it, as one imported from a file would be.
func FileKeyArea(t testing.TB) []byte {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	point, err := key.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	x, y := point[1:33], point[33:]
	return tpm2.Marshal(tpm2.New2B(tpm2.TPMTPublic{
		Type:             tpm2.TPMAlgECC,
		NameAlg:          tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{UserWithAuth: true, SignEncrypt: true},
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC, &tpm2.TPMSECCParms{
			CurveID: tpm2.TPMECCNistP256, Scheme: tpm2.TPMTECCScheme{Scheme: tpm2.TPMAlgNull}}),
		Unique: tpm2.NewTPMUPublicID(tpm2.TPMAlgECC, &tpm2.TPMSECCPoint{
			X: tpm2.TPM2BECCParameter{Buffer: x}, Y: tpm2.TPM2BECCParameter{Buffer: y}}),
	}))
}
