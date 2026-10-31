// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package attest

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"

	"github.com/google/go-tpm/tpm2"
)

// KindTPM is the kind of a key proven in a TPM 2.0.
const KindTPM = "tpm"

// TPM evidence (docs/protocol.md, section 17, "TPM evidence") is checked in
// two steps: CheckTPM checks what the device sent and makes a credential
// that only the TPM with that EK and that AK can open; the device opens it,
// and the key is proven when the value it sends back is the one the
// credential holds.

// TPMEvidence is what a device sends of a key in its TPM.
type TPMEvidence struct {
	EKCert    []byte   // the EK's certificate from the TPM's NV, DER
	EKChain   [][]byte // certificates between it and the maker's root, if the device has them
	EK        []byte   // the EK's TPM2B_PUBLIC
	AK        []byte   // the AK's TPM2B_PUBLIC
	Key       []byte   // the certified key's TPM2B_PUBLIC
	Attest    []byte   // the TPMS_ATTEST of TPM2_Certify
	Signature []byte   // the AK's TPMT_SIGNATURE of Attest
}

// TPMCredential is what the verifier sends the device, and Value what the
// device must send back.
type TPMCredential struct {
	Credential []byte // TPM2B_ID_OBJECT's buffer
	Secret     []byte // TPM2B_ENCRYPTED_SECRET's buffer
	Value      []byte // kept by the verifier
}

// TPMPolicy is what a TPM check takes: Roots are the certificates of the
// TPM makers, roots and intermediates, that EK certificates lead to;
// TPMRoots when nil.
type TPMPolicy struct {
	Roots []*x509.Certificate
}

// CheckTPM checks the evidence of the key whose SubjectPublicKeyInfo is
// spki, certified with qualifying data challenge, and returns the result
// the key gets once the device opens the credential.
func CheckTPM(ev TPMEvidence, spki, challenge []byte, p TPMPolicy) (Result, TPMCredential, error) {
	var none TPMCredential
	ekCert, err := checkEKCert(ev.EKCert, ev.EKChain, p.Roots)
	if err != nil {
		return Result{}, none, err
	}
	ek, err := publicArea(ev.EK)
	if err != nil {
		return Result{}, none, invalid("the EK: %v", err)
	}
	if a := ek.ObjectAttributes; !a.FixedTPM || !a.FixedParent || !a.Restricted || !a.Decrypt || a.SignEncrypt {
		return Result{}, none, invalid("the EK is not a TPM's endorsement key")
	}
	if err := sameKey(ek, ekCert); err != nil {
		return Result{}, none, invalid("the EK is not the certificate's: %v", err)
	}
	ak, err := publicArea(ev.AK)
	if err != nil {
		return Result{}, none, invalid("the AK: %v", err)
	}
	if a := ak.ObjectAttributes; !a.FixedTPM || !a.FixedParent || !a.SensitiveDataOrigin || !a.Restricted || !a.SignEncrypt || a.Decrypt {
		return Result{}, none, invalid("the AK is not a restricted signing key made in the TPM")
	}
	akPub, err := tpm2.Pub(*ak)
	if err != nil {
		return Result{}, none, invalid("the AK: %v", err)
	}
	key, err := publicArea(ev.Key)
	if err != nil {
		return Result{}, none, invalid("the key: %v", err)
	}
	if a := key.ObjectAttributes; !a.FixedTPM || !a.FixedParent || !a.SensitiveDataOrigin {
		return Result{}, none, invalid("the key was not made in the TPM or can leave it")
	}
	keyPub, err := tpm2.Pub(*key)
	if err != nil {
		return Result{}, none, invalid("the key: %v", err)
	}
	member, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		return Result{}, none, invalid("the member key: %v", err)
	}
	if mk, ok := member.(*ecdsa.PublicKey); !ok || !mk.Equal(keyPub) {
		return Result{}, none, invalid("the certified key is not the member key")
	}
	if err := checkCertify(ev.Attest, ev.Signature, akPub, key, challenge); err != nil {
		return Result{}, none, err
	}
	akName, err := tpm2.ObjectName(ak)
	if err != nil {
		return Result{}, none, invalid("the AK's name: %v", err)
	}
	encap, err := tpm2.ImportEncapsulationKey(ek)
	if err != nil {
		return Result{}, none, invalid("the EK: %v", err)
	}
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		return Result{}, none, err
	}
	cred, secret, err := tpm2.CreateCredential(rand.Reader, encap, akName.Buffer, value)
	if err != nil {
		return Result{}, none, fmt.Errorf("making the credential: %w", err)
	}
	return Result{Store: StoreProven, Kind: KindTPM}, TPMCredential{Credential: cred, Secret: secret, Value: value}, nil
}

// checkCertify checks that the AK signed a certification of key with
// extra data challenge.
func checkCertify(attest, sig []byte, akPub any, key *tpm2.TPMTPublic, challenge []byte) error {
	ak, ok := akPub.(*ecdsa.PublicKey)
	if !ok {
		return invalid("the AK is not an ECDSA key")
	}
	s, err := tpm2.Unmarshal[tpm2.TPMTSignature](sig)
	if err != nil {
		return invalid("the certification's signature: %v", err)
	}
	e, err := s.Signature.ECDSA()
	if err != nil || s.SigAlg != tpm2.TPMAlgECDSA || e.Hash != tpm2.TPMAlgSHA256 {
		return invalid("the certification is not signed with ECDSA and SHA-256")
	}
	sum := sha256.Sum256(attest)
	if !ecdsa.Verify(ak, sum[:], new(big.Int).SetBytes(e.SignatureR.Buffer), new(big.Int).SetBytes(e.SignatureS.Buffer)) {
		return invalid("the AK did not sign the certification")
	}
	a, err := tpm2.Unmarshal[tpm2.TPMSAttest](attest)
	if err != nil {
		return invalid("the certification: %v", err)
	}
	if a.Magic != tpm2.TPMGeneratedValue || a.Type != tpm2.TPMSTAttestCertify {
		return invalid("the certification was not made by a TPM's TPM2_Certify")
	}
	if !bytes.Equal(a.ExtraData.Buffer, challenge) {
		return invalid("the certification carries another challenge")
	}
	info, err := a.Attested.Certify()
	if err != nil {
		return invalid("the certification: %v", err)
	}
	name, err := tpm2.ObjectName(key)
	if err != nil {
		return invalid("the key's name: %v", err)
	}
	if !bytes.Equal(info.Name.Buffer, name.Buffer) {
		return invalid("the certification names another key")
	}
	return nil
}

func publicArea(b []byte) (*tpm2.TPMTPublic, error) {
	p, err := tpm2.Unmarshal[tpm2.TPM2BPublic](b)
	if err != nil {
		return nil, err
	}
	return p.Contents()
}

// checkEKCert parses an EK certificate and checks that it leads to the
// makers' certificates.
func checkEKCert(der []byte, chain [][]byte, roots []*x509.Certificate) (*x509.Certificate, error) {
	if roots == nil {
		roots = TPMRoots
	}
	if len(roots) == 0 {
		return nil, invalid("no TPM maker's certificate is known")
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, invalid("the EK certificate: %v", err)
	}
	pool, inter := x509.NewCertPool(), x509.NewCertPool()
	for _, r := range roots {
		if bytes.Equal(r.RawSubject, r.RawIssuer) {
			pool.AddCert(r)
		} else {
			inter.AddCert(r)
		}
	}
	for _, d := range chain {
		ic, err := x509.ParseCertificate(d)
		if err != nil {
			return nil, invalid("a certificate of the EK's chain: %v", err)
		}
		inter.AddCert(ic)
	}
	// EK certificates name the TPM in a critical subject alternative
	// name of their own form, which x509 does not handle.
	v := *c
	v.UnhandledCriticalExtensions = nil
	for _, oid := range c.UnhandledCriticalExtensions {
		if !oid.Equal(oidSubjectAltName) {
			v.UnhandledCriticalExtensions = append(v.UnhandledCriticalExtensions, oid)
		}
	}
	if _, err := v.Verify(x509.VerifyOptions{Roots: pool, Intermediates: inter, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		return nil, invalid("the EK certificate leads to no TPM maker: %v", err)
	}
	if err := ekProfile(c); err != nil {
		return nil, invalid("the EK certificate: %v", err)
	}
	return c, nil
}

// ekProfile checks that c is an EK certificate as TCG's EK credential
// profile makes one, not another certificate of a maker's CA: no CA, a key
// for decrypting that signs no certificates, the EK purpose if it names
// purposes, and the TPM's maker in the subject alternative name.
func ekProfile(c *x509.Certificate) error {
	if c.IsCA {
		return errors.New("it is a CA's")
	}
	if c.KeyUsage&(x509.KeyUsageKeyEncipherment|x509.KeyUsageKeyAgreement) == 0 ||
		c.KeyUsage&(x509.KeyUsageCertSign|x509.KeyUsageCRLSign) != 0 {
		return errors.New("its key is not one for decrypting")
	}
	if len(c.ExtKeyUsage) > 0 || len(c.UnknownExtKeyUsage) > 0 {
		ek := false
		for _, u := range c.UnknownExtKeyUsage {
			ek = ek || u.Equal(oidEKCertificate)
		}
		if !ek || len(c.ExtKeyUsage) > 0 {
			return errors.New("it is for another purpose than an EK")
		}
	}
	for _, e := range c.Extensions {
		if e.Id.Equal(oidSubjectAltName) && namesTPMMaker(e.Value) {
			return nil
		}
	}
	return errors.New("it names no TPM maker")
}

// namesTPMMaker tells whether a subject alternative name holds a directory
// name with the TPM's maker (tcg-at-tpmManufacturer).
func namesTPMMaker(san []byte) bool {
	var names []asn1.RawValue
	if rest, err := asn1.Unmarshal(san, &names); err != nil || len(rest) > 0 {
		return false
	}
	for _, n := range names {
		if n.Class != asn1.ClassContextSpecific || n.Tag != 4 {
			continue
		}
		var dn pkix.RDNSequence
		if rest, err := asn1.Unmarshal(n.Bytes, &dn); err != nil || len(rest) > 0 {
			continue
		}
		for _, rdn := range dn {
			for _, a := range rdn {
				if v, ok := a.Value.(string); ok && v != "" && a.Type.Equal(oidTPMManufacturer) {
					return true
				}
			}
		}
	}
	return false
}

var (
	oidSubjectAltName  = asn1.ObjectIdentifier{2, 5, 29, 17}
	oidEKCertificate   = asn1.ObjectIdentifier{2, 23, 133, 8, 1}
	oidTPMManufacturer = asn1.ObjectIdentifier{2, 23, 133, 2, 1}
	oidRSAESOAEP       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 7}
)

// sameKey checks that the public area holds the certificate's key. Some
// makers mark an RSA EK as RSAES-OAEP, which x509 leaves unparsed.
func sameKey(pub *tpm2.TPMTPublic, c *x509.Certificate) error {
	k, err := tpm2.Pub(*pub)
	if err != nil {
		return err
	}
	certKey := c.PublicKey
	if certKey == nil {
		var spki struct {
			Algorithm struct{ Algorithm asn1.ObjectIdentifier }
			Key       asn1.BitString
		}
		if _, err := asn1.Unmarshal(c.RawSubjectPublicKeyInfo, &spki); err != nil || !spki.Algorithm.Algorithm.Equal(oidRSAESOAEP) {
			return errors.New("a key of an unknown kind")
		}
		if certKey, err = x509.ParsePKCS1PublicKey(spki.Key.Bytes); err != nil {
			return err
		}
	}
	switch ck := certKey.(type) {
	case *rsa.PublicKey:
		if ck.Equal(k) {
			return nil
		}
	case *ecdsa.PublicKey:
		if ck.Equal(k) {
			return nil
		}
	}
	return errors.New("another key")
}

// ParseTPMRoots reads the PEM certificates of a roots file.
func ParseTPMRoots(data []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	for {
		var b *pem.Block
		if b, data = pem.Decode(data); b == nil {
			return out, nil
		}
		if b.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
}
