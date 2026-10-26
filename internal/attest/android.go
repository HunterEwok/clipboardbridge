// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Package attest checks the proofs that a device's key lives in its
// hardware (docs/protocol.md, section 17). Android's Key Attestation is a
// certificate chain from the Keystore: its leaf certifies the key and
// carries the Keystore's description of it, and the chain leads to one of
// Google's attestation roots.
package attest

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// GoogleRoots are the SubjectPublicKeyInfos of Google's attestation roots,
// as https://android.googleapis.com/attestation/root lists them: the RSA
// root that every chain led to until 2026 (its certificates of 2016, 2019,
// 2021 and 2022 share the key) and the ECDSA P-384 root "Key Attestation
// CA1" that signs new chains since February 2026.
var GoogleRoots = [][]byte{
	mustBase64("MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAr7bHgiuxpwHsK7Qui8xUFmOr75gvMsd/dTEDDJdSSxtf6An7xyqpRR90PL2abxM1dEqlXnf2tqw1Ne4Xwl5jlRfdnJLmN0pTy/4lj4/7tv0Sk3iiKkypnEUtR6WfMgH0QZfKHM1+di+y9TFRtv6y//0rb+T+W8a9nsNL/ggjnar86461qO0rOs2cXjp3kOG1FEJ5MVmFmBGtnrKpa73XpXyTqRxB/M0n1n/W9nGqC4FSYa04T6N5RIZGBN2z2MT5IKGbFlbC8UrW0DxW7AYImQQcHtGl/m00QLVWutHQoVJYnFPlXTcHYvASLu+RhhsbDmxMgJJ0mcDpvsC4PjvB+TxywElgS70vE0XmLD+OJtvsBslHZvPBKCOdT0MS+tgSOIfga+z1Z1g7+DVagf7quvmag8jfPioyKvxnK/EgsTUVi2ghzq8wm27ud/mIM7AY2qEORR8Go3TVB4HzWQgpZrt3i5MIlCaY504LzSRiigHCzAPlHws+W0rB5N+er5/2pJKnfBSDiCiFAVtCLOZ7gLiMm0jhO2B6tUXHI/+MRPjy02i59lINMRRev56GKtcd9qO/0kUJWdZTdA2XoS82ixPvZtXQpUpuL12ab+9EaDK8Z4RHJYYfCT3Q5vNAXaiWQ+8PTWm2QgBR/bkwSWc+NpUFgNPN9PvQi8WEg5UmAGMCAwEAAQ=="),
	mustBase64("MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEI9ojcU7fPlsFCjxy6IRqzgeOoK0b+YsV9FPQywiyw8EQRTkJ9u3qwfnI4DGoSLlBqClTXJfgfCcZvs60FikNMHnu4fkRzObfgDkU2KNXezT9/RQ+XvNslxPHrHCowhGr"),
}

func mustBase64(s string) []byte {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// The stores a check gives a key (group.StoreFile and the others).
const (
	StoreFile     = "file"
	StoreHardware = "hardware"
	StoreProven   = "proven"
)

// The kinds of a proven Android key.
const (
	KindAndroidTEE       = "android-tee"
	KindAndroidStrongBox = "android-strongbox"
)

// Result is what a valid attestation shows about a key.
type Result struct {
	// Store is StoreProven when the attestation proves the key in hardware
	// under the policy; StoreHardware when the Keystore says hardware but
	// the device's boot is not verified (an unlocked bootloader, or a
	// system with its own boot key, as GrapheneOS), or the strict policy
	// wants a chain the device did not get; StoreFile when the Keystore
	// says the key is in software.
	Store string
	// Kind is KindAndroidTEE or KindAndroidStrongBox for a key in hardware.
	Kind string
	// RKP tells that the chain was issued through Remote Key Provisioning,
	// whose attestation keys never leave the TEE.
	RKP bool
	// Why says why the key is not proven; "" when it is.
	Why string
	// Serials are the serial numbers of the chain's certificates, in
	// lowercase hex as Google's revocation list names them, leaf first.
	Serials []string
}

// Policy is what Android checks: Strict, the key level 1, proves only keys
// whose chain came through Remote Key Provisioning. Revoked holds the
// serial numbers, lowercase hex, of revoked certificates.
type Policy struct {
	Strict  bool
	Revoked map[string]bool
	// Roots are the SubjectPublicKeyInfos the chain must lead to;
	// GoogleRoots when nil.
	Roots [][]byte
}

// ErrInvalid is wrapped by every error of an attestation that proves
// nothing: a broken chain, another root, another key or challenge, or a
// revoked certificate.
var ErrInvalid = errors.New("invalid attestation")

func invalid(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, a...))
}

// The OIDs of the Keystore's key description and of the provisioning
// information that RKP attestation keys carry.
var (
	oidKeyDescription = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 1, 17}
	oidProvisioning   = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 1, 30}
)

// The security levels of a key description.
const (
	levelSoftware  = 0
	levelTEE       = 1
	levelStrongBox = 2
)

// The verified boot states of a root of trust.
const (
	bootVerified   = 0
	bootSelfSigned = 1
)

// CheckAndroid checks an Android Key Attestation chain (DER certificates,
// leaf first) for the key spki made with challenge: every certificate is
// signed by the next, the last by one of the policy's roots, none is
// revoked, and the leaf certifies spki and carries challenge. It returns
// what the leaf's key description shows under the policy, or an error
// wrapping ErrInvalid.
func CheckAndroid(chain [][]byte, spki, challenge []byte, p Policy) (Result, error) {
	if len(chain) < 2 || len(chain) > 10 {
		return Result{}, invalid("a chain of %d certificates", len(chain))
	}
	certs := make([]*x509.Certificate, len(chain))
	var res Result
	for i, der := range chain {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return Result{}, invalid("certificate %d: %v", i, err)
		}
		certs[i] = c
		res.Serials = append(res.Serials, serial(c.SerialNumber))
	}
	for i, c := range certs {
		if i+1 < len(certs) {
			if err := certs[i+1].CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature); err != nil {
				return Result{}, invalid("certificate %d is not signed by the next: %v", i, err)
			}
		}
		if p.Revoked[res.Serials[i]] {
			return Result{}, invalid("certificate %d (%s) is revoked", i, res.Serials[i])
		}
		for _, e := range c.Extensions {
			if e.Id.Equal(oidProvisioning) {
				res.RKP = true
			}
		}
	}
	if !toRoot(certs[len(certs)-1], p.Roots) {
		return Result{}, invalid("the chain does not lead to a known root")
	}
	leaf := certs[0]
	if !bytes.Equal(leaf.RawSubjectPublicKeyInfo, spki) {
		return Result{}, invalid("the leaf certifies another key")
	}
	var ext []byte
	for _, e := range leaf.Extensions {
		if e.Id.Equal(oidKeyDescription) {
			ext = e.Value
		}
	}
	if ext == nil {
		return Result{}, invalid("the leaf has no key description")
	}
	kd, err := parseKeyDescription(ext)
	if err != nil {
		return Result{}, invalid("the key description: %v", err)
	}
	if !bytes.Equal(kd.challenge, challenge) {
		return Result{}, invalid("another challenge")
	}
	switch {
	case kd.attestationLevel == levelSoftware || kd.keyMintLevel == levelSoftware:
		res.Store, res.Why = StoreFile, "the Keystore keeps the key in software"
		return res, nil
	case kd.attestationLevel == levelStrongBox && kd.keyMintLevel == levelStrongBox:
		res.Kind = KindAndroidStrongBox
	default:
		res.Kind = KindAndroidTEE
	}
	res.Store = StoreProven
	switch {
	case kd.root == nil:
		res.Store, res.Why = StoreHardware, "the key description has no root of trust"
	case !kd.root.locked:
		res.Store, res.Why = StoreHardware, "the phone's bootloader is unlocked"
	case kd.root.state == bootSelfSigned:
		res.Store, res.Why = StoreHardware, "the phone boots a system signed with its own key"
	case kd.root.state != bootVerified:
		res.Store, res.Why = StoreHardware, "the phone's boot is not verified"
	case p.Strict && !res.RKP:
		res.Store, res.Why = StoreHardware, "the chain did not come through Remote Key Provisioning"
	}
	return res, nil
}

// toRoot reports whether c is signed by one of roots, or is a root itself.
func toRoot(c *x509.Certificate, roots [][]byte) bool {
	if roots == nil {
		roots = GoogleRoots
	}
	for _, r := range roots {
		if bytes.Equal(c.RawSubjectPublicKeyInfo, r) && c.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature) == nil {
			return true
		}
		k, err := x509.ParsePKIXPublicKey(r)
		if err != nil {
			continue
		}
		parent := &x509.Certificate{PublicKey: k}
		if parent.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature) == nil {
			return true
		}
	}
	return false
}

// serial is a certificate's serial number as Google's revocation list
// writes it: lowercase hex without leading zeros.
func serial(n *big.Int) string {
	return strings.ToLower(n.Text(16))
}

// keyDescription is what CheckAndroid reads of the Keystore's
// KeyDescription.
type keyDescription struct {
	attestationLevel, keyMintLevel int
	challenge                      []byte
	root                           *rootOfTrust
}

type rootOfTrust struct {
	locked bool
	state  int
}

// The tag of the root of trust in an AuthorizationList.
const tagRootOfTrust = 704

// parseKeyDescription reads a KeyDescription: attestationVersion,
// attestationSecurityLevel, keyMintVersion (keymasterVersion before),
// keyMintSecurityLevel, attestationChallenge, uniqueId, softwareEnforced
// and hardwareEnforced. Only the hardware-enforced root of trust counts.
func parseKeyDescription(der []byte) (*keyDescription, error) {
	var seq asn1.RawValue
	if rest, err := asn1.Unmarshal(der, &seq); err != nil || len(rest) != 0 || seq.Tag != asn1.TagSequence {
		return nil, errors.New("not a sequence")
	}
	var fields []asn1.RawValue
	for rest := seq.Bytes; len(rest) > 0; {
		var f asn1.RawValue
		var err error
		if rest, err = asn1.Unmarshal(rest, &f); err != nil {
			return nil, err
		}
		fields = append(fields, f)
	}
	if len(fields) < 8 {
		return nil, fmt.Errorf("%d fields", len(fields))
	}
	var kd keyDescription
	var err error
	if kd.attestationLevel, err = enumerated(fields[1]); err != nil {
		return nil, fmt.Errorf("attestationSecurityLevel: %w", err)
	}
	if kd.keyMintLevel, err = enumerated(fields[3]); err != nil {
		return nil, fmt.Errorf("keyMintSecurityLevel: %w", err)
	}
	if fields[4].Class != asn1.ClassUniversal || fields[4].Tag != asn1.TagOctetString {
		return nil, errors.New("attestationChallenge is no octet string")
	}
	kd.challenge = fields[4].Bytes
	hw := fields[7]
	if hw.Tag != asn1.TagSequence {
		return nil, errors.New("hardwareEnforced is no sequence")
	}
	for rest := hw.Bytes; len(rest) > 0; {
		var f asn1.RawValue
		if rest, err = asn1.Unmarshal(rest, &f); err != nil {
			return nil, fmt.Errorf("hardwareEnforced: %w", err)
		}
		if f.Class != asn1.ClassContextSpecific || f.Tag != tagRootOfTrust {
			continue
		}
		var r struct {
			VerifiedBootKey   []byte
			DeviceLocked      bool
			VerifiedBootState asn1.Enumerated
			VerifiedBootHash  []byte `asn1:"optional"`
		}
		if _, err := asn1.Unmarshal(f.Bytes, &r); err != nil {
			return nil, fmt.Errorf("rootOfTrust: %w", err)
		}
		kd.root = &rootOfTrust{locked: r.DeviceLocked, state: int(r.VerifiedBootState)}
	}
	return &kd, nil
}

func enumerated(v asn1.RawValue) (int, error) {
	var e asn1.Enumerated
	if _, err := asn1.Unmarshal(v.FullBytes, &e); err != nil {
		return 0, err
	}
	return int(e), nil
}

// Challenge is the attestation challenge a key is made with
// (docs/protocol.md, section 17): SHA-256 over "cbb attest v1", the group
// tag and the member key's SubjectPublicKeyInfo, each with a two-byte
// big-endian length, and the 16-byte salt.
func Challenge(groupTag string, memberKey, salt []byte) ([]byte, error) {
	if len(salt) != 16 {
		return nil, fmt.Errorf("a salt of %d bytes", len(salt))
	}
	h := sha256.New()
	h.Write([]byte("cbb attest v1"))
	for _, f := range [][]byte{[]byte(groupTag), memberKey} {
		if len(f) > 0xffff {
			return nil, errors.New("a field longer than 65535 bytes")
		}
		h.Write([]byte{byte(len(f) >> 8), byte(len(f))})
		h.Write(f)
	}
	h.Write(salt)
	return h.Sum(nil), nil
}
