// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package group

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"testing/cryptotest"
	"time"
)

// memberChainsPath is the vectors of a peer's member chain for the Rust
// core's check_member (docs/core-api.md): the chain the peer sends, the
// roots the member trusts, the clock, the side, and the device the check
// gives, or none.
var memberChainsPath = filepath.Join("..", "..", "testdata", "interop", "member-chains.json")

type memberChains struct {
	Comment string        `json:"comment"`
	Cases   []memberChain `json:"cases"`
}

type memberChain struct {
	Name    string   `json:"name"`
	Chain   [][]byte `json:"chain"`
	Trusted [][]byte `json:"trusted"`
	Usage   string   `json:"usage"` // "server": a member this one dialed; "client": one that dialed it
	NowMS   int64    `json:"now_ms"`
	// Device is the device the chain names when it is accepted, "" when
	// it is refused; Used is the leaf and the admin CA that issued it, if
	// one did, which the records then judge.
	Device string   `json:"device"`
	Used   [][]byte `json:"used,omitempty"`
}

// checkMemberChain is the rule the vectors hold: crypto/tls's chain
// building to one of the trusted roots at verifyTime (a clock behind the
// current root, trusted[0], is taken as its start), with the leaf's usage
// listed in its extended key usage, the leaf no CA, an admin CA between
// them only of path length 0 with a P-256 key, and the leaf naming its
// device.
func checkMemberChain(chain [][]byte, trusted [][]byte, usage string, now time.Time) (DeviceID, [][]byte, error) {
	var certs []*x509.Certificate
	for _, der := range chain {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return "", nil, err
		}
		certs = append(certs, c)
	}
	if len(certs) == 0 {
		return "", nil, errors.New("no certificate")
	}
	roots, inter := x509.NewCertPool(), x509.NewCertPool()
	var current *x509.Certificate
	for i, der := range trusted {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return "", nil, err
		}
		if i == 0 {
			current = c
		}
		roots.AddCert(c)
	}
	for _, c := range certs[1:] {
		inter.AddCert(c)
	}
	eku := x509.ExtKeyUsageServerAuth
	if usage == "client" {
		eku = x509.ExtKeyUsageClientAuth
	}
	leaf := certs[0]
	if leaf.IsCA {
		return "", nil, errors.New("a CA as the leaf")
	}
	listed := false
	for _, u := range leaf.ExtKeyUsage {
		listed = listed || u == eku
	}
	if !listed {
		return "", nil, errors.New("not for this use")
	}
	chains, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, CurrentTime: verifyTime(current, now), KeyUsages: []x509.ExtKeyUsage{eku}})
	if err != nil {
		return "", nil, err
	}
	if len(chains) != 1 {
		return "", nil, errors.New("more than one chain")
	}
	used := chains[0][:len(chains[0])-1]
	if len(used) == 2 {
		admin := used[1]
		pub, ok := admin.PublicKey.(*ecdsa.PublicKey)
		if !admin.MaxPathLenZero || admin.MaxPathLen != 0 || admin.KeyUsage&x509.KeyUsageCertSign == 0 || !ok || pub.Curve != elliptic.P256() {
			return "", nil, errors.New("not an admin CA")
		}
	}
	dev, err := DeviceOf(leaf)
	if err != nil {
		return "", nil, err
	}
	var raw [][]byte
	for _, c := range used {
		raw = append(raw, c.Raw)
	}
	return dev, raw, nil
}

// TestMemberChainVectors writes (with -update) and checks
// testdata/interop/member-chains.json.
func TestMemberChainVectors(t *testing.T) {
	if *update {
		cryptotest.SetGlobalRandom(t, 7)
		writeMemberChains(t)
	}
	data, err := os.ReadFile(memberChainsPath)
	if err != nil {
		t.Fatal(err)
	}
	var f memberChains
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatal(err)
	}
	accepted, refused := 0, 0
	for _, c := range f.Cases {
		dev, used, err := checkMemberChain(c.Chain, c.Trusted, c.Usage, time.UnixMilli(c.NowMS))
		if err != nil {
			dev, used = "", nil
			refused++
		} else {
			accepted++
		}
		if string(dev) != c.Device || len(used) != len(c.Used) {
			t.Errorf("%s: device %q (%v), want %q", c.Name, dev, err, c.Device)
			continue
		}
		for i := range used {
			if string(used[i]) != string(c.Used[i]) {
				t.Errorf("%s: used certificate %d differs", c.Name, i)
			}
		}
	}
	if accepted < 5 || refused < 10 {
		t.Fatalf("%d accepted and %d refused cases; the vectors lost their spread", accepted, refused)
	}
}

func writeMemberChains(t *testing.T) {
	t0 := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	day := 24 * time.Hour
	must := func(c *x509.Certificate, err error) *x509.Certificate {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	newRoot := func() *CA {
		ca, err := NewRootCA(t0)
		if err != nil {
			t.Fatal(err)
		}
		return ca
	}
	member := func(ca *CA, id DeviceID) *x509.Certificate {
		k, err := NewKey()
		if err != nil {
			t.Fatal(err)
		}
		return must(ca.IssueMember(id, &k.PublicKey, t0))
	}
	admin := func(root *CA) *CA {
		k, err := NewKey()
		if err != nil {
			t.Fatal(err)
		}
		return &CA{Cert: must(root.IssueAdmin(NewDeviceID(), &k.PublicKey, t0)), Key: k}
	}
	// custom signs tmpl under ca with a new key.
	custom := func(ca *CA, tmpl *x509.Certificate) *CA {
		k, err := NewKey()
		if err != nil {
			t.Fatal(err)
		}
		return &CA{Cert: must(create(tmpl, ca.Cert, &k.PublicKey, ca.Key)), Key: k}
	}
	memberTmpl := func(id DeviceID, eku ...x509.ExtKeyUsage) *x509.Certificate {
		return &x509.Certificate{Subject: pkix.Name{CommonName: string(id)}, DNSNames: []string{id.HostName()},
			NotBefore: t0.Add(-day), NotAfter: t0.Add(700 * day), KeyUsage: x509.KeyUsageDigitalSignature,
			BasicConstraintsValid: true, ExtKeyUsage: eku}
	}
	both := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}

	root, other, second := newRoot(), newRoot(), newRoot()
	adm, otherAdm, secondAdm := admin(root), admin(other), admin(second)
	id := NewDeviceID()
	m := member(root, id)
	viaAdmin := member(adm, NewDeviceID())
	viaOtherAdmin := member(otherAdm, NewDeviceID())
	viaSecond := member(second, NewDeviceID())
	viaSecondAdmin := member(secondAdm, NewDeviceID())
	serverOnly := custom(root, memberTmpl(NewDeviceID(), x509.ExtKeyUsageServerAuth)).Cert
	noEKU := custom(root, memberTmpl(NewDeviceID())).Cert
	noSAN := custom(root, &x509.Certificate{Subject: pkix.Name{CommonName: string(NewDeviceID())}, NotBefore: t0.Add(-day),
		NotAfter: t0.Add(700 * day), KeyUsage: x509.KeyUsageDigitalSignature, BasicConstraintsValid: true, ExtKeyUsage: both}).Cert
	wideAdmin := custom(root, &x509.Certificate{Subject: pkix.Name{CommonName: AdminName(NewDeviceID())}, NotBefore: root.Cert.NotBefore,
		NotAfter: root.Cert.NotAfter, IsCA: true, BasicConstraintsValid: true, MaxPathLen: 1, KeyUsage: x509.KeyUsageCertSign})
	viaWideAdmin := member(wideAdmin, NewDeviceID())
	shortAdmin := custom(root, &x509.Certificate{Subject: pkix.Name{CommonName: AdminName(NewDeviceID())}, NotBefore: t0.Add(-day),
		NotAfter: t0.Add(30 * day), IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign})
	k, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	viaShortAdmin := must(create(memberTmpl(NewDeviceID(), both...), shortAdmin.Cert, &k.PublicKey, shortAdmin.Key))

	at := func(d time.Duration) int64 { return t0.Add(d).UnixMilli() }
	raw := func(cs ...*x509.Certificate) [][]byte {
		var out [][]byte
		for _, c := range cs {
			out = append(out, c.Raw)
		}
		return out
	}
	one := raw(root.Cert)
	cases := []memberChain{
		{Name: "a member, dialed", Chain: raw(m), Trusted: one, Usage: "server", NowMS: at(day)},
		{Name: "a member, dialing", Chain: raw(m), Trusted: one, Usage: "client", NowMS: at(day)},
		{Name: "a member with the root sent too", Chain: raw(m, root.Cert), Trusted: one, Usage: "server", NowMS: at(day)},
		{Name: "a clock years behind", Chain: raw(m), Trusted: one, Usage: "server", NowMS: 0},
		{Name: "expired", Chain: raw(m), Trusted: one, Usage: "server", NowMS: at(3 * 365 * day)},
		{Name: "through an admin CA", Chain: raw(viaAdmin, adm.Cert), Trusted: one, Usage: "client", NowMS: at(day)},
		{Name: "through an admin CA after another certificate", Chain: raw(viaAdmin, m, adm.Cert), Trusted: one, Usage: "server", NowMS: at(day)},
		{Name: "the admin CA left out", Chain: raw(viaAdmin), Trusted: one, Usage: "server", NowMS: at(day)},
		{Name: "an admin CA of another group", Chain: raw(viaOtherAdmin, otherAdm.Cert), Trusted: one, Usage: "server", NowMS: at(day)},
		{Name: "another group's member", Chain: raw(member(other, NewDeviceID())), Trusted: one, Usage: "server", NowMS: at(day)},
		{Name: "the second root's member", Chain: raw(viaSecond), Trusted: raw(second.Cert, root.Cert), Usage: "server", NowMS: at(day)},
		{Name: "the second root's admin", Chain: raw(viaSecondAdmin, secondAdm.Cert), Trusted: raw(second.Cert, root.Cert), Usage: "server", NowMS: at(day)},
		{Name: "the first root's member after a takeover", Chain: raw(m), Trusted: raw(second.Cert, root.Cert), Usage: "client", NowMS: at(day)},
		{Name: "an admin CA as the leaf", Chain: raw(adm.Cert), Trusted: one, Usage: "server", NowMS: at(day)},
		{Name: "the root as the leaf", Chain: raw(root.Cert), Trusted: one, Usage: "server", NowMS: at(day)},
		{Name: "server use only, dialing", Chain: raw(serverOnly), Trusted: one, Usage: "client", NowMS: at(day)},
		{Name: "server use only, dialed", Chain: raw(serverOnly), Trusted: one, Usage: "server", NowMS: at(day)},
		{Name: "no extended key usage", Chain: raw(noEKU), Trusted: one, Usage: "server", NowMS: at(day)},
		{Name: "no DNS name", Chain: raw(noSAN), Trusted: one, Usage: "server", NowMS: at(day)},
		{Name: "an admin CA of path length 1", Chain: raw(viaWideAdmin, wideAdmin.Cert), Trusted: one, Usage: "server", NowMS: at(day)},
		{Name: "an expired admin CA", Chain: raw(viaShortAdmin, shortAdmin.Cert), Trusted: one, Usage: "server", NowMS: at(60 * day)},
		{Name: "an admin CA in time", Chain: raw(viaShortAdmin, shortAdmin.Cert), Trusted: one, Usage: "server", NowMS: at(10 * day)},
		{Name: "no certificate", Chain: [][]byte{}, Trusted: one, Usage: "server", NowMS: at(day)},
	}
	for i := range cases {
		c := &cases[i]
		dev, used, err := checkMemberChain(c.Chain, c.Trusted, c.Usage, time.UnixMilli(c.NowMS))
		if err == nil {
			c.Device, c.Used = string(dev), used
		}
	}
	data, err := json.MarshalIndent(memberChains{
		Comment: "Written by internal/group's TestMemberChainVectors -update: a peer's member chain and the device the check gives, \"\" when it refuses it (docs/core-api.md, check_member).",
		Cases:   cases,
	}, "", "\t")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(memberChainsPath, append(data, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}
