// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"github.com/HunterEwok/clipboardbridge/internal/control"
	"github.com/HunterEwok/clipboardbridge/internal/release"
)

// releaseSigner signs releases under a root of its own, as
// tools/release-sign drill does.
type releaseSigner struct {
	root, key *ecdsa.PrivateKey
}

func newReleaseSigner(t *testing.T) *releaseSigner {
	t.Helper()
	var s releaseSigner
	var err error
	if s.root, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
		t.Fatal(err)
	}
	if s.key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
		t.Fatal(err)
	}
	return &s
}

func (s *releaseSigner) roots(t *testing.T) [][]byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(&s.root.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return [][]byte{der}
}

// sign returns the signed files of version on the stable channel at seq.
func (s *releaseSigner) sign(t *testing.T, version string, seq uint64) *control.Release {
	t.Helper()
	key, err := x509.MarshalPKIXPublicKey(&s.key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Now().Add(-time.Minute).UnixMilli()
	life := (30 * 24 * time.Hour).Milliseconds()
	keys, err := release.Sign(release.Keys{V: 1, Type: release.TypeKeys, Seq: 1, TimeMS: at, ExpiresMS: at + life,
		Keys: []release.Key{{Key: key, Name: "test"}}}, s.root)
	if err != nil {
		t.Fatal(err)
	}
	rel, err := release.Sign(release.Release{V: 1, Type: release.TypeRelease, Version: version, Channel: "stable", TimeMS: at,
		Files: []release.Asset{{Name: "clipboardbridge-linux-amd64.tar.gz", Size: 1, SHA256: hex.EncodeToString(make([]byte, 32))}}}, s.key)
	if err != nil {
		t.Fatal(err)
	}
	h := rel.Hash()
	ch, err := release.Sign(release.Channel{V: 1, Type: release.TypeChannel, Channel: "stable", Seq: seq, TimeMS: at,
		ExpiresMS: at + life, Release: version, ReleaseSHA256: hex.EncodeToString(h[:])}, s.key)
	if err != nil {
		t.Fatal(err)
	}
	return &control.Release{Keys: keys, Channel: ch, Release: rel}
}

// TestReleaseSpreads hands a signed release to one member, as cbb update
// does: a member connected then and one that joins later get it, keep it
// across a restart, and take no older or forged one.
func TestReleaseSpreads(t *testing.T) {
	signer := newReleaseSigner(t)
	roots := signer.roots(t)
	withRoots := func(c *Config) { c.ReleaseRoots = roots }
	var h hub
	pi := startWith(t, &h, "pi", "linux", withRoots)
	pc := startWith(t, &h, "pc", "linux", withRoots)
	pairWith(t, pi, pc)
	waitFor(t, "pc is connected", func() bool { return len(pi.status(t).Peers) == 1 })

	if _, err := pi.do(t, control.Header{Op: control.OpRelease}, releaseJSON(t, signer.sign(t, "0.6.1", 2))); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "pc holds 0.6.1", func() bool { return pc.status(t).Release == "0.6.1" })
	if st := pi.status(t); st.Release != "0.6.1" || st.Update != "" {
		// A development build is offered nothing.
		t.Errorf("pi holds %q, offers %q", st.Release, st.Update)
	}

	if _, err := pc.do(t, control.Header{Op: control.OpRelease}, releaseJSON(t, signer.sign(t, "0.6.0", 1))); err == nil {
		t.Error("pc took an older channel file")
	}
	forged := signer.sign(t, "0.6.2", 3)
	forged.Release.Sig[len(forged.Release.Sig)-1] ^= 1
	if _, err := pc.do(t, control.Header{Op: control.OpRelease}, releaseJSON(t, forged)); err == nil {
		t.Error("pc took a forged release")
	}
	other := newReleaseSigner(t)
	if _, err := pc.do(t, control.Header{Op: control.OpRelease}, releaseJSON(t, other.sign(t, "0.6.2", 3))); err == nil {
		t.Error("pc took a release under other roots")
	}
	if got := pc.status(t).Release; got != "0.6.1" {
		t.Errorf("pc holds %q after the refused ones", got)
	}

	mac := startWith(t, &h, "mac", "linux", withRoots)
	pairWith(t, pi, mac)
	waitFor(t, "mac, joining later, holds 0.6.1", func() bool { return mac.status(t).Release == "0.6.1" })

	pc.stop()
	pc = restartService(t, &h, pc)
	if got := pc.status(t).Release; got != "0.6.1" {
		t.Errorf("pc holds %q after a restart", got)
	}
}

func releaseJSON(t *testing.T, r *control.Release) string {
	t.Helper()
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
