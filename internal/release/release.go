// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Package release reads and checks the signed files that describe a
// release (docs/protocol.md, section 16): keys.json, in which a root key
// certifies the release keys; release.json, which lists a release's files
// with their hashes; and a channel file such as stable.json, which names
// the current release of its channel until it expires.
package release

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// The body types.
const (
	TypeKeys    = "keys"
	TypeRelease = "release"
	TypeChannel = "channel"
)

const (
	formatVersion = 1
	// MaxBody is the largest body a file may carry.
	MaxBody = 256 << 10
	// MaxLifetime is the longest a keys or channel file may stay valid
	// after it was signed.
	MaxLifetime = 100 * 24 * time.Hour
	maxKeys     = 8
	maxFiles    = 256
	maxBinaries = 64
	maxName     = 64
)

// File is the envelope every release file has: the body's exact bytes, an
// ECDSA P-256 signature with SHA-256 over them (DER), and the SHA-256 of
// the signer's SubjectPublicKeyInfo.
type File struct {
	Body []byte `json:"body"`
	Sig  []byte `json:"sig"`
	Key  []byte `json:"key"`
}

// Hash returns SHA-256 over the body, which names a release.json.
func (f File) Hash() [sha256.Size]byte { return sha256.Sum256(f.Body) }

// Key is a release key that keys.json certifies.
type Key struct {
	Key  []byte `json:"key"` // SubjectPublicKeyInfo, DER
	Name string `json:"name"`
}

// Keys is the body of keys.json, signed by a root key.
type Keys struct {
	V         int    `json:"v"`
	Type      string `json:"type"`
	Seq       uint64 `json:"seq"`
	TimeMS    int64  `json:"time_ms"`
	ExpiresMS int64  `json:"expires_ms"`
	Keys      []Key  `json:"keys"`
}

// Binary is a program inside an archive.
type Binary struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
}

// Asset is one file of a release.
type Asset struct {
	Name     string   `json:"name"`
	Size     int64    `json:"size"`
	SHA256   string   `json:"sha256"`
	Binaries []Binary `json:"binaries,omitempty"`
}

// Docker names the release's container image.
type Docker struct {
	Image  string `json:"image"`
	Digest string `json:"digest"`
}

// Release is the body of release.json, signed by a release key.
type Release struct {
	V       int     `json:"v"`
	Type    string  `json:"type"`
	Version string  `json:"version"`
	Channel string  `json:"channel"`
	TimeMS  int64   `json:"time_ms"`
	MinFrom string  `json:"min_from,omitempty"`
	Files   []Asset `json:"files"`
	Docker  *Docker `json:"docker,omitempty"`
}

// Channel is the body of a channel file such as stable.json, signed by a
// release key.
type Channel struct {
	V             int    `json:"v"`
	Type          string `json:"type"`
	Channel       string `json:"channel"`
	Seq           uint64 `json:"seq"`
	TimeMS        int64  `json:"time_ms"`
	ExpiresMS     int64  `json:"expires_ms"`
	Release       string `json:"release"`
	ReleaseSHA256 string `json:"release_sha256"`
}

// Seen is what a device keeps between checks so that nobody can take it
// back: the highest sequence numbers and the highest version it has taken.
type Seen struct {
	KeysSeq    uint64 `json:"keys_seq"`
	ChannelSeq uint64 `json:"channel_seq"`
	Version    string `json:"version,omitempty"`
}

var (
	// ErrSignature is returned for a file whose signature does not verify
	// or whose signer is not trusted for it.
	ErrSignature = errors.New("release: the signature is not valid")
	// ErrExpired is returned for a keys or channel file past its expiry.
	ErrExpired = errors.New("release: the file has expired")
	// ErrRollback is returned for a file older than one already taken.
	ErrRollback = errors.New("release: the file is older than one already seen")
)

// Sign signs body with key. The body's type and version are set by the
// caller; Sign only checks that the body has a known form.
func Sign(body any, key crypto.Signer) (File, error) {
	data, err := json.Marshal(body)
	if err != nil {
		return File{}, err
	}
	if err := checkBody(data); err != nil {
		return File{}, err
	}
	return signData(data, key)
}

func signData(data []byte, key crypto.Signer) (File, error) {
	spki, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return File{}, err
	}
	if e, ok := key.Public().(*ecdsa.PublicKey); !ok || e.Curve != elliptic.P256() {
		return File{}, errors.New("release: the key is not P-256")
	}
	sum := sha256.Sum256(data)
	sig, err := key.Sign(rand.Reader, sum[:], crypto.SHA256)
	if err != nil {
		return File{}, err
	}
	kh := sha256.Sum256(spki)
	return File{Body: data, Sig: sig, Key: kh[:]}, nil
}

func checkBody(data []byte) error {
	if len(data) > MaxBody {
		return errors.New("release: the body is too large")
	}
	var b struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(data, &b); err != nil {
		return err
	}
	var err error
	switch b.Type {
	case TypeKeys:
		_, err = decodeKeys(data)
	case TypeRelease:
		_, err = decodeRelease(data)
	case TypeChannel:
		_, err = decodeChannel(data)
	default:
		err = fmt.Errorf("release: unknown type %q", b.Type)
	}
	return err
}

// verify checks f's signature with the key among spkis that f names.
func (f File) verify(spkis [][]byte) error {
	if len(f.Body) > MaxBody {
		return errors.New("release: the body is too large")
	}
	for _, spki := range spkis {
		kh := sha256.Sum256(spki)
		if !bytes.Equal(kh[:], f.Key) {
			continue
		}
		pub, err := x509.ParsePKIXPublicKey(spki)
		if err != nil {
			return err
		}
		k, ok := pub.(*ecdsa.PublicKey)
		if !ok || k.Curve != elliptic.P256() {
			return ErrSignature
		}
		sum := sha256.Sum256(f.Body)
		if !ecdsa.VerifyASN1(k, sum[:], f.Sig) {
			return ErrSignature
		}
		return nil
	}
	return ErrSignature
}

var (
	assetName  = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$`)
	channelRE  = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)
	hexSHA256  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	versionRE  = regexp.MustCompile(`^(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})(-rc\.([1-9][0-9]{0,5}))?$`)
	digestRE   = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	binaryName = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._/-]{0,255}$`)
)

func decode(data []byte, typ string, v any) error {
	var b struct {
		V    int    `json:"v"`
		Type string `json:"type"`
	}
	if err := json.Unmarshal(data, &b); err != nil {
		return fmt.Errorf("release: %w", err)
	}
	if b.Type != typ {
		return fmt.Errorf("release: the file is a %q, not a %q", b.Type, typ)
	}
	if b.V != formatVersion {
		return fmt.Errorf("release: unknown version %d", b.V)
	}
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("release: %w", err)
	}
	return nil
}

func lifetime(timeMS, expiresMS int64) error {
	if expiresMS <= timeMS || expiresMS-timeMS > MaxLifetime.Milliseconds() {
		return errors.New("release: the file's lifetime is out of range")
	}
	return nil
}

func decodeKeys(data []byte) (Keys, error) {
	var k Keys
	if err := decode(data, TypeKeys, &k); err != nil {
		return k, err
	}
	if k.Seq == 0 {
		return k, errors.New("release: keys.json has no sequence number")
	}
	if err := lifetime(k.TimeMS, k.ExpiresMS); err != nil {
		return k, err
	}
	if len(k.Keys) == 0 || len(k.Keys) > maxKeys {
		return k, errors.New("release: keys.json must hold 1 to 8 keys")
	}
	for _, key := range k.Keys {
		if key.Name == "" || len(key.Name) > maxName {
			return k, errors.New("release: a release key has no valid name")
		}
		pub, err := x509.ParsePKIXPublicKey(key.Key)
		if err != nil {
			return k, fmt.Errorf("release: a release key: %w", err)
		}
		if e, ok := pub.(*ecdsa.PublicKey); !ok || e.Curve != elliptic.P256() {
			return k, errors.New("release: a release key is not P-256")
		}
	}
	return k, nil
}

func decodeRelease(data []byte) (Release, error) {
	var r Release
	if err := decode(data, TypeRelease, &r); err != nil {
		return r, err
	}
	if !versionRE.MatchString(r.Version) {
		return r, fmt.Errorf("release: %q is not a version", r.Version)
	}
	if r.MinFrom != "" && !versionRE.MatchString(r.MinFrom) {
		return r, fmt.Errorf("release: %q is not a version", r.MinFrom)
	}
	if !channelRE.MatchString(r.Channel) {
		return r, fmt.Errorf("release: %q is not a channel", r.Channel)
	}
	if len(r.Files) == 0 || len(r.Files) > maxFiles {
		return r, errors.New("release: release.json must list 1 to 256 files")
	}
	names := map[string]bool{}
	for _, a := range r.Files {
		if !assetName.MatchString(a.Name) || names[a.Name] {
			return r, fmt.Errorf("release: %q is not a valid file name", a.Name)
		}
		names[a.Name] = true
		if a.Size < 0 || !hexSHA256.MatchString(a.SHA256) || len(a.Binaries) > maxBinaries {
			return r, fmt.Errorf("release: the entry for %s is not valid", a.Name)
		}
		for _, b := range a.Binaries {
			if !binaryName.MatchString(b.Name) || strings.Contains(b.Name, "..") || !hexSHA256.MatchString(b.SHA256) {
				return r, fmt.Errorf("release: a binary in %s is not valid", a.Name)
			}
		}
	}
	if r.Docker != nil && (r.Docker.Image == "" || !digestRE.MatchString(r.Docker.Digest)) {
		return r, errors.New("release: the Docker image is not valid")
	}
	return r, nil
}

func decodeChannel(data []byte) (Channel, error) {
	var c Channel
	if err := decode(data, TypeChannel, &c); err != nil {
		return c, err
	}
	if !channelRE.MatchString(c.Channel) {
		return c, fmt.Errorf("release: %q is not a channel", c.Channel)
	}
	if c.Seq == 0 {
		return c, errors.New("release: the channel file has no sequence number")
	}
	if err := lifetime(c.TimeMS, c.ExpiresMS); err != nil {
		return c, err
	}
	if !versionRE.MatchString(c.Release) || !hexSHA256.MatchString(c.ReleaseSHA256) {
		return c, errors.New("release: the channel file names no valid release")
	}
	return c, nil
}

// VerifyKeys checks keys.json against the pinned root keys (each a
// SubjectPublicKeyInfo, DER) at now, and that it is not older than seen.
func VerifyKeys(f File, roots [][]byte, now time.Time, seen Seen) (Keys, error) {
	if err := f.verify(roots); err != nil {
		return Keys{}, err
	}
	k, err := decodeKeys(f.Body)
	if err != nil {
		return Keys{}, err
	}
	if now.UnixMilli() >= k.ExpiresMS {
		return Keys{}, ErrExpired
	}
	if k.Seq < seen.KeysSeq {
		return Keys{}, ErrRollback
	}
	return k, nil
}

func (k Keys) spkis() [][]byte {
	out := make([][]byte, len(k.Keys))
	for i, key := range k.Keys {
		out[i] = key.Key
	}
	return out
}

// Check verifies a channel file and the release.json it names: keys.json
// under the roots, the channel file and release.json under its release
// keys, the channel's name, both expiries, and that nothing is older than
// seen. It returns the release and the new Seen to keep.
func Check(keys, channel, rel File, roots [][]byte, name string, now time.Time, seen Seen) (Release, Seen, error) {
	k, err := VerifyKeys(keys, roots, now, seen)
	if err != nil {
		return Release{}, seen, fmt.Errorf("keys.json: %w", err)
	}
	if err := channel.verify(k.spkis()); err != nil {
		return Release{}, seen, fmt.Errorf("%s.json: %w", name, err)
	}
	c, err := decodeChannel(channel.Body)
	if err != nil {
		return Release{}, seen, fmt.Errorf("%s.json: %w", name, err)
	}
	switch {
	case c.Channel != name:
		return Release{}, seen, fmt.Errorf("%s.json: release: the file is for the channel %q", name, c.Channel)
	case now.UnixMilli() >= c.ExpiresMS:
		return Release{}, seen, fmt.Errorf("%s.json: %w", name, ErrExpired)
	case c.Seq < seen.ChannelSeq:
		return Release{}, seen, fmt.Errorf("%s.json: %w", name, ErrRollback)
	}
	if err := rel.verify(k.spkis()); err != nil {
		return Release{}, seen, fmt.Errorf("release.json: %w", err)
	}
	if h := rel.Hash(); hex.EncodeToString(h[:]) != c.ReleaseSHA256 {
		return Release{}, seen, fmt.Errorf("release.json: release: it is not the release %s.json names", name)
	}
	r, err := decodeRelease(rel.Body)
	if err != nil {
		return Release{}, seen, fmt.Errorf("release.json: %w", err)
	}
	if r.Version != c.Release || r.Channel != c.Channel {
		return Release{}, seen, fmt.Errorf("release.json: release: it is %s on %s, %s.json names %s", r.Version, r.Channel, name, c.Release)
	}
	if seen.Version != "" && Compare(r.Version, seen.Version) < 0 {
		return Release{}, seen, fmt.Errorf("release.json: %w", ErrRollback)
	}
	next := Seen{KeysSeq: k.Seq, ChannelSeq: c.Seq, Version: r.Version}
	if seen.Version != "" && Compare(seen.Version, r.Version) > 0 {
		next.Version = seen.Version
	}
	return r, next, nil
}

// Compare compares two versions of the form X.Y.Z or X.Y.Z-rc.N, as -1,
// 0 or 1; a release candidate comes before its release. A string that is
// not a version sorts below every version.
func Compare(a, b string) int {
	pa, oka := parseVersion(a)
	pb, okb := parseVersion(b)
	switch {
	case !oka || !okb:
		switch {
		case oka:
			return 1
		case okb:
			return -1
		}
		return 0
	}
	for i := range pa {
		if pa[i] != pb[i] {
			if pa[i] < pb[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}

// parseVersion returns X, Y, Z and the release candidate's number, or
// finalRelease for a release.
func parseVersion(s string) ([4]int, bool) {
	var out [4]int
	m := versionRE.FindStringSubmatch(s)
	if m == nil {
		return out, false
	}
	for i, p := range []string{m[1], m[2], m[3]} {
		out[i], _ = strconv.Atoi(p)
	}
	out[3] = finalRelease
	if m[5] != "" {
		out[3], _ = strconv.Atoi(m[5])
	}
	return out, true
}

const finalRelease = 1 << 30

// Direct reports whether a device at installed may update to r in one
// step, or must first take r.MinFrom.
func (r Release) Direct(installed string) bool {
	return r.MinFrom == "" || Compare(installed, r.MinFrom) >= 0
}

// Asset returns the release's entry for the file name.
func (r Release) Asset(name string) (Asset, bool) {
	for _, a := range r.Files {
		if a.Name == name {
			return a, true
		}
	}
	return Asset{}, false
}

// CheckFile reports whether data is the release's file name.
func (r Release) CheckFile(name string, data []byte) error {
	a, ok := r.Asset(name)
	if !ok {
		return fmt.Errorf("release: %s is not in the release", name)
	}
	sum := sha256.Sum256(data)
	if int64(len(data)) != a.Size || hex.EncodeToString(sum[:]) != a.SHA256 {
		return fmt.Errorf("release: %s does not match release.json", name)
	}
	return nil
}
