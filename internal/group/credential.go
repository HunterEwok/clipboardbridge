// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package group

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/HunterEwok/clipboardbridge/internal/atomicfile"
)

// A server credential is what a forwarder checks in place of the group's
// records (docs/protocol.md, section 18; D-67, D-75): the key hashes of the
// group's hubs, admins and heirs, with a version and an expiry, signed by
// the group's root. It names no device, no name, no system and no date of
// signing, and its lists are padded, so the server learns only roughly how
// many devices there are.
const (
	CredentialHubs = "hubs" // the hubs' credential, signed by a root
	CredentialLink = "link" // a new root, signed by an heir of the one before

	credentialVersion = 1
	// CredentialsFileName is the file next to the identity that keeps the
	// group's credentials.
	CredentialsFileName = "credentials.json"

	// CredentialLifetime is how long a hubs' credential lasts, and
	// CredentialRenew how much of it must remain before its root signs a
	// new one: a phone's root asks for Face ID for it about once a month.
	CredentialLifetime = 90 * 24 * time.Hour
	CredentialRenew    = 60 * 24 * time.Hour

	// MaxCredentialHubs bounds the hubs a credential lists, the first of
	// the order; maxCredentialList bounds its other lists.
	MaxCredentialHubs = 16
	maxCredentialList = 64
	maxCredentialBody = 16 << 10
	// MaxCredentialChain bounds a chain: a credential of each root on the
	// path and the links between them.
	MaxCredentialChain = 2*maxRoots + 1
	maxRoots           = 8
)

// A Credential is a signed credential body: the body's exact bytes, an
// ECDSA P-256 signature over them, and the signer's public key
// (SubjectPublicKeyInfo), which the server matches with a root or a hash
// the credential before it lists.
type Credential struct {
	Body []byte `json:"body"`
	Sig  []byte `json:"sig"`
	Key  []byte `json:"key"`
}

// A CredentialBody is what a credential says.
type CredentialBody struct {
	V     int    `json:"v"`
	Type  string `json:"type"`
	Group string `json:"group"`

	// hubs
	Version   uint64    `json:"version,omitempty"`
	ExpiresMS int64     `json:"expires_ms,omitempty"`
	Hubs      []KeyHash `json:"hubs,omitempty"`   // the hubs' member keys, in their order
	Admins    []KeyHash `json:"admins,omitempty"` // the admins' admin CAs
	Heirs     []KeyHash `json:"heirs,omitempty"`  // the admin CAs that may hand the group over

	// link
	Root []byte `json:"root,omitempty"` // the new root CA, DER
}

// ID returns the credential's ID: SHA-256 over its body.
func (c Credential) ID() [sha256.Size]byte { return sha256.Sum256(c.Body) }

// Signer returns the hash of the key that signed the credential.
func (c Credential) Signer() KeyHash { return sha256.Sum256(c.Key) }

// Expires returns when a hubs' credential stops counting.
func (b *CredentialBody) Expires() time.Time { return time.UnixMilli(b.ExpiresMS) }

// CredentialLists are the real entries of a hubs' credential, before
// padding: what the group's records say.
type CredentialLists struct {
	Hubs, Admins, Heirs []KeyHash
}

// Equal reports whether two sets of lists name the same keys, the hubs in
// the same order.
func (l CredentialLists) Equal(o CredentialLists) bool {
	sorted := func(ks []KeyHash) []KeyHash {
		out := slices.Clone(ks)
		slices.SortFunc(out, func(a, b KeyHash) int { return bytes.Compare(a[:], b[:]) })
		return out
	}
	return slices.Equal(l.Hubs, o.Hubs) && slices.Equal(sorted(l.Admins), sorted(o.Admins)) && slices.Equal(sorted(l.Heirs), sorted(o.Heirs))
}

// CredentialLists returns what the group's hubs' credential must list: the
// member keys of the hubs in their order (HubOrder), at most
// MaxCredentialHubs; the admin CAs of the admins that are neither revoked
// nor frozen; and of those the heirs, the admin CAs that may hand the
// group to a new root (docs/protocol.md, section 10, rule 2): an admin
// phone's, or a computer's when the root is a computer too.
func (s *Records) CredentialLists() CredentialLists {
	var l CredentialLists
	root, rootKey := s.RootMember()
	devs := s.Devices()
	computerRoot := false
	for _, d := range devs {
		if d.ID == root {
			computerRoot = d.Role == RoleFull
		}
	}
	for _, id := range s.HubOrder() {
		if len(l.Hubs) == MaxCredentialHubs {
			break
		}
		if id == root {
			l.Hubs = append(l.Hubs, rootKey)
			continue
		}
		for _, d := range devs {
			if d.ID == id {
				l.Hubs = append(l.Hubs, d.Key)
			}
		}
	}
	ev := s.eval()
	for _, d := range devs {
		if !d.Admin || d.AdminKey == nil || d.ID == root {
			continue
		}
		k := *d.AdminKey
		if len(l.Admins) < maxCredentialList && !slices.Contains(l.Admins, k) {
			l.Admins = append(l.Admins, k)
		}
		heir := d.Role == RolePhone && ev.phoneAdmin[k] || d.Role != RolePhone && computerRoot
		if heir && len(l.Heirs) < maxCredentialList && !slices.Contains(l.Heirs, k) {
			l.Heirs = append(l.Heirs, k)
		}
	}
	return l
}

// padTo returns the size a list of n entries is padded to: the next of 4,
// 8, 16, 32 and 64.
func padTo(n int) int {
	size := 4
	for size < n {
		size *= 2
	}
	return size
}

// pad appends random 32-byte strings to ks up to padTo(len(ks)): a key
// hash looks random, so the padding cannot be told from a real entry.
func pad(ks []KeyHash) ([]KeyHash, error) {
	out := slices.Clone(ks)
	for len(out) < padTo(len(ks)) {
		var k KeyHash
		if _, err := rand.Read(k[:]); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, nil
}

// SignHubs signs the group's hubs' credential with its root's key: the
// lists padded, with version and an expiry CredentialLifetime from now.
func SignHubs(tag string, l CredentialLists, version uint64, now time.Time, root crypto.Signer) (Credential, error) {
	b := CredentialBody{Type: CredentialHubs, Group: tag, Version: version, ExpiresMS: now.Add(CredentialLifetime).UnixMilli()}
	var err error
	if b.Hubs, err = pad(l.Hubs); err != nil {
		return Credential{}, err
	}
	if b.Admins, err = pad(l.Admins); err != nil {
		return Credential{}, err
	}
	if b.Heirs, err = pad(l.Heirs); err != nil {
		return Credential{}, err
	}
	return SignCredential(b, root)
}

// SignLink signs, with an heir's admin key, the link that hands the group
// to the new root.
func SignLink(tag string, root *x509.Certificate, heir crypto.Signer) (Credential, error) {
	return SignCredential(CredentialBody{Type: CredentialLink, Group: tag, Root: root.Raw}, heir)
}

// SignCredential signs a credential body with key.
func SignCredential(b CredentialBody, key crypto.Signer) (Credential, error) {
	b.V = credentialVersion
	if err := b.check(); err != nil {
		return Credential{}, err
	}
	data, err := json.Marshal(b)
	if err != nil {
		return Credential{}, err
	}
	if len(data) > maxCredentialBody {
		return Credential{}, errors.New("group: the credential is too large")
	}
	spki, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return Credential{}, err
	}
	sum := sha256.Sum256(data)
	sig, err := key.Sign(rand.Reader, sum[:], crypto.SHA256)
	if err != nil {
		return Credential{}, err
	}
	return Credential{Body: data, Sig: sig, Key: spki}, nil
}

func (b *CredentialBody) check() error {
	if b.V != credentialVersion {
		return fmt.Errorf("group: unknown credential version %d", b.V)
	}
	switch b.Type {
	case CredentialHubs:
		switch {
		case b.Version == 0:
			return errors.New("group: a hubs' credential has no version")
		case b.ExpiresMS <= 0:
			return errors.New("group: a hubs' credential has no expiry")
		case len(b.Hubs) > MaxCredentialHubs || len(b.Admins) > maxCredentialList || len(b.Heirs) > maxCredentialList:
			return errors.New("group: a hubs' credential lists too many keys")
		case len(b.Root) != 0:
			return errors.New("group: a hubs' credential names a root")
		}
	case CredentialLink:
		if _, err := linkRoot(b.Root); err != nil {
			return err
		}
		if b.Version != 0 || b.ExpiresMS != 0 || len(b.Hubs)+len(b.Admins)+len(b.Heirs) != 0 {
			return errors.New("group: a link carries more than its root")
		}
	default:
		return fmt.Errorf("group: unknown credential type %q", b.Type)
	}
	return nil
}

// linkRoot parses the root a link hands the group to: a self-signed CA
// with path length 1 and a P-256 key, as a root record's (section 10,
// rule 7).
func linkRoot(der []byte) (*x509.Certificate, error) {
	c, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, errors.New("group: a link's root does not parse")
	}
	if err := checkRoot(c); err != nil {
		return nil, err
	}
	return c, nil
}

// Open checks the credential's signature and returns its body. It checks
// neither who signed it nor the group.
func (c Credential) Open() (*CredentialBody, error) {
	if len(c.Body) > maxCredentialBody {
		return nil, errors.New("group: the credential is too large")
	}
	pub, err := x509.ParsePKIXPublicKey(c.Key)
	if err != nil {
		return nil, errors.New("group: the credential's key does not parse")
	}
	ec, ok := pub.(*ecdsa.PublicKey)
	if !ok || ec.Curve != elliptic.P256() {
		return nil, errors.New("group: the credential's key is not a P-256 key")
	}
	sum := sha256.Sum256(c.Body)
	if !ecdsa.VerifyASN1(ec, sum[:], c.Sig) {
		return nil, errors.New("group: the credential's signature does not verify")
	}
	var b CredentialBody
	if err := json.Unmarshal(c.Body, &b); err != nil {
		return nil, errors.New("group: the credential does not decode")
	}
	if err := b.check(); err != nil {
		return nil, err
	}
	return &b, nil
}

// A CheckedChain is a chain of credentials that a server checked: the
// group's roots from the group CA, the last of them the current one, and
// each root's hubs' credential.
type CheckedChain struct {
	Roots []*x509.Certificate
	Hubs  []*CredentialBody // Hubs[i] is the credential Roots[i] signed
}

// Last returns the current root's hubs' credential.
func (c *CheckedChain) Last() *CredentialBody { return c.Hubs[len(c.Hubs)-1] }

// CheckChain checks a chain of credentials as a server does
// (docs/protocol.md, section 18): from the group CA, each root's hubs'
// credential that root signed, then a link that an heir that credential
// lists signed, to the next root, and so on, ending with the current
// root's hubs' credential. The versions grow along the chain. It checks
// neither the expiry nor which versions the server saw.
func CheckChain(groupCA *x509.Certificate, chain []Credential) (*CheckedChain, error) {
	if len(chain) == 0 || len(chain) > MaxCredentialChain || len(chain)%2 == 0 {
		return nil, errors.New("group: the credentials do not make a chain")
	}
	tag := Tag(groupCA)
	out := &CheckedChain{Roots: []*x509.Certificate{groupCA}}
	for i, c := range chain {
		b, err := c.Open()
		if err != nil {
			return nil, err
		}
		if b.Group != tag {
			return nil, errors.New("group: a credential of another group")
		}
		root := out.Roots[len(out.Roots)-1]
		if i%2 == 0 {
			if b.Type != CredentialHubs || !bytes.Equal(c.Key, root.RawSubjectPublicKeyInfo) {
				return nil, errors.New("group: a hubs' credential that its root did not sign")
			}
			if n := len(out.Hubs); n > 0 && b.Version <= out.Hubs[n-1].Version {
				return nil, errors.New("group: a new root's credential is no newer than the old root's")
			}
			out.Hubs = append(out.Hubs, b)
			continue
		}
		if b.Type != CredentialLink || !slices.Contains(out.Hubs[len(out.Hubs)-1].Heirs, c.Signer()) {
			return nil, errors.New("group: a link that no heir of its root signed")
		}
		next, err := linkRoot(b.Root)
		if err != nil {
			return nil, err
		}
		for _, r := range out.Roots {
			if bytes.Equal(r.RawSubjectPublicKeyInfo, next.RawSubjectPublicKeyInfo) {
				return nil, errors.New("group: a link back to an earlier root")
			}
		}
		out.Roots = append(out.Roots, next)
	}
	return out, nil
}

// Credentials keeps a member's credentials (docs/protocol.md, section 18):
// for each root on the group's path, the newest hubs' credential it
// signed, and the links between them. It is safe for concurrent use.
type Credentials struct {
	mu      sync.Mutex
	groupCA *x509.Certificate
	hubs    map[KeyHash]Credential // by the root that signed it
	links   map[KeyHash]Credential // by the root it leaves
}

// NewCredentials returns an empty set for the group of groupCA.
func NewCredentials(groupCA *x509.Certificate) *Credentials {
	return &Credentials{groupCA: groupCA, hubs: map[KeyHash]Credential{}, links: map[KeyHash]Credential{}}
}

// Add takes the credentials that are valid for the group and newer than
// what it keeps, against the group's roots (the group CA first), and
// returns those it took. A hubs' credential counts when a root on the path
// signed it; a link when an heir of the credential it keeps for the root
// it leaves signed it, and its root is the next root on the path.
func (s *Credentials) Add(roots []*x509.Certificate, cs []Credential) (fresh []Credential, errs []error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tag := Tag(s.groupCA)
	rootIndex := func(spki []byte) int {
		return slices.IndexFunc(roots, func(r *x509.Certificate) bool { return bytes.Equal(r.RawSubjectPublicKeyInfo, spki) })
	}
	// Hubs' credentials first: a link counts against its root's.
	order := slices.Clone(cs)
	isLink := func(c Credential) int {
		if credType(c) == CredentialLink {
			return 1
		}
		return 0
	}
	slices.SortStableFunc(order, func(a, b Credential) int { return isLink(a) - isLink(b) })
	for _, c := range order {
		b, err := c.Open()
		switch {
		case err != nil:
			errs = append(errs, err)
			continue
		case b.Group != tag:
			errs = append(errs, errors.New("group: a credential of another group"))
			continue
		}
		switch b.Type {
		case CredentialHubs:
			i := rootIndex(c.Key)
			if i < 0 {
				errs = append(errs, errors.New("group: a hubs' credential that no root of the group signed"))
				continue
			}
			k := KeyHashOf(roots[i])
			if old, ok := s.hubs[k]; ok {
				if ob, err := old.Open(); err == nil && ob.Version >= b.Version {
					continue
				}
			}
			s.hubs[k] = c
			fresh = append(fresh, c)
		case CredentialLink:
			next, _ := linkRoot(b.Root)
			i := rootIndex(next.RawSubjectPublicKeyInfo)
			if i < 1 {
				errs = append(errs, errors.New("group: a link to no root of the group"))
				continue
			}
			from := KeyHashOf(roots[i-1])
			if _, ok := s.links[from]; ok {
				continue
			}
			hc, ok := s.hubs[from]
			if !ok {
				errs = append(errs, errors.New("group: a link from a root whose credential is unknown"))
				continue
			}
			hb, err := hc.Open()
			if err != nil || !slices.Contains(hb.Heirs, c.Signer()) {
				errs = append(errs, errors.New("group: a link that no heir of its root signed"))
				continue
			}
			s.links[from] = c
			fresh = append(fresh, c)
		}
	}
	return fresh, errs
}

func credType(c Credential) string {
	var b struct {
		Type string `json:"type"`
	}
	json.Unmarshal(c.Body, &b)
	return b.Type
}

// All returns every credential it keeps.
func (s *Credentials) All() []Credential {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Credential
	for _, m := range []map[KeyHash]Credential{s.hubs, s.links} {
		for _, c := range m {
			out = append(out, c)
		}
	}
	slices.SortFunc(out, func(a, b Credential) int {
		x, y := a.ID(), b.ID()
		return bytes.Compare(x[:], y[:])
	})
	return out
}

// Current returns the current root's hubs' credential and its body, or
// false when it keeps none.
func (s *Credentials) Current(roots []*x509.Certificate) (Credential, *CredentialBody, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.hubs[KeyHashOf(roots[len(roots)-1])]
	if !ok {
		return Credential{}, nil, false
	}
	b, err := c.Open()
	if err != nil {
		return Credential{}, nil, false
	}
	return c, b, true
}

// Chain returns the chain a hub presents its forwarder, from the group CA
// to the current root of roots (the group CA first), or nil when a
// credential or a link on the way is missing.
func (s *Credentials) Chain(roots []*x509.Certificate) []Credential {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Credential
	for i, r := range roots {
		k := KeyHashOf(r)
		c, ok := s.hubs[k]
		if !ok {
			return nil
		}
		out = append(out, c)
		if i < len(roots)-1 {
			l, ok := s.links[k]
			if !ok {
				return nil
			}
			out = append(out, l)
		}
	}
	return out
}

// Stale reports whether the current root's hubs' credential needs a new
// version: there is none, it lists other keys than the records say (its
// real entries come first, so a key the records still name must be among
// them and no other key the records know may follow), or less than
// CredentialRenew of it remains.
func Stale(b *CredentialBody, want CredentialLists, known func(KeyHash) bool, now time.Time) bool {
	if b == nil || b.Expires().Sub(now) < CredentialRenew {
		return true
	}
	lists := func(got, want []KeyHash, ordered bool) bool {
		if len(got) != padTo(len(want)) {
			return false
		}
		if ordered && !slices.Equal(got[:len(want)], want) {
			return false
		}
		for _, k := range want {
			if !slices.Contains(got, k) {
				return false
			}
		}
		for _, k := range got {
			if !slices.Contains(want, k) && known(k) {
				return false
			}
		}
		return true
	}
	return !lists(b.Hubs, want.Hubs, true) || !lists(b.Admins, want.Admins, false) || !lists(b.Heirs, want.Heirs, false)
}

// KnownKey reports whether the records name the key k anywhere: a device's
// key, an admin CA, a root, or a revoked key. Padding never matches one.
func (s *Records) KnownKey(k KeyHash) bool {
	if s.eval().revoked[k] || s.onPath()[k] {
		return true
	}
	for _, r := range s.byID {
		b := r.body
		if b.Key != nil && *b.Key == k || b.Admin != nil && *b.Admin == k || r.signer == k {
			return true
		}
	}
	return false
}

// NextVersion returns the version of a hubs' credential after prev: one
// above it, or the time in seconds when that is more, so a root that lost
// its state still signs a newer version.
func NextVersion(prev uint64, now time.Time) uint64 {
	return max(prev+1, uint64(max(now.Unix(), 0)))
}

// Save writes the credentials to dir/credentials.json.
func (s *Credentials) Save(dir string) error {
	data, err := json.MarshalIndent(s.All(), "", "\t")
	if err != nil {
		return err
	}
	return atomicfile.Write(filepath.Join(dir, CredentialsFileName), append(data, '\n'), 0o600)
}

// LoadCredentials reads dir/credentials.json for the group of groupCA with
// the roots of its path; a missing file is an empty set, and credentials
// that are not valid for the group are left out.
func LoadCredentials(dir string, roots []*x509.Certificate) (*Credentials, error) {
	s := NewCredentials(roots[0])
	data, err := os.ReadFile(filepath.Join(dir, CredentialsFileName))
	if errors.Is(err, fs.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	var all []Credential
	if err := json.Unmarshal(data, &all); err != nil {
		return nil, fmt.Errorf("%s: %w", filepath.Join(dir, CredentialsFileName), err)
	}
	s.Add(roots, all)
	return s, nil
}

// MaxVersion returns the highest version of the hubs' credentials it
// keeps, from any root; 0 when it keeps none.
func (s *Credentials) MaxVersion() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	var v uint64
	for _, c := range s.hubs {
		if b, err := c.Open(); err == nil {
			v = max(v, b.Version)
		}
	}
	return v
}

// GroupCA returns the group CA of the set.
func (s *Credentials) GroupCA() *x509.Certificate { return s.groupCA }
