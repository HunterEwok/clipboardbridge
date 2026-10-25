// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package group

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/HunterEwok/clipboardbridge/internal/atomicfile"
)

// RecordsFileName is the name of the records file in the state directory.
const RecordsFileName = "records.json"

// Limits of the record set (docs/protocol.md, section 10).
const (
	MaxRecords = 4096
	// MaxPerAdmin bounds the records one signer (an admin CA, or a root's
	// own key) signs, so a stolen admin cannot fill the set and shut the
	// others out. Past MaxRecords, the set still takes up to MaxPerAdmin
	// records signed by the own key of a root on the path, so a full set
	// still takes the record that removes the admin that filled it.
	MaxPerAdmin   = 1024
	maxRecordBody = 8 << 10
	recordVersion = 1
)

// Record types.
const (
	RecordDevice = "device"
	RecordRevoke = "revoke"
	RecordRoot   = "root"
	RecordFreeze = "freeze"
	RecordThaw   = "thaw"
)

// Device roles in device records: the member roles, and shortcut for an
// iPhone without the app that uses the shortcut and its token.
const (
	RoleFull     = "full"
	RolePhone    = "phone"
	RoleLite     = "lite"
	RoleShortcut = "shortcut"
)

// The roles of records made before a device's system was apart from its
// role; Role reads them as RoleFull and RoleShortcut.
const (
	roleLinux  = "linux"
	roleMac    = "mac"
	roleIPhone = "iphone"
)

// Operating systems in device records, hellos and the pairing Info: what
// the device runs, shown and never trusted for anything else.
const (
	OSLinux   = "linux"
	OSWindows = "windows"
	OSMacOS   = "macos"
	OSiOS     = "ios"
	OSAndroid = "android"
	OSNone    = "none" // firmware without an operating system
)

// ValidOS reports whether os names a known operating system.
func ValidOS(os string) bool {
	switch os {
	case OSLinux, OSWindows, OSMacOS, OSiOS, OSAndroid, OSNone:
		return true
	}
	return false
}

// OSName names an operating system for the user: "Linux", "Windows",
// "macOS", "iOS", "Android", "device" for firmware, "?" when unknown.
func OSName(os string) string {
	switch os {
	case OSLinux:
		return "Linux"
	case OSWindows:
		return "Windows"
	case OSMacOS:
		return "macOS"
	case OSiOS:
		return "iOS"
	case OSAndroid:
		return "Android"
	case OSNone:
		return "device"
	}
	return "?"
}

// role returns the role a record body names, with the roles of earlier
// records read as today's.
func role(r string) string {
	switch r {
	case roleLinux, roleMac:
		return RoleFull
	case roleIPhone:
		return RoleShortcut
	}
	return r
}

// osOf returns the system a record body names, or the one its earlier role
// implies; "" when neither tells.
func osOf(b RecordBody) string {
	switch {
	case b.OS != "":
		return b.OS
	case b.Role == roleMac:
		return OSMacOS
	case b.Role == roleIPhone || b.Role == RoleShortcut:
		return OSiOS
	}
	return ""
}

// A KeyHash names a key in records: SHA-256 over a SubjectPublicKeyInfo, or
// over the 16 bytes of a phone ID for an iPhone's token.
type KeyHash [sha256.Size]byte

// KeyHashOf returns the hash of a certificate's public key.
func KeyHashOf(cert *x509.Certificate) KeyHash { return sha256.Sum256(cert.RawSubjectPublicKeyInfo) }

// PhoneKeyHash returns the hash that names an iPhone's token: SHA-256 over
// the phone ID's 16 bytes.
func PhoneKeyHash(phoneID []byte) KeyHash { return sha256.Sum256(phoneID) }

func (h KeyHash) MarshalJSON() ([]byte, error) {
	return json.Marshal(h[:])
}

func (h *KeyHash) UnmarshalJSON(b []byte) error {
	var raw []byte
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	if len(raw) != len(h) {
		return errors.New("group: a key hash is not 32 bytes")
	}
	copy(h[:], raw)
	return nil
}

// A RecordBody is what a record says; its fields depend on its type.
type RecordBody struct {
	V      int      `json:"v"`
	Type   string   `json:"type"`
	Group  string   `json:"group"`
	TimeMS int64    `json:"time_ms"`
	By     DeviceID `json:"by,omitempty"`

	// device
	Device DeviceID `json:"device,omitempty"`
	Name   string   `json:"name,omitempty"`
	Role   string   `json:"role,omitempty"`
	OS     string   `json:"os,omitempty"`
	Key    *KeyHash `json:"key,omitempty"`
	Admin  *KeyHash `json:"admin,omitempty"` // the key of the device's admin CA

	// revoke
	Keys []KeyHash `json:"keys,omitempty"`
	Keep []KeyHash `json:"keep,omitempty"`

	// root
	Root []byte `json:"root,omitempty"`

	// freeze: the records of the frozen admins that still count; thaw: the
	// freeze records it ends. Both are record IDs.
	Records []KeyHash `json:"records,omitempty"`
}

// A Record is a signed record body: the body's exact bytes, an ECDSA
// signature over them, and the signer's certificates below the group CA
// (none when the group CA key signed).
type Record struct {
	Body  []byte   `json:"body"`
	Sig   []byte   `json:"sig"`
	Chain [][]byte `json:"chain,omitempty"`
}

// ID returns the record's ID: SHA-256 over its body.
func (r Record) ID() [sha256.Size]byte { return sha256.Sum256(r.Body) }

// Type returns the type its body names, without checking the record.
func (r Record) Type() string {
	var b struct {
		Type string `json:"type"`
	}
	json.Unmarshal(r.Body, &b)
	return b.Type
}

// SignRecord signs body with key, the group CA key (chain empty) or an
// admin CA key (chain holds the admin CA certificate).
func SignRecord(body RecordBody, key *ecdsa.PrivateKey, chain ...*x509.Certificate) (Record, error) {
	body.V = recordVersion
	if err := body.check(); err != nil {
		return Record{}, err
	}
	data, err := json.Marshal(body)
	if err != nil {
		return Record{}, err
	}
	if len(data) > maxRecordBody {
		return Record{}, errors.New("group: the record is too large")
	}
	sum := sha256.Sum256(data)
	sig, err := ecdsa.SignASN1(rand.Reader, key, sum[:])
	if err != nil {
		return Record{}, err
	}
	r := Record{Body: data, Sig: sig}
	for _, c := range chain {
		r.Chain = append(r.Chain, c.Raw)
	}
	return r, nil
}

func (b *RecordBody) check() error {
	if b.V != recordVersion {
		return fmt.Errorf("group: unknown record version %d", b.V)
	}
	switch b.Type {
	case RecordDevice:
		if _, err := ParseDeviceID(string(b.Device)); err != nil {
			return err
		}
		if !ValidName(b.Name) {
			return errors.New("group: a device record has no valid name")
		}
		switch role(b.Role) {
		case RoleFull, RolePhone, RoleLite, RoleShortcut:
		default:
			return fmt.Errorf("group: unknown role %q in a device record", b.Role)
		}
		if b.OS != "" && !ValidOS(b.OS) {
			return fmt.Errorf("group: unknown system %q in a device record", b.OS)
		}
		if b.Key == nil {
			return errors.New("group: a device record names no key")
		}
	case RecordRevoke:
		if len(b.Keys) == 0 {
			return errors.New("group: a revocation record names no key")
		}
	case RecordRoot:
		if len(b.Root) == 0 {
			return errors.New("group: a root record has no certificate")
		}
	case RecordFreeze:
		if len(b.Keys) == 0 {
			return errors.New("group: a freeze record names no admin")
		}
	case RecordThaw:
		if len(b.Records) == 0 {
			return errors.New("group: a thaw record names no freeze record")
		}
	default:
		return fmt.Errorf("group: unknown record type %q", b.Type)
	}
	return nil
}

// ValidName reports whether s is a device name: 1 to 64 bytes of UTF-8
// without control characters.
func ValidName(s string) bool {
	if s == "" || len(s) > 64 || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// A signedRecord is a record whose signature was checked, with what
// evaluating the set needs from it.
type signedRecord struct {
	Record
	id     KeyHash // the record ID
	body   RecordBody
	signer KeyHash
	anchor KeyHash           // the root it was signed under: the signer, or the root of its admin CA
	root   *x509.Certificate // the new root of a root record
}

// Records is the set of a group's records. It only grows; what it says
// depends on the records alone, never on the order in which they were added
// (docs/protocol.md, section 10). It is not safe for concurrent use.
type Records struct {
	groupCA *x509.Certificate
	tag     string
	caKey   KeyHash
	byID    map[[sha256.Size]byte]*signedRecord
	// roots are the roots records may be signed under: the group CA and
	// the new root of every root record that may make it a known root
	// (mayBeKnown); the others wait in pending.
	roots   map[KeyHash]*x509.Certificate
	pending []*signedRecord
	// named holds, for each root, the admin CAs that device records signed
	// by its own key name: namedPhone for a phone's record, namedOther for
	// any other; own the roles of the root's own device records.
	named map[KeyHash]map[KeyHash]uint8
	own   map[KeyHash]uint8
	// perSigner counts the records each signer signed (MaxPerAdmin).
	perSigner map[KeyHash]int
	// ev is what the set says about revocations, worked out on first use
	// after a change.
	ev *evaluation
}

// NewRecords returns an empty set for the group of groupCA, the group's
// first root, which names the group for good.
func NewRecords(groupCA *x509.Certificate) *Records {
	caKey := KeyHashOf(groupCA)
	return &Records{
		groupCA:   groupCA,
		tag:       Tag(groupCA),
		caKey:     caKey,
		byID:      map[[sha256.Size]byte]*signedRecord{},
		roots:     map[KeyHash]*x509.Certificate{caKey: groupCA},
		named:     map[KeyHash]map[KeyHash]uint8{},
		own:       map[KeyHash]uint8{},
		perSigner: map[KeyHash]int{},
	}
}

// Bits of Records.named and Records.own.
const (
	namedPhone uint8 = 1 << iota
	namedOther
)

// Len returns the number of records.
func (s *Records) Len() int { return len(s.byID) }

// Add checks a record and adds it. It reports whether the record was new; a
// record that is not valid for this group is an error. The limits are
// checked after the signature, so that a record nobody signed never fills
// the set.
func (s *Records) Add(r Record) (bool, error) {
	id := r.ID()
	if _, ok := s.byID[id]; ok {
		return false, nil
	}
	sr, err := s.verify(r)
	if err != nil {
		return false, err
	}
	if s.perSigner[sr.signer] >= MaxPerAdmin {
		return false, errors.New("group: too many records from one signer")
	}
	if n := len(s.byID); n >= MaxRecords && (n >= MaxRecords+MaxPerAdmin || sr.signer != sr.anchor || !s.onPath()[sr.anchor]) {
		return false, errors.New("group: too many records")
	}
	s.perSigner[sr.signer]++
	s.byID[id] = sr
	s.ev = nil
	b := sr.body
	if b.Type == RecordDevice && sr.signer == sr.anchor {
		bit := namedOther
		if role(b.Role) == RolePhone {
			bit = namedPhone
		}
		if b.Admin != nil {
			if s.named[sr.anchor] == nil {
				s.named[sr.anchor] = map[KeyHash]uint8{}
			}
			s.named[sr.anchor][*b.Admin] |= bit
		}
		if b.Device == b.By {
			s.own[sr.anchor] |= bit
		}
	}
	if sr.root != nil {
		s.pending = append(s.pending, sr)
	}
	s.promote()
	return true, nil
}

// promote moves the root records of pending that may make their new root a
// known root into roots, until none does.
func (s *Records) promote() {
	for grew := true; grew; {
		grew = false
		rest := s.pending[:0]
		for _, r := range s.pending {
			if !s.mayBeKnown(r) {
				rest = append(rest, r)
				continue
			}
			if k := KeyHashOf(r.root); s.roots[k] == nil {
				s.roots[k], grew = r.root, true
			}
		}
		clear(s.pending[len(rest):])
		s.pending = rest
	}
}

// mayBeKnown reports whether the root record r may make its new root a
// known root (knownRoots), leaving out the revocations and freezes that can
// still stop it: it was signed by its root's own key, by an admin CA that a
// phone's device record from that root's own key names, or by one a
// computer's names when that root is a computer. A root that a computer's
// admin CA names in a phone's group is never known, so nothing signed under
// it enters the set, and its key cannot fill the set past the admin's own
// limit.
func (s *Records) mayBeKnown(r *signedRecord) bool {
	named := s.named[r.anchor][r.signer]
	return r.signer == r.anchor || named&namedPhone != 0 || named&namedOther != 0 && s.own[r.anchor] == namedOther
}

// AddAll adds the valid records among rs and returns those that were new,
// and an error for each record that is not valid. A record signed under a
// new root is taken once the records that may make that root known are in
// the set, so the result does not depend on the order of rs.
func (s *Records) AddAll(rs []Record) (fresh []Record, errs []error) {
	pending := rs
	for {
		var rest []Record
		errs = errs[:0]
		roots := len(s.roots)
		for _, r := range pending {
			isNew, err := s.Add(r)
			switch {
			case err != nil:
				rest = append(rest, r)
				errs = append(errs, err)
			case isNew:
				fresh = append(fresh, r)
			}
		}
		if len(s.roots) == roots || len(rest) == 0 {
			return fresh, errs
		}
		pending = rest
	}
}

func (s *Records) verify(r Record) (*signedRecord, error) {
	if len(r.Body) > maxRecordBody {
		return nil, errors.New("group: the record is too large")
	}
	var body RecordBody
	if err := json.Unmarshal(r.Body, &body); err != nil {
		return nil, fmt.Errorf("group: a record: %w", err)
	}
	if err := body.check(); err != nil {
		return nil, err
	}
	if body.Group != s.tag {
		return nil, errors.New("group: the record is for another group")
	}
	sr := &signedRecord{Record: r, id: r.ID(), body: body}
	sum := sha256.Sum256(r.Body)
	switch len(r.Chain) {
	case 0:
		// Signed by a root's own key.
		for k, root := range s.roots {
			if ecdsa.VerifyASN1(root.PublicKey.(*ecdsa.PublicKey), sum[:], r.Sig) {
				sr.signer, sr.anchor = k, k
				break
			}
		}
		if sr.signer == (KeyHash{}) {
			return nil, errors.New("group: the record's signature is not valid")
		}
	case 1:
		admin, err := x509.ParseCertificate(r.Chain[0])
		if err != nil {
			return nil, fmt.Errorf("group: a record's signer: %w", err)
		}
		anchor, ok := KeyHash{}, false
		err = errors.New("group: the signer is not an admin CA of the group")
		for k, root := range s.roots {
			if err = checkAdminCA(admin, root); err == nil {
				anchor, ok = k, true
				break
			}
		}
		if !ok {
			return nil, err
		}
		if !ecdsa.VerifyASN1(admin.PublicKey.(*ecdsa.PublicKey), sum[:], r.Sig) {
			return nil, errors.New("group: the record's signature is not valid")
		}
		sr.signer, sr.anchor = KeyHashOf(admin), anchor
	default:
		return nil, errors.New("group: a record's chain is too long")
	}
	if body.Type == RecordRoot {
		// A legacy group CA hands the group to its first root itself, with
		// its own key (cbb upgrade); a root with path length 1 also through
		// its admins.
		switch anchor := s.roots[sr.anchor]; {
		case anchor.MaxPathLen == 1:
		case sr.anchor == s.caKey && sr.signer == sr.anchor:
		default:
			return nil, errors.New("group: only a group with a root is handed to a new root")
		}
		root, err := x509.ParseCertificate(body.Root)
		if err != nil {
			return nil, fmt.Errorf("group: a root record: %w", err)
		}
		if err := checkRoot(root); err != nil {
			return nil, err
		}
		sr.root = root
	}
	return sr, nil
}

// checkRoot checks the new root of a root record: a self-signed CA with
// path length 1 and a P-256 key, as the root a phone creates.
func checkRoot(c *x509.Certificate) error {
	if err := checkCA(&CA{Cert: c}, "new root", maxGroupCAPath); err != nil {
		return err
	}
	if c.MaxPathLen != 1 || c.KeyUsage&x509.KeyUsageCertSign == 0 {
		return errors.New("group: the new root does not certify admin CAs")
	}
	return nil
}

// path returns the roots the group went through, from the group CA to the
// current root (docs/protocol.md, section 10, rule 7): from each root, the
// root record signed under it that counts and whose new root has the
// smallest SHA-256 leads to the next.
func (s *Records) path() []*x509.Certificate {
	path, _ := s.steps()
	return path
}

// steps returns the path and the root records that lead along it, one for
// each root after the group CA.
func (s *Records) steps() ([]*x509.Certificate, []*signedRecord) {
	path := []*x509.Certificate{s.groupCA}
	var steps []*signedRecord
	on := map[KeyHash]bool{s.caKey: true}
	for {
		cur := KeyHashOf(path[len(path)-1])
		var next *signedRecord
		var best [sha256.Size]byte
		for _, r := range s.byID {
			if r.root == nil || r.anchor != cur || on[KeyHashOf(r.root)] || s.Revoked(r.signer) && !s.upgradeStands(r) || !s.fromRoot(r) || !s.mayHandOver(r) {
				continue
			}
			if sum := sha256.Sum256(r.root.Raw); next == nil || bytes.Compare(sum[:], best[:]) < 0 {
				next, best = r, sum
			}
		}
		if next == nil {
			return path, steps
		}
		path = append(path, next.root)
		steps = append(steps, next)
		on[KeyHashOf(next.root)] = true
	}
}

// PathRecords returns the records that lead to the path: each root record
// on it and, for one an admin CA signed, the device records its root's own
// key signed that name that admin CA or the root's own device. A new
// member gets them in the Welcome's records and checks with them that the
// Welcome's roots are the group's (docs/protocol.md, section 5).
func (s *Records) PathRecords() []Record {
	_, steps := s.steps()
	var out []Record
	for _, st := range steps {
		out = append(out, st.Record)
		if st.signer == st.anchor {
			continue
		}
		for _, id := range s.sortedIDs() {
			r := s.byID[id]
			b := r.body
			if b.Type == RecordDevice && r.signer == st.anchor && r.anchor == st.anchor && (b.Device == b.By || b.Admin != nil && *b.Admin == st.signer) {
				out = append(out, r.Record)
			}
		}
	}
	return out
}

// upgradeStands reports whether the root record r, in which a legacy group
// CA hands the group to its first root (cbb upgrade), still counts though
// the group CA's key is revoked: every record that revokes it was signed
// under the root that r names. A leftover copy of the old key can sign a
// rival root record or a revocation of its own, which breaks the group,
// but it never takes it over.
func (s *Records) upgradeStands(r *signedRecord) bool {
	if r.anchor != s.caKey || r.signer != r.anchor || s.groupCA.MaxPathLen != 0 {
		return false
	}
	root := KeyHashOf(r.root)
	for _, rv := range s.byID {
		if rv.body.Type == RecordRevoke && slices.Contains(rv.body.Keys, r.signer) && rv.anchor != root {
			return false
		}
	}
	return true
}

// Roots returns the roots that took the group over from the group CA, in
// order; the last is the current root. It is empty in a group that was
// never handed over.
func (s *Records) Roots() []*x509.Certificate { return s.path()[1:] }

// onPath returns the keys of the roots on the path.
func (s *Records) onPath() map[KeyHash]bool {
	on := map[KeyHash]bool{}
	for _, c := range s.path() {
		on[KeyHashOf(c)] = true
	}
	return on
}

// fromRoot reports whether the admin CA that signed a record still stands
// under its root: the root is not revoked, or every record that revoked it
// keeps the admin CA. A root's own signature always does.
func (s *Records) fromRoot(r *signedRecord) bool {
	return r.signer == r.anchor || s.issued(r.anchor, r.signer)
}

// issued reports whether what issuer certified, the key k, still stands:
// the issuer is not revoked, or every record that revoked it keeps k.
func (s *Records) issued(issuer, k KeyHash) bool {
	return !s.Revoked(issuer) || s.kept(issuer, k)
}

// CheckAdminCA checks that c is an admin CA certified by root: a CA with
// path length 0 and a P-256 key, signed by root, which allows one level of
// CAs below it.
func CheckAdminCA(c, root *x509.Certificate) error { return checkAdminCA(c, root) }

// checkAdminCA checks that c is an admin CA certified by root: a CA with
// path length 0 and a P-256 key, signed by root, which allows one level of
// CAs below it.
func checkAdminCA(c, root *x509.Certificate) error {
	if !c.IsCA || !c.BasicConstraintsValid || c.MaxPathLen != 0 || c.KeyUsage&x509.KeyUsageCertSign == 0 {
		return errors.New("group: the signer is not an admin CA")
	}
	if pub, ok := c.PublicKey.(*ecdsa.PublicKey); !ok || pub.Curve != elliptic.P256() {
		return errors.New("group: the admin CA key is not a P-256 key")
	}
	if root.MaxPathLen < 1 {
		return errors.New("group: the group CA certifies no admin CAs")
	}
	if err := c.CheckSignatureFrom(root); err != nil {
		return fmt.Errorf("group: the admin CA is not from the group CA: %w", err)
	}
	return nil
}

// Revoked reports whether a key is revoked (docs/protocol.md, section 10,
// rules 2 and 3): named by a revocation record that counts, or an admin or root
// key named by a revocation from a root or an admin phone.
func (s *Records) Revoked(k KeyHash) bool { return s.eval().revoked[k] }

// Frozen reports whether a key is frozen (docs/protocol.md, section 10,
// rule 4): a computer's admin CA that a freeze that counts names, or the
// device key of such an admin.
func (s *Records) Frozen(k KeyHash) bool {
	ev := s.eval()
	return len(ev.freezes[k]) > 0 || ev.frozenKeys[k]
}

// SignedBy returns the IDs of the records that the admin CA with key admin
// signed: what a freeze of that admin keeps.
func (s *Records) SignedBy(admin KeyHash) []KeyHash {
	var out []KeyHash
	for _, id := range s.sortedIDs() {
		if r := s.byID[id]; r.signer == admin && r.signer != r.anchor {
			out = append(out, r.id)
		}
	}
	return out
}

// FreezesOf returns the IDs of the freezes of the admin CA with key admin
// that count: what a thaw of that admin ends.
func (s *Records) FreezesOf(admin KeyHash) []KeyHash {
	var out []KeyHash
	for _, r := range s.eval().freezes[admin] {
		out = append(out, r.id)
	}
	slices.SortFunc(out, func(a, b KeyHash) int { return bytes.Compare(a[:], b[:]) })
	return out
}

// mayHandOver reports whether the signer of a root record may hand the
// group over: a root's own key, an admin phone's admin CA, or a computer's
// admin CA when the root it replaces is a computer too (computerHandOver).
func (s *Records) mayHandOver(r *signedRecord) bool {
	ev := s.eval()
	return ev.rootSigned(r) || ev.phoneAdmin[r.signer] && ev.roots[r.anchor] || ev.roots[r.anchor] && s.computerHandOver(r)
}

// computerHandOver reports whether r, a root record, was signed by the
// admin CA of a computer under its anchor, a root that is a computer
// itself: the root's own key signed a device record that names that admin
// CA, and the root's own device record is a computer's. Only that root's
// own records can stop it: a revocation from its own key that names the
// admin CA, or a freeze of it that the root's own key or another admin CA
// it certified (and did not revoke) signed and the root's own key did not
// thaw. In a group whose root is a computer the root key sits in a file as
// the admin's does, so an admin computer may take the group over from a
// lost root; a root that is still there undoes it by removing that admin
// (docs/protocol.md, section 10, rule 2).
func (s *Records) computerHandOver(r *signedRecord) bool {
	if r.root == nil || r.signer == r.anchor {
		return false
	}
	R := r.anchor
	admins, revoked, thawed := map[KeyHash]bool{}, map[KeyHash]bool{}, map[KeyHash]bool{}
	computer := false
	for _, o := range s.byID {
		b := o.body
		if o.signer != R || o.anchor != R {
			continue
		}
		switch b.Type {
		case RecordRevoke:
			for _, k := range b.Keys {
				revoked[k] = true
			}
		case RecordThaw:
			for _, id := range b.Records {
				thawed[id] = true
			}
		case RecordDevice:
			switch {
			case role(b.Role) == RolePhone && b.Device == b.By:
				return false
			case b.Device == b.By && role(b.Role) == RoleFull:
				computer = true
			}
			if b.Admin != nil && role(b.Role) != RolePhone {
				admins[*b.Admin] = true
			}
		}
	}
	if !computer || !admins[r.signer] || revoked[r.signer] {
		return false
	}
	for _, o := range s.byID {
		if o.body.Type != RecordFreeze || o.anchor != R || !slices.Contains(o.body.Keys, r.signer) || thawed[o.id] {
			continue
		}
		if o.signer == R || admins[o.signer] && !revoked[o.signer] {
			return false
		}
	}
	return true
}

// An evaluation is what the set says about revocations (docs/protocol.md,
// section 10, rules 2 and 3), in strata that do not depend on each other
// in a circle:
//
//  1. A revocation signed by a root's own key always counts.
//  2. An admin CA is an admin phone's when a device record of a phone,
//     signed by a root's own key that the root revocations leave standing
//     for it, names it as its admin CA.
//  3. An admin or root key that a revocation from a root or an admin phone
//     names is disabled: the records its admin CA signs no longer count.
//  4. A computer's admin CA is one that a device record of a computer,
//     signed by a root's own key, names. A thaw signed by a root's own key
//     or an admin phone that is not disabled ends the freeze records it
//     names.
//  5. A freeze that no thaw ended counts when a root's own key signed it,
//     or an admin CA that is not disabled and still stands under its root,
//     and every key it names is a computer's admin CA. A frozen admin CA's
//     records count only when every freeze of it names them, and its
//     device's key is refused.
//  6. A revocation signed by an admin CA counts when that admin CA is not
//     disabled and still stands under its root, and, for a computer's
//     admin CA, when it names no admin or root key; an admin phone's names
//     no root key.
type evaluation struct {
	revoked    map[KeyHash]bool
	revokers   map[KeyHash][]*signedRecord // the records that revoked each key
	phoneAdmin map[KeyHash]bool
	roots      map[KeyHash]bool            // the known roots (knownRoots)
	freezes    map[KeyHash][]*signedRecord // the freezes that count, for each frozen admin CA
	frozenKeys map[KeyHash]bool            // the device keys of the frozen admins
}

// kept reports whether every freeze of r's signer names r, as for the
// records of an admin that is not frozen.
func (ev *evaluation) kept(r *signedRecord) bool {
	for _, f := range ev.freezes[r.signer] {
		if !slices.Contains(f.body.Records, r.id) {
			return false
		}
	}
	return true
}

func (s *Records) eval() *evaluation {
	if s.ev != nil {
		return s.ev
	}
	ev := &evaluation{revoked: map[KeyHash]bool{}, revokers: map[KeyHash][]*signedRecord{}, phoneAdmin: map[KeyHash]bool{},
		roots: s.knownRoots(), freezes: map[KeyHash][]*signedRecord{}, frozenKeys: map[KeyHash]bool{}}
	byRoot := map[KeyHash][]*signedRecord{} // the root revocations of each key
	privileged := map[KeyHash]bool{}        // the root and admin keys
	for k := range s.roots {
		privileged[k] = true
	}
	for _, r := range s.byID {
		switch {
		case r.body.Type == RecordRevoke && ev.rootSigned(r):
			for _, k := range r.body.Keys {
				byRoot[k] = append(byRoot[k], r)
			}
		case r.body.Type == RecordDevice && r.body.Admin != nil:
			privileged[*r.body.Admin] = true
		}
		if r.signer != r.anchor {
			privileged[r.signer] = true
		}
	}
	// standsForRoots reports whether what issuer certified, the key k,
	// stands as far as the root revocations go.
	standsForRoots := func(issuer, k KeyHash) bool {
		for _, r := range byRoot[issuer] {
			if !slices.Contains(r.body.Keep, k) {
				return false
			}
		}
		return true
	}
	for _, r := range s.byID {
		if a := phoneAdminOf(r, ev.roots); a != nil && standsForRoots(r.signer, *a) {
			ev.phoneAdmin[*a] = true
		}
	}
	disabled := map[KeyHash]bool{}
	for _, r := range s.byID {
		if r.body.Type != RecordRevoke || !ev.rootSigned(r) && !(ev.phoneAdmin[r.signer] && ev.roots[r.anchor]) {
			continue
		}
		for _, k := range r.body.Keys {
			if privileged[k] && (ev.rootSigned(r) || !ev.roots[k]) {
				disabled[k] = true
				ev.revoked[k] = true
				ev.revokers[k] = append(ev.revokers[k], r)
			}
		}
	}
	computers := map[KeyHash][]KeyHash{} // the device keys of each computer's admin CA
	thawed := map[KeyHash]bool{}
	for _, r := range s.byID {
		b := r.body
		switch {
		case b.Type == RecordDevice && b.Admin != nil && role(b.Role) != RolePhone && ev.rootSigned(r) && !ev.phoneAdmin[*b.Admin]:
			computers[*b.Admin] = append(computers[*b.Admin], *b.Key)
		case b.Type == RecordThaw && (ev.rootSigned(r) || ev.phoneAdmin[r.signer] && ev.roots[r.anchor] && !disabled[r.signer]):
			for _, id := range b.Records {
				thawed[id] = true
			}
		}
	}
	for _, r := range s.byID {
		if !ev.freezeCounts(r, disabled, computers, thawed, standsForRoots) {
			continue
		}
		for _, k := range r.body.Keys {
			ev.freezes[k] = append(ev.freezes[k], r)
			for _, d := range computers[k] {
				ev.frozenKeys[d] = true
			}
		}
	}
	for _, r := range s.byID {
		if r.body.Type != RecordRevoke || !ev.counts(r, disabled, privileged, standsForRoots) || !ev.kept(r) {
			continue
		}
		for _, k := range r.body.Keys {
			if !slices.Contains(ev.revokers[k], r) {
				ev.revoked[k] = true
				ev.revokers[k] = append(ev.revokers[k], r)
			}
		}
	}
	s.ev = ev
	return ev
}

// knownRoots returns the roots whose own signatures may count: the group CA
// and the new root of every root record that a known root's own key or an
// admin phone under a known root signed, or that an admin computer signed
// under a root that is a computer (computerHandOver). A root that a
// computer's admin CA named in any other case is not one of them, so its
// key, which that admin holds, signs nothing that counts.
func (s *Records) knownRoots() map[KeyHash]bool {
	known := map[KeyHash]bool{s.caKey: true}
	for {
		phones := map[KeyHash]bool{}
		for _, r := range s.byID {
			if a := phoneAdminOf(r, known); a != nil {
				phones[*a] = true
			}
		}
		grew := false
		for _, r := range s.byID {
			if r.root == nil || !known[r.anchor] || r.signer != r.anchor && !phones[r.signer] && !s.computerHandOver(r) {
				continue
			}
			if k := KeyHashOf(r.root); !known[k] {
				known[k], grew = true, true
			}
		}
		if !grew {
			return known
		}
	}
}

// phoneAdminOf returns the admin CA key that r, a device record of a phone
// signed by the own key of one of roots, names; nil for any other record.
func phoneAdminOf(r *signedRecord, roots map[KeyHash]bool) *KeyHash {
	b := r.body
	if b.Type != RecordDevice || b.Admin == nil || role(b.Role) != RolePhone || r.signer != r.anchor || !roots[r.signer] {
		return nil
	}
	return b.Admin
}

// rootSigned reports whether a known root's own key signed r.
func (ev *evaluation) rootSigned(r *signedRecord) bool {
	return r.signer == r.anchor && ev.roots[r.anchor]
}

// freezeCounts reports whether r is a freeze that counts (rule 5 above). A
// frozen admin's freezes still count, so two admins that freeze each other
// both stay frozen until the root or an admin phone decides.
func (ev *evaluation) freezeCounts(r *signedRecord, disabled map[KeyHash]bool, computers map[KeyHash][]KeyHash, thawed map[KeyHash]bool, standsForRoots func(issuer, k KeyHash) bool) bool {
	if r.body.Type != RecordFreeze || thawed[r.id] || !ev.roots[r.anchor] {
		return false
	}
	if r.signer != r.anchor && (disabled[r.signer] || !standsForRoots(r.anchor, r.signer)) {
		return false
	}
	for _, k := range r.body.Keys {
		if computers[k] == nil {
			return false
		}
	}
	return true
}

// counts reports whether a revocation record counts (rule 6 above).
func (ev *evaluation) counts(r *signedRecord, disabled, privileged map[KeyHash]bool, standsForRoots func(issuer, k KeyHash) bool) bool {
	if r.signer == r.anchor {
		return ev.roots[r.anchor]
	}
	if !ev.roots[r.anchor] || disabled[r.signer] || !standsForRoots(r.anchor, r.signer) {
		return false
	}
	for _, k := range r.body.Keys {
		if ev.roots[k] || privileged[k] && !ev.phoneAdmin[r.signer] {
			return false
		}
	}
	return true
}

// counts reports whether a device record counts: it was signed under a
// root on the path, by an admin CA that still stands under it, and its
// signer's key is not revoked, or every record that revoked it keeps the
// device's key, as when an admin is removed and the devices it admitted
// stay.
func (s *Records) counts(r *signedRecord, on map[KeyHash]bool) bool {
	return on[r.anchor] && s.fromRoot(r) && s.issued(r.signer, *r.body.Key) && s.eval().kept(r)
}

// kept reports whether admin is revoked only by records that keep the key
// leaf. A key that one record keeps and another drops is not kept.
func (s *Records) kept(admin, leaf KeyHash) bool {
	rs := s.eval().revokers[admin]
	for _, r := range rs {
		if !slices.Contains(r.body.Keep, leaf) {
			return false
		}
	}
	return len(rs) > 0
}

// Refused reports why a member certificate chain (leaf first, then its
// issuer when that is an admin CA) is refused, or nil. A chain whose top
// is not signed by a root on the path is refused. A certificate is
// refused when its key is revoked, or when its issuer's key is revoked and
// not every record that revoked the issuer keeps it: for the leaf and, when
// an admin CA issued it, for that admin CA under its root.
//
// The issuer checked is the certificate that signed the leaf, wherever it
// is in the chain: a peer may present certificates it does not need, and
// TLS verification ignores them, so position alone proves nothing.
func (s *Records) Refused(chain []*x509.Certificate) error {
	if len(chain) == 0 {
		return errors.New("group: no certificate")
	}
	leaf := KeyHashOf(chain[0])
	if s.Revoked(leaf) {
		return errors.New("group: the device was removed from the group")
	}
	if s.Frozen(leaf) {
		return errors.New("group: the device is a frozen admin; the root or an admin phone unfreezes or removes it")
	}
	path := s.path()
	top := chain[0]
	if !signedByAny(top, path) {
		var issuer *x509.Certificate
		for _, c := range chain[1:] {
			if top.CheckSignatureFrom(c) == nil {
				issuer = c
				break
			}
		}
		if issuer == nil {
			return errors.New("group: the certificate's issuer is not in its chain")
		}
		admin := KeyHashOf(issuer)
		if !s.issued(admin, leaf) {
			return errors.New("group: the admin that admitted the device was removed")
		}
		// A frozen admin's certificates hold only for devices the records
		// already list, so it cannot bring in a new one.
		if s.Frozen(admin) && !s.listed(leaf) {
			return errors.New("group: the admin that certified the device is frozen")
		}
		top, leaf = issuer, admin
	}
	// The chain must end at a root on the path: a root that only an
	// identity or a TLS pool trusts, as one a Welcome named, is no anchor.
	for _, root := range path {
		if top.CheckSignatureFrom(root) == nil {
			if !s.issued(KeyHashOf(root), leaf) {
				return errors.New("group: the certificate is from a root that handed the group over")
			}
			return nil
		}
	}
	return errors.New("group: the certificate is not from a root of the group")
}

// listed reports whether a device record that counts names the key k.
func (s *Records) listed(k KeyHash) bool {
	on := s.onPath()
	for _, r := range s.byID {
		if r.body.Type == RecordDevice && *r.body.Key == k && s.counts(r, on) {
			return true
		}
	}
	return false
}

// A Device is one entry of the devices list.
type Device struct {
	ID    DeviceID
	Name  string
	Role  string // RoleFull, RolePhone, RoleLite or RoleShortcut
	OS    string // "" when its record does not tell
	Key   KeyHash
	Admin bool
	// AdminKey is the key of its admin CA, as its record names it; nil
	// when it has none.
	AdminKey *KeyHash
	By       DeviceID // the admin that admitted it, as its record says
	Since    time.Time
	// Frozen says that it is an admin computer that another admin froze:
	// it is no admin until the root or an admin phone unfreezes it, and its
	// connections are refused.
	Frozen bool
}

// Devices returns the devices list: the latest device record that counts
// for each device, without revoked keys, sorted by name and then ID. The
// "latest" record of a device is the one with the largest time, then the
// largest record ID, so every member picks the same one.
func (s *Records) Devices() []Device {
	latest := map[DeviceID]*signedRecord{}
	first := map[DeviceID]int64{}
	on := s.onPath()
	for _, r := range s.byID {
		if r.body.Type != RecordDevice || !s.counts(r, on) {
			continue
		}
		d := r.body.Device
		if t, ok := first[d]; !ok || r.body.TimeMS < t {
			first[d] = r.body.TimeMS
		}
		if cur, ok := latest[d]; !ok || newer(r, cur) {
			latest[d] = r
		}
	}
	var out []Device
	for id, r := range latest {
		if s.Revoked(*r.body.Key) {
			continue
		}
		out = append(out, Device{
			ID:       id,
			Name:     r.body.Name,
			Role:     role(r.body.Role),
			OS:       osOf(r.body),
			Key:      *r.body.Key,
			Admin:    r.body.Admin != nil && !s.Revoked(*r.body.Admin) && !s.Frozen(*r.body.Admin),
			AdminKey: r.body.Admin,
			By:       r.body.By,
			Since:    time.UnixMilli(first[id]),
			Frozen:   s.Frozen(*r.body.Key) || r.body.Admin != nil && s.Frozen(*r.body.Admin),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// Admitted returns the keys of the devices whose records the admin with
// key admin signed, and that a freeze of it keeps: what a revocation of
// that admin keeps, so the devices it admitted stay in the group.
func (s *Records) Admitted(admin KeyHash) []KeyHash {
	ev := s.eval()
	var out []KeyHash
	for _, id := range s.sortedIDs() {
		r := s.byID[id]
		if r.body.Type == RecordDevice && r.signer == admin && ev.kept(r) && !slices.Contains(out, *r.body.Key) {
			out = append(out, *r.body.Key)
		}
	}
	return out
}

// RevokedBy returns the keys that revocations signed by the admin CA with
// key admin revoked and that count: what the record that removes that
// admin names again, so its removals stand once its own records no longer
// count (docs/protocol.md, section 10).
func (s *Records) RevokedBy(admin KeyHash) []KeyHash {
	ev := s.eval()
	var out []KeyHash
	for _, id := range s.sortedIDs() {
		r := s.byID[id]
		if r.body.Type != RecordRevoke || r.signer != admin {
			continue
		}
		for _, k := range r.body.Keys {
			if slices.Contains(ev.revokers[k], r) && !slices.Contains(out, k) {
				out = append(out, k)
			}
		}
	}
	return out
}

// RootDevice returns the phone or computer that holds the group's current
// root: the one whose own device record the current root's key signed, the
// latest of them; "" when there is none, as in a legacy group not yet
// upgraded, whose key every Linux member holds.
func (s *Records) RootDevice() DeviceID {
	path := s.path()
	if path[len(path)-1].MaxPathLen == 0 {
		return ""
	}
	cur := KeyHashOf(path[len(path)-1])
	var best *signedRecord
	for _, r := range s.byID {
		b := r.body
		if b.Type == RecordDevice && r.signer == cur && (role(b.Role) == RolePhone || role(b.Role) == RoleFull) && b.Device == b.By && (best == nil || newer(r, best)) {
			best = r
		}
	}
	if best == nil {
		return ""
	}
	return best.body.Device
}

func newer(a, b *signedRecord) bool {
	if a.body.TimeMS != b.body.TimeMS {
		return a.body.TimeMS > b.body.TimeMS
	}
	ai, bi := a.ID(), b.ID()
	return bytes.Compare(ai[:], bi[:]) > 0
}

// All returns every record, sorted by ID.
func (s *Records) All() []Record {
	ids := s.sortedIDs()
	out := make([]Record, len(ids))
	for i, id := range ids {
		out[i] = s.byID[id].Record
	}
	return out
}

func (s *Records) sortedIDs() [][sha256.Size]byte {
	ids := make([][sha256.Size]byte, 0, len(s.byID))
	for id := range s.byID {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return bytes.Compare(ids[i][:], ids[j][:]) < 0 })
	return ids
}

// Digest returns SHA-256 over the sorted record IDs in base64, the value a
// hello carries; "" for an empty set.
func (s *Records) Digest() string {
	if len(s.byID) == 0 {
		return ""
	}
	h := sha256.New()
	for _, id := range s.sortedIDs() {
		h.Write(id[:])
	}
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// Save writes the records to dir/records.json, replacing the file in one
// step.
func (s *Records) Save(dir string) error {
	data, err := json.MarshalIndent(s.All(), "", "\t")
	if err != nil {
		return err
	}
	return atomicfile.Write(filepath.Join(dir, RecordsFileName), append(data, '\n'), 0o600)
}

// LoadRecords reads dir/records.json for the group of groupCA. A missing
// file is an empty set; records that are not valid for the group, such as
// those of an earlier group, are left out.
func LoadRecords(dir string, groupCA *x509.Certificate) (*Records, error) {
	s := NewRecords(groupCA)
	data, err := os.ReadFile(filepath.Join(dir, RecordsFileName))
	if errors.Is(err, fs.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	var all []Record
	if err := json.Unmarshal(data, &all); err != nil {
		return nil, fmt.Errorf("%s: %w", filepath.Join(dir, RecordsFileName), err)
	}
	s.AddAll(all) // records of another group are dropped
	return s, nil
}

// signedByAny reports whether one of roots signed c.
func signedByAny(c *x509.Certificate, roots []*x509.Certificate) bool {
	for _, root := range roots {
		if c.CheckSignatureFrom(root) == nil {
			return true
		}
	}
	return false
}
