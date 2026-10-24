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
	MaxRecords    = 4096
	maxRecordBody = 8 << 10
	recordVersion = 1
)

// Record types.
const (
	RecordDevice = "device"
	RecordRevoke = "revoke"
	RecordRoot   = "root"
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
	// the new root of every root record in the set.
	roots map[KeyHash]*x509.Certificate
}

// NewRecords returns an empty set for the group of groupCA, the group's
// first root, which names the group for good.
func NewRecords(groupCA *x509.Certificate) *Records {
	caKey := KeyHashOf(groupCA)
	return &Records{
		groupCA: groupCA,
		tag:     Tag(groupCA),
		caKey:   caKey,
		byID:    map[[sha256.Size]byte]*signedRecord{},
		roots:   map[KeyHash]*x509.Certificate{caKey: groupCA},
	}
}

// Len returns the number of records.
func (s *Records) Len() int { return len(s.byID) }

// Add checks a record and adds it. It reports whether the record was new; a
// record that is not valid for this group is an error.
func (s *Records) Add(r Record) (bool, error) {
	id := r.ID()
	if _, ok := s.byID[id]; ok {
		return false, nil
	}
	if len(s.byID) >= MaxRecords {
		return false, errors.New("group: too many records")
	}
	sr, err := s.verify(r)
	if err != nil {
		return false, err
	}
	s.byID[id] = sr
	if sr.root != nil {
		if k := KeyHashOf(sr.root); s.roots[k] == nil {
			s.roots[k] = sr.root
		}
	}
	return true, nil
}

// AddAll adds the valid records among rs and returns those that were new,
// and an error for each record that is not valid. A record signed under a
// new root is taken once the root record that names that root is in the
// set, so the result does not depend on the order of rs.
func (s *Records) AddAll(rs []Record) (fresh []Record, errs []error) {
	pending := rs
	for {
		var rest []Record
		errs = errs[:0]
		rooted := false
		for _, r := range pending {
			isNew, err := s.Add(r)
			switch {
			case err != nil:
				rest = append(rest, r)
				errs = append(errs, err)
			case isNew:
				fresh = append(fresh, r)
				rooted = rooted || r.Type() == RecordRoot
			}
		}
		if !rooted || len(rest) == 0 {
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
	sr := &signedRecord{Record: r, body: body}
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
		if s.roots[sr.anchor].MaxPathLen != 1 {
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
// current root (docs/protocol.md, section 10, rule 5): from each root, the
// root record signed under it that counts and whose new root has the
// smallest SHA-256 leads to the next.
func (s *Records) path() []*x509.Certificate {
	path := []*x509.Certificate{s.groupCA}
	on := map[KeyHash]bool{s.caKey: true}
	for {
		cur := KeyHashOf(path[len(path)-1])
		var next *signedRecord
		var best [sha256.Size]byte
		for _, r := range s.byID {
			if r.root == nil || r.anchor != cur || on[KeyHashOf(r.root)] || s.Revoked(r.signer) || !s.fromRoot(r) {
				continue
			}
			if sum := sha256.Sum256(r.root.Raw); next == nil || bytes.Compare(sum[:], best[:]) < 0 {
				next, best = r, sum
			}
		}
		if next == nil {
			return path
		}
		path = append(path, next.root)
		on[KeyHashOf(next.root)] = true
	}
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

// Revoked reports whether a key is revoked: named by a revocation record
// from an admin, whether or not that admin is itself revoked.
func (s *Records) Revoked(k KeyHash) bool {
	for _, r := range s.byID {
		if r.body.Type == RecordRevoke && slices.Contains(r.body.Keys, k) {
			return true
		}
	}
	return false
}

// counts reports whether a device record counts: it was signed under a
// root on the path, by an admin CA that still stands under it, and its
// signer's key is not revoked, or every record that revoked it keeps the
// device's key, as when an admin is removed and the devices it admitted
// stay.
func (s *Records) counts(r *signedRecord, on map[KeyHash]bool) bool {
	return on[r.anchor] && s.fromRoot(r) && s.issued(r.signer, *r.body.Key)
}

// kept reports whether admin is revoked only by records that keep the key
// leaf. A key that one record keeps and another drops is not kept.
func (s *Records) kept(admin, leaf KeyHash) bool {
	revoked := false
	for _, r := range s.byID {
		if r.body.Type != RecordRevoke || !slices.Contains(r.body.Keys, admin) {
			continue
		}
		if !slices.Contains(r.body.Keep, leaf) {
			return false
		}
		revoked = true
	}
	return revoked
}

// Refused reports why a member certificate chain (leaf first, then its
// issuer when that is an admin CA) is refused, or nil. The chain is assumed
// to be verified to one of the group's roots already. A certificate is
// refused when its key is revoked, or when its issuer's key is revoked and
// not every record that revoked the issuer keeps it: for the leaf and, when
// an admin CA issued it, for that admin CA under its root.
func (s *Records) Refused(chain []*x509.Certificate) error {
	if len(chain) == 0 {
		return errors.New("group: no certificate")
	}
	leaf := KeyHashOf(chain[0])
	if s.Revoked(leaf) {
		return errors.New("group: the device was removed from the group")
	}
	top := chain[0]
	if len(chain) >= 2 {
		admin := KeyHashOf(chain[1])
		if !s.issued(admin, leaf) {
			return errors.New("group: the admin that admitted the device was removed")
		}
		top, leaf = chain[1], admin
	}
	for _, root := range s.path() {
		if top.CheckSignatureFrom(root) == nil {
			if !s.issued(KeyHashOf(root), leaf) {
				return errors.New("group: the certificate is from a root that handed the group over")
			}
			break
		}
	}
	return nil
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
			Admin:    r.body.Admin != nil && !s.Revoked(*r.body.Admin),
			AdminKey: r.body.Admin,
			By:       r.body.By,
			Since:    time.UnixMilli(first[id]),
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
// key admin signed: what a revocation of that admin keeps, so the devices
// it admitted stay in the group.
func (s *Records) Admitted(admin KeyHash) []KeyHash {
	var out []KeyHash
	for _, id := range s.sortedIDs() {
		r := s.byID[id]
		if r.body.Type == RecordDevice && r.signer == admin && !slices.Contains(out, *r.body.Key) {
			out = append(out, *r.body.Key)
		}
	}
	return out
}

// RootDevice returns the phone or computer that holds the group's current
// root: the one whose own device record the current root's key signed, the
// latest of them; "" when there is none, as in a legacy group, whose key
// every Linux member holds.
func (s *Records) RootDevice() DeviceID {
	if s.groupCA.MaxPathLen == 0 {
		return ""
	}
	path := s.path()
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
