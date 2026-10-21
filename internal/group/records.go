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

	"github.com/HunterEwok/clipbridge/internal/atomicfile"
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

// Device roles in device records: the member roles, and iphone for a phone
// that uses the shortcut and its token.
const (
	RoleLinux  = "linux"
	RoleMac    = "mac"
	RolePhone  = "phone"
	RoleLite   = "lite"
	RoleIPhone = "iphone"
)

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
		switch b.Role {
		case RoleLinux, RoleMac, RolePhone, RoleLite, RoleIPhone:
		default:
			return fmt.Errorf("group: unknown role %q in a device record", b.Role)
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
}

// Records is the set of a group's records. It only grows; what it says
// depends on the records alone, never on the order in which they were added
// (docs/protocol.md, section 10). It is not safe for concurrent use.
type Records struct {
	groupCA *x509.Certificate
	tag     string
	caKey   KeyHash
	byID    map[[sha256.Size]byte]*signedRecord
}

// NewRecords returns an empty set for the group of groupCA.
func NewRecords(groupCA *x509.Certificate) *Records {
	return &Records{
		groupCA: groupCA,
		tag:     Tag(groupCA),
		caKey:   KeyHashOf(groupCA),
		byID:    map[[sha256.Size]byte]*signedRecord{},
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
	return true, nil
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
	if body.Type == RecordRoot {
		// Handing a group to a new root comes with the phone apps.
		return nil, errors.New("group: root records are not supported yet")
	}
	pub, signer, err := s.signerKey(r.Chain)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(r.Body)
	if !ecdsa.VerifyASN1(pub, sum[:], r.Sig) {
		return nil, errors.New("group: the record's signature is not valid")
	}
	return &signedRecord{Record: r, body: body, signer: signer}, nil
}

// signerKey returns the key that must have signed a record with chain: the
// group CA's, or that of an admin CA the group CA certified.
func (s *Records) signerKey(chain [][]byte) (*ecdsa.PublicKey, KeyHash, error) {
	switch len(chain) {
	case 0:
		return s.groupCA.PublicKey.(*ecdsa.PublicKey), s.caKey, nil
	case 1:
		admin, err := x509.ParseCertificate(chain[0])
		if err != nil {
			return nil, KeyHash{}, fmt.Errorf("group: a record's signer: %w", err)
		}
		if err := checkAdminCA(admin, s.groupCA); err != nil {
			return nil, KeyHash{}, err
		}
		return admin.PublicKey.(*ecdsa.PublicKey), KeyHashOf(admin), nil
	}
	return nil, KeyHash{}, errors.New("group: a record's chain is too long")
}

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

// counts reports whether a device record counts: its signer's key is not
// revoked, or every record that revoked it keeps the device's key, as when
// an admin is removed and the devices it admitted stay.
func (s *Records) counts(r *signedRecord) bool {
	return !s.Revoked(r.signer) || s.kept(r.signer, *r.body.Key)
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
// to be verified to the group CA already.
func (s *Records) Refused(chain []*x509.Certificate) error {
	if len(chain) == 0 {
		return errors.New("group: no certificate")
	}
	leaf := KeyHashOf(chain[0])
	if s.Revoked(leaf) {
		return errors.New("group: the device was removed from the group")
	}
	if len(chain) < 2 {
		return nil
	}
	if admin := KeyHashOf(chain[1]); s.Revoked(admin) && !s.kept(admin, leaf) {
		return errors.New("group: the admin that admitted the device was removed")
	}
	return nil
}

// A Device is one entry of the devices list.
type Device struct {
	ID    DeviceID
	Name  string
	Role  string
	Key   KeyHash
	Admin bool
	By    DeviceID // the admin that admitted it, as its record says
	Since time.Time
}

// Devices returns the devices list: the latest device record that counts
// for each device, without revoked keys, sorted by name and then ID. The
// "latest" record of a device is the one with the largest time, then the
// largest record ID, so every member picks the same one.
func (s *Records) Devices() []Device {
	latest := map[DeviceID]*signedRecord{}
	first := map[DeviceID]int64{}
	for _, r := range s.byID {
		if r.body.Type != RecordDevice || !s.counts(r) {
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
			ID:    id,
			Name:  r.body.Name,
			Role:  r.body.Role,
			Key:   *r.body.Key,
			Admin: r.body.Admin != nil && !s.Revoked(*r.body.Admin),
			By:    r.body.By,
			Since: time.UnixMilli(first[id]),
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
	for _, r := range all {
		_, _ = s.Add(r) // records of another group are dropped
	}
	return s, nil
}
