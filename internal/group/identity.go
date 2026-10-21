// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package group

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/HunterEwok/clipbridge/internal/atomicfile"
)

// FileName is the name of the identity file in the state directory.
const FileName = "identity.json"

// ErrNoGroup reports that the device is in no group yet.
var ErrNoGroup = errors.New("group: this device is in no group; run clipbridge pair or clipbridge join")

// An Identity is this device's place in a group: its device ID, its key,
// its member certificate and the group CA. A Linux member also holds the
// keys of both CAs and its own clipbridge.local certificate, so it can admit
// devices and serve the iPhone; a Mac holds neither.
//
// An Identity is not changed after it is made; renewing returns a new one.
type Identity struct {
	ID      DeviceID
	Key     *ecdsa.PrivateKey
	Cert    *x509.Certificate // from the group CA
	GroupCA CA
	PhoneCA *CA               // nil on a Mac
	Phone   *x509.Certificate // the clipbridge.local certificate, with Key; nil on a Mac
}

// Create creates a new group on this device: a device ID, a key, both CAs
// and the device's certificates.
func Create(now time.Time) (*Identity, error) {
	key, err := NewKey()
	if err != nil {
		return nil, err
	}
	groupCA, err := NewGroupCA(now)
	if err != nil {
		return nil, err
	}
	phoneCA, err := NewPhoneCA(now)
	if err != nil {
		return nil, err
	}
	id := NewDeviceID()
	cert, err := groupCA.IssueMember(id, &key.PublicKey, now)
	if err != nil {
		return nil, err
	}
	phone, err := phoneCA.IssuePhone(&key.PublicKey, now)
	if err != nil {
		return nil, err
	}
	return &Identity{ID: id, Key: key, Cert: cert, GroupCA: *groupCA, PhoneCA: phoneCA, Phone: phone}, nil
}

// Admin reports whether this device holds the CA keys and can admit
// devices, renew certificates and serve the iPhone.
func (id *Identity) Admin() bool {
	return id.GroupCA.Key != nil && id.PhoneCA != nil && id.PhoneCA.Key != nil && id.Phone != nil
}

// Check reports whether the parts of the identity belong together: the
// certificates name this device and its key and were signed by the CAs, and
// the CA keys match the CA certificates. It does not check expiry.
func (id *Identity) Check() error {
	if _, err := ParseDeviceID(string(id.ID)); err != nil {
		return err
	}
	if id.Key == nil || id.Key.Curve != elliptic.P256() {
		return errors.New("group: the device key is not a P-256 key")
	}
	if err := checkCA(&id.GroupCA, "group CA"); err != nil {
		return err
	}
	if err := checkLeaf(id.Cert, id.GroupCA.Cert, id.Key, "member certificate"); err != nil {
		return err
	}
	if dev, err := DeviceOf(id.Cert); err != nil || dev != id.ID {
		return fmt.Errorf("group: the member certificate does not name the device %s", id.ID)
	}
	if !hasUsage(id.Cert, x509.ExtKeyUsageServerAuth) || !hasUsage(id.Cert, x509.ExtKeyUsageClientAuth) {
		return errors.New("group: the member certificate is not for client and server use")
	}
	// A Linux member holds all of the admin parts, a Mac none of them.
	admin := id.GroupCA.Key != nil
	if (id.PhoneCA != nil) != admin || (id.PhoneCA != nil && id.PhoneCA.Key == nil) || (id.Phone != nil) != admin {
		return errors.New("group: the identity holds only some of the CA keys and the clipbridge.local certificate")
	}
	if !admin {
		return nil
	}
	if err := checkCA(id.PhoneCA, "iPhone CA"); err != nil {
		return err
	}
	if err := checkLeaf(id.Phone, id.PhoneCA.Cert, id.Key, "clipbridge.local certificate"); err != nil {
		return err
	}
	if err := id.Phone.VerifyHostname(PhoneName); err != nil {
		return fmt.Errorf("group: %w", err)
	}
	return nil
}

func checkCA(ca *CA, what string) error {
	c := ca.Cert
	if c == nil || !c.IsCA || !c.BasicConstraintsValid || c.MaxPathLen != 0 {
		return fmt.Errorf("group: the %s certificate is not a CA with path length 0", what)
	}
	if pub, ok := c.PublicKey.(*ecdsa.PublicKey); !ok || pub.Curve != elliptic.P256() {
		return fmt.Errorf("group: the %s key is not a P-256 key", what)
	}
	if c.CheckSignatureFrom(c) != nil {
		return fmt.Errorf("group: the %s certificate is not self-signed", what)
	}
	if ca.Key != nil && !ca.Key.PublicKey.Equal(c.PublicKey) {
		return fmt.Errorf("group: the %s key does not match its certificate", what)
	}
	return nil
}

func checkLeaf(c, ca *x509.Certificate, key *ecdsa.PrivateKey, what string) error {
	if c == nil {
		return fmt.Errorf("group: the %s is missing", what)
	}
	if c.IsCA {
		return fmt.Errorf("group: the %s is a CA", what)
	}
	if err := c.CheckSignatureFrom(ca); err != nil {
		return fmt.Errorf("group: the %s is not from its CA: %w", what, err)
	}
	if !key.PublicKey.Equal(c.PublicKey) {
		return fmt.Errorf("group: the %s does not match the device key", what)
	}
	return nil
}

func hasUsage(c *x509.Certificate, u x509.ExtKeyUsage) bool {
	for _, have := range c.ExtKeyUsage {
		if have == u {
			return true
		}
	}
	return false
}

// Renew returns an identity with new certificates for those that end
// within their renewal period (240 days for the member certificate, 60 days
// for the clipbridge.local one), and reports whether anything changed. A
// clipbridge.local certificate that starts in the future, issued while the
// clock was ahead, is replaced too, since the iPhone would reject it. A
// certificate that already ends with its CA is kept: a new one could not
// last longer. Only a device that holds the CA keys renews its own
// certificates; others get theirs from a member that does (RenewMember).
func (id *Identity) Renew(now time.Time) (*Identity, bool, error) {
	next := *id
	changed := false
	if id.GroupCA.Key != nil && renewable(id.Cert, id.GroupCA.Cert, now, memberRenewBefore) {
		cert, err := id.GroupCA.IssueMember(id.ID, &id.Key.PublicKey, now)
		if err != nil {
			return id, false, err
		}
		next.Cert, changed = cert, true
	}
	if id.Phone != nil && id.PhoneCA.Key != nil && renewable(id.Phone, id.PhoneCA.Cert, now, phoneRenewBefore) {
		cert, err := id.PhoneCA.IssuePhone(&id.Key.PublicKey, now)
		if err != nil {
			return id, false, err
		}
		next.Phone, changed = cert, true
	}
	return &next, changed, nil
}

// RenewMember returns a new member certificate for the member at the other
// end of a connection, whose certificate peer is from the group CA and ends
// within its renewal period, for the same device and key. It returns nil
// when the certificate is not due, or this device does not hold the group
// CA key: then another member renews it.
func (id *Identity) RenewMember(peer *x509.Certificate, now time.Time) (*x509.Certificate, error) {
	if id.GroupCA.Key == nil || !renewable(peer, id.GroupCA.Cert, now, memberRenewBefore) {
		return nil, nil
	}
	if err := peer.CheckSignatureFrom(id.GroupCA.Cert); err != nil {
		return nil, fmt.Errorf("group: the certificate to renew is not from the group CA: %w", err)
	}
	dev, err := DeviceOf(peer)
	if err != nil {
		return nil, err
	}
	pub, ok := peer.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("group: the certificate to renew has no ECDSA key")
	}
	return id.GroupCA.IssueMember(dev, pub, now)
}

// WithCert returns the identity with a member certificate that another
// member renewed for it. The certificate must be from the group CA, name
// this device and its key, and end later than the current one.
func (id *Identity) WithCert(der []byte) (*Identity, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("group: the renewed certificate: %w", err)
	}
	next := *id
	next.Cert = cert
	if err := next.Check(); err != nil {
		return nil, err
	}
	if !cert.NotAfter.After(id.Cert.NotAfter) {
		return nil, errors.New("group: the renewed certificate does not end later than the current one")
	}
	return &next, nil
}

// renewable reports whether a certificate should be replaced: it starts in
// the future, or it ends within before and its CA lasts longer than it. A
// clock before the CA's start is wrong, and nothing is renewed then.
func renewable(c, ca *x509.Certificate, now time.Time, before time.Duration) bool {
	switch {
	case now.Before(ca.NotBefore):
		return false
	case now.Before(c.NotBefore):
		return true
	}
	return now.After(c.NotAfter.Add(-before)) && ca.NotAfter.After(c.NotAfter)
}

// identityFile is the format of the identity file. Keys are PKCS #8 and
// certificates DER, both base64 in JSON.
type identityFile struct {
	Version    int    `json:"v"`
	Device     string `json:"device"`
	Key        []byte `json:"key"`
	Cert       []byte `json:"cert"`
	GroupCA    []byte `json:"group_ca"`
	GroupCAKey []byte `json:"group_ca_key,omitempty"`
	PhoneCA    []byte `json:"phone_ca,omitempty"`
	PhoneCAKey []byte `json:"phone_ca_key,omitempty"`
	Phone      []byte `json:"phone,omitempty"`
}

const fileVersion = 1

// Save writes the identity to dir/identity.json, readable only by its
// owner. It replaces the file in one step, so a crash leaves either the old
// identity or the new one.
func (id *Identity) Save(dir string) error {
	if err := id.Check(); err != nil {
		return err
	}
	f := identityFile{
		Version: fileVersion,
		Device:  string(id.ID),
		Cert:    id.Cert.Raw,
		GroupCA: id.GroupCA.Cert.Raw,
	}
	var err error
	if f.Key, err = x509.MarshalPKCS8PrivateKey(id.Key); err != nil {
		return err
	}
	if id.GroupCA.Key != nil {
		if f.GroupCAKey, err = x509.MarshalPKCS8PrivateKey(id.GroupCA.Key); err != nil {
			return err
		}
	}
	if id.PhoneCA != nil {
		f.PhoneCA, f.Phone = id.PhoneCA.Cert.Raw, id.Phone.Raw
		if id.PhoneCA.Key != nil {
			if f.PhoneCAKey, err = x509.MarshalPKCS8PrivateKey(id.PhoneCA.Key); err != nil {
				return err
			}
		}
	}
	data, err := json.MarshalIndent(f, "", "\t")
	if err != nil {
		return err
	}
	return atomicfile.Write(filepath.Join(dir, FileName), append(data, '\n'), 0o600)
}

// Load reads the identity from dir/identity.json. It returns ErrNoGroup if
// there is none.
func Load(dir string) (*Identity, error) {
	data, err := os.ReadFile(filepath.Join(dir, FileName))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNoGroup
	}
	if err != nil {
		return nil, err
	}
	id, err := parseIdentity(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", filepath.Join(dir, FileName), err)
	}
	return id, nil
}

func parseIdentity(data []byte) (*Identity, error) {
	var f identityFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, err
	}
	if f.Version != fileVersion {
		return nil, fmt.Errorf("unknown identity file version %d", f.Version)
	}
	id := &Identity{ID: DeviceID(f.Device)}
	var err error
	if id.Key, err = parseKey(f.Key); err != nil {
		return nil, err
	}
	if id.Cert, err = x509.ParseCertificate(f.Cert); err != nil {
		return nil, err
	}
	if id.GroupCA, err = parseCA(f.GroupCA, f.GroupCAKey); err != nil {
		return nil, err
	}
	if f.PhoneCA != nil || f.PhoneCAKey != nil || f.Phone != nil {
		phoneCA, err := parseCA(f.PhoneCA, f.PhoneCAKey)
		if err != nil {
			return nil, err
		}
		id.PhoneCA = &phoneCA
		if id.Phone, err = x509.ParseCertificate(f.Phone); err != nil {
			return nil, err
		}
	}
	if err := id.Check(); err != nil {
		return nil, err
	}
	return id, nil
}

func parseCA(cert, key []byte) (CA, error) {
	var ca CA
	var err error
	if ca.Cert, err = x509.ParseCertificate(cert); err != nil {
		return CA{}, err
	}
	if key != nil {
		if ca.Key, err = parseKey(key); err != nil {
			return CA{}, err
		}
	}
	return ca, nil
}

func parseKey(der []byte) (*ecdsa.PrivateKey, error) {
	k, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, err
	}
	key, ok := k.(*ecdsa.PrivateKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, errors.New("a key is not a P-256 key")
	}
	return key, nil
}
