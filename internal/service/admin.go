// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"

	"github.com/HunterEwok/clipboardbridge/internal/control"
	"github.com/HunterEwok/clipboardbridge/internal/group"
	"github.com/HunterEwok/clipboardbridge/internal/node"
)

// Admins of a group a computer created (docs/design.md, "Full members,
// admins and the operating system"): the root makes a full member an admin
// by certifying the admin key its hello offers, and the admins share the
// iPhone CA, which an admin that removes another admin replaces.

// makeAdmin makes the device that target names an admin, on the group's
// root: it issues the admin CA for the admin key the device's hello
// offers, records it in the device's record and sends it, followed by the
// iPhone CA. The device must be connected.
func (s *Service) makeAdmin(target string) (string, error) {
	d, err := s.findDevice(target)
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	id, nd := s.id, s.nd
	s.mu.Unlock()
	switch {
	case !id.IsRoot():
		return "", errors.New("only the group's root makes admins: run cbb admin on the computer that created the group, or use \"Make it an admin\" on the root phone")
	case d.Self:
		return "", errors.New("this device is the group's root, which is more than an admin")
	case d.Role != group.RoleFull:
		return "", fmt.Errorf("%s is no computer with the service; only those can be admins", d.Name)
	case d.Admin:
		return "", fmt.Errorf("%s is already an admin", d.Name)
	}
	var peer *node.Peer
	for _, p := range nd.Peers() {
		if string(p.ID) == d.ID {
			peer = &p
			break
		}
	}
	switch {
	case peer == nil:
		return "", fmt.Errorf("%s is not connected; it gets its admin CA over its connection, so start it and try again", d.Name)
	case peer.AdminKey == nil:
		return "", fmt.Errorf("%s offers no admin key; update clipboardbridge there", d.Name)
	}
	k, err := x509.ParsePKIXPublicKey(peer.AdminKey)
	pub, ok := k.(*ecdsa.PublicKey)
	if err != nil || !ok {
		return "", fmt.Errorf("the admin key that %s offers is no ECDSA key", d.Name)
	}
	adminCA, err := id.GroupCA.IssueAdmin(peer.ID, pub, s.cfg.now())
	if err != nil {
		return "", err
	}
	// The device record names the admin CA first, so the iPhone CA that
	// follows the admin message goes to a listed admin.
	adminKey := group.KeyHashOf(adminCA)
	r, err := s.signRecord(id, group.RecordBody{Type: group.RecordDevice, Device: peer.ID, Name: d.Name, Role: group.RoleFull,
		OS: d.OS, Key: &peer.Key, Admin: &adminKey})
	if err != nil {
		return "", err
	}
	s.publish(nd, r)
	if !nd.SendAdmin(peer.ID, adminCA) {
		return "", fmt.Errorf("%s left before it got its admin CA; it is listed as an admin, so run cbb admin again when it is back", d.Name)
	}
	s.logf("cbb: made %s (%s) an admin of the group", d.Name, d.ID)
	return d.Name, nil
}

// adminPeer reports whether the peer dev, whose verified chain is chain, is the
// group's root or one of its admins: its chain carries its own admin CA,
// or the records list it as the root or as an admin with that key.
func (s *Service) adminPeer(dev group.DeviceID, chain []*x509.Certificate) bool {
	if len(chain) == 0 {
		return false
	}
	s.mu.Lock()
	id := s.id
	s.mu.Unlock()
	s.recMu.Lock()
	defer s.recMu.Unlock()
	if s.records == nil {
		return false
	}
	if len(chain) > 1 && chain[1].IsCA && chain[1].Subject.CommonName == group.AdminName(dev) {
		// The chain is the verified one (node's peerChain), but the admin
		// CA is checked here too: it must have issued the leaf and stand
		// under one of the group's roots, or it proves nothing.
		return chain[0].CheckSignatureFrom(chain[1]) == nil && underRoot(id, chain[1]) &&
			!s.records.Revoked(group.KeyHashOf(chain[1]))
	}
	if s.records.RootDevice() == dev {
		return true
	}
	key := group.KeyHashOf(chain[0])
	for _, d := range s.records.Devices() {
		if d.ID == dev && d.Key == key && d.Admin {
			return true
		}
	}
	return false
}

// underRoot reports whether c is an admin CA that one of the roots of the
// group of id certified.
func underRoot(id *group.Identity, c *x509.Certificate) bool {
	if id == nil {
		return false
	}
	for _, root := range id.Trusted() {
		if group.CheckAdminCA(c, root) == nil {
			return true
		}
	}
	return false
}

// phoneCAFor returns the iPhone CA to send the peer dev, whose hello names
// the iPhone CA key hash theirs: this member's, when it holds one that is
// not revoked, the peer holds another and the peer is the root or an
// admin.
func (s *Service) phoneCAFor(dev group.DeviceID, chain []*x509.Certificate, theirs []byte) *group.CA {
	s.mu.Lock()
	id := s.id
	s.mu.Unlock()
	if id == nil || id.Legacy() || !id.ServesPhone() {
		return nil
	}
	mine := group.KeyHashOf(id.PhoneCA.Cert)
	if bytes.Equal(theirs, mine[:]) || s.revoked(mine) || !s.adminPeer(dev, chain) {
		return nil
	}
	ca := *id.PhoneCA
	return &ca
}

func (s *Service) revoked(k group.KeyHash) bool {
	s.recMu.Lock()
	defer s.recMu.Unlock()
	return s.records != nil && s.records.Revoked(k)
}

// phoneCAReceived takes the iPhone CA and its key that the root or an
// admin sent. An admin keeps it when it holds none, when the records revoke
// the one it holds, or when both stand and the new one's key hash is the
// smaller, so that two admins that replaced it at once agree; otherwise it
// keeps it aside in case the records revoke its own.
func (s *Service) phoneCAReceived(from group.DeviceID, chain []*x509.Certificate, certDER, keyDER []byte) error {
	if !s.adminPeer(from, chain) {
		return errors.New("only the group's root or an admin sends the iPhone CA")
	}
	ca := group.CA{}
	var err error
	if ca.Cert, err = x509.ParseCertificate(certDER); err != nil {
		return fmt.Errorf("the iPhone CA: %w", err)
	}
	k, err := x509.ParsePKCS8PrivateKey(keyDER)
	key, ok := k.(*ecdsa.PrivateKey)
	if err != nil || !ok {
		return errors.New("the iPhone CA key is no ECDSA key")
	}
	ca.Key = key
	h := group.KeyHashOf(ca.Cert)
	if s.revoked(h) {
		return errors.New("the records revoke this iPhone CA")
	}
	s.mu.Lock()
	id := s.id
	switch {
	case id == nil || id.Legacy() || (!id.IsRoot() && id.AdminCA == nil):
		s.mu.Unlock()
		return errors.New("this member is no admin of a group a computer created")
	case id.ServesPhone():
		cur := group.KeyHashOf(id.PhoneCA.Cert)
		if cur == h {
			s.mu.Unlock()
			return nil
		}
		if !s.revoked(cur) && bytes.Compare(h[:], cur[:]) > 0 {
			s.pendingPhoneCA = &ca
			s.mu.Unlock()
			return nil
		}
	}
	err = s.takePhoneCALocked(ca)
	nd := s.nd
	s.mu.Unlock()
	if err != nil {
		return err
	}
	// The other admins that this member is connected to may not have it yet.
	if nd != nil {
		nd.SharePhoneCA()
	}
	return nil
}

// takePhoneCALocked starts serving the shortcut with the iPhone CA ca.
// s.mu is held.
func (s *Service) takePhoneCALocked(ca group.CA) error {
	next, err := s.id.WithPhoneCA(ca, s.cfg.now())
	if err != nil {
		return err
	}
	if err := s.setIdentityLocked(next); err != nil {
		return err
	}
	s.pendingPhoneCA = nil
	s.logf("cbb: this admin holds the group's iPhone CA %s and serves the shortcut", group.Fingerprint(ca.Cert)[:23])
	return nil
}

// dropRevokedPhoneCA stops serving the shortcut with an iPhone CA that the
// records revoke, as after another admin removed an admin and replaced the
// iPhone CA; it takes the new one if it arrived first.
func (s *Service) dropRevokedPhoneCA() {
	s.mu.Lock()
	defer s.mu.Unlock()
	id := s.id
	if id == nil || id.Legacy() || !id.ServesPhone() || !s.revoked(group.KeyHashOf(id.PhoneCA.Cert)) {
		return
	}
	if p := s.pendingPhoneCA; p != nil && !s.revoked(group.KeyHashOf(p.Cert)) {
		if err := s.takePhoneCALocked(*p); err == nil {
			return
		}
	}
	s.pendingPhoneCA = nil
	if err := s.setIdentityLocked(id.WithoutPhoneCA()); err != nil {
		s.logf("cbb: dropping the revoked iPhone CA: %v", err)
		return
	}
	s.logf("cbb: the group replaced its iPhone CA; this admin serves the shortcut again once another admin sends the new one")
}

// computerRooted reports whether the group's root is a computer, from the
// records: then its admins hold the iPhone CA.
func (s *Service) computerRooted() bool {
	s.recMu.Lock()
	defer s.recMu.Unlock()
	if s.records == nil {
		return false
	}
	root := s.records.RootDevice()
	for _, d := range s.records.Devices() {
		if d.ID == root {
			return d.Role == group.RoleFull
		}
	}
	return false
}

// findDevice returns the device that target names, by its device ID or its
// name (case-insensitive).
func (s *Service) findDevice(target string) (control.Device, error) {
	devs, err := s.devices()
	if err != nil {
		return control.Device{}, err
	}
	var match []control.Device
	for _, d := range devs {
		if d.ID == target {
			return d, nil
		}
		if strings.EqualFold(d.Name, target) {
			match = append(match, d)
		}
	}
	switch len(match) {
	case 0:
		return control.Device{}, fmt.Errorf("no device %q in the group; cbb status lists them", target)
	case 1:
		return match[0], nil
	}
	var ids []string
	for _, d := range match {
		ids = append(ids, d.ID)
	}
	return control.Device{}, fmt.Errorf("several devices are named %q; name one by its ID: %s", target, strings.Join(ids, ", "))
}
