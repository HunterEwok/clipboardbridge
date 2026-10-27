// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"fmt"
	"slices"
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
// iPhone CA. The device must be connected. A device whose keys sit in a
// file becomes an admin only with allowFileKey, which the user gives after
// a warning (docs/protocol.md, section 17).
func (s *Service) makeAdmin(target string, allowFileKey bool) (string, error) {
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
		return "", fmt.Errorf("%s offers no admin key: it runs an older Clipboard Bridge, or in a container that may not hold the group's keys (its log says so)", d.Name)
	}
	store, kind, proof := group.StoreOf(peer.KeyStore, group.RoleFull), "", ""
	if rec := s.deviceRecord(peer.ID); rec != nil && rec.Key == peer.Key && rec.Store == group.StoreProven {
		store, kind, proof = rec.Store, rec.Kind, rec.Proof
	}
	if store == group.StoreFile && !allowFileKey {
		return "", fmt.Errorf("%s keeps its keys in a file, which a thief with it can copy and then act as an admin until another admin removes it; to make it an admin anyway, run cbb admin -allow-file-key %s", d.Name, target)
	}
	k, err := x509.ParsePKIXPublicKey(peer.AdminKey)
	pub, ok := k.(*ecdsa.PublicKey)
	if err != nil || !ok {
		return "", fmt.Errorf("the admin key that %s offers is no ECDSA key", d.Name)
	}
	adminCA, err := id.RootCA().IssueAdmin(peer.ID, pub, s.cfg.now())
	if err != nil {
		return "", err
	}
	// The device record names the admin CA first, so the iPhone CA that
	// follows the admin message goes to a listed admin.
	adminKey := group.KeyHashOf(adminCA)
	r, err := s.signRecord(id, group.RecordBody{Type: group.RecordDevice, Device: peer.ID, Name: d.Name, Role: group.RoleFull,
		OS: d.OS, Key: &peer.Key, Admin: &adminKey, Store: store, Kind: kind, Proof: proof})
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
			!s.records.Revoked(group.KeyHashOf(chain[1])) && !s.records.Frozen(group.KeyHashOf(chain[1]))
	}
	// The root is the device whose own record has this key: an ID alone is
	// what a joining device picks itself.
	key := group.KeyHashOf(chain[0])
	if root, rootKey := s.records.RootMember(); root == dev && rootKey == key && !s.records.Revoked(key) {
		return true
	}
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
	if _, _, taken := s.takenOver(id); taken {
		// A root taken over keeps it, for when it undoes the takeover.
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

// takeOver takes the group over from its lost root, on an admin of a group
// whose root is a computer, as an admin phone does in a phone group
// (docs/protocol.md, section 10): it makes a new root and names it in a
// root record that its admin CA signs. Under the new root it then revokes
// the old root's key and the lost root's own key, keeping every device the
// old root admitted and every other admin, records itself as the group's
// root, and replaces the iPhone CA, which the lost root held.
func (s *Service) takeOver(target string) (string, error) {
	if err := s.keysAllowed(); err != nil {
		return "", err
	}
	d, err := s.findDevice(target)
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	id, nd := s.id, s.nd
	s.mu.Unlock()
	s.recMu.Lock()
	root := s.records.RootDevice()
	s.recMu.Unlock()
	switch {
	case id.Legacy():
		return "", errors.New("this group was made before roots and admins: every Linux and Windows member holds its keys, so there is no root to take over")
	case id.IsRoot():
		return "", errors.New("this device is the group's root already")
	case !id.IsAdmin():
		return "", errors.New("only an admin takes the group over; this device is none")
	case !s.computerRooted():
		return "", errors.New("the group's root is a phone: an admin phone takes the group over, never a computer")
	case d.ID != string(root):
		return "", fmt.Errorf("%s is not the group's root; cbb status shows which device is", d.Name)
	case !id.ServesPhone():
		return "", errors.New("this admin does not hold the iPhone CA yet, which the new root replaces; connect it to another admin first, or take the group over on another admin")
	}
	lostKeys := s.keysOf(group.DeviceID(d.ID), nd)
	if len(lostKeys) == 0 {
		return "", fmt.Errorf("the key of %s is unknown", d.ID)
	}
	now := s.cfg.now()
	newRoot, err := group.NewRootCA(now)
	if err != nil {
		return "", err
	}
	phoneCA, err := group.NewPhoneCA(now)
	if err != nil {
		return "", err
	}
	oldRoot, oldPhoneCA := group.KeyHashOf(id.Root()), group.KeyHashOf(id.PhoneCA.Cert)
	rr, err := s.signRecord(id, group.RecordBody{Type: group.RecordRoot, Root: newRoot.Cert.Raw})
	if err != nil {
		return "", err
	}
	// The root record goes into the records first: what the new root signs
	// counts only with it.
	s.addRecords("", []group.Record{rr})
	s.recMu.Lock()
	roots := s.records.Roots()
	keep := s.records.Admitted(oldRoot)
	devs := s.records.Devices()
	s.recMu.Unlock()
	s.mu.Lock()
	next, err := s.id.TakenOver(newRoot, roots, now)
	if err == nil {
		err = s.setIdentityLocked(next)
	}
	s.mu.Unlock()
	if err != nil {
		return "", err
	}
	nd.SendRecords([]group.Record{rr})
	// The new root starts a period of its own once the records below
	// settle (refreshCredential), under a tag the servers never saw.

	revoke := group.RecordBody{Type: group.RecordRevoke, Keys: append(append([]group.KeyHash{oldRoot}, lostKeys...), oldPhoneCA)}
	var self *group.Device
	for i, dev := range devs {
		switch {
		case dev.Role == group.RoleShortcut:
			revoke.Keys = append(revoke.Keys, dev.Key)
		case dev.ID == id.ID:
			self = &devs[i]
		}
		if dev.AdminKey != nil && dev.ID != group.DeviceID(d.ID) && !slices.Contains(keep, *dev.AdminKey) {
			keep = append(keep, *dev.AdminKey)
		}
	}
	revoke.Keep = slices.DeleteFunc(keep, func(k group.KeyHash) bool { return slices.Contains(lostKeys, k) })
	name := s.cfg.Name
	if self != nil {
		name = self.Name
	}
	if !group.ValidName(name) {
		name = defaultName(group.RoleFull, id.ID)
	}
	key := group.KeyHashOf(id.Cert)
	var rs []group.Record
	for _, body := range []group.RecordBody{revoke, {Type: group.RecordDevice, Device: id.ID, Name: name, Role: group.RoleFull, OS: s.cfg.OS, Key: &key, Store: group.KeyStoreOf(id.Key)}} {
		r, err := s.signRecord(next, body)
		if err != nil {
			return "", err
		}
		rs = append(rs, r)
	}
	s.mu.Lock()
	err = s.takePhoneCALocked(*phoneCA)
	s.mu.Unlock()
	if err != nil {
		return "", fmt.Errorf("replacing the iPhone CA: %w", err)
	}
	s.publish(nd, rs...)
	nd.SharePhoneCA()
	s.logf("cbb: took the group over from %s (%s); this device is the group's root now", d.Name, d.ID)
	s.logf("cbb: replaced the group's iPhone CA; the iPhones that use the shortcut must pair again (cbb pair -phone)")
	return d.Name, nil
}
