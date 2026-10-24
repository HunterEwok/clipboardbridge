// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/HunterEwok/clipboardbridge/internal/control"
	"github.com/HunterEwok/clipboardbridge/internal/group"
	"github.com/HunterEwok/clipboardbridge/internal/node"
	"github.com/HunterEwok/clipboardbridge/internal/pair"
)

// The group's devices list and revocation (docs/protocol.md, section 10):
// the member keeps the group's signed records, gives them to its peers,
// refuses the devices they revoke, and, where it is an admin (it holds the
// group CA key, or an admin CA from the root phone), records the devices it
// admits and removes devices on request.

// recordStore is the service as the node's store of records.
type recordStore struct{ s *Service }

func (r recordStore) Digest() string {
	r.s.recMu.Lock()
	defer r.s.recMu.Unlock()
	if r.s.records == nil {
		return ""
	}
	return r.s.records.Digest()
}

func (r recordStore) All() []group.Record {
	r.s.recMu.Lock()
	defer r.s.recMu.Unlock()
	if r.s.records == nil {
		return nil
	}
	return r.s.records.All()
}

func (r recordStore) Add(from group.DeviceID, rs []group.Record) []group.Record {
	return r.s.addRecords(from, rs)
}

func (r recordStore) Settle(fresh []group.Record) { r.s.settleRecords(fresh) }

// loadRecords reads the records of the group of id; a file that cannot be
// read leaves the set empty, since the peers give the records again.
func (s *Service) loadRecords(id *group.Identity) *group.Records {
	recs, err := group.LoadRecords(s.cfg.StateDir, id.GroupCA.Cert)
	if err != nil {
		s.logf("cbb: reading the device records: %v", err)
		return group.NewRecords(id.GroupCA.Cert)
	}
	return recs
}

// addRecords adds the valid records among rs, saves them, and returns
// those that were new. settleRecords carries out what they change once
// they are on their way to the peers.
func (s *Service) addRecords(from group.DeviceID, rs []group.Record) []group.Record {
	s.recMu.Lock()
	defer s.recMu.Unlock()
	recs := s.records
	if recs == nil {
		return nil
	}
	fresh, errs := recs.AddAll(rs)
	for _, err := range errs {
		s.logf("cbb: dropped a device record from %s: %v", orThis(from), err)
	}
	if len(fresh) > 0 {
		if err := recs.Save(s.cfg.StateDir); err != nil {
			s.logf("cbb: saving the device records: %v", err)
		}
	}
	return fresh
}

// settleRecords follows records addRecords returned: a new root is
// trusted, and after a revocation the connections to devices that are now
// refused close. It runs after the records were queued for the peers, so
// that a revoked device gets the record that revokes it.
func (s *Service) settleRecords(fresh []group.Record) {
	revoked, rooted := false, false
	for _, r := range fresh {
		revoked = revoked || r.Type() == group.RecordRevoke
		rooted = rooted || r.Type() == group.RecordRoot
	}
	if rooted {
		s.mu.Lock()
		err := s.adoptRootsLocked()
		s.mu.Unlock()
		if err != nil {
			s.logf("cbb: trusting the group's new root: %v", err)
		}
	}
	if revoked || rooted {
		s.afterRevocation()
	}
}

// adoptRootsLocked starts trusting the roots the records lead to when they
// go further than the identity's, after a root record handed the group to
// a new root (docs/protocol.md, section 10). s.mu is held.
func (s *Service) adoptRootsLocked() error {
	if s.id == nil || s.nd == nil {
		return nil
	}
	s.recMu.Lock()
	roots := s.records.Roots()
	s.recMu.Unlock()
	if len(roots) <= len(s.id.Roots) {
		return nil
	}
	next, err := s.id.WithRoots(roots)
	if err != nil {
		return err
	}
	if err := s.setIdentityLocked(next); err != nil {
		return err
	}
	s.logf("cbb: the group has a new root, %s", roots[len(roots)-1].Subject.CommonName)
	return nil
}

func orThis(from group.DeviceID) string {
	if from == "" {
		return "this device"
	}
	return string(from)
}

// afterRevocation closes the connections to devices that are now refused,
// and tells whether this device itself was removed.
func (s *Service) afterRevocation() {
	s.mu.Lock()
	id, nd := s.id, s.nd
	s.mu.Unlock()
	if nd != nil {
		nd.Recheck()
	}
	s.pruneTunnel()
	s.dropRevokedPhoneCA()
	if id != nil && s.allow(id.ID, []*x509.Certificate{id.Cert}) != nil {
		s.logf("cbb: this device was removed from the group; the other members refuse it until it pairs again")
	}
}

// allow is the TLS check of member connections: it refuses devices that the
// records revoke.
func (s *Service) allow(_ group.DeviceID, chain []*x509.Certificate) error {
	s.recMu.Lock()
	defer s.recMu.Unlock()
	if s.records == nil {
		return nil
	}
	return s.records.Refused(chain)
}

// signRecord signs a record for this group with the group CA key of id, or
// with its admin CA.
func (s *Service) signRecord(id *group.Identity, body group.RecordBody) (group.Record, error) {
	ca, chain := id.Signer()
	if ca == nil {
		return group.Record{}, errNotAdmin
	}
	body.Group = group.Tag(id.GroupCA.Cert)
	body.TimeMS = s.cfg.now().UnixMilli()
	body.By = id.ID
	return group.SignRecord(body, ca.Key, chain...)
}

var errNotAdmin = errors.New("only an admin can change the devices list: the group's root, an admin it made (cbb admin), or an admin phone")

// publish adds records made on this member and sends them to the peers.
func (s *Service) publish(nd *node.Node, rs ...group.Record) {
	fresh := s.addRecords("", rs)
	if len(fresh) > 0 && nd != nil {
		nd.SendRecords(fresh)
	}
	s.settleRecords(fresh)
}

// recordDevice records a device this member admitted, if it is an admin.
func (s *Service) recordDevice(dev group.DeviceID, name, role, os string, key group.KeyHash) {
	s.mu.Lock()
	id, nd := s.id, s.nd
	s.mu.Unlock()
	if id == nil {
		return
	}
	if ca, _ := id.Signer(); ca == nil {
		return
	}
	if !group.ValidName(name) {
		name = defaultName(role, dev)
	}
	r, err := s.signRecord(id, group.RecordBody{Type: group.RecordDevice, Device: dev, Name: name, Role: role, OS: os, Key: &key})
	if err != nil {
		s.logf("cbb: recording %s in the devices list: %v", dev, err)
		return
	}
	s.publish(nd, r)
}

// recordAdmitted records a computer that a pairing window admitted.
func (s *Service) recordAdmitted(res *pair.Result) {
	role := group.RoleFull
	if res.Info.Role == pair.RoleLite {
		role = group.RoleLite
	}
	s.recordDevice(res.Device, res.Info.Name, role, res.Info.OS, group.KeyHashOf(res.Cert))
}

// recordPhone records an iPhone that paired for the shortcut.
func (s *Service) recordPhone(phoneID string) {
	raw, err := hex.DecodeString(phoneID)
	if err != nil {
		return
	}
	s.recordDevice(group.DeviceID(phoneID), "iPhone", group.RoleShortcut, group.OSiOS, group.PhoneKeyHash(raw))
}

// defaultName names a device that has no valid name: its role and the start
// of its ID.
func defaultName(role string, dev group.DeviceID) string {
	return role + " " + string(dev)[:min(8, len(dev))]
}

// roleOf maps a member role to the role in a device record.
func roleOf(r node.Role) string {
	switch r {
	case node.Full:
		return group.RoleFull
	case node.Phone:
		return group.RolePhone
	}
	return group.RoleLite
}

// ensureListed records this member, and the connected peers, in the devices
// list when they are not in it yet, as in a group made before the list
// existed. Only a member that holds the root's key does.
func (s *Service) ensureListed() {
	s.listMu.Lock()
	defer s.listMu.Unlock()
	s.mu.Lock()
	id, nd := s.id, s.nd
	s.mu.Unlock()
	if id == nil || nd == nil || id.RootCA() == nil {
		return
	}
	s.recMu.Lock()
	listed := map[group.KeyHash]group.Device{}
	for _, d := range s.records.Devices() {
		listed[d.Key] = d
	}
	s.recMu.Unlock()
	var rs []group.Record
	add := func(dev group.DeviceID, name, role, os string, key group.KeyHash) {
		body := group.RecordBody{Type: group.RecordDevice, Device: dev, Name: name, Role: role, OS: os, Key: &key}
		if d, ok := listed[key]; ok {
			// A computer whose record names no system or another one, as a
			// Windows PC that joined as a Linux member: record what its
			// hello says, keeping the rest of its record.
			if d.Role != group.RoleFull || os == "" || d.OS == os {
				return
			}
			body.Name, body.Admin = d.Name, d.AdminKey
		}
		if !group.ValidName(body.Name) {
			body.Name = defaultName(role, dev)
		}
		r, err := s.signRecord(id, body)
		if err != nil {
			s.logf("cbb: recording %s in the devices list: %v", dev, err)
			return
		}
		rs = append(rs, r)
	}
	add(id.ID, s.cfg.Name, roleOf(s.cfg.Role), s.cfg.OS, group.KeyHashOf(id.Cert))
	for _, p := range nd.Peers() {
		add(p.ID, p.Name, roleOf(p.Role), p.OS, p.Key)
	}
	if len(rs) > 0 {
		s.publish(nd, rs...)
	}
}

// trackSeen notes when the connected peers were last seen.
func (s *Service) trackSeen(peers []node.Peer) {
	now := s.cfg.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	online := map[group.DeviceID]bool{}
	for _, p := range peers {
		online[p.ID] = true
		s.seen[p.ID] = now
	}
	for id := range s.online {
		if !online[id] {
			s.seen[id] = now // it was there until now
		}
	}
	s.online = online
}

// devices returns the devices list as cbb status shows it: the
// devices in the records, then this device and the connected peers that
// are not in them yet.
func (s *Service) devices() ([]control.Device, error) {
	s.mu.Lock()
	id, nd := s.id, s.nd
	seen := make(map[group.DeviceID]time.Time, len(s.seen))
	for k, v := range s.seen {
		seen[k] = v
	}
	s.mu.Unlock()
	if id == nil || nd == nil {
		return nil, s.errNoGroup()
	}
	peers := map[group.DeviceID]node.Peer{}
	for _, p := range nd.Peers() {
		peers[p.ID] = p
	}
	s.recMu.Lock()
	list := s.records.Devices()
	root := s.records.RootDevice()
	s.recMu.Unlock()

	// In a legacy group every Linux and Windows member holds the CA keys.
	legacy := id.Legacy()
	now := s.cfg.now()
	var out []control.Device
	shown := map[group.DeviceID]bool{}
	entry := func(dev group.DeviceID, name, role, os string, admin, listed bool) {
		d := control.Device{ID: string(dev), Name: name, Role: role, OS: os, Listed: listed, Self: dev == id.ID, Root: dev == root}
		d.Admin = admin || (legacy && keyHolder(role, os))
		if _, ok := peers[dev]; ok || d.Self {
			d.Online, d.LastSeenMS = true, now.UnixMilli()
		} else if t, ok := seen[dev]; ok {
			d.LastSeenMS = t.UnixMilli()
		}
		if d.Self {
			d.Admin = id.IsAdmin()
		}
		out = append(out, d)
		shown[dev] = true
	}
	for _, d := range list {
		os := d.OS
		if p, ok := peers[d.ID]; ok && p.OS != "" {
			os = p.OS
		}
		entry(d.ID, d.Name, d.Role, os, d.Admin, true)
	}
	if !shown[id.ID] {
		entry(id.ID, s.cfg.Name, roleOf(s.cfg.Role), s.cfg.OS, false, false)
	}
	for _, p := range nd.Peers() {
		if !shown[p.ID] {
			entry(p.ID, p.Name, roleOf(p.Role), p.OS, false, false)
		}
	}
	return out, nil
}

// revoke removes a device, named by its device ID or its name, from the
// group: it signs a revocation of its key, which spreads to every member.
func (s *Service) revoke(target string) (string, error) {
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
	admin := s.adminKeyOf(group.DeviceID(d.ID))
	// An admin of a group whose root is a computer held the iPhone CA,
	// which goes with it.
	replace := admin != nil && !id.Legacy() && (id.IsRoot() || s.computerRooted())
	switch {
	case !id.IsAdmin():
		return "", errNotAdmin
	case d.Self:
		return "", errors.New("a device cannot remove itself; run cbb revoke on another member")
	case id.Legacy() && keyHolder(d.Role, d.OS):
		return "", errors.New("this member holds the group's keys, so removing it needs a new group; this is not supported yet")
	case d.ID == string(root) && d.Role == group.RolePhone:
		return "", errors.New("this phone holds the group's root; remove it from another admin phone, which takes the group over")
	case d.ID == string(root):
		return "", fmt.Errorf("this computer holds the group's root; run cbb takeover %s on an admin, which takes the group over and removes it", d.Name)
	case admin != nil && !id.IsRoot():
		return "", fmt.Errorf("%s is an admin; only the group's root or an admin phone removes an admin, since this computer's admin key sits in a file", d.Name)
	case replace && !id.ServesPhone():
		return "", fmt.Errorf("%s is an admin and holds the iPhone CA, which goes with it, but this device does not hold it yet; remove it on the root or on another admin", d.Name)
	}
	key, ok := s.keyOf(group.DeviceID(d.ID), nd)
	if !ok {
		return "", fmt.Errorf("the key of %s is unknown", d.ID)
	}
	// An admin goes with its admin key, and the devices it admitted stay.
	body := group.RecordBody{Type: group.RecordRevoke, Keys: []group.KeyHash{key}}
	if admin != nil {
		body.Keys = append(body.Keys, *admin)
		s.recMu.Lock()
		// Its own removals stop counting with it, so this record names
		// them again.
		for _, k := range s.records.RevokedBy(*admin) {
			if !slices.Contains(body.Keys, k) {
				body.Keys = append(body.Keys, k)
			}
		}
		for _, k := range s.records.Admitted(*admin) {
			if k != key && !slices.Contains(body.Keys, k) {
				body.Keep = append(body.Keep, k)
			}
		}
		s.recMu.Unlock()
	}
	var phoneCA *group.CA
	if replace {
		// A new iPhone CA, and the old one and every shortcut's token
		// revoked: the iPhones pair again with the new profile.
		if phoneCA, err = group.NewPhoneCA(s.cfg.now()); err != nil {
			return "", err
		}
		body.Keys = append(body.Keys, group.KeyHashOf(id.PhoneCA.Cert))
		s.recMu.Lock()
		for _, dev := range s.records.Devices() {
			if dev.Role == group.RoleShortcut {
				body.Keys = append(body.Keys, dev.Key)
			}
		}
		s.recMu.Unlock()
	}
	r, err := s.signRecord(id, body)
	if err != nil {
		return "", err
	}
	if phoneCA != nil {
		s.mu.Lock()
		err = s.takePhoneCALocked(*phoneCA)
		s.mu.Unlock()
		if err != nil {
			return "", fmt.Errorf("replacing the iPhone CA: %w", err)
		}
	}
	s.publish(nd, r)
	if phoneCA != nil {
		nd.SharePhoneCA()
		s.logf("cbb: replaced the group's iPhone CA; the iPhones that use the shortcut must pair again (cbb pair -phone)")
	}
	s.logf("cbb: removed %s (%s) from the group", d.Name, d.ID)
	return d.Name, nil
}

// adminKeyOf returns the key of a listed device's admin CA, nil when it has
// none.
func (s *Service) adminKeyOf(dev group.DeviceID) *group.KeyHash {
	s.recMu.Lock()
	defer s.recMu.Unlock()
	for _, d := range s.records.Devices() {
		if d.ID == dev {
			return d.AdminKey
		}
	}
	return nil
}

// keyOf returns the key of a device: from its record, or from its
// connection when it has none.
func (s *Service) keyOf(dev group.DeviceID, nd *node.Node) (group.KeyHash, bool) {
	s.recMu.Lock()
	list := s.records.Devices()
	s.recMu.Unlock()
	for _, d := range list {
		if d.ID == dev {
			return d.Key, true
		}
	}
	for _, p := range nd.Peers() {
		if p.ID == dev {
			return p.Key, true
		}
	}
	return group.KeyHash{}, false
}

// PhoneRevoked reports whether the iPhone with this phone ID was removed.
func (g phoneGroup) PhoneRevoked(phoneID string) bool {
	raw, err := hex.DecodeString(phoneID)
	if err != nil {
		return true
	}
	g.s.recMu.Lock()
	defer g.s.recMu.Unlock()
	return g.s.records != nil && g.s.records.Revoked(group.PhoneKeyHash(raw))
}

// keyHolder reports whether a device of a legacy group holds the CA keys:
// every computer but a Mac does.
func keyHolder(role, os string) bool { return role == group.RoleFull && os != group.OSMacOS }
