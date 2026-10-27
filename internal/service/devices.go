// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
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
		// A freeze refuses devices as a revocation does.
		switch r.Type() {
		case group.RecordRevoke, group.RecordFreeze, group.RecordThaw:
			revoked = true
		}
		rooted = rooted || r.Type() == group.RecordRoot
	}
	// A root record may not count yet when it comes: a takeover's root
	// record counts once the records that make its signer an admin are in,
	// and those may come later from another peer. So the roots are checked
	// after every record that can change them.
	if rooted || revoked {
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
	if len(fresh) > 0 {
		s.refreshCredential()
	}
}

// adoptRootsLocked makes the identity trust the roots the records lead to
// when they differ from its own, after a root record handed the group to a
// new root or a takeover stopped counting (docs/protocol.md, section 10).
// The roots are compared by content, not by number, so a root the records
// do not name never stays trusted. s.mu is held.
func (s *Service) adoptRootsLocked() error {
	if s.id == nil || s.nd == nil {
		return nil
	}
	s.recMu.Lock()
	roots, empty := s.records.Roots(), s.records.Len() == 0
	s.recMu.Unlock()
	// A set that is empty, as after a records file that could not be read,
	// says nothing yet: the peers give the records again.
	if empty || slices.EqualFunc(roots, s.id.Roots, (*x509.Certificate).Equal) {
		return nil
	}
	if _, _, taken := s.takenOver(s.id); taken {
		// A root computer an admin took the group over from keeps its
		// root key, so that removing that admin undoes the takeover.
		return nil
	}
	next, err := s.id.WithRoots(roots)
	if err != nil {
		return err
	}
	dropped := s.id.GroupCA.Key != nil && next.GroupCA.Key == nil
	if dropped {
		next = s.withAdminKey(next)
	}
	if err := s.setIdentityLocked(next); err != nil {
		return err
	}
	if dropped {
		// The hellos of new connections tell the others that this member
		// no longer holds the old keys.
		s.logf("cbb: the group was upgraded; deleted this member's copies of its old CA keys")
		go s.nd.Reconnect()
	}
	if len(roots) == 0 {
		// A takeover from the first root stopped counting.
		s.logf("cbb: the group's root is its first one again")
		return nil
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
	if id != nil {
		switch err := s.allow(id.ID, ownChain(id)); {
		case errors.Is(err, group.ErrRecordsOnly):
			s.logf("cbb: %s took the group over from this computer, its root; if this computer is not lost, cbb revoke %s undoes it", s.takenOverBy(id), s.takenOverBy(id))
		case err != nil:
			s.logf("cbb: this device was removed from the group; the other members refuse it until it pairs again")
		}
	}
}

// takenOverBy names the admin that took the group over from this root
// computer, "" when none did.
func (s *Service) takenOverBy(id *group.Identity) string {
	dev, _, ok := s.takenOver(id)
	if !ok {
		return ""
	}
	s.recMu.Lock()
	defer s.recMu.Unlock()
	for _, d := range s.records.Devices() {
		if d.ID == dev {
			return d.Name
		}
	}
	return string(dev)
}

// takenOver returns the device of the admin that took the group over from
// this root computer, and that admin's CA key (group.Records.TakenOver).
func (s *Service) takenOver(id *group.Identity) (group.DeviceID, group.KeyHash, bool) {
	s.recMu.Lock()
	defer s.recMu.Unlock()
	if s.records == nil || id == nil || !id.IsRoot() {
		return "", group.KeyHash{}, false
	}
	return s.records.TakenOver(ownChain(id))
}

// ownChain is the chain this device presents: its member certificate and
// the admin CA that issued it, if one did.
func ownChain(id *group.Identity) []*x509.Certificate {
	if id.Issuer != nil {
		return []*x509.Certificate{id.Cert, id.Issuer}
	}
	return []*x509.Certificate{id.Cert}
}

// allow is the TLS check of member connections: it refuses devices that the
// records revoke.
func (s *Service) allow(_ group.DeviceID, chain []*x509.Certificate) error {
	s.recMu.Lock()
	defer s.recMu.Unlock()
	if s.records == nil {
		return nil
	}
	err := s.records.Refused(chain)
	if err != nil {
		if _, _, ok := s.records.TakenOver(chain); ok {
			return group.ErrRecordsOnly
		}
	}
	return err
}

// signRecord signs a record for this group with the group CA key of id, or
// with its admin CA.
func (s *Service) signRecord(id *group.Identity, body group.RecordBody) (group.Record, error) {
	ca, chain := id.Signer()
	if ca == nil {
		return group.Record{}, errNotAdmin
	}
	if s.frozen(id) {
		return group.Record{}, errFrozen
	}
	body.Group = group.Tag(id.GroupCA.Cert)
	body.TimeMS = s.cfg.now().UnixMilli()
	body.By = id.ID
	return group.SignRecord(body, ca.Key, chain...)
}

var errFrozen = errors.New("another admin froze this computer's admin key: it changes nothing until the group's root or an admin phone unfreezes it")

// frozen reports whether the records freeze this device's admin CA.
func (s *Service) frozen(id *group.Identity) bool {
	ca, chain := id.Signer()
	if ca == nil || len(chain) == 0 {
		return false
	}
	s.recMu.Lock()
	defer s.recMu.Unlock()
	return s.records != nil && s.records.Frozen(group.KeyHashOf(ca.Cert))
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
	add := func(dev group.DeviceID, name, role, os string, key group.KeyHash, store string) {
		body := group.RecordBody{Type: group.RecordDevice, Device: dev, Name: name, Role: role, OS: os, Key: &key, Store: store}
		if d, ok := listed[key]; ok {
			// A computer whose record names no system or another one, as a
			// Windows PC that joined as a Linux member, or that its record
			// has in a file while its hello says hardware, as a computer
			// with its keys in a TPM recorded when it was admitted: record
			// what its hello says, keeping the rest of its record.
			newOS := os != "" && d.OS != os
			newStore := d.Store == group.StoreFile && store == group.StoreHardware
			if d.Role != group.RoleFull || !newOS && !newStore {
				return
			}
			body.Name, body.Admin, body.Kind, body.Proof = d.Name, d.AdminKey, d.Kind, d.Proof
			if !newOS {
				body.OS = d.OS
			}
			if !newStore {
				body.Store = d.Store
			}
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
	add(id.ID, s.cfg.Name, roleOf(s.cfg.Role), s.cfg.OS, group.KeyHashOf(id.Cert), group.KeyStoreOf(id.Key))
	for _, p := range nd.Peers() {
		add(p.ID, p.Name, roleOf(p.Role), p.OS, p.Key, p.KeyStore)
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
		// A member with the lower device ID dials this one; when the
		// connection came up only once this one dialed back, the member
		// could not reach it, as a firewall here would do.
		if d := s.dialers[p.ID]; d != nil && d.fallback && !s.online[p.ID] {
			s.unreached[p.ID] = true
		}
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
	id, nd, eng := s.id, s.nd, s.eng
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

	frozen := map[group.DeviceID]bool{}
	for _, d := range list {
		frozen[d.ID] = d.Frozen
	}
	selfFrozen := s.frozen(id)
	// In a legacy group every Linux and Windows member holds the CA keys.
	legacy := id.Legacy()
	now := s.cfg.now()
	var out []control.Device
	shown := map[group.DeviceID]bool{}
	entry := func(dev group.DeviceID, name, role, os, store string, admin, listed bool) {
		d := control.Device{ID: string(dev), Name: name, Role: role, OS: os, Store: store, Listed: listed, Self: dev == id.ID, Root: dev == root, Frozen: frozen[dev]}
		d.Admin = admin || (legacy && keyHolder(role, os))
		d.OldKeys = !legacy && !d.Self && s.holdsOldKeys(dev, peers)
		if _, ok := peers[dev]; ok || d.Self {
			d.Online, d.LastSeenMS = true, now.UnixMilli()
		} else if t, ok := seen[dev]; ok {
			d.LastSeenMS = t.UnixMilli()
		}
		if d.Self {
			d.Admin = id.IsAdmin() && !selfFrozen
		}
		info := s.cfg.Device.Clean()
		if d.Self {
			d.Mode = eng.Mode().String()
		}
		if p, ok := peers[dev]; ok {
			info, d.Mode = p.Device, p.Mode
		} else if !d.Self {
			info = group.DeviceInfo{}
		}
		d.Form, d.OSVersion, d.Version, d.MAC = info.Form, info.OSVersion, info.Version, info.MAC
		out = append(out, d)
		shown[dev] = true
	}
	for _, d := range list {
		os := d.OS
		if p, ok := peers[d.ID]; ok && p.OS != "" {
			os = p.OS
		}
		entry(d.ID, d.Name, d.Role, os, d.Store, d.Admin, true)
	}
	if !shown[id.ID] {
		entry(id.ID, s.cfg.Name, roleOf(s.cfg.Role), s.cfg.OS, group.KeyStoreOf(id.Key), false, false)
	}
	for _, p := range nd.Peers() {
		if !shown[p.ID] {
			entry(p.ID, p.Name, roleOf(p.Role), p.OS, group.StoreOf(p.KeyStore, roleOf(p.Role)), false, false)
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
	// The root an admin took the group over from removes that admin,
	// which undoes the takeover (docs/protocol.md, section 10).
	undo, undoCA, _ := s.takenOver(id)
	undoing := undo != "" && d.ID == string(undo)
	if undoing {
		admin = &undoCA
	}
	// An admin of a group whose root is a computer held the iPhone CA,
	// which goes with it; a watch never held it.
	replace := admin != nil && d.Role != group.RoleWatch && !id.Legacy() && (id.IsRoot() || s.computerRooted())
	switch {
	case !id.IsAdmin():
		return "", errNotAdmin
	case d.Self:
		return "", errors.New("a device cannot remove itself; run cbb revoke on another member")
	case id.Legacy() && keyHolder(d.Role, d.OS):
		return "", fmt.Errorf("%s holds the group's keys, so removing it needs a new group; this is not supported yet", d.Name)
	case d.ID == string(root) && !undoing && d.Role == group.RolePhone:
		return "", fmt.Errorf("%s holds the group's root; remove it on another admin phone, which takes the group over", d.Name)
	case d.ID == string(root) && !undoing:
		return "", fmt.Errorf("%s holds the group's root; run cbb takeover %s on an admin, which takes the group over and removes it", d.Name, d.Name)
	case !id.Legacy() && s.holdsOldKeys(group.DeviceID(d.ID), peersOf(nd)):
		return "", errOldKeys(d.Name)
	case admin != nil && !id.IsRoot():
		return "", fmt.Errorf("%s is an admin; only the group's root or an admin phone removes an admin, since this computer's admin key sits in a file", d.Name)
	case replace && !id.ServesPhone():
		return "", fmt.Errorf("%s is an admin and holds the iPhone CA, which goes with it, but this device does not hold it yet; remove it on the root or on another admin", d.Name)
	}
	keys := s.keysOf(group.DeviceID(d.ID), nd)
	if len(keys) == 0 {
		return "", fmt.Errorf("the key of %s is unknown", d.ID)
	}
	// Every key the device ever had in the group goes, so none of them
	// stays a member nobody sees. An admin goes with its admin key, and the
	// devices it admitted stay.
	body := group.RecordBody{Type: group.RecordRevoke, Keys: keys}
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
			if !slices.Contains(keys, k) && !slices.Contains(body.Keys, k) {
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

// rename gives the device that target names a new name: an admin signs a
// device record like its newest one with that name, and the newest record
// of a device names it everywhere (docs/protocol.md, section 10). It
// returns the old name.
func (s *Service) rename(target, name string) (string, error) {
	name = strings.TrimSpace(name)
	if !group.ValidName(name) {
		return "", errors.New("a device name has 1 to 64 characters and no control characters")
	}
	d, err := s.findDevice(target)
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	id, nd := s.id, s.nd
	s.mu.Unlock()
	if !id.IsAdmin() {
		return "", errNotAdmin
	}
	rec := s.deviceRecord(group.DeviceID(d.ID))
	if rec == nil {
		return "", fmt.Errorf("%s is not in the devices list yet; rename it once it is", d.Name)
	}
	if rec.Name == name {
		return rec.Name, nil
	}
	r, err := s.signRecord(id, group.RecordBody{Type: group.RecordDevice, Device: rec.ID, Name: name, Role: rec.Role,
		OS: rec.OS, Key: &rec.Key, Admin: rec.AdminKey, Store: rec.Store, Kind: rec.Kind, Proof: rec.Proof})
	if err != nil {
		return "", err
	}
	s.publish(nd, r)
	s.logf("cbb: renamed %s (%s) to %s", rec.Name, rec.ID, name)
	return rec.Name, nil
}

// freeze freezes (on true) or unfreezes the admin computer that target
// names (docs/design.md, "Who may remove an admin"). Any admin freezes
// another admin computer: from then on nothing the frozen admin signs
// counts, beyond the records it signed before, and its connections are
// refused. Only the root unfreezes it here; the root and the admin phones
// remove it with cbb revoke or Remove.
func (s *Service) freeze(target string, on bool) (string, error) {
	d, err := s.findDevice(target)
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	id, nd := s.id, s.nd
	s.mu.Unlock()
	admin := s.adminKeyOf(group.DeviceID(d.ID))
	s.recMu.Lock()
	root := s.records.RootDevice()
	frozen := admin != nil && s.records.Frozen(*admin)
	s.recMu.Unlock()
	switch {
	case !id.IsAdmin():
		return "", errNotAdmin
	case d.Self:
		return "", errors.New("a device cannot freeze or unfreeze itself")
	case id.Legacy():
		return "", errors.New("a legacy group has no admins to freeze")
	case d.ID == string(root):
		return "", fmt.Errorf("%s holds the group's root, which nobody freezes", d.Name)
	case admin == nil || d.Role == group.RolePhone:
		return "", fmt.Errorf("%s is no admin computer; only those are frozen, and an ordinary device is removed with cbb revoke", d.Name)
	case on && frozen:
		return "", fmt.Errorf("%s is frozen already", d.Name)
	case !on && !frozen:
		return "", fmt.Errorf("%s is not frozen", d.Name)
	case !on && !id.IsRoot():
		return "", errors.New("only the group's root or an admin phone unfreezes an admin, since this computer's admin key sits in a file")
	}
	body := group.RecordBody{Type: group.RecordFreeze, Keys: []group.KeyHash{*admin}}
	s.recMu.Lock()
	if on {
		// What it signed until now keeps counting, so the devices it
		// admitted stay; nothing it signs later does.
		body.Records = s.records.SignedBy(*admin)
	} else {
		body.Type, body.Keys, body.Records = group.RecordThaw, nil, s.records.FreezesOf(*admin)
	}
	s.recMu.Unlock()
	r, err := s.signRecord(id, body)
	if err != nil {
		return "", err
	}
	s.publish(nd, r)
	if on {
		s.logf("cbb: froze the admin %s (%s)", d.Name, d.ID)
	} else {
		s.logf("cbb: unfroze the admin %s (%s)", d.Name, d.ID)
	}
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

// keysOf returns the keys of a device that are not revoked: every key its
// records name, and the key of its connection when it has one.
func (s *Service) keysOf(dev group.DeviceID, nd *node.Node) []group.KeyHash {
	s.recMu.Lock()
	list := s.records.Devices()
	s.recMu.Unlock()
	var keys []group.KeyHash
	for _, d := range list {
		if d.ID == dev {
			keys = append(keys, d.Keys...)
		}
	}
	for _, p := range nd.Peers() {
		if p.ID == dev && !slices.Contains(keys, p.Key) {
			keys = append(keys, p.Key)
		}
	}
	return keys
}

// idTaken reports whether a joining device may not take the device ID dev:
// a device record names it, with any key, or a member with it is connected
// (docs/protocol.md, section 6). A device that joins again gets a new ID.
func (s *Service) idTaken(dev group.DeviceID) bool {
	s.mu.Lock()
	id, nd := s.id, s.nd
	s.mu.Unlock()
	if id != nil && id.ID == dev {
		return true
	}
	s.recMu.Lock()
	known := s.records != nil && s.records.Known(dev)
	s.recMu.Unlock()
	if known || nd == nil {
		return known
	}
	return slices.ContainsFunc(nd.Peers(), func(p node.Peer) bool { return p.ID == dev })
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

// deviceRecord returns the devices list's entry for dev, or nil.
func (s *Service) deviceRecord(dev group.DeviceID) *group.Device {
	s.recMu.Lock()
	defer s.recMu.Unlock()
	for _, d := range s.records.Devices() {
		if d.ID == dev {
			return &d
		}
	}
	return nil
}
